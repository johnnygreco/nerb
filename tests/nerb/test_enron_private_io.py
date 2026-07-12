from __future__ import annotations

import errno
import gc
import json
import os
import shutil
import stat
import subprocess
import sys
import weakref
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

import pytest

import nerb.enron_private_io as enron_private_io
from nerb.enron_private_io import (
    EnronPrivateIOError,
    PrivateRun,
    ensure_private_output_allowed,
    find_workspace_root,
    iter_strict_jsonl,
    open_private_binary_input_at,
    open_private_directory_input,
)


def _resolved(path: Path) -> Path:
    return path.resolve()


def _git_workspace(tmp_path: Path, ignore: str = ".private/\n") -> Path:
    if shutil.which("git") is None:
        pytest.skip("git is required for workspace ignore tests")
    root = _resolved(tmp_path / "workspace")
    root.mkdir()
    subprocess.run(["git", "init", "--quiet", str(root)], check=True)
    (root / ".gitignore").write_text(ignore, encoding="utf-8")
    return root


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux capability assertion")
def test_linux_private_transaction_capabilities_are_available() -> None:
    assert enron_private_io._TRANSACTION_CAPABILITIES_AVAILABLE is True  # noqa: SLF001
    assert enron_private_io._LINUX_PROC_FD_CHMOD_AVAILABLE is True  # noqa: SLF001


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _assert_cleanup_fd_accounting() -> None:
    assert enron_private_io._PENDING_CLEANUP_FDS == len(  # noqa: SLF001
        enron_private_io._PENDING_CLEANUP_RESERVATIONS  # noqa: SLF001
    )
    assert enron_private_io._LIVE_CLEANUP_FDS == len(enron_private_io._ACCOUNTED_CLEANUP_FDS)  # noqa: SLF001


def _open_descriptors_for_identity(identity: tuple[int, int]) -> set[int]:
    """Return every descriptor currently bound to one test-created inode."""

    for inventory_path in (Path(f"/proc/{os.getpid()}/fd"), Path("/dev/fd")):
        try:
            names = os.listdir(inventory_path)
        except OSError:
            continue
        matching: set[int] = set()
        for name in names:
            try:
                descriptor = int(name)
                info = os.fstat(descriptor)
            except (OSError, ValueError):
                continue
            if (int(info.st_dev), int(info.st_ino)) == identity:
                matching.add(descriptor)
        return matching
    raise AssertionError("The cleanup regression requires a process descriptor inventory.")


@pytest.mark.parametrize("mode", [0o400, 0o500, 0o600, 0o700])
def test_owner_only_private_mode_accepts_read_only_and_writable_owner_modes(mode: int) -> None:
    assert enron_private_io.is_owner_only_private_mode(mode) is True


@pytest.mark.parametrize("mode", [0o004, 0o040, 0o640, 0o750])
def test_owner_only_private_mode_rejects_group_or_other_access(mode: int) -> None:
    assert enron_private_io.is_owner_only_private_mode(mode) is False


def test_find_workspace_root_from_nonexistent_descendant(tmp_path: Path) -> None:
    root = _git_workspace(tmp_path)

    assert find_workspace_root(root / "missing" / "run") == root


def test_pinned_directory_relative_input_is_private_nofollow_and_caller_owned(tmp_path: Path) -> None:
    root = tmp_path / "private-input"
    root.mkdir(mode=0o700)
    payload = root / "payload.bin"
    payload.write_bytes(b"bound payload")
    payload.chmod(0o600)
    link = root / "link.bin"
    link.symlink_to(payload)
    directory_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        with open_private_binary_input_at(directory_fd, "payload.bin") as handle:
            assert handle.read() == b"bound payload"
        assert os.fstat(directory_fd)
        with pytest.raises(EnronPrivateIOError, match=r"(?i)(regular|private|symlink)"):
            open_private_binary_input_at(directory_fd, "link.bin")
        with pytest.raises(EnronPrivateIOError, match=r"(?i)(name|path|component)"):
            open_private_binary_input_at(directory_fd, "../payload.bin")
    finally:
        os.close(directory_fd)


def test_private_directory_input_rejects_symlinked_parent_components(tmp_path: Path) -> None:
    parent = tmp_path / "actual-parent"
    root = parent / "private-root"
    root.mkdir(parents=True, mode=0o700)
    root.chmod(0o700)
    link = tmp_path / "linked-parent"
    link.symlink_to(parent, target_is_directory=True)

    descriptor = open_private_directory_input(root)
    os.close(descriptor)
    with pytest.raises(EnronPrivateIOError, match=r"(?i)(symlink|directory|safe)"):
        open_private_directory_input(link / root.name)


def test_output_inside_workspace_requires_ignored_target(tmp_path: Path) -> None:
    root = _git_workspace(tmp_path)
    ignored = root / ".private" / "run"
    visible = root / "visible" / "run"

    assert ensure_private_output_allowed(ignored) == ignored
    with pytest.raises(EnronPrivateIOError, match="must be ignored"):
        ensure_private_output_allowed(visible)
    assert ensure_private_output_allowed(visible, allow_unignored_output=True) == visible


def test_unrelated_workspace_hint_cannot_bypass_actual_workspace_policy(tmp_path: Path) -> None:
    root = _git_workspace(tmp_path)
    unrelated = _resolved(tmp_path / "unrelated")
    unrelated.mkdir()

    with pytest.raises(EnronPrivateIOError, match="must be ignored"):
        ensure_private_output_allowed(root / "visible" / "run", workspace_root=unrelated)


def test_output_below_tracked_unignored_directory_is_rejected(tmp_path: Path) -> None:
    root = _git_workspace(tmp_path)
    visible = root / "visible"
    visible.mkdir()
    (visible / ".keep").write_text("tracked\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", ".gitignore", "visible/.keep"], check=True)

    with pytest.raises(EnronPrivateIOError, match="must be ignored"):
        ensure_private_output_allowed(visible / "run")


def test_private_run_requires_ignored_staging_sibling(tmp_path: Path) -> None:
    root = _git_workspace(tmp_path, ignore="/only-final\n")
    final = root / "only-final"

    assert ensure_private_output_allowed(final) == final
    with pytest.raises(EnronPrivateIOError, match="must be ignored"):
        with PrivateRun(final):
            pass
    assert not final.exists()


def test_existing_target_and_non_directory_ancestor_are_rejected(tmp_path: Path) -> None:
    root = _resolved(tmp_path)
    existing = root / "existing"
    existing.mkdir()
    blocker = root / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")

    with pytest.raises(EnronPrivateIOError, match="already exists"):
        ensure_private_output_allowed(existing, workspace_root=None)
    with pytest.raises(EnronPrivateIOError, match="ancestors"):
        ensure_private_output_allowed(blocker / "run", workspace_root=None)


def test_output_rejects_parent_traversal_and_symlink_ancestor(tmp_path: Path) -> None:
    root = _resolved(tmp_path)
    with pytest.raises(EnronPrivateIOError, match="parent traversal"):
        ensure_private_output_allowed(root / "safe" / ".." / "run", workspace_root=None)

    target = root / "real"
    target.mkdir()
    link = root / "link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("directory symlinks are unavailable")
    with pytest.raises(EnronPrivateIOError, match="non-symlink directories"):
        ensure_private_output_allowed(link / "run", workspace_root=None)


def test_private_run_commits_private_tree_despite_umask(tmp_path: Path) -> None:
    final = _resolved(tmp_path) / "private" / "run"
    previous_umask = os.umask(0o777)
    try:
        with PrivateRun(final) as run:
            with run.open_text("records/data.jsonl") as file:
                file.write('{"id":1}\n')
            with run.open_binary("profile.bin") as file:
                file.write(b"profile")

            assert _mode(run.stage_dir) == 0o700
            committed = run.commit()
    finally:
        os.umask(previous_umask)

    assert committed == final
    assert _mode(final) == 0o700
    assert _mode(final / "records") == 0o700
    assert _mode(final / "records" / "data.jsonl") == 0o600
    assert _mode(final / "profile.bin") == 0o600
    assert _mode(final / "COMMITTED") == 0o600
    assert (final / "COMMITTED").read_bytes() == b"nerb.enron.private-run.v2\n"
    assert not list(final.parent.glob(f".{final.name}.stage-*"))


def test_private_run_uses_strict_precommitted_stage_token(tmp_path: Path) -> None:
    final = _resolved(tmp_path) / "run"
    token = "0123456789abcdef01234567"

    with PrivateRun(final, stage_token=token) as run:
        assert run.stage_dir.name == f".{final.name}.stage-{token}"
        with run.open_text("payload.txt") as handle:
            handle.write("private")
        run.commit()

    assert (final / "payload.txt").read_text(encoding="utf-8") == "private"


@pytest.mark.parametrize(
    "token",
    ["", "0" * 23, "0" * 25, "A" * 24, "g" * 24, "../" + "0" * 21],
)
def test_private_run_rejects_invalid_precommitted_stage_token(tmp_path: Path, token: str) -> None:
    final = _resolved(tmp_path) / "run"

    with pytest.raises(EnronPrivateIOError, match="staging token"):
        PrivateRun(final, stage_token=token)

    assert not final.exists()


def test_private_run_rejects_reused_precommitted_stage_token_without_replacing_it(tmp_path: Path) -> None:
    final = _resolved(tmp_path) / "run"
    token = "0123456789abcdef01234567"
    existing = final.parent / f".{final.name}.stage-{token}"
    existing.mkdir(mode=0o700)
    sentinel = existing / "sentinel"
    sentinel.write_text("preserve", encoding="utf-8")
    sentinel.chmod(0o600)

    with pytest.raises(EnronPrivateIOError, match="already in use"):
        with PrivateRun(final, stage_token=token):
            pass

    assert sentinel.read_text(encoding="utf-8") == "preserve"
    assert not final.exists()


def test_private_run_checks_precommitted_parent_identity_before_stage_allocation(tmp_path: Path) -> None:
    final = _resolved(tmp_path) / "run"
    parent = final.parent.stat()
    wrong_identity = (parent.st_dev, parent.st_ino + 1)

    with pytest.raises(EnronPrivateIOError, match="parent identity changed"):
        with PrivateRun(
            final,
            stage_token="0123456789abcdef01234567",
            expected_parent_identity=wrong_identity,
        ):
            pass

    assert not final.exists()
    assert not list(final.parent.glob(f".{final.name}.stage-*"))


def test_private_run_surfaces_cleanup_failure_even_during_body_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    final = _resolved(tmp_path) / "run"
    real_cleanup = PrivateRun._cleanup

    def cleanup_then_fail(run: PrivateRun) -> None:
        real_cleanup(run)
        raise OSError("injected cleanup reporting failure")

    monkeypatch.setattr(PrivateRun, "_cleanup", cleanup_then_fail)
    with pytest.raises(EnronPrivateIOError, match="cleaned up safely") as caught:
        with PrivateRun(final):
            raise RuntimeError("injected body failure")

    assert isinstance(caught.value.__cause__, RuntimeError)
    assert not final.exists()


def test_output_files_use_exclusive_nofollow_open(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    final = _resolved(tmp_path) / "run"
    real_open = enron_private_io.os.open
    opened_flags: list[int] = []

    def recording_open(*args: Any, **kwargs: Any) -> int:
        opened_flags.append(args[1])
        return real_open(*args, **kwargs)

    monkeypatch.setattr(enron_private_io.os, "open", recording_open)
    with PrivateRun(final) as run:
        with run.open_binary("payload.bin") as file:
            file.write(b"payload")
        run.commit()

    assert any(flags & os.O_EXCL for flags in opened_flags)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow:
        assert any(flags & os.O_EXCL and flags & nofollow for flags in opened_flags)


def test_private_run_cleans_stage_when_body_fails(tmp_path: Path) -> None:
    final = _resolved(tmp_path) / "run"

    with pytest.raises(RuntimeError, match="stop"):
        with PrivateRun(final) as run:
            with run.open_text("nested/partial.txt") as file:
                file.write("private")
            raise RuntimeError("stop")

    assert not final.exists()
    assert not list(final.parent.glob(f".{final.name}.stage-*"))
    tombstones = list(final.parent.glob(".nerb-cleanup-*"))
    assert len(tombstones) == 1
    tombstone = tombstones[0]
    token = tombstone.name.removeprefix(".nerb-cleanup-")
    assert len(token) == 48 and all(character in "0123456789abcdef" for character in token)
    assert _mode(tombstone) == 0o700
    assert _mode(tombstone / "nested") == 0o700
    assert _mode(tombstone / "nested" / "partial.txt") == 0o600
    assert (tombstone / "nested" / "partial.txt").read_bytes() == b""
    assert run.cleanup_sensitive_content_wiped is True
    assert run.cleanup_path_tree_removed is False
    assert run.cleanup_tombstone_count == 1


def test_cleanup_never_reports_sensitive_content_wiped_when_a_registered_descriptor_wipe_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    final = _resolved(tmp_path) / "run"
    real_wipe = PrivateRun._wipe_cleanup_descriptors

    def wipe_then_report_failure(run: PrivateRun) -> bool:
        assert real_wipe(run) is True
        return False

    monkeypatch.setattr(PrivateRun, "_wipe_cleanup_descriptors", wipe_then_report_failure)

    with pytest.raises(EnronPrivateIOError, match="cleaned up safely"):
        with PrivateRun(final) as run:
            with run.open_text("private.txt") as handle:
                handle.write("private")
            raise RuntimeError("injected body failure")

    assert run.cleanup_sensitive_content_wiped is False
    assert run.cleanup_tombstone_count == 0


def test_private_run_wipes_open_payload_moved_out_and_its_same_uid_replacement(tmp_path: Path) -> None:
    final = _resolved(tmp_path) / "run"
    parked = final.parent / "parked-private-payload.txt"

    with pytest.raises(RuntimeError, match="stop"):
        with PrivateRun(final) as run:
            payload = run.stage_dir / "private-payload.txt"
            with run.open_text(payload.name) as handle:
                handle.write("original private payload")
            payload.replace(parked)
            payload.write_text("replacement private payload", encoding="utf-8")
            payload.chmod(0o600)
            raise RuntimeError("stop")

    assert parked.read_bytes() == b""
    tombstones = list(final.parent.glob(".nerb-cleanup-*"))
    assert len(tombstones) == 1
    assert (tombstones[0] / "private-payload.txt").read_bytes() == b""


def test_child_cleanup_descriptors_transfer_to_ancestor_and_wipe_file_on_later_failure(tmp_path: Path) -> None:
    outer_final = _resolved(tmp_path) / "outer"
    parked = _resolved(tmp_path) / "parked-child-secret.txt"

    with pytest.raises(RuntimeError, match="later phase failed"):
        with PrivateRun(outer_final) as outer:
            phase_dir = outer.ensure_directory("phases/preparation")
            with PrivateRun(phase_dir / "prepared", allow_unignored_output=True) as child:
                with child.open_text("nested/secret.txt") as handle:
                    handle.write("private child payload")
                child.commit(cleanup_successor=outer)
            (phase_dir / "prepared" / "nested" / "secret.txt").replace(parked)
            raise RuntimeError("later phase failed")

    assert parked.read_bytes() == b""


def test_child_cleanup_descriptors_transfer_to_ancestor_and_wipe_moved_subtree(tmp_path: Path) -> None:
    outer_final = _resolved(tmp_path) / "outer"
    parked = _resolved(tmp_path) / "parked-child-tree"

    with pytest.raises(RuntimeError, match="later phase failed"):
        with PrivateRun(outer_final) as outer:
            phase_dir = outer.ensure_directory("phases/split")
            with PrivateRun(phase_dir / "development", allow_unignored_output=True) as child:
                with child.open_text("nested/secret.txt") as handle:
                    handle.write("private child subtree")
                child.commit(cleanup_successor=outer)
            (phase_dir / "development").replace(parked)
            raise RuntimeError("later phase failed")

    assert (parked / "nested" / "secret.txt").read_bytes() == b""
    assert (parked / "COMMITTED").read_bytes() == b"nerb.enron.private-run.v2\n"


@pytest.mark.parametrize("control_error", [KeyboardInterrupt, SystemExit])
def test_cleanup_successor_transfer_rolls_back_on_control_flow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    control_error: type[BaseException],
) -> None:
    outer_final = _resolved(tmp_path) / "outer"
    real_require = enron_private_io._require_cleanup_descriptors_current

    with PrivateRun(outer_final) as outer:
        with outer.open_text("outer.txt") as handle:
            handle.write("outer private")
        child_final = outer.ensure_directory("phase") / "child"
        with PrivateRun(child_final, allow_unignored_output=True) as child:
            with child.open_text("child.txt") as handle:
                handle.write("child private")
            outer_before = dict(outer._cleanup_file_fds)  # noqa: SLF001
            child_before = dict(child._cleanup_file_fds)  # noqa: SLF001
            restored_before_cleanup: list[dict[tuple[int, int], int]] = []
            real_wipe = PrivateRun._wipe_cleanup_descriptors

            def interrupt_combined_map(descriptors: Mapping[tuple[int, int], int]) -> None:
                real_require(descriptors)
                if len(descriptors) == 2:
                    raise control_error("injected cleanup transfer interruption")

            def observe_cleanup(run: PrivateRun) -> bool:
                if run is child and not restored_before_cleanup:
                    restored_before_cleanup.append(dict(run._cleanup_file_fds))  # noqa: SLF001
                return real_wipe(run)

            monkeypatch.setattr(
                enron_private_io,
                "_require_cleanup_descriptors_current",
                interrupt_combined_map,
            )
            monkeypatch.setattr(PrivateRun, "_wipe_cleanup_descriptors", observe_cleanup)
            with pytest.raises(control_error, match="cleanup transfer interruption"):
                child.commit(cleanup_successor=outer)
            assert restored_before_cleanup == [child_before]
            assert outer._cleanup_file_fds == outer_before  # noqa: SLF001
            assert not (set(child_before) & set(outer_before))
            monkeypatch.setattr(enron_private_io, "_require_cleanup_descriptors_current", real_require)
            monkeypatch.setattr(PrivateRun, "_wipe_cleanup_descriptors", real_wipe)

    assert enron_private_io._LIVE_CLEANUP_FDS == 0  # noqa: SLF001
    assert enron_private_io._PENDING_CLEANUP_FDS == 0  # noqa: SLF001
    assert not enron_private_io._UNRESOLVED_CLEANUP_FDS  # noqa: SLF001


def test_cleanup_successor_must_be_a_distinct_active_ancestor(tmp_path: Path) -> None:
    root = _resolved(tmp_path)

    with pytest.raises(EnronPrivateIOError, match="own cleanup successor"):
        with PrivateRun(root / "self") as run:
            with run.open_text("secret.txt") as handle:
                handle.write("private")
            run.commit(cleanup_successor=run)

    with pytest.raises(EnronPrivateIOError, match="not an ancestor"):
        with PrivateRun(root / "unrelated") as unrelated:
            with PrivateRun(root / "child") as child:
                with child.open_text("secret.txt") as handle:
                    handle.write("private")
                child.commit(cleanup_successor=unrelated)

    with PrivateRun(root / "committed-successor") as committed:
        committed.commit()
    with pytest.raises(EnronPrivateIOError, match="active and uncommitted"):
        with PrivateRun(root / "later-child") as child:
            with child.open_text("secret.txt") as handle:
                handle.write("private")
            child.commit(cleanup_successor=committed)


def test_process_wide_cleanup_bound_rejects_nested_overcommit_atomically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(enron_private_io, "_MAX_PINNED_CLEANUP_FILES", 2)
    outer_final = _resolved(tmp_path) / "outer"

    with pytest.raises(RuntimeError, match="later failure"):
        with PrivateRun(outer_final) as outer:
            with outer.open_text("outer-secret.txt") as handle:
                handle.write("outer private")
            phase_dir = outer.ensure_directory("phase")
            with pytest.raises(EnronPrivateIOError, match="process-wide live limit"):
                with PrivateRun(phase_dir / "child", allow_unignored_output=True) as child:
                    with child.open_text("one.txt") as handle:
                        handle.write("one")
                    with child.open_text("two.txt") as handle:
                        handle.write("two")
                    child.commit(cleanup_successor=outer)
            assert len(outer._cleanup_file_fds) == 1  # noqa: SLF001
            raise RuntimeError("later failure")

    tombstone = next(outer_final.parent.glob(".nerb-cleanup-*"))
    assert (tombstone / "outer-secret.txt").read_bytes() == b""


def test_private_run_preflights_rlimit_with_cleanup_descriptor_reserve(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import resource

    monkeypatch.setattr(enron_private_io, "_current_open_descriptor_count", lambda: 10)
    insufficient = 10 + enron_private_io._PRIVATE_RUN_PERSISTENT_FDS + enron_private_io._PINNED_CLEANUP_FD_RESERVE - 1
    monkeypatch.setattr(resource, "getrlimit", lambda _limit: (insufficient, insufficient))
    final = _resolved(tmp_path) / "run"

    with pytest.raises(EnronPrivateIOError, match="descriptor capacity is insufficient"):
        with PrivateRun(final):
            pass

    assert not final.exists()


def test_private_run_deep_cleanup_succeeds_at_accepted_rlimit(tmp_path: Path) -> None:
    final = _resolved(tmp_path) / "deep-run"
    script = """
import os
import resource
import sys
from pathlib import Path

import nerb.enron_private_io as private_io

final = Path(sys.argv[1])
current = private_io._current_open_descriptor_count()
soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
required = current + private_io._PRIVATE_RUN_PERSISTENT_FDS + private_io._PINNED_CLEANUP_FD_RESERVE
if hard != resource.RLIM_INFINITY and hard < required:
    raise SystemExit(77)
resource.setrlimit(resource.RLIMIT_NOFILE, (required, hard))
try:
    with private_io.PrivateRun(final) as run:
        directory = run.stage_dir
        for index in range(private_io._MAX_PRIVATE_TOMBSTONE_DEPTH):
            directory = directory / f"depth-{index:02d}"
            directory.mkdir(mode=0o700)
            directory.chmod(0o700)
        payload = directory / "secret.bin"
        payload.write_bytes(b"sensitive deep payload")
        payload.chmod(0o600)
        raise RuntimeError("injected body failure")
except RuntimeError:
    pass
tombstones = tuple(final.parent.glob(".nerb-cleanup-*"))
assert len(tombstones) == 1
payloads = tuple(tombstones[0].rglob("secret.bin"))
assert len(payloads) == 1 and payloads[0].read_bytes() == b""
assert private_io._LIVE_CLEANUP_FDS == 0
assert private_io._PENDING_CLEANUP_FDS == 0
assert not private_io._UNRESOLVED_CLEANUP_FDS
"""
    completed = subprocess.run(
        [sys.executable, "-c", script, os.fspath(final)],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode == 77:
        pytest.skip("RLIMIT_NOFILE hard limit is below the cleanup regression requirement")
    assert completed.returncode == 0, completed.stderr


def test_pin_cleanup_tree_adopts_direct_writer_files_once_and_wipes_moved_inode(tmp_path: Path) -> None:
    final = _resolved(tmp_path) / "run"
    parked = _resolved(tmp_path) / "parked-cache.bin"

    with pytest.raises(RuntimeError, match="stop"):
        with PrivateRun(final) as run:
            cache = run.ensure_directory("runtime/cache")
            payload = cache / "third-party.bin"
            payload.write_bytes(b"private third-party cache")
            payload.chmod(0o600)
            assert run.pin_cleanup_tree("runtime/cache") == 1
            assert run.pin_cleanup_tree("runtime/cache") == 0
            payload.replace(parked)
            raise RuntimeError("stop")

    assert parked.read_bytes() == b""


@pytest.mark.parametrize("control_error", [KeyboardInterrupt, SystemExit])
def test_pin_cleanup_tree_settles_helper_return_interruption_after_descriptor_insert(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    control_error: type[BaseException],
) -> None:
    final = _resolved(tmp_path) / "tree-helper-interruption"
    next_final = _resolved(tmp_path) / "tree-helper-next"
    moved = _resolved(tmp_path) / "moved-tree-helper-private.bin"
    interrupted = False
    real_open_cleanup = enron_private_io._open_cleanup_descriptor_at

    with pytest.raises(control_error, match="tree helper return interruption"):
        with PrivateRun(final) as run:
            cache = run.ensure_directory("runtime/cache")
            payload = cache / "third-party.bin"
            payload.write_bytes(b"private tree helper payload")
            payload.chmod(0o600)

            def open_helper_then_interrupt(
                directory_fd: int,
                directory_path: Path,
                name: str,
                flags: int,
                *,
                expected_identity: tuple[int, int],
                target: dict[tuple[int, int], int],
            ) -> None:
                nonlocal interrupted
                real_open_cleanup(
                    directory_fd,
                    directory_path,
                    name,
                    flags,
                    expected_identity=expected_identity,
                    target=target,
                )
                if name == payload.name and not interrupted:
                    interrupted = True
                    payload.replace(moved)
                    raise control_error("injected tree helper return interruption")

            monkeypatch.setattr(enron_private_io, "_open_cleanup_descriptor_at", open_helper_then_interrupt)
            run.pin_cleanup_tree("runtime/cache")

    assert interrupted
    assert moved.read_bytes() == b""
    _assert_cleanup_fd_accounting()
    assert enron_private_io._PENDING_CLEANUP_FDS == 0  # noqa: SLF001
    assert enron_private_io._LIVE_CLEANUP_FDS == 0  # noqa: SLF001
    assert not enron_private_io._UNRESOLVED_CLEANUP_FDS  # noqa: SLF001
    with PrivateRun(next_final) as next_run:
        next_run.commit()
    _assert_cleanup_fd_accounting()
    assert enron_private_io._LIVE_CLEANUP_FDS == 0  # noqa: SLF001
    assert not enron_private_io._UNRESOLVED_CLEANUP_FDS  # noqa: SLF001


@pytest.mark.parametrize("control_error", [KeyboardInterrupt, SystemExit])
def test_pin_cleanup_tree_line_interruption_after_direct_retention_keeps_run_authority(
    tmp_path: Path,
    control_error: type[BaseException],
) -> None:
    final = _resolved(tmp_path) / "tree-direct-retention-interruption"
    moved = _resolved(tmp_path) / "moved-tree-direct-retention-private.bin"
    interrupted = False
    collector_code = enron_private_io._collect_cleanup_tree_descriptors.__code__

    with pytest.raises(control_error, match="tree direct-retention line interruption"):
        with PrivateRun(final) as run:
            cache = run.ensure_directory("runtime/cache")
            payload = cache / "third-party.bin"
            payload.write_bytes(b"private tree direct-retention payload")
            payload.chmod(0o600)
            payload_info = payload.stat()
            payload_identity = int(payload_info.st_dev), int(payload_info.st_ino)

            def interrupt_after_direct_retention(frame: Any, event: str, _argument: Any) -> Any:
                nonlocal interrupted
                if (
                    frame.f_code is collector_code
                    and event == "line"
                    and not interrupted
                    and payload_identity in run._cleanup_file_fds  # noqa: SLF001
                    and frame.f_locals.get("retained_descriptor") == run._cleanup_file_fds.get(payload_identity)  # noqa: SLF001
                ):
                    interrupted = True
                    payload.replace(moved)
                    raise control_error("injected tree direct-retention line interruption")
                return interrupt_after_direct_retention

            sys.settrace(interrupt_after_direct_retention)
            try:
                run.pin_cleanup_tree("runtime/cache")
            finally:
                sys.settrace(None)

    assert interrupted
    assert moved.read_bytes() == b""
    _assert_cleanup_fd_accounting()
    assert enron_private_io._PENDING_CLEANUP_FDS == 0  # noqa: SLF001
    assert enron_private_io._LIVE_CLEANUP_FDS == 0  # noqa: SLF001
    assert not enron_private_io._UNRESOLVED_CLEANUP_FDS  # noqa: SLF001


def test_pin_cleanup_tree_registers_empty_files_in_complete_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(enron_private_io, "_MAX_PINNED_CLEANUP_FILES", 3)
    final = _resolved(tmp_path) / "run"
    parked = _resolved(tmp_path) / "parked-nonempty-cache.bin"

    with pytest.raises(RuntimeError, match="stop"):
        with PrivateRun(final) as run:
            cache = run.ensure_directory("runtime/cache")
            nested = run.ensure_directory("runtime/cache/empty-tombstones")
            for path in (cache / "empty.bin", nested / "also-empty.bin"):
                path.write_bytes(b"")
                path.chmod(0o600)
            payload = cache / "private.bin"
            payload.write_bytes(b"private cache payload")
            payload.chmod(0o600)

            assert run.pin_cleanup_tree("runtime/cache") == 3
            payload.replace(parked)
            raise RuntimeError("stop")

    assert parked.read_bytes() == b""


@pytest.mark.parametrize("payload", [b"", b"late private payload"])
def test_commit_rejects_late_regular_inode_not_in_final_adoption(tmp_path: Path, payload: bytes) -> None:
    final = _resolved(tmp_path) / "run"

    with pytest.raises(EnronPrivateIOError, match="changed before promotion"):
        with PrivateRun(final) as run:
            cache = run.ensure_directory("runtime/cache")
            adopted = cache / "adopted.bin"
            adopted.write_bytes(b"registered")
            adopted.chmod(0o600)
            assert run.pin_cleanup_tree("runtime/cache") == 1
            late = cache / "late.bin"
            late.write_bytes(payload)
            late.chmod(0o600)
            run.commit()

    assert not final.exists()


def test_overlapping_nested_transactions_share_live_cleanup_budget_under_rlimit_256(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import resource

    monkeypatch.setattr(resource, "getrlimit", lambda _limit: (256, 256))
    monkeypatch.setattr(
        enron_private_io,
        "_current_open_descriptor_count",
        lambda: 20 + enron_private_io._LIVE_CLEANUP_FDS,
    )
    outer_final = _resolved(tmp_path) / "outer"

    with pytest.raises(RuntimeError, match="later failure"):
        with PrivateRun(outer_final) as outer:
            for index in range(80):
                with outer.open_text(f"outer-{index:03d}.txt") as handle:
                    handle.write("outer private")
            phase = outer.ensure_directory("phase")
            with (
                PrivateRun(phase / "development", allow_unignored_output=True) as development,
                PrivateRun(phase / "sealed", allow_unignored_output=True) as sealed,
            ):
                for index in range(20):
                    with development.open_text(f"development-{index:03d}.txt") as handle:
                        handle.write("development private")
                    with sealed.open_text(f"sealed-{index:03d}.txt") as handle:
                        handle.write("sealed private")
                sealed.commit(cleanup_successor=outer)
                development.commit(cleanup_successor=outer)
            assert enron_private_io._LIVE_CLEANUP_FDS == 120
            raise RuntimeError("later failure")

    assert enron_private_io._LIVE_CLEANUP_FDS == 0
    assert enron_private_io._PENDING_CLEANUP_FDS == 0


def test_retained_cleanup_authority_keeps_failed_descriptor_for_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    final = _resolved(tmp_path) / "retained"
    with PrivateRun(final) as run:
        with run.open_text("first.txt") as handle:
            handle.write("first private")
        with run.open_text("second.txt") as handle:
            handle.write("second private")
        run.commit(retain_cleanup_authority=True)

    original = enron_private_io._wipe_authenticated_cleanup_descriptor
    failed_identity = next(iter(run._cleanup_file_fds))  # noqa: SLF001

    def fail_one(identity: tuple[int, int], descriptor: int) -> bool:
        return False if identity == failed_identity else original(identity, descriptor)

    monkeypatch.setattr(enron_private_io, "_wipe_authenticated_cleanup_descriptor", fail_one)
    assert run.wipe_retained_cleanup_authority() is False
    assert run.cleanup_authority_retained is True
    assert set(run._cleanup_file_fds) == {failed_identity}  # noqa: SLF001

    monkeypatch.setattr(enron_private_io, "_wipe_authenticated_cleanup_descriptor", original)
    assert run.wipe_retained_cleanup_authority() is True
    assert run.cleanup_authority_retained is False
    assert (final / "first.txt").read_bytes() == b""
    assert (final / "second.txt").read_bytes() == b""


def test_unresolved_cleanup_registry_blocks_then_retries_moved_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    final = _resolved(tmp_path) / "retained"
    moved = _resolved(tmp_path) / "moved-private.txt"
    with PrivateRun(final) as run:
        with run.open_text("private.txt") as handle:
            handle.write("private payload")
        run.commit(retain_cleanup_authority=True)
    (final / "private.txt").replace(moved)
    identity = next(iter(run._cleanup_file_fds))  # noqa: SLF001
    real_wipe = enron_private_io._wipe_authenticated_cleanup_descriptor
    fail_wipe = True

    def injected_wipe(candidate: tuple[int, int], descriptor: int) -> bool:
        if fail_wipe and candidate == identity:
            return False
        return real_wipe(candidate, descriptor)

    monkeypatch.setattr(enron_private_io, "_wipe_authenticated_cleanup_descriptor", injected_wipe)
    try:
        assert run.wipe_retained_cleanup_authority() is False
        assert run.wipe_retained_cleanup_authority() is False
        run.park_unresolved_cleanup_authority()
        assert not run.cleanup_authority_retained
        assert set(enron_private_io._UNRESOLVED_CLEANUP_FDS) == {identity}  # noqa: SLF001
        assert enron_private_io._LIVE_CLEANUP_FDS == 1  # noqa: SLF001

        blocked = _resolved(tmp_path) / "blocked"
        with pytest.raises(EnronPrivateIOError, match="blocks a new private transaction"):
            with PrivateRun(blocked):
                pass
        assert not blocked.exists()
        assert not tuple(blocked.parent.glob(f".{blocked.name}.stage-*"))

        fail_wipe = False
        retry = _resolved(tmp_path) / "retry"
        with PrivateRun(retry) as retry_run:
            retry_run.commit()
        assert moved.read_bytes() == b""
        assert not enron_private_io._UNRESOLVED_CLEANUP_FDS  # noqa: SLF001
        assert enron_private_io._LIVE_CLEANUP_FDS == 0  # noqa: SLF001
        assert enron_private_io._PENDING_CLEANUP_FDS == 0  # noqa: SLF001
    finally:
        fail_wipe = False
        if run.cleanup_authority_retained:
            run.wipe_retained_cleanup_authority()
        enron_private_io._retry_unresolved_cleanup_descriptors()  # noqa: SLF001


def test_failed_generic_cleanup_parks_moved_inode_for_next_entry_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    final = _resolved(tmp_path) / "failed-run"
    moved = _resolved(tmp_path) / "moved-private.txt"
    real_wipe = enron_private_io._wipe_authenticated_cleanup_descriptor
    fail_wipe = True

    def injected_wipe(identity: tuple[int, int], descriptor: int) -> bool:
        if fail_wipe:
            return False
        return real_wipe(identity, descriptor)

    monkeypatch.setattr(enron_private_io, "_wipe_authenticated_cleanup_descriptor", injected_wipe)
    try:
        with pytest.raises(EnronPrivateIOError, match="cleaned up safely"):
            with PrivateRun(final) as run:
                with run.open_text("private.txt") as handle:
                    handle.write("private payload")
                (run.stage_dir / "private.txt").replace(moved)
                raise RuntimeError("injected body failure")
        assert moved.read_text(encoding="utf-8") == "private payload"
        assert len(enron_private_io._UNRESOLVED_CLEANUP_FDS) == 1  # noqa: SLF001
        assert enron_private_io._LIVE_CLEANUP_FDS == 1  # noqa: SLF001

        fail_wipe = False
        retry = _resolved(tmp_path) / "retry"
        with PrivateRun(retry) as retry_run:
            retry_run.commit()
        assert moved.read_bytes() == b""
        assert not enron_private_io._UNRESOLVED_CLEANUP_FDS  # noqa: SLF001
        assert enron_private_io._LIVE_CLEANUP_FDS == 0  # noqa: SLF001
    finally:
        fail_wipe = False
        enron_private_io._retry_unresolved_cleanup_descriptors()  # noqa: SLF001


@pytest.mark.parametrize("control_error", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("interrupt_after_publication", [False, True])
def test_generic_cleanup_publication_survives_control_flow_and_owner_gc(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    control_error: type[BaseException],
    interrupt_after_publication: bool,
) -> None:
    final = _resolved(tmp_path) / "failed-run"
    moved = _resolved(tmp_path) / "moved-private.txt"
    real_wipe = enron_private_io._wipe_authenticated_cleanup_descriptor
    real_publish = enron_private_io._publish_unresolved_cleanup_descriptors
    fail_wipe = True
    interruptions = 0

    def injected_wipe(identity: tuple[int, int], descriptor: int) -> bool:
        if fail_wipe:
            return False
        return real_wipe(identity, descriptor)

    def interrupt_publication(descriptors: dict[tuple[int, int], int]) -> None:
        nonlocal interruptions
        if interruptions < 2:
            interruptions += 1
            if interrupt_after_publication:
                real_publish(descriptors)
            raise control_error("injected registry publication interruption")
        real_publish(descriptors)

    monkeypatch.setattr(enron_private_io, "_wipe_authenticated_cleanup_descriptor", injected_wipe)
    monkeypatch.setattr(enron_private_io, "_publish_unresolved_cleanup_descriptors", interrupt_publication)
    try:
        with pytest.raises(EnronPrivateIOError, match="cleaned up safely"):
            with PrivateRun(final) as run:
                with run.open_text("private.txt") as handle:
                    handle.write("private payload")
                (run.stage_dir / "private.txt").replace(moved)
                raise RuntimeError("injected body failure")
        assert interruptions == (1 if interrupt_after_publication else 2)
        assert not run._cleanup_file_fds  # noqa: SLF001
        assert len(enron_private_io._UNRESOLVED_CLEANUP_FDS) == 1  # noqa: SLF001
        run_reference = weakref.ref(run)
        del run
        gc.collect()
        assert run_reference() is None
        assert moved.read_text(encoding="utf-8") == "private payload"

        fail_wipe = False
        monkeypatch.setattr(enron_private_io, "_publish_unresolved_cleanup_descriptors", real_publish)
        retry = _resolved(tmp_path) / "retry"
        with PrivateRun(retry) as retry_run:
            retry_run.commit()
        assert moved.read_bytes() == b""
        assert not enron_private_io._UNRESOLVED_CLEANUP_FDS  # noqa: SLF001
        assert enron_private_io._LIVE_CLEANUP_FDS == 0  # noqa: SLF001
    finally:
        fail_wipe = False
        monkeypatch.setattr(enron_private_io, "_publish_unresolved_cleanup_descriptors", real_publish)
        enron_private_io._retry_unresolved_cleanup_descriptors()  # noqa: SLF001


@pytest.mark.parametrize("control_error", [KeyboardInterrupt, SystemExit])
def test_registry_postpublication_line_boundary_retries_exact_source_idempotently(
    tmp_path: Path,
    control_error: type[BaseException],
) -> None:
    final = _resolved(tmp_path) / "registry-boundary-run"
    moved = _resolved(tmp_path) / "moved-registry-boundary-private.bin"
    interrupted = False
    park_code = enron_private_io._park_cleanup_descriptor_map.__code__

    with PrivateRun(final) as run:
        with run.open_binary("private.bin") as handle:
            handle.write(b"private registry boundary payload")
        run.commit(retain_cleanup_authority=True)
    (final / "private.bin").replace(moved)

    def interrupt_after_registry_publication(frame: Any, event: str, _argument: Any) -> Any:
        nonlocal interrupted
        if (
            frame.f_code is park_code
            and event == "line"
            and not interrupted
            and frame.f_locals.get("combined") is enron_private_io._UNRESOLVED_CLEANUP_FDS  # noqa: SLF001
            and bool(frame.f_locals["descriptors"])
        ):
            interrupted = True
            raise control_error("injected registry postpublication line interruption")
        return interrupt_after_registry_publication

    try:
        sys.settrace(interrupt_after_registry_publication)
        with pytest.raises(control_error, match="registry postpublication line interruption"):
            run.park_unresolved_cleanup_authority()
        sys.settrace(None)
        assert interrupted
        assert not run._cleanup_file_fds  # noqa: SLF001
        enron_private_io._retry_unresolved_cleanup_descriptors()  # noqa: SLF001
        assert moved.read_bytes() == b""
        _assert_cleanup_fd_accounting()
        assert enron_private_io._PENDING_CLEANUP_FDS == 0  # noqa: SLF001
        assert enron_private_io._LIVE_CLEANUP_FDS == 0  # noqa: SLF001
        assert not enron_private_io._UNRESOLVED_CLEANUP_FDS  # noqa: SLF001
    finally:
        sys.settrace(None)
        enron_private_io._retry_unresolved_cleanup_descriptors()  # noqa: SLF001


@pytest.mark.parametrize("control_error", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("interrupt_after_release", [False, True])
def test_cleanup_close_accounting_survives_control_flow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    control_error: type[BaseException],
    interrupt_after_release: bool,
) -> None:
    final = _resolved(tmp_path) / "retained"
    with PrivateRun(final) as run:
        for name in ("first.txt", "second.txt"):
            with run.open_text(name) as handle:
                handle.write("private payload")
        run.commit(retain_cleanup_authority=True)
    target_identity, target_descriptor = next(iter(run._cleanup_file_fds.items()))  # noqa: SLF001
    real_release = enron_private_io._release_cleanup_fd_slot
    interrupted = False

    def interrupt_release(descriptor: int) -> None:
        nonlocal interrupted
        if descriptor == target_descriptor and not interrupted:
            interrupted = True
            if interrupt_after_release:
                real_release(descriptor)
            raise control_error("injected close accounting interruption")
        real_release(descriptor)

    monkeypatch.setattr(enron_private_io, "_release_cleanup_fd_slot", interrupt_release)
    with pytest.raises(control_error, match="close accounting interruption"):
        run.release_cleanup_authority()
    assert target_identity not in run._cleanup_file_fds  # noqa: SLF001
    assert run.cleanup_authority_retained
    assert enron_private_io._LIVE_CLEANUP_FDS == len(run._cleanup_file_fds) == 1  # noqa: SLF001
    assert enron_private_io._ACCOUNTED_CLEANUP_FDS == set(run._cleanup_file_fds.values())  # noqa: SLF001
    assert enron_private_io._PENDING_CLEANUP_FDS == 0  # noqa: SLF001

    monkeypatch.setattr(enron_private_io, "_release_cleanup_fd_slot", real_release)
    run.release_cleanup_authority()
    assert not run.cleanup_authority_retained
    assert enron_private_io._LIVE_CLEANUP_FDS == 0  # noqa: SLF001
    assert not enron_private_io._ACCOUNTED_CLEANUP_FDS  # noqa: SLF001


@pytest.mark.parametrize("control_error", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("acquisition", ["open", "dup"])
@pytest.mark.parametrize("seam", ["reserve", "activate"])
def test_cleanup_acquisition_reconciles_control_after_real_state_transition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    control_error: type[BaseException],
    acquisition: str,
    seam: str,
) -> None:
    final = _resolved(tmp_path) / f"{acquisition}-{seam}"
    interrupted = False
    if seam == "reserve":
        real_reserve = enron_private_io._reserve_cleanup_fd_slot

        def interrupt_reserve(reservation: object) -> None:
            nonlocal interrupted
            real_reserve(reservation)
            if not interrupted:
                interrupted = True
                raise control_error("injected reserve interruption")

        monkeypatch.setattr(enron_private_io, "_reserve_cleanup_fd_slot", interrupt_reserve)
    else:
        real_activate = enron_private_io._activate_cleanup_fd_slot

        def interrupt_activate(reservation: object, descriptor: int) -> None:
            nonlocal interrupted
            real_activate(reservation, descriptor)
            if not interrupted:
                interrupted = True
                raise control_error("injected activate interruption")

        monkeypatch.setattr(enron_private_io, "_activate_cleanup_fd_slot", interrupt_activate)

    with pytest.raises(control_error, match=f"injected {seam} interruption"):
        with PrivateRun(final) as run:
            if acquisition == "open":
                payload = run.stage_dir / "direct-private.bin"
                payload.write_bytes(b"private payload")
                payload.chmod(0o600)
                run.pin_cleanup_file(payload.name)
            else:
                run.open_text("private.txt")
    assert interrupted
    _assert_cleanup_fd_accounting()
    assert enron_private_io._PENDING_CLEANUP_FDS == 0  # noqa: SLF001
    assert enron_private_io._LIVE_CLEANUP_FDS == 0  # noqa: SLF001
    assert not enron_private_io._UNRESOLVED_CLEANUP_FDS  # noqa: SLF001


@pytest.mark.parametrize("control_error", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("activate_before_interrupt", [False, True])
def test_cleanup_acquisition_parks_authority_when_reconciliation_close_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    control_error: type[BaseException],
    activate_before_interrupt: bool,
) -> None:
    final = _resolved(tmp_path) / "failed-acquisition"
    moved = _resolved(tmp_path) / "moved-private.bin"
    real_activate = enron_private_io._activate_cleanup_fd_slot
    real_close = enron_private_io.os.close
    target_descriptor: int | None = None
    failed_closes = 0

    def interrupt_activate(reservation: object, descriptor: int) -> None:
        nonlocal target_descriptor
        target_descriptor = descriptor
        if activate_before_interrupt:
            real_activate(reservation, descriptor)
        raise control_error("injected activation interruption")

    def fail_reconciliation_close(descriptor: int) -> None:
        nonlocal failed_closes
        if descriptor == target_descriptor and failed_closes < 2:
            failed_closes += 1
            raise OSError("injected acquisition close failure")
        real_close(descriptor)

    monkeypatch.setattr(enron_private_io, "_activate_cleanup_fd_slot", interrupt_activate)
    monkeypatch.setattr(enron_private_io.os, "close", fail_reconciliation_close)
    try:
        with PrivateRun(final) as run:
            payload = run.stage_dir / "direct-private.bin"
            payload.write_bytes(b"private payload")
            payload.chmod(0o600)
            with pytest.raises(control_error, match="activation interruption"):
                run.pin_cleanup_file(payload.name)
            payload.replace(moved)
        assert failed_closes == 2
        assert len(enron_private_io._UNRESOLVED_CLEANUP_FDS) == 1  # noqa: SLF001
        _assert_cleanup_fd_accounting()
        assert enron_private_io._PENDING_CLEANUP_FDS == 0  # noqa: SLF001
        assert enron_private_io._LIVE_CLEANUP_FDS == 1  # noqa: SLF001

        retry = _resolved(tmp_path) / "retry"
        with PrivateRun(retry) as retry_run:
            retry_run.commit()
        assert moved.read_bytes() == b""
        _assert_cleanup_fd_accounting()
        assert enron_private_io._LIVE_CLEANUP_FDS == 0  # noqa: SLF001
    finally:
        monkeypatch.setattr(enron_private_io.os, "close", real_close)
        enron_private_io._retry_unresolved_cleanup_descriptors()  # noqa: SLF001


@pytest.mark.parametrize("control_error", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("acquisition", ["open", "dup"])
@pytest.mark.parametrize("boundary", ["primitive", "helper"])
def test_cleanup_acquisition_recovers_raw_descriptor_after_success_before_return(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    control_error: type[BaseException],
    acquisition: str,
    boundary: str,
) -> None:
    final = _resolved(tmp_path) / f"raw-{acquisition}-{boundary}"
    moved = _resolved(tmp_path) / f"moved-raw-{acquisition}-{boundary}.bin"
    interrupted = False
    with pytest.raises(control_error, match=f"raw {acquisition} {boundary} return interruption"):
        with PrivateRun(final) as run:
            if acquisition == "open":
                payload = run.stage_dir / "direct-private.bin"
                payload.write_bytes(b"private raw-open payload")
                payload.chmod(0o600)
                if boundary == "primitive":
                    real_open_at = enron_private_io._open_at

                    def open_then_interrupt(
                        parent_fd: int,
                        parent_path: Path,
                        name: str,
                        flags: int,
                        mode: int | None = None,
                    ) -> int:
                        nonlocal interrupted
                        descriptor = real_open_at(parent_fd, parent_path, name, flags, mode)
                        if name == payload.name and not interrupted:
                            interrupted = True
                            payload.replace(moved)
                            raise control_error("injected raw open primitive return interruption")
                        return descriptor

                    monkeypatch.setattr(enron_private_io, "_open_at", open_then_interrupt)
                else:
                    real_open_cleanup = enron_private_io._open_cleanup_descriptor_at

                    def open_helper_then_interrupt(
                        directory_fd: int,
                        directory_path: Path,
                        name: str,
                        flags: int,
                        *,
                        expected_identity: tuple[int, int],
                        target: dict[tuple[int, int], int],
                    ) -> None:
                        nonlocal interrupted
                        real_open_cleanup(
                            directory_fd,
                            directory_path,
                            name,
                            flags,
                            expected_identity=expected_identity,
                            target=target,
                        )
                        interrupted = True
                        payload.replace(moved)
                        raise control_error("injected raw open helper return interruption")

                    monkeypatch.setattr(enron_private_io, "_open_cleanup_descriptor_at", open_helper_then_interrupt)
                run.pin_cleanup_file(payload.name)
            else:
                payload = run.stage_dir / "private.txt"
                if boundary == "primitive":
                    real_dup = enron_private_io.os.dup

                    def duplicate_then_interrupt(descriptor: int) -> int:
                        nonlocal interrupted
                        duplicate = real_dup(descriptor)
                        if stat.S_ISREG(os.fstat(descriptor).st_mode) and not interrupted:
                            interrupted = True
                            payload.replace(moved)
                            raise control_error("injected raw dup primitive return interruption")
                        return duplicate

                    monkeypatch.setattr(enron_private_io.os, "dup", duplicate_then_interrupt)
                else:
                    real_duplicate_cleanup = enron_private_io._duplicate_cleanup_descriptor

                    def duplicate_helper_then_interrupt(
                        descriptor: int,
                        *,
                        target: dict[tuple[int, int], int],
                    ) -> None:
                        nonlocal interrupted
                        real_duplicate_cleanup(descriptor, target=target)
                        interrupted = True
                        payload.replace(moved)
                        raise control_error("injected raw dup helper return interruption")

                    monkeypatch.setattr(
                        enron_private_io,
                        "_duplicate_cleanup_descriptor",
                        duplicate_helper_then_interrupt,
                    )
                run.open_text(payload.name)

    assert interrupted
    assert moved.read_bytes() == b""
    _assert_cleanup_fd_accounting()
    assert enron_private_io._PENDING_CLEANUP_FDS == 0  # noqa: SLF001
    assert enron_private_io._LIVE_CLEANUP_FDS == 0  # noqa: SLF001
    assert not enron_private_io._UNRESOLVED_CLEANUP_FDS  # noqa: SLF001


@pytest.mark.parametrize("control_error", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("acquisition", ["open", "dup"])
def test_cleanup_acquisition_settles_two_raw_same_inode_descriptors_after_primitive_control(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    control_error: type[BaseException],
    acquisition: str,
) -> None:
    final = _resolved(tmp_path) / f"two-raw-{acquisition}"
    moved = _resolved(tmp_path) / f"moved-two-raw-{acquisition}.bin"
    private_payload = b"synthetic confidential payload"
    created_descriptors: list[int] = []
    payload_identity: tuple[int, int] | None = None
    interrupted = False

    with monkeypatch.context() as patch:
        with pytest.raises(control_error, match=f"two raw {acquisition} descriptors"):
            with PrivateRun(final) as run:
                payload = run.stage_dir / "payload.bin"
                if acquisition == "open":
                    payload.write_bytes(private_payload)
                    payload.chmod(0o600)
                    payload_info = payload.stat()
                    payload_identity = int(payload_info.st_dev), int(payload_info.st_ino)
                    real_open_at = enron_private_io._open_at

                    def open_twice_then_interrupt(
                        parent_fd: int,
                        parent_path: Path,
                        name: str,
                        flags: int,
                        mode: int | None = None,
                    ) -> int:
                        nonlocal interrupted
                        if name == payload.name and not interrupted:
                            assert flags & os.O_ACCMODE == os.O_RDWR
                            created_descriptors.extend(
                                (
                                    real_open_at(parent_fd, parent_path, name, flags, mode),
                                    real_open_at(parent_fd, parent_path, name, flags, mode),
                                )
                            )
                            interrupted = True
                            payload.replace(moved)
                            raise control_error("injected two raw open descriptors")
                        return real_open_at(parent_fd, parent_path, name, flags, mode)

                    patch.setattr(enron_private_io, "_open_at", open_twice_then_interrupt)
                    run.pin_cleanup_file(payload.name)
                else:
                    real_dup = enron_private_io.os.dup

                    def duplicate_twice_then_interrupt(descriptor: int) -> int:
                        nonlocal interrupted, payload_identity
                        if stat.S_ISREG(os.fstat(descriptor).st_mode) and not interrupted:
                            os.write(descriptor, private_payload)
                            os.fsync(descriptor)
                            os.lseek(descriptor, 0, os.SEEK_SET)
                            assert os.read(descriptor, len(private_payload)) == private_payload
                            payload_info = os.fstat(descriptor)
                            payload_identity = int(payload_info.st_dev), int(payload_info.st_ino)
                            created_descriptors.extend((real_dup(descriptor), real_dup(descriptor)))
                            interrupted = True
                            payload.replace(moved)
                            raise control_error("injected two raw dup descriptors")
                        return real_dup(descriptor)

                    patch.setattr(enron_private_io.os, "dup", duplicate_twice_then_interrupt)
                    run.open_binary(payload.name)

    assert interrupted
    assert len(created_descriptors) == 2
    assert payload_identity is not None
    assert moved.read_bytes() == b""
    _assert_cleanup_fd_accounting()
    assert enron_private_io._PENDING_CLEANUP_FDS == 0  # noqa: SLF001
    assert enron_private_io._LIVE_CLEANUP_FDS == 0  # noqa: SLF001
    assert not enron_private_io._ACCOUNTED_CLEANUP_FDS  # noqa: SLF001
    assert not enron_private_io._UNRESOLVED_CLEANUP_FDS  # noqa: SLF001
    assert not _open_descriptors_for_identity(payload_identity)


@pytest.mark.parametrize("control_error", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("acquisition", ["open", "dup"])
def test_cleanup_acquisition_finally_entry_control_cannot_bypass_settlement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    control_error: type[BaseException],
    acquisition: str,
) -> None:
    final = _resolved(tmp_path) / f"finally-entry-{acquisition}"
    moved = _resolved(tmp_path) / f"moved-finally-entry-{acquisition}.bin"
    private_payload = b"synthetic finally-entry payload"
    payload_identity: tuple[int, int] | None = None
    primitive_failed = False
    interrupted = False
    acquisition_code = (
        enron_private_io._open_cleanup_descriptor_at.__code__
        if acquisition == "open"
        else enron_private_io._duplicate_cleanup_descriptor.__code__
    )

    def interrupt_finally_entry(frame: Any, event: str, _argument: Any) -> Any:
        nonlocal interrupted
        if (
            frame.f_code is acquisition_code
            and event == "line"
            and primitive_failed
            and not interrupted
            and frame.f_locals.get("operation_completed") is False
            and frame.f_locals.get("settlement_completed") is False
            and frame.f_locals.get("reservation") in enron_private_io._PENDING_CLEANUP_RESERVATIONS  # noqa: SLF001
        ):
            interrupted = True
            raise control_error("injected acquisition finally-entry control")
        return interrupt_finally_entry

    with monkeypatch.context() as patch:
        sys.settrace(interrupt_finally_entry)
        try:
            with pytest.raises(control_error, match="finally-entry control"):
                with PrivateRun(final) as run:
                    payload = run.stage_dir / "payload.bin"
                    if acquisition == "open":
                        payload.write_bytes(private_payload)
                        payload.chmod(0o600)
                        payload_info = payload.stat()
                        payload_identity = int(payload_info.st_dev), int(payload_info.st_ino)
                        real_open_at = enron_private_io._open_at

                        def open_twice_then_fail(
                            parent_fd: int,
                            parent_path: Path,
                            name: str,
                            flags: int,
                            mode: int | None = None,
                        ) -> int:
                            nonlocal primitive_failed
                            if name == payload.name and not primitive_failed:
                                real_open_at(parent_fd, parent_path, name, flags, mode)
                                real_open_at(parent_fd, parent_path, name, flags, mode)
                                primitive_failed = True
                                payload.replace(moved)
                                raise RuntimeError("injected raw open failure")
                            return real_open_at(parent_fd, parent_path, name, flags, mode)

                        patch.setattr(enron_private_io, "_open_at", open_twice_then_fail)
                        run.pin_cleanup_file(payload.name)
                    else:
                        real_dup = enron_private_io.os.dup

                        def duplicate_twice_then_fail(descriptor: int) -> int:
                            nonlocal payload_identity, primitive_failed
                            if stat.S_ISREG(os.fstat(descriptor).st_mode) and not primitive_failed:
                                os.write(descriptor, private_payload)
                                os.fsync(descriptor)
                                payload_info = os.fstat(descriptor)
                                payload_identity = int(payload_info.st_dev), int(payload_info.st_ino)
                                real_dup(descriptor)
                                real_dup(descriptor)
                                primitive_failed = True
                                payload.replace(moved)
                                raise RuntimeError("injected raw dup failure")
                            return real_dup(descriptor)

                        patch.setattr(enron_private_io.os, "dup", duplicate_twice_then_fail)
                        run.open_binary(payload.name)
        finally:
            sys.settrace(None)

    assert primitive_failed and interrupted
    assert payload_identity is not None
    assert moved.read_bytes() == b""
    _assert_cleanup_fd_accounting()
    assert not enron_private_io._PENDING_CLEANUP_RESERVATIONS  # noqa: SLF001
    assert not enron_private_io._ACCOUNTED_CLEANUP_FDS  # noqa: SLF001
    assert not enron_private_io._UNRESOLVED_CLEANUP_FDS  # noqa: SLF001
    assert not _open_descriptors_for_identity(payload_identity)


@pytest.mark.parametrize("control_error", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("boundary", ["handle", "stage", "parent"])
def test_private_run_cleanup_settles_moved_payload_after_post_close_control(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    control_error: type[BaseException],
    boundary: str,
) -> None:
    final = _resolved(tmp_path) / f"post-close-{boundary}"
    moved = _resolved(tmp_path) / f"moved-post-close-{boundary}.bin"
    private_payload = b"synthetic cleanup payload"
    payload_identity: tuple[int, int] | None = None
    run_reference: weakref.ReferenceType[PrivateRun] | None = None
    interrupted = False

    def exercise_cleanup() -> None:
        nonlocal interrupted, payload_identity, run_reference
        run = PrivateRun(final)
        run.__enter__()
        run_reference = weakref.ref(run)
        payload = run.stage_dir / "payload.bin"
        handle = run.open_binary(payload.name)
        handle.write(private_payload)
        handle.flush()
        os.fsync(handle.fileno())
        payload_info = payload.stat()
        payload_identity = int(payload_info.st_dev), int(payload_info.st_ino)
        payload.replace(moved)

        with monkeypatch.context() as patch:
            if boundary == "handle":

                class CloseThenInterrupt:
                    @property
                    def closed(self) -> bool:
                        return handle.closed

                    def close(self) -> None:
                        nonlocal interrupted
                        handle.close()
                        if not interrupted:
                            interrupted = True
                            raise control_error("injected handle post-close control")

                run._open_handles[-1] = cast(Any, CloseThenInterrupt())  # noqa: SLF001
            else:
                handle.close()
                target_descriptor = run._stage_fd if boundary == "stage" else run._parent_fd  # noqa: SLF001
                assert target_descriptor is not None
                real_close = enron_private_io.os.close

                def close_then_interrupt(descriptor: int) -> None:
                    nonlocal interrupted
                    real_close(descriptor)
                    if descriptor == target_descriptor and not interrupted:
                        interrupted = True
                        raise control_error(f"injected {boundary} post-close control")

                patch.setattr(enron_private_io.os, "close", close_then_interrupt)

            with pytest.raises(control_error, match=f"{boundary} post-close control"):
                run._cleanup()  # noqa: SLF001

        assert not run._cleanup_file_fds  # noqa: SLF001

    exercise_cleanup()
    gc.collect()

    assert interrupted
    assert run_reference is not None and run_reference() is None
    assert payload_identity is not None
    assert moved.read_bytes() == b""
    _assert_cleanup_fd_accounting()
    assert enron_private_io._PENDING_CLEANUP_FDS == 0  # noqa: SLF001
    assert enron_private_io._LIVE_CLEANUP_FDS == 0  # noqa: SLF001
    assert not enron_private_io._ACCOUNTED_CLEANUP_FDS  # noqa: SLF001
    assert not enron_private_io._UNRESOLVED_CLEANUP_FDS  # noqa: SLF001
    assert not _open_descriptors_for_identity(payload_identity)


@pytest.mark.parametrize("control_error", [KeyboardInterrupt, SystemExit])
def test_cleanup_acquisition_settlement_line_control_cannot_orphan_raw_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    control_error: type[BaseException],
) -> None:
    final = _resolved(tmp_path) / "settlement-line"
    moved = _resolved(tmp_path) / "moved-settlement-line.bin"
    payload_identity: tuple[int, int] | None = None
    primitive_failed = False
    interrupted = False
    real_open_at = enron_private_io._open_at
    settlement_code = enron_private_io._settle_failed_cleanup_acquisition_to_completion.__code__

    def open_then_fail(
        parent_fd: int,
        parent_path: Path,
        name: str,
        flags: int,
        mode: int | None = None,
    ) -> int:
        nonlocal primitive_failed
        descriptor = real_open_at(parent_fd, parent_path, name, flags, mode)
        if name == "payload.bin" and not primitive_failed:
            primitive_failed = True
            (parent_path / name).replace(moved)
            raise RuntimeError("injected primitive failure")
        return descriptor

    def interrupt_after_accounting(frame: Any, event: str, _argument: Any) -> Any:
        nonlocal interrupted
        if frame.f_code is settlement_code and event == "line" and not interrupted:
            reservation = frame.f_locals.get("reservation")
            candidates = frame.f_locals.get("candidates")
            if (
                isinstance(candidates, set)
                and candidates
                and reservation not in enron_private_io._PENDING_CLEANUP_RESERVATIONS  # noqa: SLF001
                and candidates <= enron_private_io._ACCOUNTED_CLEANUP_FDS  # noqa: SLF001
            ):
                interrupted = True
                raise control_error("injected settlement line control")
        return interrupt_after_accounting

    monkeypatch.setattr(enron_private_io, "_open_at", open_then_fail)
    sys.settrace(interrupt_after_accounting)
    try:
        with pytest.raises(RuntimeError, match="primitive failure"):
            with PrivateRun(final) as run:
                payload = run.stage_dir / "payload.bin"
                payload.write_bytes(b"synthetic settlement payload")
                payload.chmod(0o600)
                payload_info = payload.stat()
                payload_identity = int(payload_info.st_dev), int(payload_info.st_ino)
                run.pin_cleanup_file(payload.name)
    finally:
        sys.settrace(None)

    assert primitive_failed and interrupted
    assert payload_identity is not None
    assert moved.read_bytes() == b""
    _assert_cleanup_fd_accounting()
    assert not enron_private_io._PENDING_CLEANUP_RESERVATIONS  # noqa: SLF001
    assert not enron_private_io._ACCOUNTED_CLEANUP_FDS  # noqa: SLF001
    assert not enron_private_io._UNRESOLVED_CLEANUP_FDS  # noqa: SLF001
    assert not _open_descriptors_for_identity(payload_identity)


@pytest.mark.parametrize("control_error", [KeyboardInterrupt, SystemExit])
def test_private_run_outer_cleanup_boundary_settles_loop_line_control(
    tmp_path: Path,
    control_error: type[BaseException],
) -> None:
    final = _resolved(tmp_path) / "cleanup-loop-line"
    moved = _resolved(tmp_path) / "moved-cleanup-loop-line.bin"
    run = PrivateRun(final)
    run.__enter__()
    run_reference = weakref.ref(run)
    payload = run.stage_dir / "payload.bin"
    handle = run.open_binary(payload.name)
    handle.write(b"synthetic loop-line payload")
    handle.flush()
    payload_info = payload.stat()
    payload_identity = int(payload_info.st_dev), int(payload_info.st_ino)
    payload.replace(moved)
    cleanup_once_code = run._cleanup_once.__code__  # noqa: SLF001
    run_holder = [run]
    interrupted = False

    def interrupt_after_writer_close(frame: Any, event: str, _argument: Any) -> Any:
        nonlocal interrupted
        if (
            frame.f_code is cleanup_once_code
            and event == "line"
            and not interrupted
            and handle.closed
            and run_holder[0]._stage_fd is not None  # noqa: SLF001
            and bool(run_holder[0]._cleanup_file_fds)  # noqa: SLF001
        ):
            interrupted = True
            raise control_error("injected cleanup loop line control")
        return interrupt_after_writer_close

    sys.settrace(interrupt_after_writer_close)
    try:
        with pytest.raises(control_error, match="cleanup loop line control"):
            run._cleanup()  # noqa: SLF001
    finally:
        sys.settrace(None)
    run_holder.clear()
    del run
    gc.collect()

    assert interrupted
    assert run_reference() is None
    assert moved.read_bytes() == b""
    _assert_cleanup_fd_accounting()
    assert not enron_private_io._PENDING_CLEANUP_RESERVATIONS  # noqa: SLF001
    assert not enron_private_io._ACCOUNTED_CLEANUP_FDS  # noqa: SLF001
    assert not enron_private_io._UNRESOLVED_CLEANUP_FDS  # noqa: SLF001
    assert not _open_descriptors_for_identity(payload_identity)


@pytest.mark.parametrize("control_error", [KeyboardInterrupt, SystemExit])
def test_private_run_destructor_settles_control_at_cleanup_entry(
    tmp_path: Path,
    control_error: type[BaseException],
) -> None:
    final = _resolved(tmp_path) / "cleanup-entry"
    moved = _resolved(tmp_path) / "moved-cleanup-entry.bin"
    run = PrivateRun(final)
    run.__enter__()
    run_reference = weakref.ref(run)
    payload = run.stage_dir / "payload.bin"
    handle = run.open_binary(payload.name)
    handle.write(b"synthetic cleanup-entry payload")
    handle.flush()
    payload_info = payload.stat()
    payload_identity = int(payload_info.st_dev), int(payload_info.st_ino)
    payload.replace(moved)
    cleanup_code = run._cleanup.__code__  # noqa: SLF001
    interrupted = False

    def interrupt_cleanup_entry(frame: Any, event: str, _argument: Any) -> Any:
        nonlocal interrupted
        if frame.f_code is cleanup_code and event == "line" and not interrupted:
            interrupted = True
            raise control_error("injected cleanup entry control")
        return interrupt_cleanup_entry

    sys.settrace(interrupt_cleanup_entry)
    try:
        with pytest.raises(control_error, match="cleanup entry control"):
            run._cleanup()  # noqa: SLF001
    finally:
        sys.settrace(None)
    del run
    gc.collect()

    assert interrupted
    assert run_reference() is None
    assert moved.read_bytes() == b""
    _assert_cleanup_fd_accounting()
    assert not enron_private_io._PENDING_CLEANUP_RESERVATIONS  # noqa: SLF001
    assert not enron_private_io._ACCOUNTED_CLEANUP_FDS  # noqa: SLF001
    assert not enron_private_io._UNRESOLVED_CLEANUP_FDS  # noqa: SLF001
    assert not _open_descriptors_for_identity(payload_identity)


@pytest.mark.parametrize("control_error", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("acquisition", ["open", "dup"])
def test_cleanup_acquisition_closes_inventory_after_post_open_line_control(
    tmp_path: Path,
    control_error: type[BaseException],
    acquisition: str,
) -> None:
    final = _resolved(tmp_path) / f"inventory-line-{acquisition}"
    acquisition_code = (
        enron_private_io._open_cleanup_descriptor_at.__code__
        if acquisition == "open"
        else enron_private_io._duplicate_cleanup_descriptor.__code__
    )
    interrupted = False
    inventory_descriptor: int | None = None

    def interrupt_after_inventory_open(frame: Any, event: str, _argument: Any) -> Any:
        nonlocal interrupted, inventory_descriptor
        candidate = frame.f_locals.get("inventory_fd")
        if (
            frame.f_code is acquisition_code
            and event == "line"
            and not interrupted
            and isinstance(candidate, int)
            and frame.f_locals.get("before_descriptors") is None
        ):
            inventory_descriptor = candidate
            interrupted = True
            raise control_error("injected inventory post-open line control")
        return interrupt_after_inventory_open

    sys.settrace(interrupt_after_inventory_open)
    try:
        with pytest.raises(control_error, match="inventory post-open line control"):
            with PrivateRun(final) as run:
                if acquisition == "open":
                    payload = run.stage_dir / "payload.bin"
                    payload.write_bytes(b"synthetic inventory payload")
                    payload.chmod(0o600)
                    run.pin_cleanup_file(payload.name)
                else:
                    run.open_binary("payload.bin")
    finally:
        sys.settrace(None)

    assert interrupted and inventory_descriptor is not None
    with pytest.raises(OSError) as closed:
        os.fstat(inventory_descriptor)
    assert closed.value.errno == errno.EBADF
    _assert_cleanup_fd_accounting()
    assert not enron_private_io._PENDING_CLEANUP_RESERVATIONS  # noqa: SLF001
    assert not enron_private_io._ACCOUNTED_CLEANUP_FDS  # noqa: SLF001
    assert not enron_private_io._UNRESOLVED_CLEANUP_FDS  # noqa: SLF001


@pytest.mark.parametrize("control_error", [KeyboardInterrupt, SystemExit])
def test_pinned_inventory_recovers_raw_directory_fd_after_open_control(
    monkeypatch: pytest.MonkeyPatch,
    control_error: type[BaseException],
) -> None:
    real_open = enron_private_io.os.open
    opened_descriptor: int | None = None
    interrupted = False

    def open_then_interrupt(path: str | bytes | os.PathLike[str] | os.PathLike[bytes], flags: int, *args: Any) -> int:
        nonlocal interrupted, opened_descriptor
        descriptor = real_open(path, flags, *args)
        if not interrupted and Path(os.fsdecode(path)) in {
            Path(f"/proc/{os.getpid()}/fd"),
            Path("/dev/fd"),
        }:
            interrupted = True
            opened_descriptor = descriptor
            raise control_error("injected raw inventory open control")
        return descriptor

    monkeypatch.setattr(enron_private_io.os, "open", open_then_interrupt)
    with pytest.raises(control_error, match="raw inventory open control"):
        enron_private_io._open_pinned_descriptor_inventory()  # noqa: SLF001

    assert interrupted and opened_descriptor is not None
    with pytest.raises(OSError) as closed:
        os.fstat(opened_descriptor)
    assert closed.value.errno == errno.EBADF


@pytest.mark.parametrize("control_error", [KeyboardInterrupt, SystemExit])
def test_cleanup_target_map_commit_survives_control_after_descriptor_insert(
    tmp_path: Path,
    control_error: type[BaseException],
) -> None:
    final = _resolved(tmp_path) / "target-map-commit"
    moved = _resolved(tmp_path) / "moved-target-map-private.bin"
    interrupted = False

    class InterruptingOwnershipMap(dict[tuple[int, int], int]):
        def __setitem__(self, identity: tuple[int, int], descriptor: int) -> None:
            nonlocal interrupted
            super().__setitem__(identity, descriptor)
            if not interrupted:
                interrupted = True
                (run.stage_dir / "private.bin").replace(moved)
                raise control_error("injected target-map commit interruption")

    with pytest.raises(control_error, match="target-map commit interruption"):
        with PrivateRun(final) as run:
            run._cleanup_file_fds = InterruptingOwnershipMap()  # noqa: SLF001
            run.open_binary("private.bin")

    assert interrupted
    assert moved.read_bytes() == b""
    _assert_cleanup_fd_accounting()
    assert enron_private_io._LIVE_CLEANUP_FDS == 0  # noqa: SLF001
    assert not enron_private_io._UNRESOLVED_CLEANUP_FDS  # noqa: SLF001


def test_pin_cleanup_tree_rejects_symlinks_and_hardlinks(tmp_path: Path) -> None:
    final = _resolved(tmp_path) / "run"

    with PrivateRun(final) as run:
        cache = run.ensure_directory("cache")
        payload = cache / "payload.bin"
        payload.write_bytes(b"private")
        payload.chmod(0o600)
        link = cache / "link.bin"
        try:
            link.symlink_to(payload)
        except (NotImplementedError, OSError):
            pytest.skip("file symlinks are unavailable")
        with pytest.raises(EnronPrivateIOError, match="must not contain symlinks"):
            run.pin_cleanup_tree("cache")
        link.unlink()
        try:
            os.link(payload, cache / "hardlink.bin")
        except (NotImplementedError, OSError):
            pytest.skip("hard links are unavailable")
        with pytest.raises(EnronPrivateIOError, match="unsafe file"):
            run.pin_cleanup_tree("cache")
        (cache / "hardlink.bin").unlink()


def test_commit_rejects_mode_change_after_sync_before_promotion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    final = _resolved(tmp_path) / "run"
    real_marker = enron_private_io._write_commit_marker

    def corrupt_mode_then_write_marker(stage_fd: int, stage_path: Path) -> None:
        (stage_path / "nested").chmod(0o750)
        real_marker(stage_fd, stage_path)

    monkeypatch.setattr(enron_private_io, "_write_commit_marker", corrupt_mode_then_write_marker)
    with pytest.raises(EnronPrivateIOError, match="changed before promotion"):
        with PrivateRun(final) as run:
            with run.open_text("nested/secret.txt") as handle:
                handle.write("private")
            run.commit()

    tombstone = next(final.parent.glob(".nerb-cleanup-*"))
    assert (tombstone / "nested" / "secret.txt").read_bytes() == b""


def test_commit_rejects_file_mode_change_during_promotion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    final = _resolved(tmp_path) / "run"
    real_rename = enron_private_io._rename_noreplace

    def rename_then_corrupt_mode(parent_fd: int, parent_path: Path, source_name: str, destination_name: str) -> None:
        real_rename(parent_fd, parent_path, source_name, destination_name)
        (parent_path / destination_name / "secret.txt").chmod(0o640)

    monkeypatch.setattr(enron_private_io, "_rename_noreplace", rename_then_corrupt_mode)
    with pytest.raises(EnronPrivateIOError, match="changed during promotion"):
        with PrivateRun(final) as run:
            with run.open_text("secret.txt") as handle:
                handle.write("private")
            run.commit()

    assert not final.exists()
    tombstone = next(final.parent.glob(".nerb-cleanup-*"))
    assert (tombstone / "secret.txt").read_bytes() == b""


def test_commit_rejects_retained_descriptor_owner_change_after_sync(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    final = _resolved(tmp_path) / "run"
    real_marker = enron_private_io._write_commit_marker
    real_fstat = enron_private_io.os.fstat
    changed_descriptor: int | None = None
    armed = False

    def arm_owner_change(stage_fd: int, stage_path: Path) -> None:
        nonlocal armed
        real_marker(stage_fd, stage_path)
        armed = True

    def changed_owner_once(descriptor: int) -> os.stat_result:
        nonlocal armed
        info = real_fstat(descriptor)
        if armed and descriptor == changed_descriptor:
            armed = False
            values = list(info)
            values[4] = info.st_uid + 1
            return os.stat_result(values)
        return info

    monkeypatch.setattr(enron_private_io, "_write_commit_marker", arm_owner_change)
    monkeypatch.setattr(enron_private_io.os, "fstat", changed_owner_once)
    with pytest.raises(EnronPrivateIOError, match="descriptor identity or permissions changed"):
        with PrivateRun(final) as run:
            with run.open_text("secret.txt") as handle:
                handle.write("private")
            changed_descriptor = next(iter(run._cleanup_file_fds.values()))  # noqa: SLF001
            run.commit()

    tombstone = next(final.parent.glob(".nerb-cleanup-*"))
    assert (tombstone / "secret.txt").read_bytes() == b""


def test_cleanup_tombstone_remains_inside_the_validated_git_ignore_boundary(tmp_path: Path) -> None:
    root = _git_workspace(tmp_path)
    final = root / ".private" / "run"

    with pytest.raises(RuntimeError, match="stop"):
        with PrivateRun(final) as run:
            with run.open_text("private-name.txt") as handle:
                handle.write("private")
            raise RuntimeError("stop")

    tombstone = next(final.parent.glob(".nerb-cleanup-*"))
    ignored = subprocess.run(
        ["git", "-C", str(root), "check-ignore", "-q", str(tombstone)],
        check=False,
    )
    assert ignored.returncode == 0
    assert (tombstone / "private-name.txt").read_bytes() == b""


def test_commit_failure_after_marker_leaves_no_partial_final(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    final = _resolved(tmp_path) / "run"
    observed_marker: list[bytes] = []

    def fail_promotion(_parent_fd: int, parent_path: Path, source_name: str, _destination_name: str) -> None:
        observed_marker.append((parent_path / source_name / "COMMITTED").read_bytes())
        raise OSError("injected promotion failure")

    monkeypatch.setattr(enron_private_io, "_rename_noreplace", fail_promotion)
    with pytest.raises(EnronPrivateIOError, match="committed safely"):
        with PrivateRun(final) as run:
            with run.open_text("data.txt") as file:
                file.write("private")
            run.commit()

    assert observed_marker == [b"nerb.enron.private-run.v2\n"]
    assert not final.exists()
    assert not list(final.parent.glob(f".{final.name}.stage-*"))


def test_commit_never_overwrites_target_created_during_run(tmp_path: Path) -> None:
    final = _resolved(tmp_path) / "run"

    with PrivateRun(final) as run:
        with run.open_text("data.txt") as file:
            file.write("private")
        final.mkdir()
        sentinel = final / "sentinel.txt"
        sentinel.write_text("keep", encoding="utf-8")
        with pytest.raises(EnronPrivateIOError, match="already exists"):
            run.commit()

    assert sentinel.read_text(encoding="utf-8") == "keep"
    assert not list(final.parent.glob(f".{final.name}.stage-*"))


def test_commit_fails_closed_without_atomic_noreplace_support(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    final = _resolved(tmp_path) / "run"
    monkeypatch.setattr(enron_private_io.sys, "platform", "unsupported-posix")

    with pytest.raises(EnronPrivateIOError, match="cleaned up safely"):
        with PrivateRun(final) as run:
            with run.open_text("data.txt") as file:
                file.write("private")
            run.commit()

    assert not final.exists()
    stages = list(final.parent.glob(f".{final.name}.stage-*"))
    assert len(stages) == 1
    assert (stages[0] / "data.txt").read_bytes() == b""


def test_cleanup_never_falls_back_to_overwriting_rename_when_noreplace_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    final = _resolved(tmp_path) / "run"
    plain_rename_calls: list[tuple[object, ...]] = []

    def unavailable(*_args: object) -> None:
        raise EnronPrivateIOError("Atomic no-replace directory promotion is unavailable on this platform.")

    def forbidden_plain_rename(*args: object, **_kwargs: object) -> None:
        plain_rename_calls.append(args)
        raise AssertionError("cleanup must not use overwriting rename")

    monkeypatch.setattr(enron_private_io, "_rename_noreplace_at", unavailable)
    monkeypatch.setattr(enron_private_io.os, "rename", forbidden_plain_rename)

    with pytest.raises(EnronPrivateIOError, match="cleaned up safely"):
        with PrivateRun(final) as run:
            with run.open_text("private.txt") as handle:
                handle.write("private")
            raise RuntimeError("injected body failure")

    assert plain_rename_calls == []
    stages = list(final.parent.glob(f".{final.name}.stage-*"))
    assert len(stages) == 1
    assert (stages[0] / "private.txt").read_bytes() == b""


def test_commit_requires_closed_files_and_cleans_stage(tmp_path: Path) -> None:
    final = _resolved(tmp_path) / "run"

    with pytest.raises(EnronPrivateIOError, match="must be closed"):
        with PrivateRun(final) as run:
            run.open_text("still-open.txt")
            run.commit()

    assert not final.exists()
    assert not list(final.parent.glob(f".{final.name}.stage-*"))


def test_commit_race_rolls_substitute_out_of_final_without_deleting_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    final = _resolved(tmp_path) / "run"
    moved = final.parent / "moved-authentic-stage"
    real_rename = enron_private_io._rename_noreplace
    stage: Path | None = None
    sentinel: Path | None = None

    def rename_then_substitute(parent_fd: int, parent_path: Path, source_name: str, destination_name: str) -> None:
        nonlocal sentinel
        real_rename(parent_fd, parent_path, source_name, destination_name)
        promoted = parent_path / destination_name
        promoted.rename(moved)
        promoted.mkdir(mode=0o700)
        sentinel = promoted / "preserve"
        sentinel.write_text("unrelated", encoding="utf-8")
        sentinel.chmod(0o600)

    monkeypatch.setattr(enron_private_io, "_rename_noreplace", rename_then_substitute)
    with pytest.raises(EnronPrivateIOError, match="cleaned up safely"):
        with PrivateRun(final) as run:
            stage = run.stage_dir
            with run.open_text("secret.txt") as handle:
                handle.write("private")
            run.commit()

    assert stage is not None and sentinel is not None
    assert not final.exists()
    assert not sentinel.exists()
    assert (stage / "preserve").read_text(encoding="utf-8") == "unrelated"
    assert moved.is_dir()
    assert {path.name for path in moved.iterdir()} == {"COMMITTED", "secret.txt"}
    assert all(path.read_bytes() == b"" for path in moved.iterdir())


def test_commit_rejects_registered_payload_move_out_and_wipes_original_and_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    final = _resolved(tmp_path) / "run"
    parked = final.parent / "parked-committed-payload.txt"
    real_rename = enron_private_io._rename_noreplace

    def promote_then_substitute(parent_fd: int, parent_path: Path, source_name: str, destination_name: str) -> None:
        real_rename(parent_fd, parent_path, source_name, destination_name)
        payload = parent_path / destination_name / "secret.txt"
        payload.replace(parked)
        payload.write_text("replacement private payload", encoding="utf-8")
        payload.chmod(0o600)

    monkeypatch.setattr(enron_private_io, "_rename_noreplace", promote_then_substitute)

    with pytest.raises(EnronPrivateIOError, match=r"(?i)(pinned|output|promotion)"):
        with PrivateRun(final) as run:
            with run.open_text("secret.txt") as handle:
                handle.write("original private payload")
            run.commit()

    assert parked.read_bytes() == b""
    assert not final.exists()
    tombstones = list(final.parent.glob(".nerb-cleanup-*"))
    assert len(tombstones) == 1
    assert (tombstones[0] / "secret.txt").read_bytes() == b""


def test_cleanup_race_wipes_pinned_stage_but_preserves_substitute(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    final = _resolved(tmp_path) / "run"
    moved = final.parent / "moved-cleanup-stage"
    real_quarantine = enron_private_io._rename_cleanup_entry_at
    stage: Path | None = None
    sentinel: Path | None = None
    swapped = False

    def swap_before_root_quarantine(
        parent_fd: int,
        parent_path: Path,
        source_name: str,
        destination_name: str,
    ) -> None:
        nonlocal sentinel, swapped
        if (
            stage is not None
            and source_name == stage.name
            and destination_name.startswith(".nerb-cleanup-")
            and not swapped
        ):
            swapped = True
            stage.rename(moved)
            stage.mkdir(mode=0o700)
            sentinel = stage / "preserve"
            sentinel.write_text("unrelated", encoding="utf-8")
            sentinel.chmod(0o600)
        real_quarantine(parent_fd, parent_path, source_name, destination_name)

    monkeypatch.setattr(enron_private_io, "_rename_cleanup_entry_at", swap_before_root_quarantine)
    with pytest.raises(EnronPrivateIOError, match="cleaned up safely") as caught:
        with PrivateRun(final) as run:
            stage = run.stage_dir
            with run.open_text("secret.txt") as handle:
                handle.write("private")
            raise RuntimeError("stop")

    assert isinstance(caught.value.__cause__, RuntimeError)
    assert stage is not None and sentinel is not None
    assert sentinel.read_text(encoding="utf-8") == "unrelated"
    assert moved.is_dir()
    assert (moved / "secret.txt").read_bytes() == b""
    assert not final.exists()


def test_cleanup_quarantine_rename_swap_restores_bound_substitute_and_wipes_authentic_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    final = _resolved(tmp_path) / "run"
    moved = final.parent / "moved-authentic-cleanup-stage"
    real_quarantine = enron_private_io._rename_cleanup_entry_at
    stage: Path | None = None
    sentinel: Path | None = None
    swapped = False

    def rename_then_swap_quarantine(
        parent_fd: int,
        parent_path: Path,
        source_name: str,
        destination_name: str,
    ) -> None:
        nonlocal sentinel, swapped
        real_quarantine(parent_fd, parent_path, source_name, destination_name)
        if (
            stage is not None
            and source_name == stage.name
            and destination_name.startswith(".nerb-cleanup-")
            and not swapped
        ):
            swapped = True
            quarantined = parent_path / destination_name
            quarantined.rename(moved)
            quarantined.mkdir(mode=0o700)
            sentinel = quarantined / "preserve.txt"
            sentinel.write_text("unrelated substitute bytes", encoding="utf-8")
            sentinel.chmod(0o600)

    monkeypatch.setattr(enron_private_io, "_rename_cleanup_entry_at", rename_then_swap_quarantine)
    with pytest.raises(EnronPrivateIOError, match="cleaned up safely") as caught:
        with PrivateRun(final) as run:
            stage = run.stage_dir
            with run.open_text("secret.txt") as handle:
                handle.write("private authentic bytes")
            raise RuntimeError("stop")

    assert isinstance(caught.value.__cause__, RuntimeError)
    assert stage is not None and sentinel is not None
    restored_sentinel = stage / "preserve.txt"
    assert restored_sentinel.read_text(encoding="utf-8") == "unrelated substitute bytes"
    assert not sentinel.exists()
    assert (moved / "secret.txt").read_bytes() == b""
    assert not final.exists()


def test_empty_root_substitute_is_rolled_back_and_never_removed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    final = _resolved(tmp_path) / "run"
    moved = final.parent / "moved-empty-root"
    real_quarantine = enron_private_io._rename_cleanup_entry_at
    stage: Path | None = None
    swapped = False

    def swap_empty_root(
        parent_fd: int,
        parent_path: Path,
        source_name: str,
        destination_name: str,
    ) -> None:
        nonlocal swapped
        if (
            stage is not None
            and source_name == stage.name
            and destination_name.startswith(".nerb-cleanup-")
            and not swapped
        ):
            swapped = True
            stage.rename(moved)
            stage.mkdir(mode=0o700)
        real_quarantine(parent_fd, parent_path, source_name, destination_name)

    monkeypatch.setattr(enron_private_io, "_rename_cleanup_entry_at", swap_empty_root)
    with pytest.raises(EnronPrivateIOError, match="cleaned up safely"):
        with PrivateRun(final) as run:
            stage = run.stage_dir
            raise RuntimeError("stop")

    assert stage is not None
    assert stage.is_dir()
    assert not list(stage.iterdir())
    assert moved.is_dir()
    assert not list(moved.iterdir())
    assert not final.exists()


def test_regular_file_swap_after_pinned_wipe_leaves_both_empty_shells(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    final = _resolved(tmp_path) / "run"
    real_ftruncate = enron_private_io.os.ftruncate
    stage: Path | None = None
    swapped = False

    def truncate_then_swap(descriptor: int, length: int) -> None:
        nonlocal swapped
        real_ftruncate(descriptor, length)
        if stage is not None and not swapped:
            swapped = True
            source = stage / "secret.txt"
            source.rename(stage / "moved-authentic.txt")
            source.write_bytes(b"")
            source.chmod(0o600)

    monkeypatch.setattr(enron_private_io.os, "ftruncate", truncate_then_swap)
    with pytest.raises(RuntimeError, match="stop"):
        with PrivateRun(final) as run:
            stage = run.stage_dir
            with run.open_text("secret.txt") as handle:
                handle.write("private")
            raise RuntimeError("stop")

    tombstone = next(final.parent.glob(".nerb-cleanup-*"))
    assert (tombstone / "secret.txt").read_bytes() == b""
    assert (tombstone / "moved-authentic.txt").read_bytes() == b""
    assert not final.exists()


def test_empty_child_directory_swap_after_pinned_wipe_is_not_removed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    final = _resolved(tmp_path) / "run"
    real_clear = enron_private_io._clear_pinned_private_directory
    stage: Path | None = None
    swapped = False

    def clear_then_swap(directory_fd: int, directory_path: Path) -> bool:
        nonlocal swapped
        cleared = real_clear(directory_fd, directory_path)
        if stage is not None and directory_path.name == "child" and not swapped:
            swapped = True
            directory_path.rename(stage / "moved-child")
            directory_path.mkdir(mode=0o700)
        return cleared

    monkeypatch.setattr(enron_private_io, "_clear_pinned_private_directory", clear_then_swap)
    with pytest.raises(RuntimeError, match="stop"):
        with PrivateRun(final) as run:
            stage = run.stage_dir
            with run.open_text("child/secret.txt") as handle:
                handle.write("private")
            raise RuntimeError("stop")

    tombstone = next(final.parent.glob(".nerb-cleanup-*"))
    assert (tombstone / "child").is_dir()
    assert not list((tombstone / "child").iterdir())
    assert (tombstone / "moved-child" / "secret.txt").read_bytes() == b""
    assert not final.exists()


def test_cleanup_has_no_final_name_based_unlink_or_rmdir_window(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    final = _resolved(tmp_path) / "run"
    delete_calls: list[str] = []

    def forbidden_delete(_parent_fd: int, _parent_path: Path, name: str) -> None:
        delete_calls.append(name)
        raise AssertionError("cleanup must retain wiped tombstones")

    monkeypatch.setattr(enron_private_io, "_unlink_at", forbidden_delete)
    monkeypatch.setattr(enron_private_io, "_rmdir_at", forbidden_delete)
    with pytest.raises(RuntimeError, match="stop"):
        with PrivateRun(final) as run:
            with run.open_text("child/secret.txt") as handle:
                handle.write("private")
            raise RuntimeError("stop")

    assert delete_calls == []
    tombstone = next(final.parent.glob(".nerb-cleanup-*"))
    assert (tombstone / "child" / "secret.txt").read_bytes() == b""
    assert not final.exists()


def test_moved_stage_is_wiped_by_descriptor_and_replacement_is_never_deleted(tmp_path: Path) -> None:
    final = _resolved(tmp_path) / "run"
    moved = final.parent / "moved-before-commit"
    stage: Path | None = None
    sentinel: Path | None = None

    with pytest.raises(EnronPrivateIOError, match="cleaned up safely"):
        with PrivateRun(final) as run:
            stage = run.stage_dir
            with run.open_text("secret.txt") as handle:
                handle.write("private")
            stage.rename(moved)
            stage.mkdir(mode=0o700)
            sentinel = stage / "preserve"
            sentinel.write_text("unrelated", encoding="utf-8")
            sentinel.chmod(0o600)
            run.commit()

    assert stage is not None and sentinel is not None
    assert sentinel.read_text(encoding="utf-8") == "unrelated"
    assert moved.is_dir()
    assert {path.name for path in moved.iterdir()} == {"COMMITTED", "secret.txt"}
    assert all(path.read_bytes() == b"" for path in moved.iterdir())
    assert not final.exists()


def test_private_output_relative_paths_reject_traversal_and_reserved_marker(tmp_path: Path) -> None:
    final = _resolved(tmp_path) / "run"

    with PrivateRun(final) as run:
        with pytest.raises(EnronPrivateIOError, match="non-traversing"):
            run.open_text("../outside.txt")
        with pytest.raises(EnronPrivateIOError, match="reserved"):
            run.open_text("COMMITTED")

    assert not final.exists()


def test_iter_strict_jsonl_returns_exact_raw_lines_and_objects(tmp_path: Path) -> None:
    source = _resolved(tmp_path) / "input.jsonl"
    first = b'{"id":1,"nested":{"ok":true}}\r\n'
    second = '{"id":2,"text":"caf\u00e9"}'.encode()  # No final newline is valid JSONL.
    source.write_bytes(first + second)

    rows = list(iter_strict_jsonl(source, max(len(first), len(second))))

    assert rows == [
        (1, first, {"id": 1, "nested": {"ok": True}}),
        (2, second, {"id": 2, "text": "café"}),
    ]


def test_iter_strict_jsonl_enforces_raw_line_byte_cap(tmp_path: Path) -> None:
    source = _resolved(tmp_path) / "input.jsonl"
    raw = b'{"id":1}\n'
    source.write_bytes(raw)

    assert list(iter_strict_jsonl(source, len(raw)))[0][1] == raw
    with pytest.raises(EnronPrivateIOError, match="line 1 exceeds"):
        list(iter_strict_jsonl(source, len(raw) - 1))


def test_iter_strict_jsonl_handles_large_bounded_line(tmp_path: Path) -> None:
    source = _resolved(tmp_path) / "large.jsonl"
    raw = json.dumps({"body": "x" * (1024 * 1024)}, separators=(",", ":")).encode() + b"\n"
    source.write_bytes(raw)

    rows = list(iter_strict_jsonl(source, len(raw)))

    assert len(rows) == 1
    assert rows[0][1] == raw
    assert len(rows[0][2]["body"]) == 1024 * 1024


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (b'{"id":}\n', "not valid JSON"),
        (b'{"id":1,"id":2}\n', "duplicate object key"),
        (b'{"value":NaN}\n', "non-finite number"),
        (b'{"value":1e400}\n', "non-finite number"),
        (b"[]\n", "JSON object"),
        (b"\xff\n", "not valid UTF-8"),
        (b"\n", "not valid JSON"),
    ],
)
def test_iter_strict_jsonl_rejects_invalid_inputs_without_echo(tmp_path: Path, payload: bytes, message: str) -> None:
    source = _resolved(tmp_path) / "input.jsonl"
    secret = b"private-person@example.test"
    source.write_bytes(payload + secret)

    with pytest.raises(EnronPrivateIOError, match=message) as raised:
        list(iter_strict_jsonl(source, 1024))

    assert secret.decode() not in str(raised.value)


def test_iter_strict_jsonl_rejects_duplicate_nested_key_without_echoing_key(tmp_path: Path) -> None:
    source = _resolved(tmp_path) / "input.jsonl"
    sensitive_key = "private-person@example.test"
    source.write_text(json.dumps({"outer": {sensitive_key: 1}})[:-2] + f',"{sensitive_key}":2}}}}\n', encoding="utf-8")

    with pytest.raises(EnronPrivateIOError, match="duplicate object key") as raised:
        list(iter_strict_jsonl(source, 1024))

    assert sensitive_key not in str(raised.value)


def test_iter_strict_jsonl_rejects_symlink_and_directory_inputs(tmp_path: Path) -> None:
    root = _resolved(tmp_path)
    source = root / "input.jsonl"
    source.write_text('{"id":1}\n', encoding="utf-8")
    link = root / "input-link.jsonl"
    try:
        link.symlink_to(source)
    except (NotImplementedError, OSError):
        pytest.skip("file symlinks are unavailable")

    with pytest.raises(EnronPrivateIOError, match="regular non-symlink"):
        list(iter_strict_jsonl(link, 1024))
    with pytest.raises(EnronPrivateIOError, match="regular non-symlink"):
        list(iter_strict_jsonl(root, 1024))


def test_iter_strict_jsonl_uses_nofollow_open(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = _resolved(tmp_path) / "input.jsonl"
    source.write_text('{"id":1}\n', encoding="utf-8")
    real_open = enron_private_io.os.open
    opened_flags: list[int] = []

    def recording_open(*args: Any, **kwargs: Any) -> int:
        opened_flags.append(args[1])
        return real_open(*args, **kwargs)

    monkeypatch.setattr(enron_private_io.os, "open", recording_open)

    assert list(iter_strict_jsonl(source, 1024))[0][2] == {"id": 1}
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow:
        assert opened_flags[-1] & nofollow


@pytest.mark.parametrize("limit", [0, -1, True, 1.5])
def test_iter_strict_jsonl_rejects_invalid_limits(tmp_path: Path, limit: Any) -> None:
    source = _resolved(tmp_path) / "input.jsonl"
    source.write_text('{"id":1}\n', encoding="utf-8")

    with pytest.raises(EnronPrivateIOError, match="positive integer"):
        iter_strict_jsonl(source, limit)
