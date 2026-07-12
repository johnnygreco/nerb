from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import nerb.enron_private_io as enron_private_io
from nerb.enron_private_io import (
    EnronPrivateIOError,
    PrivateRun,
    ensure_private_output_allowed,
    find_workspace_root,
    iter_strict_jsonl,
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


@pytest.mark.parametrize("mode", [0o400, 0o500, 0o600, 0o700])
def test_owner_only_private_mode_accepts_read_only_and_writable_owner_modes(mode: int) -> None:
    assert enron_private_io.is_owner_only_private_mode(mode) is True


@pytest.mark.parametrize("mode", [0o004, 0o040, 0o640, 0o750])
def test_owner_only_private_mode_rejects_group_or_other_access(mode: int) -> None:
    assert enron_private_io.is_owner_only_private_mode(mode) is False


def test_find_workspace_root_from_nonexistent_descendant(tmp_path: Path) -> None:
    root = _git_workspace(tmp_path)

    assert find_workspace_root(root / "missing" / "run") == root


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
            with run.open_text("partial.txt") as file:
                file.write("private")
            raise RuntimeError("stop")

    assert not final.exists()
    assert not list(final.parent.glob(f".{final.name}.stage-*"))


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

    with pytest.raises(EnronPrivateIOError, match="Atomic no-replace"):
        with PrivateRun(final) as run:
            with run.open_text("data.txt") as file:
                file.write("private")
            run.commit()

    assert not final.exists()
    assert not list(final.parent.glob(f".{final.name}.stage-*"))


def test_commit_requires_closed_files_and_cleans_stage(tmp_path: Path) -> None:
    final = _resolved(tmp_path) / "run"

    with pytest.raises(EnronPrivateIOError, match="must be closed"):
        with PrivateRun(final) as run:
            run.open_text("still-open.txt")
            run.commit()

    assert not final.exists()
    assert not list(final.parent.glob(f".{final.name}.stage-*"))


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
