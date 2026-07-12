"""Private transactional output and strict JSONL input for Enron preparation.

This module deliberately has no dependency on the Enron preparation schema.  It
provides the narrow filesystem boundary used by that pipeline: private files are
assembled in an ignored sibling directory and become visible only after the
complete tree has been flushed and marked committed.
"""

from __future__ import annotations

import ctypes
import errno
import json
import math
import os
import secrets
import stat
import subprocess
import sys
import threading
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import Any, BinaryIO, TextIO, TypeVar, cast

_COMMIT_MARKER = "COMMITTED"
_COMMIT_PAYLOAD = b"nerb.enron.private-run.v2\n"
_DIRECTORY_MODE = 0o700
_FILE_MODE = 0o600
_JSONL_BUFFER_BYTES = 64 * 1024
_MAX_JSON_INTEGER_DIGITS = 256
_STAGE_TOKEN_HEX_LENGTH = 24
_MAX_PRIVATE_TOMBSTONE_ENTRIES = 1_000_000
_MAX_PRIVATE_TOMBSTONE_DEPTH = 64
_MAX_PINNED_CLEANUP_FILES = 128
_MAX_PINNED_CLEANUP_TREE_ENTRIES = 4_096
_MAX_PINNED_CLEANUP_TREE_DEPTH = 32
_PRIVATE_RUN_PERSISTENT_FDS = 2
_PINNED_CLEANUP_FD_RESERVE = _MAX_PRIVATE_TOMBSTONE_DEPTH + 8
_CLEANUP_FD_ACCOUNTING_LOCK = threading.Lock()
_CLEANUP_FD_ACQUISITION_LOCK = threading.Lock()
_CLEANUP_TREE_ADOPTION_LOCK = threading.Lock()
_UNRESOLVED_CLEANUP_LOCK = threading.RLock()
_LIVE_CLEANUP_FDS = 0
_PENDING_CLEANUP_FDS = 0
_PENDING_CLEANUP_RESERVATIONS: set[object] = set()
_ACCOUNTED_CLEANUP_FDS: set[int] = set()
_UNRESOLVED_CLEANUP_FDS: dict[tuple[int, ...], int] = {}
_LINUX_PROC_FD_CHMOD_AVAILABLE = (
    sys.platform.startswith("linux") and bool(getattr(os, "O_PATH", 0)) and Path("/proc/self/fd").is_dir()
)
_FOLLOW_SAFE_CHMOD_AVAILABLE = os.chmod in os.supports_dir_fd and os.chmod in os.supports_follow_symlinks
_TRANSACTION_CAPABILITIES_AVAILABLE = (
    os.name == "posix"
    and all(
        function in os.supports_dir_fd
        for function in (os.open, os.mkdir, os.rename, os.stat, os.unlink, os.rmdir, os.chmod)
    )
    and os.listdir in os.supports_fd
    and bool(getattr(os, "O_DIRECTORY", 0))
    and bool(getattr(os, "O_NOFOLLOW", 0))
    and hasattr(os, "fchmod")
    and (_FOLLOW_SAFE_CHMOD_AVAILABLE or _LINUX_PROC_FD_CHMOD_AVAILABLE)
)


class EnronPrivateIOError(RuntimeError):
    """Raised when private I/O cannot be completed without weakening safety."""


_CleanupOwnerKey = TypeVar("_CleanupOwnerKey", bound=tuple[int, ...])


def is_owner_only_private_mode(mode: int) -> bool:
    """Return whether a permission mode grants no group or other access."""

    return type(mode) is int and mode >= 0 and mode & 0o077 == 0


def find_workspace_root(start: Path) -> Path | None:
    """Return the containing Git workspace root, if one can be identified."""

    try:
        candidate = Path(start).expanduser()
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        while True:
            try:
                info = candidate.lstat()
            except FileNotFoundError:
                parent = candidate.parent
                if parent == candidate:
                    return None
                candidate = parent
                continue
            except (OSError, ValueError):
                return None
            if not stat.S_ISDIR(info.st_mode):
                candidate = candidate.parent
            break
    except (OSError, RuntimeError, TypeError, ValueError):
        return None

    try:
        completed = subprocess.run(
            ["git", "-C", os.fspath(candidate), "rev-parse", "--show-toplevel"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        completed = None
    if completed is not None and completed.returncode == 0:
        try:
            output = os.fsdecode(completed.stdout.strip())
            if output:
                root = Path(output)
                root_info = root.lstat()
                if (
                    stat.S_ISDIR(root_info.st_mode)
                    and not stat.S_ISLNK(root_info.st_mode)
                    and _is_within(candidate, root)
                ):
                    return root
        except (OSError, RuntimeError, TypeError, ValueError):
            pass

    # Preserve fail-closed workspace detection when Git itself is unavailable.
    for directory in (candidate, *candidate.parents):
        marker = directory / ".git"
        try:
            marker.lstat()
        except FileNotFoundError:
            continue
        except (OSError, ValueError):
            return None
        # Any .git entry is enough to treat the directory as a possible
        # workspace.  A malformed or symlinked marker must not turn into a
        # privacy-policy bypass when Git is unavailable.
        return directory
    return None


def ensure_private_output_allowed(
    final_dir: Path,
    workspace_root: Path | None = None,
    allow_unignored_output: bool = False,
) -> Path:
    """Validate and return an absolute, non-existing private output directory."""

    final = _absolute_path_without_traversal(final_dir, description="Output")
    _reject_unsafe_existing_components(final, reject_target=True)
    root = _workspace_for_path(final, workspace_root)
    if root is not None and _is_within(final, root) and not allow_unignored_output:
        _require_git_ignored(final, root)
    return final


class PrivateRun:
    """Build a private directory transactionally and promote it exactly once."""

    def __init__(
        self,
        final_dir: Path,
        *,
        workspace_root: Path | None = None,
        allow_unignored_output: bool = False,
        stage_token: str | None = None,
        expected_parent_identity: tuple[int, int] | None = None,
    ) -> None:
        if stage_token is not None and (
            not isinstance(stage_token, str)
            or len(stage_token) != _STAGE_TOKEN_HEX_LENGTH
            or any(character not in "0123456789abcdef" for character in stage_token)
        ):
            raise EnronPrivateIOError("Private staging token must be fixed-length lowercase hexadecimal.")
        if expected_parent_identity is not None and (
            not isinstance(expected_parent_identity, tuple)
            or len(expected_parent_identity) != 2
            or any(type(value) is not int or value < 0 for value in expected_parent_identity)
        ):
            raise EnronPrivateIOError("Expected private staging parent identity is invalid.")
        self._requested_final_dir = Path(final_dir)
        self._requested_workspace_root = workspace_root
        self._allow_unignored_output = allow_unignored_output
        self._requested_stage_token = stage_token
        self._expected_parent_identity = expected_parent_identity
        self._final_dir: Path | None = None
        self._workspace_root: Path | None = None
        self._stage_dir: Path | None = None
        self._stage_name: str | None = None
        self._parent_fd: int | None = None
        self._stage_fd: int | None = None
        self._stage_identity: tuple[int, int] | None = None
        self._open_handles: list[BinaryIO | TextIO] = []
        self._cleanup_file_fds: dict[tuple[int, int], int] = {}
        self._cleanup_authority_retained = False
        self._entered = False
        self._committed = False
        self._sealing = False
        self._promoted = False
        self._cleanup_sensitive_content_wiped: bool | None = None
        self._cleanup_path_tree_removed: bool | None = None
        self._cleanup_tombstone_count = 0

    def __del__(self) -> None:
        """Finish or release transaction authority dropped by a caller."""

        try:
            if getattr(self, "_committed", False):
                while getattr(self, "_cleanup_file_fds", {}):
                    try:
                        self._close_cleanup_descriptors()
                    except BaseException:
                        continue
                return
            while not self._cleanup_is_settled():
                try:
                    self._cleanup()
                except BaseException:
                    continue
        except BaseException:
            # Destructors cannot report failures. One-shot control flow is
            # retried above while the object still owns every writer and fd.
            pass

    @property
    def stage_dir(self) -> Path:
        """The active private staging directory."""

        if self._stage_dir is None:
            raise EnronPrivateIOError("Private run has not been entered.")
        return self._stage_dir

    @property
    def final_dir(self) -> Path:
        """The validated final directory once the run has been entered."""

        if self._final_dir is None:
            raise EnronPrivateIOError("Private run has not been entered.")
        return self._final_dir

    @property
    def cleanup_sensitive_content_wiped(self) -> bool | None:
        """Whether a failed transaction proved its pinned payload was wiped."""

        return self._cleanup_sensitive_content_wiped

    @property
    def cleanup_path_tree_removed(self) -> bool | None:
        """Whether failed-transaction cleanup removed every path-tree shell."""

        return self._cleanup_path_tree_removed

    @property
    def cleanup_tombstone_count(self) -> int:
        """Number of retained owner-only, payload-empty cleanup tombstones."""

        return self._cleanup_tombstone_count

    @property
    def cleanup_authority_retained(self) -> bool:
        """Whether a committed run still owns authenticated writable payload descriptors."""

        return self._cleanup_authority_retained

    def __enter__(self) -> PrivateRun:
        if self._entered:
            raise EnronPrivateIOError("Private run cannot be entered more than once.")
        _retry_unresolved_cleanup_descriptors()
        self._entered = True
        try:
            _require_transaction_capabilities()
            _require_cleanup_fd_headroom(additional_descriptors=_PRIVATE_RUN_PERSISTENT_FDS)
            final = ensure_private_output_allowed(
                self._requested_final_dir,
                workspace_root=self._requested_workspace_root,
                allow_unignored_output=self._allow_unignored_output,
            )
            root = _workspace_for_path(final, self._requested_workspace_root)
            self._workspace_root = root
            parent_fd = _open_or_create_private_directory(final.parent)
            parent_info = os.fstat(parent_fd)
            if (
                self._expected_parent_identity is not None
                and (
                    parent_info.st_dev,
                    parent_info.st_ino,
                )
                != self._expected_parent_identity
            ):
                os.close(parent_fd)
                raise EnronPrivateIOError("Private staging parent identity changed before allocation.")
            self._final_dir = final
            self._parent_fd = parent_fd
            _require_absent_at(parent_fd, final.parent, final.name)

            attempts = 1 if self._requested_stage_token is not None else 128
            for _ in range(attempts):
                stage_token = self._requested_stage_token or secrets.token_hex(12)
                stage_name = f".{final.name}.stage-{stage_token}"
                stage = final.parent / stage_name
                if root is not None and _is_within(stage, root) and not self._allow_unignored_output:
                    _require_git_ignored(stage, root)
                try:
                    _mkdir_at(parent_fd, final.parent, stage_name, _DIRECTORY_MODE)
                except FileExistsError:
                    if self._requested_stage_token is not None:
                        raise EnronPrivateIOError("The requested private staging token is already in use.") from None
                    continue
                self._stage_name = stage_name
                self._stage_dir = stage
                stage_fd = _open_directory_at(parent_fd, final.parent, stage_name)
                self._stage_fd = stage_fd
                os.fchmod(stage_fd, _DIRECTORY_MODE)
                stage_info = os.fstat(stage_fd)
                self._stage_identity = _private_directory_identity(stage_info)
                _require_directory_entry_identity(
                    parent_fd,
                    final.parent,
                    stage_name,
                    self._stage_identity,
                )
                return self
            raise EnronPrivateIOError("A unique private staging directory could not be created.")
        except BaseException as exc:
            self._cleanup()
            if isinstance(exc, (EnronPrivateIOError, KeyboardInterrupt, SystemExit)):
                raise
            raise EnronPrivateIOError("Private run could not be initialized safely.") from None

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if not self._committed:
            try:
                self._cleanup()
            except BaseException:
                cleanup_error = EnronPrivateIOError("Private staging data could not be cleaned up safely.")
                if isinstance(exc, BaseException):
                    raise cleanup_error from exc
                raise cleanup_error from None

    def open_binary(self, relative: Path | str) -> BinaryIO:
        """Create a new private binary file below the staging directory."""

        fd = self._create_output_file(relative)
        try:
            handle = os.fdopen(fd, "wb")
        except BaseException:
            os.close(fd)
            raise
        self._open_handles.append(handle)
        return handle

    def open_text(self, relative: Path | str) -> TextIO:
        """Create a new UTF-8 text file below the staging directory."""

        fd = self._create_output_file(relative)
        try:
            handle = os.fdopen(fd, "w", encoding="utf-8", newline="\n")
        except BaseException:
            os.close(fd)
            raise
        self._open_handles.append(handle)
        return handle

    def ensure_directory(self, relative: Path | str) -> Path:
        """Create or verify a private directory below the staging root."""

        self._require_active()
        if self._committed or self._sealing:
            raise EnronPrivateIOError("Committed private runs cannot be modified.")
        relative_path = _safe_relative_path(relative)
        assert self._stage_fd is not None
        assert self._stage_dir is not None
        descriptor: int | None = None
        try:
            descriptor, path = _open_or_create_relative_directory(
                self._stage_fd,
                self._stage_dir,
                relative_path.parts,
            )
            os.fchmod(descriptor, _DIRECTORY_MODE)
            return path
        except EnronPrivateIOError:
            raise
        except (OSError, ValueError):
            raise EnronPrivateIOError("Private output directory could not be created safely.") from None
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def create_external_file(self, relative: Path | str) -> Path:
        """Create an empty private file and retain its inode for failure cleanup."""

        relative_path = _safe_relative_path(relative)
        descriptor = self._create_output_file(relative_path)
        try:
            os.close(descriptor)
        except OSError:
            raise EnronPrivateIOError("Private external file could not be prepared safely.") from None
        return self.stage_dir / relative_path

    def pin_cleanup_file(self, relative: Path | str) -> None:
        """Retain the current private file inode so move-out cleanup can wipe it."""

        self._require_active()
        if self._committed or self._sealing:
            raise EnronPrivateIOError("Committed private runs cannot pin cleanup files.")
        relative_path = _safe_relative_path(relative)
        assert self._stage_fd is not None
        assert self._stage_dir is not None
        parent_fd: int | None = None
        try:
            parent_fd, parent_path = _open_relative_directory(
                self._stage_fd,
                self._stage_dir,
                relative_path.parts[:-1],
            )
            flags = (
                os.O_RDWR
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
            )
            before = _stat_at(parent_fd, parent_path, relative_path.name)
            identity = int(before.st_dev), int(before.st_ino)
            _open_cleanup_descriptor_at(
                parent_fd,
                parent_path,
                relative_path.name,
                flags,
                expected_identity=identity,
                target=self._cleanup_file_fds,
            )
        except EnronPrivateIOError:
            raise
        except (OSError, ValueError):
            raise EnronPrivateIOError("Private cleanup file could not be pinned safely.") from None
        finally:
            if parent_fd is not None:
                os.close(parent_fd)

    def pin_cleanup_tree(self, relative: Path | str) -> int:
        """Pin a stopped writer's private regular-file tree for later cleanup.

        The caller must stop every writer before calling this method.  The
        bounded, no-follow walk retains each owned, exactly-private regular file
        as it is authenticated and returns the number of newly retained inodes.
        """

        self._require_active()
        if self._committed or self._sealing:
            raise EnronPrivateIOError("Committed private runs cannot pin cleanup trees.")
        relative_path = _safe_relative_path(relative)
        assert self._stage_fd is not None
        assert self._stage_dir is not None
        directory_fd: int | None = None
        starting_count = len(self._cleanup_file_fds)
        try:
            with _CLEANUP_TREE_ADOPTION_LOCK:
                directory_fd, directory_path = _open_relative_directory(
                    self._stage_fd,
                    self._stage_dir,
                    relative_path.parts,
                )
                _require_exact_private_directory(os.fstat(directory_fd))
                _collect_cleanup_tree_descriptors(
                    directory_fd,
                    directory_path,
                    retained=self._cleanup_file_fds,
                    limit=_MAX_PINNED_CLEANUP_FILES,
                    depth=0,
                    entries=[0],
                )
                _require_cleanup_fd_headroom()
                return len(self._cleanup_file_fds) - starting_count
        except EnronPrivateIOError:
            raise
        except (OSError, ValueError):
            raise EnronPrivateIOError("Private cleanup tree could not be pinned safely.") from None
        finally:
            if directory_fd is not None:
                os.close(directory_fd)

    def commit(
        self,
        *,
        cleanup_successor: PrivateRun | None = None,
        retain_cleanup_authority: bool = False,
        before_promotion: Callable[[tuple[tuple[int, int], ...]], None] | None = None,
    ) -> Path:
        """Flush, mark, and atomically promote the complete private run."""

        self._require_active()
        if self._committed:
            raise EnronPrivateIOError("Private run has already been committed.")
        if cleanup_successor is not None and retain_cleanup_authority:
            raise EnronPrivateIOError("Retained cleanup authority cannot also be transferred to a successor.")
        if before_promotion is not None and not callable(before_promotion):
            raise EnronPrivateIOError("Private pre-promotion callback is invalid.")
        self._sealing = True
        try:
            if any(not handle.closed for handle in self._open_handles):
                raise EnronPrivateIOError("All private output files must be closed before commit.")
            assert self._stage_fd is not None
            assert self._stage_name is not None
            assert self._parent_fd is not None
            assert self._final_dir is not None
            assert self._stage_dir is not None
            assert self._stage_identity is not None

            _sync_private_tree(self._stage_fd, self._stage_dir, root=True)
            self._require_cleanup_files_current()
            _write_commit_marker(self._stage_fd, self._stage_dir)
            os.fsync(self._stage_fd)
            self._require_cleanup_files_current()
            if before_promotion is not None:
                before_promotion(tuple(sorted(self._cleanup_file_fds)))
                self._require_cleanup_files_current()
            _require_absent_at(self._parent_fd, self._final_dir.parent, self._final_dir.name)
            _require_directory_entry_identity(
                self._parent_fd,
                self._final_dir.parent,
                self._stage_name,
                self._stage_identity,
            )
            _rename_noreplace(
                self._parent_fd,
                self._final_dir.parent,
                self._stage_name,
                self._final_dir.name,
            )
            try:
                _require_directory_entry_identity(
                    self._parent_fd,
                    self._final_dir.parent,
                    self._final_dir.name,
                    self._stage_identity,
                )
                self._require_cleanup_files_current()
            except EnronPrivateIOError:
                _rollback_unverified_promotion(
                    self._parent_fd,
                    self._final_dir.parent,
                    self._stage_name,
                    self._final_dir.name,
                )
                raise EnronPrivateIOError("Private staging directory changed during promotion.") from None
            self._promoted = True
            os.fsync(self._parent_fd)
            try:
                _require_directory_entry_identity(
                    self._parent_fd,
                    self._final_dir.parent,
                    self._final_dir.name,
                    self._stage_identity,
                )
                self._require_cleanup_files_current()
            except EnronPrivateIOError:
                _rollback_unverified_promotion(
                    self._parent_fd,
                    self._final_dir.parent,
                    self._stage_name,
                    self._final_dir.name,
                )
                raise EnronPrivateIOError("Private staging directory changed during promotion.") from None
            if cleanup_successor is not None:
                self._transfer_cleanup_ownership(cleanup_successor)
            stage_fd = self._stage_fd
            parent_fd = self._parent_fd
            self._stage_fd = None
            self._parent_fd = None
            self._stage_identity = None
            try:
                os.close(stage_fd)
            except OSError:
                pass
            try:
                os.close(parent_fd)
            except OSError:
                pass
            if cleanup_successor is None and not retain_cleanup_authority:
                self._close_cleanup_descriptors()
            self._cleanup_authority_retained = retain_cleanup_authority
            self._committed = True
            return self._final_dir
        except BaseException as exc:
            self._cleanup()
            if isinstance(exc, (EnronPrivateIOError, KeyboardInterrupt, SystemExit)):
                raise
            raise EnronPrivateIOError("Private run could not be committed safely.") from None

    def release_cleanup_authority(self) -> None:
        """Release explicitly retained post-commit cleanup authority."""

        if not self._committed or not self._cleanup_authority_retained:
            raise EnronPrivateIOError("Private cleanup authority is not retained.")
        self._close_cleanup_descriptors()
        self._cleanup_authority_retained = False

    def wipe_retained_cleanup_authority(self) -> bool:
        """Wipe retained post-commit inodes, releasing only proven-empty descriptors."""

        if not self._committed or not self._cleanup_authority_retained:
            raise EnronPrivateIOError("Private cleanup authority is not retained.")
        succeeded = True
        for identity, descriptor in tuple(self._cleanup_file_fds.items()):
            if not _wipe_authenticated_cleanup_descriptor(identity, descriptor):
                succeeded = False
                continue
            try:
                _close_owned_cleanup_descriptor(self._cleanup_file_fds, identity)
            except (EnronPrivateIOError, OSError):
                succeeded = False
        if not self._cleanup_file_fds:
            self._cleanup_authority_retained = False
        return succeeded

    def park_unresolved_cleanup_authority(self) -> None:
        """Transfer failed cleanup authority to the bounded process retry registry."""

        if not self._committed or not self._cleanup_authority_retained:
            raise EnronPrivateIOError("Private cleanup authority is not retained.")
        _park_run_cleanup_descriptors(self)

    def _create_output_file(self, relative: Path | str) -> int:
        self._require_active()
        if self._committed or self._sealing:
            raise EnronPrivateIOError("Committed private runs cannot be modified.")
        relative_path = _safe_relative_path(relative)
        assert self._stage_fd is not None
        assert self._stage_dir is not None
        parent_fd: int | None = None
        try:
            parent_fd, parent_path = _open_or_create_relative_directory(
                self._stage_fd,
                self._stage_dir,
                relative_path.parts[:-1],
            )
            flags = (
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
            )
            fd = _open_at(parent_fd, parent_path, relative_path.name, flags, _FILE_MODE)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise EnronPrivateIOError("Private output must be a new regular file.")
                os.fchmod(fd, _FILE_MODE)
                _duplicate_cleanup_descriptor(fd, target=self._cleanup_file_fds)
                return fd
            except BaseException:
                os.close(fd)
                raise
        except EnronPrivateIOError:
            raise
        except (OSError, ValueError):
            raise EnronPrivateIOError("Private output file could not be created safely.") from None
        finally:
            if parent_fd is not None:
                os.close(parent_fd)

    def _transfer_cleanup_ownership(self, successor: PrivateRun) -> None:
        if not isinstance(successor, PrivateRun):
            raise EnronPrivateIOError("Private cleanup successor is invalid.")
        if successor is self:
            raise EnronPrivateIOError("A private run cannot be its own cleanup successor.")
        if successor._committed or successor._promoted:
            raise EnronPrivateIOError("Private cleanup successor must be active and uncommitted.")
        successor._require_active()
        assert self._stage_identity is not None
        assert self._final_dir is not None
        assert successor._stage_dir is not None
        assert successor._stage_fd is not None
        assert successor._parent_fd is not None
        assert successor._stage_name is not None
        assert successor._stage_identity is not None
        assert successor._final_dir is not None

        try:
            relative = self._final_dir.relative_to(successor._stage_dir)
        except ValueError:
            raise EnronPrivateIOError("Private cleanup successor is not an ancestor of the committed run.") from None
        if not relative.parts or any(part in {os.curdir, os.pardir} for part in relative.parts):
            raise EnronPrivateIOError("Private cleanup successor must be a strict ancestor of the committed run.")

        _require_directory_entry_identity(
            successor._parent_fd,
            successor._final_dir.parent,
            successor._stage_name,
            successor._stage_identity,
        )
        _require_exact_private_directory(os.fstat(successor._stage_fd))
        _require_nested_directory_identity(
            successor._stage_fd,
            successor._stage_dir,
            relative.parts,
            self._stage_identity,
        )
        _require_cleanup_descriptors_current(successor._cleanup_file_fds)
        _require_cleanup_descriptors_current(self._cleanup_file_fds)
        if set(successor._cleanup_file_fds) & set(self._cleanup_file_fds):
            raise EnronPrivateIOError("Private cleanup ownership transfer overlaps its successor.")
        if len(successor._cleanup_file_fds) + len(self._cleanup_file_fds) > _MAX_PINNED_CLEANUP_FILES:
            raise EnronPrivateIOError("Private cleanup successor exceeds its cumulative pinned file limit.")
        _require_cleanup_fd_headroom()

        source_before = self._cleanup_file_fds
        successor_before = successor._cleanup_file_fds
        with _UNRESOLVED_CLEANUP_LOCK:
            try:
                successor._cleanup_file_fds = {**successor_before, **source_before}
                self._cleanup_file_fds = {}
                _require_cleanup_descriptors_current(successor._cleanup_file_fds)
                _require_directory_entry_identity(
                    successor._parent_fd,
                    successor._final_dir.parent,
                    successor._stage_name,
                    successor._stage_identity,
                )
                _require_nested_directory_identity(
                    successor._stage_fd,
                    successor._stage_dir,
                    relative.parts,
                    self._stage_identity,
                )
            except BaseException:
                self._cleanup_file_fds = source_before
                successor._cleanup_file_fds = successor_before
                raise

    def _wipe_cleanup_descriptors(self) -> bool:
        succeeded = True
        for identity, descriptor in self._cleanup_file_fds.items():
            if not _wipe_authenticated_cleanup_descriptor(identity, descriptor):
                succeeded = False
        return succeeded

    def _wipe_and_close_cleanup_descriptors(self) -> bool:
        """Release only authenticated descriptors whose payload reached durable zero."""

        succeeded = True
        for identity, descriptor in tuple(self._cleanup_file_fds.items()):
            if not _wipe_authenticated_cleanup_descriptor(identity, descriptor):
                succeeded = False
                continue
            try:
                _close_owned_cleanup_descriptor(self._cleanup_file_fds, identity)
            except (EnronPrivateIOError, OSError):
                succeeded = False
        return succeeded and not self._cleanup_file_fds

    def _require_cleanup_files_current(self) -> None:
        assert self._stage_fd is not None
        assert self._stage_identity is not None
        root_info = os.fstat(self._stage_fd)
        _require_exact_private_directory(root_info)
        if (root_info.st_dev, root_info.st_ino) != self._stage_identity:
            raise EnronPrivateIOError("Pinned private staging identity changed before promotion completed.")
        _require_cleanup_descriptors_current(self._cleanup_file_fds)
        expected = set(self._cleanup_file_fds)
        counts = {identity: 0 for identity in expected}
        if not _count_registered_private_files(
            self._stage_fd,
            expected=expected,
            counts=counts,
            depth=0,
            entries=[0],
            root=True,
        ) or any(count != 1 for count in counts.values()):
            raise EnronPrivateIOError("Pinned private output file changed before promotion completed.")

    def _close_cleanup_descriptors(self) -> None:
        for identity, descriptor in tuple(self._cleanup_file_fds.items()):
            try:
                _close_owned_cleanup_descriptor(self._cleanup_file_fds, identity)
            except (EnronPrivateIOError, OSError):
                pass
        if self._cleanup_file_fds:
            raise EnronPrivateIOError("Private cleanup descriptors could not be closed safely.")

    def _require_active(self) -> None:
        if not self._entered or self._stage_fd is None or self._parent_fd is None:
            raise EnronPrivateIOError("Private run is not active.")

    def _cleanup(self) -> None:
        """Run cleanup behind an outer boundary that cannot skip settlement."""

        try:
            self._cleanup_once()
        finally:
            # If control escaped at any loop/assignment seam in the first
            # attempt, Python enters this finally before unwinding the owner.
            # Replay the idempotent cleanup until no local authority or writer
            # remains; the original exception is then restored automatically.
            while not self._cleanup_is_settled():
                try:
                    self._cleanup_once()
                except BaseException:
                    continue

    def _cleanup_is_settled(self) -> bool:
        try:
            writers_closed = all(handle.closed for handle in getattr(self, "_open_handles", ()))
        except Exception:
            return False
        return (
            writers_closed
            and not getattr(self, "_cleanup_file_fds", {})
            and getattr(self, "_stage_fd", None) is None
            and getattr(self, "_parent_fd", None) is None
        )

    def _cleanup_once(self) -> None:
        cleanup_failed = False
        cleanup_control_error: BaseException | None = None
        for handle in self._open_handles:
            while not handle.closed:
                try:
                    handle.close()
                except BaseException as exc:
                    if cleanup_control_error is None:
                        cleanup_control_error = exc
                    # A writer must be quiesced before its cleanup descriptor
                    # is wiped; a one-shot interrupt cannot skip this boundary.
                    continue
        self._open_handles.clear()
        stage_fd = self._stage_fd
        parent_fd = self._parent_fd
        expected_identity = self._stage_identity
        content_wiped = False
        retained_tombstone = False
        try:
            initial_cleanup_descriptors_wiped = self._wipe_cleanup_descriptors()
            if not initial_cleanup_descriptors_wiped:
                cleanup_failed = True
            if stage_fd is not None:
                try:
                    stage_info = os.fstat(stage_fd)
                    if (
                        expected_identity is None
                        or not stat.S_ISDIR(stage_info.st_mode)
                        or stage_info.st_uid != os.geteuid()
                        or (stage_info.st_dev, stage_info.st_ino) != expected_identity
                    ):
                        raise EnronPrivateIOError("Pinned private staging identity changed.")
                    os.fchmod(stage_fd, _DIRECTORY_MODE)
                    if not _clear_pinned_private_directory(stage_fd, self._stage_dir or Path.cwd()) or not (
                        _private_tree_payload_is_empty(stage_fd, depth=0, entries=[0])
                    ):
                        cleanup_failed = True
                    else:
                        content_wiped = True
                except (EnronPrivateIOError, OSError):
                    cleanup_failed = True
            elif self._stage_name is not None and not self._committed:
                cleanup_failed = True

            if stage_fd is not None and parent_fd is not None and expected_identity is not None:
                candidate_names = [
                    name for name in (self._stage_name, self._final_dir.name if self._final_dir else None) if name
                ]
                matching_names: list[str] = []
                for name in dict.fromkeys(candidate_names):
                    try:
                        info = _stat_at(parent_fd, self._final_dir.parent if self._final_dir else Path.cwd(), name)
                    except FileNotFoundError:
                        continue
                    except OSError:
                        cleanup_failed = True
                        continue
                    try:
                        if _private_directory_identity(info) == expected_identity:
                            matching_names.append(name)
                    except EnronPrivateIOError:
                        continue
                if len(matching_names) == 1:
                    name = matching_names[0]
                    try:
                        if cleanup_failed:
                            raise EnronPrivateIOError("Private staging contents could not be wiped safely.")
                        quarantine_name = f".nerb-cleanup-{secrets.token_hex(24)}"
                        quarantine_path = (self._final_dir.parent if self._final_dir else Path.cwd()) / quarantine_name
                        if (
                            self._workspace_root is not None
                            and _is_within(quarantine_path, self._workspace_root)
                            and not self._allow_unignored_output
                        ):
                            _require_git_ignored(quarantine_path, self._workspace_root)
                        _quarantine_verified_cleanup_entry(
                            parent_fd,
                            self._final_dir.parent if self._final_dir else Path.cwd(),
                            name,
                            expected_identity,
                            directory=True,
                            quarantine_name=quarantine_name,
                        )
                        retained_tombstone = True
                        if not _private_tree_payload_is_empty(stage_fd, depth=0, entries=[0]):
                            raise EnronPrivateIOError("Private cleanup tombstone payload is not empty.")
                        os.fsync(parent_fd)
                    except (EnronPrivateIOError, OSError):
                        cleanup_failed = True
                else:
                    cleanup_failed = True
            elif stage_fd is not None:
                cleanup_failed = True
        finally:
            # Settle private file authority while the stage/parent descriptors
            # are still live.  Directory closure is deliberately last.
            try:
                cleanup_descriptors_wiped = self._wipe_and_close_cleanup_descriptors()
            except BaseException as exc:
                cleanup_descriptors_wiped = False
                if cleanup_control_error is None:
                    cleanup_control_error = exc
            while self._cleanup_file_fds:
                try:
                    _park_run_cleanup_descriptors(self)
                except BaseException as exc:
                    if cleanup_control_error is None:
                        cleanup_control_error = exc
                    continue
            if self._cleanup_file_fds:
                cleanup_failed = True
            if not cleanup_descriptors_wiped:
                cleanup_failed = True
                content_wiped = False
            if cleanup_failed:
                content_wiped = False

            for descriptor in (stage_fd, parent_fd):
                if descriptor is None:
                    continue
                close_error = _close_unaccounted_descriptor_to_completion(descriptor)
                if close_error is not None:
                    if cleanup_control_error is None:
                        cleanup_control_error = close_error
                    if not isinstance(close_error, (KeyboardInterrupt, SystemExit)):
                        cleanup_failed = True
            self._stage_fd = None
            self._parent_fd = None
            self._stage_identity = None
            self._stage_name = None
            self._stage_dir = None
            self._workspace_root = None
            if stage_fd is not None:
                self._cleanup_sensitive_content_wiped = content_wiped
                self._cleanup_path_tree_removed = False
                self._cleanup_tombstone_count = 1 if retained_tombstone else 0
        if cleanup_control_error is not None:
            raise cleanup_control_error
        if cleanup_failed:
            raise EnronPrivateIOError("Private staging data could not be cleaned up safely.") from None


def iter_strict_jsonl(path: Path, max_line_bytes: int) -> Iterator[tuple[int, bytes, Mapping[str, Any]]]:
    """Yield bounded UTF-8 JSON-object lines without accepting JSON extensions."""

    if (
        isinstance(max_line_bytes, bool)
        or not isinstance(max_line_bytes, int)
        or max_line_bytes <= 0
        or max_line_bytes >= sys.maxsize
    ):
        raise EnronPrivateIOError("JSONL line limit must be a positive integer.")
    source = _absolute_path_without_traversal(path, description="Input")
    return _iter_strict_jsonl(source, max_line_bytes)


def open_private_binary_input(path: Path, *, buffer_bytes: int = _JSONL_BUFFER_BYTES) -> BinaryIO:
    """Open a regular input through a no-follow descriptor walk."""

    if isinstance(buffer_bytes, bool) or not isinstance(buffer_bytes, int) or buffer_bytes <= 0:
        raise EnronPrivateIOError("Private input buffer size must be a positive integer.")
    source = _absolute_path_without_traversal(path, description="Input")
    descriptor = _open_regular_input(source)
    try:
        return os.fdopen(descriptor, "rb", buffering=buffer_bytes)
    except BaseException:
        os.close(descriptor)
        raise


def open_private_directory_input(path: Path) -> int:
    """Pin a private directory through a no-follow descriptor walk."""

    source = _absolute_path_without_traversal(path, description="Private directory")
    _require_transaction_capabilities()
    current_path = Path(source.anchor)
    current_fd: int | None = None
    try:
        current_fd = os.open(current_path, _directory_open_flags())
        for component in source.parts[1:]:
            next_fd = _open_directory_at(current_fd, current_path, component)
            os.close(current_fd)
            current_fd = next_fd
            current_path /= component
        info = os.fstat(current_fd)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or not is_owner_only_private_mode(stat.S_IMODE(info.st_mode))
        ):
            raise EnronPrivateIOError("Private directory input must be an owned owner-only directory.")
        descriptor = current_fd
        current_fd = None
        return descriptor
    except EnronPrivateIOError:
        raise
    except (OSError, ValueError):
        raise EnronPrivateIOError("Private directory input could not be opened safely.") from None
    finally:
        if current_fd is not None:
            os.close(current_fd)


def open_private_binary_input_at(
    directory_fd: int,
    name: str,
    *,
    buffer_bytes: int = _JSONL_BUFFER_BYTES,
) -> BinaryIO:
    """Open one private regular file relative to an already pinned directory."""

    if type(directory_fd) is not int or directory_fd < 0:
        raise EnronPrivateIOError("Private input directory descriptor is invalid.")
    if not isinstance(name, str) or not name or Path(name).name != name or name in {os.curdir, os.pardir}:
        raise EnronPrivateIOError("Private input name must be one non-traversing path component.")
    if isinstance(buffer_bytes, bool) or not isinstance(buffer_bytes, int) or buffer_bytes <= 0:
        raise EnronPrivateIOError("Private input buffer size must be a positive integer.")
    _require_transaction_capabilities()
    descriptor: int | None = None
    try:
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not is_owner_only_private_mode(stat.S_IMODE(before.st_mode))
        ):
            raise EnronPrivateIOError("Private input must be a private single-link regular file.")
        descriptor = os.open(name, _regular_read_flags(), dir_fd=directory_fd)
        after = os.fstat(descriptor)
        if (
            not stat.S_ISREG(after.st_mode)
            or after.st_nlink != 1
            or not is_owner_only_private_mode(stat.S_IMODE(after.st_mode))
            or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
        ):
            raise EnronPrivateIOError("Private input changed while it was opened.")
        handle = os.fdopen(descriptor, "rb", buffering=buffer_bytes)
        descriptor = None
        return handle
    except EnronPrivateIOError:
        raise
    except (OSError, ValueError):
        raise EnronPrivateIOError("Private input could not be opened safely.") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _iter_strict_jsonl(path: Path, max_line_bytes: int) -> Iterator[tuple[int, bytes, Mapping[str, Any]]]:
    with open_private_binary_input(path) as file:
        line_no = 0
        while True:
            try:
                raw_line = file.readline(max_line_bytes + 1)
            except (OSError, OverflowError):
                raise EnronPrivateIOError("JSONL input could not be read safely.") from None
            if not raw_line:
                return
            line_no += 1
            if len(raw_line) > max_line_bytes:
                raise EnronPrivateIOError(f"JSONL line {line_no} exceeds the byte limit.")
            try:
                payload = raw_line.decode("utf-8")
            except UnicodeDecodeError:
                raise EnronPrivateIOError(f"JSONL line {line_no} is not valid UTF-8.") from None
            try:
                value = json.loads(
                    payload,
                    parse_constant=_reject_json_constant,
                    parse_float=_parse_finite_float,
                    parse_int=_parse_bounded_int,
                    object_pairs_hook=_reject_duplicate_json_keys,
                )
            except _StrictJSONError as exc:
                raise EnronPrivateIOError(f"JSONL line {line_no} {exc.reason}.") from None
            except (json.JSONDecodeError, RecursionError, ValueError):
                raise EnronPrivateIOError(f"JSONL line {line_no} is not valid JSON.") from None
            if not isinstance(value, dict):
                raise EnronPrivateIOError(f"JSONL line {line_no} must contain a JSON object.")
            yield line_no, raw_line, value


class _StrictJSONError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _reject_json_constant(_value: str) -> None:
    raise _StrictJSONError("contains a non-finite number")


def _parse_finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise _StrictJSONError("contains a non-finite number")
    return parsed


def _parse_bounded_int(value: str) -> int:
    digits = value[1:] if value.startswith("-") else value
    if len(digits) > _MAX_JSON_INTEGER_DIGITS:
        raise _StrictJSONError("contains an integer exceeding the digit limit")
    try:
        return int(value)
    except (OverflowError, ValueError):
        raise _StrictJSONError("contains an invalid integer") from None


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _StrictJSONError("contains a duplicate object key")
        value[key] = item
    return value


def _absolute_path_without_traversal(path: Path | str, *, description: str) -> Path:
    try:
        candidate = Path(path).expanduser()
    except (OSError, RuntimeError, TypeError, ValueError):
        raise EnronPrivateIOError(f"{description} path is invalid.") from None
    if any(part == os.pardir for part in candidate.parts):
        raise EnronPrivateIOError(f"{description} path must not contain parent traversal.")
    try:
        return candidate if candidate.is_absolute() else Path.cwd() / candidate
    except (OSError, RuntimeError, ValueError):
        raise EnronPrivateIOError(f"{description} path is invalid.") from None


def _safe_relative_path(relative: Path | str) -> Path:
    try:
        path = Path(relative)
    except (OSError, RuntimeError, TypeError, ValueError):
        raise EnronPrivateIOError("Private output relative path is invalid.") from None
    if path.is_absolute() or not path.parts or any(part in {os.curdir, os.pardir} for part in path.parts):
        raise EnronPrivateIOError("Private output path must be a non-traversing relative path.")
    if len(path.parts) == 1 and path.name == _COMMIT_MARKER:
        raise EnronPrivateIOError("The private commit marker name is reserved.")
    return path


def _reject_unsafe_existing_components(path: Path, *, reject_target: bool) -> None:
    for ancestor in reversed(path.parents):
        try:
            info = ancestor.lstat()
        except FileNotFoundError:
            continue
        except (OSError, ValueError):
            raise EnronPrivateIOError("Output path ancestors could not be inspected safely.") from None
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise EnronPrivateIOError("Output path ancestors must be non-symlink directories.")
    if reject_target:
        try:
            path.lstat()
        except FileNotFoundError:
            return
        except (OSError, ValueError):
            raise EnronPrivateIOError("Output target could not be inspected safely.") from None
        raise EnronPrivateIOError("Private output target already exists.")


def _workspace_for_path(path: Path, requested_root: Path | None) -> Path | None:
    root = (
        find_workspace_root(path)
        if requested_root is None
        else _absolute_path_without_traversal(requested_root, description="Workspace")
    )
    if root is None:
        return None
    try:
        info = root.lstat()
    except (OSError, ValueError):
        raise EnronPrivateIOError("Workspace root could not be inspected safely.") from None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise EnronPrivateIOError("Workspace root must be a non-symlink directory.")
    if requested_root is not None and not _is_within(path, root):
        return find_workspace_root(path)
    return root


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _require_git_ignored(path: Path, root: Path) -> None:
    try:
        relative = path.relative_to(root)
        completed = subprocess.run(
            ["git", "-C", os.fspath(root), "check-ignore", "--quiet", "--", os.fspath(relative)],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        raise EnronPrivateIOError("Git ignore status could not be determined safely.") from None
    if completed.returncode != 0:
        raise EnronPrivateIOError("Private output inside a Git workspace must be ignored.")


def _directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )


def _require_transaction_capabilities() -> None:
    if not _TRANSACTION_CAPABILITIES_AVAILABLE:
        raise EnronPrivateIOError("Private transactions require POSIX no-follow and directory-fd support.")


def _cleanup_fd_soft_limit() -> int | None:
    try:
        import resource

        soft_limit, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft_limit == resource.RLIM_INFINITY:
            return None
        if type(soft_limit) is not int or soft_limit <= 0:
            raise EnronPrivateIOError("Private cleanup descriptor limit is unavailable.")
        return soft_limit
    except EnronPrivateIOError:
        raise
    except (ImportError, OSError, ValueError):
        raise EnronPrivateIOError("Private cleanup descriptor capacity could not be verified.") from None


def _require_cleanup_fd_headroom(*, additional_descriptors: int = 0) -> None:
    """Require the process reserve without claiming per-transaction worst-case slots."""

    if type(additional_descriptors) is not int or additional_descriptors < 0:
        raise EnronPrivateIOError("Private cleanup descriptor headroom request is invalid.")
    with _CLEANUP_FD_ACCOUNTING_LOCK:
        soft_limit = _cleanup_fd_soft_limit()
        if soft_limit is None:
            return
        if (
            _current_open_descriptor_count()
            + _PENDING_CLEANUP_FDS
            + additional_descriptors
            + _PINNED_CLEANUP_FD_RESERVE
            > soft_limit
        ):
            raise EnronPrivateIOError("Private cleanup descriptor capacity is insufficient.")


def _sync_cleanup_fd_counts_locked() -> None:
    global _LIVE_CLEANUP_FDS, _PENDING_CLEANUP_FDS
    _PENDING_CLEANUP_FDS = len(_PENDING_CLEANUP_RESERVATIONS)
    _LIVE_CLEANUP_FDS = len(_ACCOUNTED_CLEANUP_FDS)


def _reserve_cleanup_fd_slot(reservation: object) -> None:
    """Reserve one process-wide cleanup descriptor before opening it."""

    with _CLEANUP_FD_ACCOUNTING_LOCK:
        if reservation in _PENDING_CLEANUP_RESERVATIONS:
            raise EnronPrivateIOError("Private cleanup descriptor reservation is not unique.")
        if len(_ACCOUNTED_CLEANUP_FDS) + len(_PENDING_CLEANUP_RESERVATIONS) >= _MAX_PINNED_CLEANUP_FILES:
            raise EnronPrivateIOError("Private cleanup descriptors exceed the process-wide live limit.")
        soft_limit = _cleanup_fd_soft_limit()
        if soft_limit is not None and (
            _current_open_descriptor_count() + len(_PENDING_CLEANUP_RESERVATIONS) + 1 + _PINNED_CLEANUP_FD_RESERVE
            > soft_limit
        ):
            raise EnronPrivateIOError("Private cleanup descriptor capacity is insufficient.")
        try:
            _PENDING_CLEANUP_RESERVATIONS.add(reservation)
        finally:
            _sync_cleanup_fd_counts_locked()


def _activate_cleanup_fd_slot(reservation: object, descriptor: int) -> None:
    with _CLEANUP_FD_ACCOUNTING_LOCK:
        if reservation not in _PENDING_CLEANUP_RESERVATIONS:
            raise EnronPrivateIOError("Private cleanup descriptor accounting is inconsistent.")
        if descriptor in _ACCOUNTED_CLEANUP_FDS:
            raise EnronPrivateIOError("Private cleanup descriptor accounting is not unique.")
        try:
            _PENDING_CLEANUP_RESERVATIONS.remove(reservation)
            _ACCOUNTED_CLEANUP_FDS.add(descriptor)
        except BaseException:
            _ACCOUNTED_CLEANUP_FDS.discard(descriptor)
            _PENDING_CLEANUP_RESERVATIONS.add(reservation)
            raise
        finally:
            _sync_cleanup_fd_counts_locked()


def _cancel_cleanup_fd_slot(reservation: object) -> None:
    with _CLEANUP_FD_ACCOUNTING_LOCK:
        try:
            _PENDING_CLEANUP_RESERVATIONS.discard(reservation)
        finally:
            _sync_cleanup_fd_counts_locked()


def _release_cleanup_fd_slot(descriptor: int) -> None:
    with _CLEANUP_FD_ACCOUNTING_LOCK:
        try:
            _ACCOUNTED_CLEANUP_FDS.discard(descriptor)
        finally:
            _sync_cleanup_fd_counts_locked()


def _cleanup_fd_slot_is_accounted(descriptor: int) -> bool:
    with _CLEANUP_FD_ACCOUNTING_LOCK:
        return descriptor in _ACCOUNTED_CLEANUP_FDS


def _descriptor_inventory_signature(descriptor: int) -> tuple[int, ...]:
    """Return a stable-enough signature to detect ordinary fd-number reuse."""

    try:
        import fcntl

        info = os.fstat(descriptor)
        return (
            int(info.st_dev),
            int(info.st_ino),
            int(info.st_mode),
            int(info.st_uid),
            int(info.st_rdev),
            int(fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE),
            int(fcntl.fcntl(descriptor, fcntl.F_GETFD)),
        )
    except (ImportError, OSError, ValueError):
        raise EnronPrivateIOError("Open descriptor identity could not be inspected.") from None


def _descriptor_numbers_from_path(path: Path) -> set[int]:
    try:
        names = os.listdir(path)
    except (OSError, ValueError):
        raise EnronPrivateIOError("Open descriptor inventory path could not be read.") from None
    descriptors: set[int] = set()
    for name in names:
        if not name.isdecimal():
            continue
        descriptor = int(name)
        try:
            os.fstat(descriptor)
        except OSError:
            continue
        descriptors.add(descriptor)
    return descriptors


def _close_unreturned_inventory_descriptors(
    path: Path,
    before: set[int],
    expected_identity: tuple[int, int],
) -> None:
    """Recover inventory-directory fds when an open wrapper raises post-syscall."""

    while True:
        try:
            candidates = _descriptor_numbers_from_path(path) - before
            break
        except BaseException:
            continue
    for descriptor in sorted(candidates):
        try:
            info = os.fstat(descriptor)
        except OSError:
            continue
        if stat.S_ISDIR(info.st_mode) and (int(info.st_dev), int(info.st_ino)) == expected_identity:
            _close_unaccounted_descriptor_to_completion(descriptor)


def _open_pinned_descriptor_inventory() -> int:
    """Pin and authenticate this process's descriptor table before acquisition."""

    candidates = [Path(f"/proc/{os.getpid()}/fd")] if sys.platform.startswith("linux") else []
    candidates.append(Path("/dev/fd"))
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    for path in candidates:
        descriptor: int | None = None
        try:
            path_info = path.stat()
            expected_identity = int(path_info.st_dev), int(path_info.st_ino)
            before = _descriptor_numbers_from_path(path)
        except (EnronPrivateIOError, OSError, ValueError):
            continue
        try:
            descriptor = os.open(path, flags)
            directory_info = os.fstat(descriptor)
            if not stat.S_ISDIR(directory_info.st_mode):
                raise EnronPrivateIOError("Open descriptor inventory is not a directory.")
            names = os.listdir(descriptor)
            if str(descriptor) not in names:
                raise EnronPrivateIOError("Open descriptor inventory is not this process's descriptor table.")
            self_info = os.stat(str(descriptor), dir_fd=descriptor)
            if (
                int(self_info.st_dev),
                int(self_info.st_ino),
                stat.S_IFMT(self_info.st_mode),
            ) != (
                int(directory_info.st_dev),
                int(directory_info.st_ino),
                stat.S_IFMT(directory_info.st_mode),
            ):
                raise EnronPrivateIOError("Open descriptor inventory identity is invalid.")
            return descriptor
        except (EnronPrivateIOError, OSError, ValueError):
            if descriptor is not None:
                _close_unaccounted_descriptor_to_completion(descriptor)
        except BaseException:
            if descriptor is not None:
                _close_unaccounted_descriptor_to_completion(descriptor)
            else:
                _close_unreturned_inventory_descriptors(path, before, expected_identity)
            raise
    raise EnronPrivateIOError("A pinned open descriptor inventory is unavailable.")


def _snapshot_pinned_descriptor_inventory(inventory_fd: int) -> dict[int, tuple[int, ...]]:
    """Snapshot live fd numbers and identities through a previously pinned table."""

    try:
        try:
            os.lseek(inventory_fd, 0, os.SEEK_SET)
        except OSError:
            pass
        names = os.listdir(inventory_fd)
    except (OSError, ValueError):
        raise EnronPrivateIOError("Pinned open descriptor inventory could not be read.") from None
    descriptors: dict[int, tuple[int, ...]] = {}
    for name in names:
        if not name.isdecimal():
            continue
        descriptor = int(name)
        try:
            descriptors[descriptor] = _descriptor_inventory_signature(descriptor)
        except EnronPrivateIOError:
            # A descriptor owned by an unrelated thread may disappear while it
            # is enumerated.  Acquisition candidates are recovered below from
            # every descriptor that remains live and matches the private inode.
            continue
    return descriptors


def _recover_cleanup_acquisition_candidates(
    inventory_fd: int,
    before: Mapping[int, tuple[int, ...]],
    identity: tuple[int, int],
    *,
    known_descriptor: int | None,
    target_descriptor: int | None,
) -> tuple[int, ...]:
    """Return every new/reused writable descriptor for the expected inode."""

    try:
        import fcntl

        after = _snapshot_pinned_descriptor_inventory(inventory_fd)
        possible = {descriptor for descriptor, signature in after.items() if before.get(descriptor) != signature}
        if known_descriptor is not None:
            possible.add(known_descriptor)
        if target_descriptor is not None:
            possible.add(target_descriptor)
        candidates: list[int] = []
        for descriptor in sorted(possible):
            try:
                info = os.fstat(descriptor)
                access_mode = fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE
            except (OSError, ValueError):
                continue
            if (
                (int(info.st_dev), int(info.st_ino)) == identity
                and stat.S_ISREG(info.st_mode)
                and info.st_uid == os.geteuid()
                and access_mode == os.O_RDWR
            ):
                candidates.append(descriptor)
        return tuple(candidates)
    except (ImportError, OSError, ValueError):
        raise EnronPrivateIOError("Private cleanup acquisition descriptors could not be recovered.") from None


def _normalize_failed_cleanup_acquisition_accounting(
    reservation: object,
    descriptors: tuple[int, ...],
) -> None:
    """Atomically own every recovered fd before releasing the reservation."""

    with _CLEANUP_FD_ACCOUNTING_LOCK:
        try:
            # A misbehaving primitive can create more than the one reserved fd.
            # Those already-live descriptors must be accounted before any
            # bounded-limit error can safely be reported.
            _ACCOUNTED_CLEANUP_FDS.update(descriptors)
            _PENDING_CLEANUP_RESERVATIONS.discard(reservation)
        finally:
            _sync_cleanup_fd_counts_locked()


def _cleanup_owner_identity(key: tuple[int, ...]) -> tuple[int, int]:
    if len(key) not in {2, 3}:
        raise EnronPrivateIOError("Private cleanup owner key is invalid.")
    return int(key[0]), int(key[1])


def _park_failed_acquisition_descriptors_to_completion(
    descriptors: dict[tuple[int, ...], int],
) -> None:
    """Publish exceptional same-inode authorities without dropping duplicates."""

    while descriptors:
        try:
            _park_cleanup_descriptor_map(descriptors)
        except BaseException:
            # Returning while this local map is the sole owner would leak
            # cleanup authority.  Publication is therefore a to-completion
            # boundary; one-shot control errors are deferred by retrying.
            continue


def _settle_failed_cleanup_acquisition_to_completion(
    reservation: object,
    inventory_fd: int,
    before: Mapping[int, tuple[int, ...]],
    identity: tuple[int, int],
    *,
    known_descriptor: int | None,
    target_before: int | None,
    target: dict[tuple[int, int], int],
) -> None:
    """Settle every reserve/open/publish seam before restoring control flow."""

    candidates: set[int] | None = None
    unresolved: dict[tuple[int, ...], int] = {}
    while True:
        try:
            if candidates is None:
                target_after = target.get(identity)
                recovered = _recover_cleanup_acquisition_candidates(
                    inventory_fd,
                    before,
                    identity,
                    known_descriptor=known_descriptor,
                    target_descriptor=target_after if target_after != target_before else None,
                )
                candidates = set(recovered)

            _normalize_failed_cleanup_acquisition_accounting(reservation, tuple(candidates))
            with _CLEANUP_FD_ACCOUNTING_LOCK:
                if reservation in _PENDING_CLEANUP_RESERVATIONS or any(
                    descriptor not in _ACCOUNTED_CLEANUP_FDS for descriptor in candidates
                ):
                    continue

            target_after = target.get(identity)
            target_owned = target_after if target_after != target_before and target_after in candidates else None
            for descriptor in tuple(candidates):
                if descriptor == target_owned:
                    candidates.discard(descriptor)
                    continue
                key = (*identity, descriptor)
                if key in unresolved:
                    candidates.discard(descriptor)
                    continue
                wiped = _wipe_authenticated_cleanup_descriptor(identity, descriptor)
                if wiped:
                    closed, _error = _attempt_close_cleanup_descriptor(identity, descriptor)
                    if closed:
                        candidates.discard(descriptor)
                        continue
                # Publish the local ownership transition before removing the
                # fd from the work set, so interruption at either line is
                # recoverable on the next state-machine iteration.
                unresolved[key] = descriptor
                candidates.discard(descriptor)

            if candidates:
                continue
            _park_failed_acquisition_descriptors_to_completion(unresolved)
            with _CLEANUP_FD_ACCOUNTING_LOCK:
                if reservation in _PENDING_CLEANUP_RESERVATIONS:
                    continue
            return
        except BaseException:
            # Every local transition above is monotonic and replayable.  This
            # outer boundary catches control at loop/assignment lines as well
            # as inside helpers, so no raw authority can escape on stack unwind.
            continue


def _close_unaccounted_descriptor_to_completion(descriptor: int) -> BaseException | None:
    """Prove an unaccounted fd closed/reused before restoring control flow."""

    first_error: BaseException | None = None
    expected: tuple[int, int, int] | None = None
    while expected is None:
        try:
            info = os.fstat(descriptor)
            expected = int(info.st_dev), int(info.st_ino), stat.S_IFMT(info.st_mode)
        except (KeyboardInterrupt, SystemExit) as exc:
            if first_error is None:
                first_error = exc
        except OSError as exc:
            if exc.errno == errno.EBADF:
                return first_error
            if first_error is None:
                first_error = exc
    while True:
        try:
            os.close(descriptor)
        except BaseException as exc:
            if first_error is None:
                first_error = exc
        try:
            current = os.fstat(descriptor)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                return first_error
            if first_error is None:
                first_error = exc
            continue
        current_identity = int(current.st_dev), int(current.st_ino), stat.S_IFMT(current.st_mode)
        if current_identity != expected:
            return first_error


def _open_cleanup_descriptor_at(
    directory_fd: int,
    directory_path: Path,
    name: str,
    flags: int,
    *,
    expected_identity: tuple[int, int],
    target: dict[tuple[int, int], int],
) -> None:
    reservation = object()
    descriptor: int | None = None
    before_info = _stat_at(directory_fd, directory_path, name)
    identity = int(before_info.st_dev), int(before_info.st_ino)
    if identity != expected_identity:
        raise EnronPrivateIOError("Private cleanup acquisition identity changed before open.")
    target_before = target.get(identity)
    with _CLEANUP_FD_ACQUISITION_LOCK:
        inventory_fd: int | None = None
        before_descriptors: dict[int, tuple[int, ...]] | None = None
        operation_completed = False
        settlement_completed = False
        try:
            inventory_fd = _open_pinned_descriptor_inventory()
            before_descriptors = _snapshot_pinned_descriptor_inventory(inventory_fd)
            try:
                try:
                    _reserve_cleanup_fd_slot(reservation)
                    descriptor = _open_at(directory_fd, directory_path, name, flags)
                    info = os.fstat(descriptor)
                    identity = int(info.st_dev), int(info.st_ino)
                    if identity != expected_identity:
                        raise EnronPrivateIOError("Private cleanup acquisition identity changed while opening.")
                    _activate_cleanup_fd_slot(reservation, descriptor)
                    _require_cleanup_descriptors_current({identity: descriptor})
                    if identity in target:
                        _close_cleanup_descriptor(identity, descriptor)
                        descriptor = None
                    else:
                        target[identity] = descriptor
                        descriptor = None
                    operation_completed = True
                finally:
                    if not operation_completed:
                        _settle_failed_cleanup_acquisition_to_completion(
                            reservation,
                            inventory_fd,
                            before_descriptors,
                            expected_identity,
                            known_descriptor=descriptor,
                            target_before=target_before,
                            target=target,
                        )
                        settlement_completed = True
            finally:
                if not operation_completed and not settlement_completed:
                    _settle_failed_cleanup_acquisition_to_completion(
                        reservation,
                        inventory_fd,
                        before_descriptors,
                        expected_identity,
                        known_descriptor=descriptor,
                        target_before=target_before,
                        target=target,
                    )
        finally:
            if inventory_fd is not None:
                close_error = _close_unaccounted_descriptor_to_completion(inventory_fd)
                if operation_completed and close_error is not None:
                    raise close_error


def _duplicate_cleanup_descriptor(
    descriptor: int,
    *,
    target: dict[tuple[int, int], int],
) -> None:
    reservation = object()
    duplicate: int | None = None
    source_info = os.fstat(descriptor)
    identity = int(source_info.st_dev), int(source_info.st_ino)
    expected_identity = identity
    target_before = target.get(expected_identity)
    with _CLEANUP_FD_ACQUISITION_LOCK:
        inventory_fd: int | None = None
        before_descriptors: dict[int, tuple[int, ...]] | None = None
        operation_completed = False
        settlement_completed = False
        try:
            inventory_fd = _open_pinned_descriptor_inventory()
            before_descriptors = _snapshot_pinned_descriptor_inventory(inventory_fd)
            try:
                try:
                    _reserve_cleanup_fd_slot(reservation)
                    duplicate = os.dup(descriptor)
                    info = os.fstat(duplicate)
                    identity = int(info.st_dev), int(info.st_ino)
                    if identity != expected_identity:
                        raise EnronPrivateIOError("Private cleanup acquisition identity changed while duplicating.")
                    _activate_cleanup_fd_slot(reservation, duplicate)
                    _require_cleanup_descriptors_current({identity: duplicate})
                    if identity in target:
                        _close_cleanup_descriptor(identity, duplicate)
                        duplicate = None
                    else:
                        if len(target) >= _MAX_PINNED_CLEANUP_FILES:
                            raise EnronPrivateIOError("Private run exceeds its pinned cleanup file limit.")
                        target[identity] = duplicate
                        duplicate = None
                    operation_completed = True
                finally:
                    if not operation_completed:
                        _settle_failed_cleanup_acquisition_to_completion(
                            reservation,
                            inventory_fd,
                            before_descriptors,
                            expected_identity,
                            known_descriptor=duplicate,
                            target_before=target_before,
                            target=target,
                        )
                        settlement_completed = True
            finally:
                if not operation_completed and not settlement_completed:
                    _settle_failed_cleanup_acquisition_to_completion(
                        reservation,
                        inventory_fd,
                        before_descriptors,
                        expected_identity,
                        known_descriptor=duplicate,
                        target_before=target_before,
                        target=target,
                    )
        finally:
            if inventory_fd is not None:
                close_error = _close_unaccounted_descriptor_to_completion(inventory_fd)
                if operation_completed and close_error is not None:
                    raise close_error


def _attempt_close_cleanup_descriptor(
    identity: tuple[int, int] | None,
    descriptor: int,
) -> tuple[bool, BaseException | None]:
    """Close one accounted fd and report whether its original authority is gone."""

    first_error: BaseException | None = None
    expected_identity = identity
    if expected_identity is None:
        try:
            initial = os.fstat(descriptor)
            expected_identity = int(initial.st_dev), int(initial.st_ino)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                return False, exc
    for _attempt in range(2):
        try:
            os.close(descriptor)
        except BaseException as exc:
            if first_error is None:
                first_error = exc
        try:
            current = os.fstat(descriptor)
        except OSError as probe_error:
            if probe_error.errno != errno.EBADF:
                return False, first_error or probe_error
            original_gone = True
        else:
            original_gone = (
                expected_identity is not None
                and (
                    int(current.st_dev),
                    int(current.st_ino),
                )
                != expected_identity
            )
        if not original_gone:
            continue
        for _release_attempt in range(2):
            try:
                _release_cleanup_fd_slot(descriptor)
            except BaseException as exc:
                if first_error is None:
                    first_error = exc
                continue
            if not _cleanup_fd_slot_is_accounted(descriptor):
                return True, first_error
        return not _cleanup_fd_slot_is_accounted(descriptor), first_error
    return False, first_error


def _close_cleanup_descriptor(identity: tuple[int, int] | None, descriptor: int) -> None:
    closed, error = _attempt_close_cleanup_descriptor(identity, descriptor)
    if error is not None:
        raise error
    if not closed:
        raise EnronPrivateIOError("Private cleanup descriptor could not be closed safely.")


def _close_owned_cleanup_descriptor(
    descriptors: dict[_CleanupOwnerKey, int],
    key: _CleanupOwnerKey,
) -> None:
    """Close map-owned authority without losing the entry on an ambiguous failure."""

    descriptor = descriptors[key]
    identity = _cleanup_owner_identity(key)
    closed, error = _attempt_close_cleanup_descriptor(identity, descriptor)
    if closed and descriptors.get(key) == descriptor:
        descriptors.pop(key)
    if error is not None:
        raise error
    if not closed:
        raise EnronPrivateIOError("Private cleanup descriptor could not be closed safely.")


def _require_cleanup_descriptor_authority(descriptors: Mapping[_CleanupOwnerKey, int]) -> None:
    """Authenticate writable inode authority, including already-unlinked files."""

    try:
        import fcntl

        for key, descriptor in descriptors.items():
            identity = _cleanup_owner_identity(key)
            info = os.fstat(descriptor)
            access_mode = fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE
            if (
                (int(info.st_dev), int(info.st_ino)) != identity
                or not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or access_mode != os.O_RDWR
            ):
                raise EnronPrivateIOError("Private cleanup authority changed identity.")
    except EnronPrivateIOError:
        raise
    except (ImportError, OSError, ValueError):
        raise EnronPrivateIOError("Private cleanup authority could not be authenticated.") from None


def _cleanup_descriptor_original_is_gone(identity: tuple[int, int], descriptor: int) -> bool:
    try:
        info = os.fstat(descriptor)
    except OSError as exc:
        if exc.errno == errno.EBADF:
            return True
        raise EnronPrivateIOError("Private cleanup authority could not be inspected.") from None
    return (int(info.st_dev), int(info.st_ino)) != identity


def _require_cleanup_retry_entries(descriptors: Mapping[_CleanupOwnerKey, int]) -> None:
    for key, descriptor in descriptors.items():
        identity = _cleanup_owner_identity(key)
        if _cleanup_descriptor_original_is_gone(identity, descriptor):
            continue
        _require_cleanup_descriptor_authority({key: descriptor})


def _clear_cleanup_descriptor_map(descriptors: dict[_CleanupOwnerKey, int]) -> None:
    descriptors.clear()


def _clear_cleanup_descriptor_map_to_completion(
    descriptors: dict[_CleanupOwnerKey, int],
    *,
    deferred_error: BaseException | None,
) -> None:
    """Clear a published map's former owner before restoring deferred control flow."""

    first_error = deferred_error
    while descriptors:
        try:
            _clear_cleanup_descriptor_map(descriptors)
        except (KeyboardInterrupt, SystemExit) as exc:
            if first_error is None:
                first_error = exc
    if first_error is not None:
        raise first_error


def _publish_unresolved_cleanup_descriptors(descriptors: dict[_CleanupOwnerKey, int]) -> None:
    """Publish a fully validated registry snapshot as the ownership commit point."""

    global _UNRESOLVED_CLEANUP_FDS
    _UNRESOLVED_CLEANUP_FDS = cast(dict[tuple[int, ...], int], descriptors)


def _park_cleanup_descriptor_map(descriptors: dict[_CleanupOwnerKey, int]) -> None:
    """Monotonically publish map-owned authority, then clear its former owner."""

    with _UNRESOLVED_CLEANUP_LOCK:
        registry_before = _UNRESOLVED_CLEANUP_FDS
        if not descriptors:
            return
        if all(registry_before.get(identity) == descriptor for identity, descriptor in descriptors.items()):
            _clear_cleanup_descriptor_map_to_completion(
                descriptors,
                deferred_error=None,
            )
            return
        if set(descriptors) & set(registry_before):
            raise EnronPrivateIOError("Private cleanup retry ownership overlaps an existing entry.")
        if len(descriptors) + len(registry_before) > _MAX_PINNED_CLEANUP_FILES:
            raise EnronPrivateIOError("Private cleanup retry registry exceeds its bounded limit.")
        combined = dict(registry_before)
        for key, descriptor in descriptors.items():
            combined[tuple(key)] = descriptor
        _require_cleanup_retry_entries(combined)
        publication_error: BaseException | None = None
        try:
            _publish_unresolved_cleanup_descriptors(combined)
        except BaseException as exc:
            publication_error = exc
        finally:
            if _UNRESOLVED_CLEANUP_FDS is combined:
                _clear_cleanup_descriptor_map_to_completion(
                    descriptors,
                    deferred_error=publication_error,
                )
        if publication_error is not None:
            raise publication_error


def _park_cleanup_descriptor_map_to_completion(
    descriptors: dict[_CleanupOwnerKey, int],
) -> BaseException | None:
    """Defer control flow until registry publication owns every descriptor."""

    first_control_error: BaseException | None = None
    while descriptors:
        try:
            _park_cleanup_descriptor_map(descriptors)
        except (KeyboardInterrupt, SystemExit) as exc:
            if first_control_error is None:
                first_control_error = exc
            continue
    return first_control_error


def _park_run_cleanup_descriptors(run: PrivateRun) -> None:
    """Move one run's unresolved descriptors to the process retry registry."""

    control_error: BaseException | None = None
    try:
        control_error = _park_cleanup_descriptor_map_to_completion(run._cleanup_file_fds)
    finally:
        if not run._cleanup_file_fds:
            run._cleanup_authority_retained = False
    if control_error is not None:
        raise control_error


def _retry_unresolved_cleanup_descriptors() -> None:
    """Retry every parked wipe and block new private runs until all reach zero."""

    with _UNRESOLVED_CLEANUP_LOCK:
        first_error: BaseException | None = None
        for key, descriptor in tuple(_UNRESOLVED_CLEANUP_FDS.items()):
            identity = _cleanup_owner_identity(key)
            if _cleanup_descriptor_original_is_gone(identity, descriptor):
                try:
                    _release_cleanup_fd_slot(descriptor)
                except BaseException as exc:
                    if first_error is None:
                        first_error = exc
                if not _cleanup_fd_slot_is_accounted(descriptor):
                    _UNRESOLVED_CLEANUP_FDS.pop(key, None)
                continue
            if not _wipe_authenticated_cleanup_descriptor(identity, descriptor):
                continue
            try:
                _close_owned_cleanup_descriptor(_UNRESOLVED_CLEANUP_FDS, key)
            except BaseException as exc:
                if first_error is None:
                    first_error = exc
        if _UNRESOLVED_CLEANUP_FDS:
            raise EnronPrivateIOError(
                "Unresolved private cleanup authority blocks a new private transaction."
            ) from first_error
        if first_error is not None:
            raise first_error


def _current_open_descriptor_count() -> int:
    for directory in (Path("/proc/self/fd"), Path("/dev/fd")):
        try:
            names = os.listdir(directory)
        except OSError:
            continue
        count = sum(name.isdecimal() for name in names)
        if count > 0:
            return count
    raise EnronPrivateIOError("Open descriptor inventory is unavailable.")


def _require_exact_private_directory(info: os.stat_result) -> None:
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != _DIRECTORY_MODE
    ):
        raise EnronPrivateIOError("Private directory ownership or permissions changed.")


def _require_cleanup_descriptors_current(descriptors: Mapping[tuple[int, int], int]) -> None:
    try:
        import fcntl

        for identity, descriptor in descriptors.items():
            info = os.fstat(descriptor)
            access_mode = fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE
            if (
                (info.st_dev, info.st_ino) != identity
                or not stat.S_ISREG(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != _FILE_MODE
                or access_mode != os.O_RDWR
            ):
                raise EnronPrivateIOError("Private cleanup descriptor identity or permissions changed.")
    except EnronPrivateIOError:
        raise
    except (ImportError, OSError, ValueError):
        raise EnronPrivateIOError("Private cleanup descriptor could not be authenticated.") from None


def _wipe_authenticated_cleanup_descriptor(identity: tuple[int, int], descriptor: int) -> bool:
    try:
        import fcntl

        info = os.fstat(descriptor)
        access_mode = fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE
        if (
            (info.st_dev, info.st_ino) != identity
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or access_mode != os.O_RDWR
        ):
            return False
        os.fchmod(descriptor, _FILE_MODE)
        os.ftruncate(descriptor, 0)
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        return (after.st_dev, after.st_ino) == identity and after.st_size == 0
    except (ImportError, OSError, ValueError):
        return False


def _require_nested_directory_identity(
    root_fd: int,
    root_path: Path,
    parts: tuple[str, ...],
    expected_identity: tuple[int, int],
) -> None:
    descriptor: int | None = None
    try:
        descriptor, _ = _open_relative_directory(root_fd, root_path, parts)
        info = os.fstat(descriptor)
        _require_exact_private_directory(info)
        if (info.st_dev, info.st_ino) != expected_identity:
            raise EnronPrivateIOError("Nested private directory changed identity.")
    except EnronPrivateIOError:
        raise
    except (OSError, ValueError):
        raise EnronPrivateIOError("Nested private directory could not be authenticated.") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _collect_cleanup_tree_descriptors(
    directory_fd: int,
    directory_path: Path,
    *,
    retained: dict[tuple[int, int], int],
    limit: int,
    depth: int,
    entries: list[int],
) -> None:
    if depth > _MAX_PINNED_CLEANUP_TREE_DEPTH:
        raise EnronPrivateIOError("Private cleanup tree exceeds its depth limit.")
    try:
        names = sorted(os.listdir(directory_fd))
    except OSError:
        raise EnronPrivateIOError("Private cleanup tree could not be inspected safely.") from None
    for name in names:
        entries[0] += 1
        if entries[0] > _MAX_PINNED_CLEANUP_TREE_ENTRIES:
            raise EnronPrivateIOError("Private cleanup tree exceeds its entry limit.")
        child_fd: int | None = None
        file_fd: int | None = None
        try:
            before = _stat_at(directory_fd, directory_path, name)
            if stat.S_ISLNK(before.st_mode):
                raise EnronPrivateIOError("Private cleanup tree must not contain symlinks.")
            if stat.S_ISDIR(before.st_mode):
                _require_exact_private_directory(before)
                child_fd = _open_directory_at(directory_fd, directory_path, name)
                opened = os.fstat(child_fd)
                _require_exact_private_directory(opened)
                if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                    raise EnronPrivateIOError("Private cleanup directory changed while it was opened.")
                _collect_cleanup_tree_descriptors(
                    child_fd,
                    directory_path / name,
                    retained=retained,
                    limit=limit,
                    depth=depth + 1,
                    entries=entries,
                )
                continue
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.geteuid()
                or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != _FILE_MODE
            ):
                raise EnronPrivateIOError("Private cleanup tree contains an unsafe file.")
            flags = (
                os.O_RDWR
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
            )
            before_identity = int(before.st_dev), int(before.st_ino)
            needs_retention = before_identity not in retained
            if needs_retention and len(retained) >= limit:
                raise EnronPrivateIOError("Private run exceeds its pinned cleanup file limit.")
            if needs_retention:
                _open_cleanup_descriptor_at(
                    directory_fd,
                    directory_path,
                    name,
                    flags,
                    expected_identity=before_identity,
                    target=retained,
                )
                retained_descriptor = retained[before_identity]
                opened = os.fstat(retained_descriptor)
                identity = int(opened.st_dev), int(opened.st_ino)
                if (
                    identity != (before.st_dev, before.st_ino)
                    or not stat.S_ISREG(opened.st_mode)
                    or opened.st_uid != os.geteuid()
                    or opened.st_nlink != 1
                    or stat.S_IMODE(opened.st_mode) != _FILE_MODE
                    or opened.st_size != before.st_size
                ):
                    raise EnronPrivateIOError("Private cleanup file changed while it was opened.")
                continue
            file_fd = _open_at(directory_fd, directory_path, name, flags)
            opened = os.fstat(file_fd)
            identity = int(opened.st_dev), int(opened.st_ino)
            if (
                identity != (before.st_dev, before.st_ino)
                or not stat.S_ISREG(opened.st_mode)
                or opened.st_uid != os.geteuid()
                or opened.st_nlink != 1
                or stat.S_IMODE(opened.st_mode) != _FILE_MODE
                or opened.st_size != before.st_size
            ):
                raise EnronPrivateIOError("Private cleanup file changed while it was opened.")
            if identity in retained:
                os.close(file_fd)
                file_fd = None
                continue
            raise EnronPrivateIOError("Private cleanup descriptor reservation changed during adoption.")
        except EnronPrivateIOError:
            raise
        except (OSError, ValueError):
            raise EnronPrivateIOError("Private cleanup tree could not be pinned safely.") from None
        finally:
            if file_fd is not None:
                os.close(file_fd)
            if child_fd is not None:
                os.close(child_fd)


def _regular_read_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )


def _open_or_create_private_directory(path: Path) -> int:
    if path.anchor == "":
        raise EnronPrivateIOError("Private output parent must be absolute.")
    current_fd: int | None = None
    try:
        current_path = Path(path.anchor)
        current_fd = os.open(current_path, _directory_open_flags())
        for component in path.parts[1:]:
            try:
                next_fd = _open_directory_at(current_fd, current_path, component)
            except FileNotFoundError:
                try:
                    _mkdir_at(current_fd, current_path, component, _DIRECTORY_MODE)
                    created = True
                except FileExistsError:
                    created = False
                next_fd = _open_directory_at(current_fd, current_path, component)
                if created:
                    os.fchmod(next_fd, _DIRECTORY_MODE)
            os.close(current_fd)
            current_fd = next_fd
            current_path /= component
        return current_fd
    except (EnronPrivateIOError, OSError, ValueError) as exc:
        try:
            if current_fd is not None:
                os.close(current_fd)
        except OSError:
            pass
        if isinstance(exc, EnronPrivateIOError):
            raise
        raise EnronPrivateIOError("Private output parent could not be created safely.") from None


def _open_or_create_relative_directory(root_fd: int, root_path: Path, parts: tuple[str, ...]) -> tuple[int, Path]:
    current_fd = os.dup(root_fd)
    current_path = root_path
    try:
        for component in parts:
            try:
                next_fd = _open_directory_at(current_fd, current_path, component)
            except FileNotFoundError:
                try:
                    _mkdir_at(current_fd, current_path, component, _DIRECTORY_MODE)
                    created = True
                except FileExistsError:
                    created = False
                next_fd = _open_directory_at(current_fd, current_path, component)
                if created:
                    os.fchmod(next_fd, _DIRECTORY_MODE)
            os.close(current_fd)
            current_fd = next_fd
            current_path /= component
        return current_fd, current_path
    except BaseException:
        os.close(current_fd)
        raise


def _open_relative_directory(root_fd: int, root_path: Path, parts: tuple[str, ...]) -> tuple[int, Path]:
    current_fd = os.dup(root_fd)
    current_path = root_path
    try:
        for component in parts:
            next_fd = _open_directory_at(current_fd, current_path, component)
            os.close(current_fd)
            current_fd = next_fd
            current_path /= component
        return current_fd, current_path
    except BaseException:
        os.close(current_fd)
        raise


def _open_directory_at(parent_fd: int, parent_path: Path, name: str) -> int:
    before = _stat_at(parent_fd, parent_path, name)
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        raise EnronPrivateIOError("Private path components must be non-symlink directories.")
    descriptor = _open_at(parent_fd, parent_path, name, _directory_open_flags())
    try:
        after = os.fstat(descriptor)
        if not stat.S_ISDIR(after.st_mode) or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise EnronPrivateIOError("Private directory changed while it was opened.")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_at(parent_fd: int, parent_path: Path, name: str, flags: int, mode: int | None = None) -> int:
    if os.open in os.supports_dir_fd:
        if mode is None:
            return os.open(name, flags, dir_fd=parent_fd)
        return os.open(name, flags, mode, dir_fd=parent_fd)
    if mode is None:
        return os.open(parent_path / name, flags)
    return os.open(parent_path / name, flags, mode)


def _mkdir_at(parent_fd: int, parent_path: Path, name: str, mode: int) -> None:
    if os.mkdir in os.supports_dir_fd:
        os.mkdir(name, mode, dir_fd=parent_fd)
    else:
        os.mkdir(parent_path / name, mode)
    try:
        if _FOLLOW_SAFE_CHMOD_AVAILABLE:
            os.chmod(name, mode, dir_fd=parent_fd, follow_symlinks=False)
        elif _LINUX_PROC_FD_CHMOD_AVAILABLE:
            flags = os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_PATH
            descriptor = os.open(name, flags, dir_fd=parent_fd)
            try:
                before = os.fstat(descriptor)
                if not stat.S_ISDIR(before.st_mode):
                    raise EnronPrivateIOError("New private path is not a directory.")
                os.chmod(f"/proc/self/fd/{descriptor}", mode)
                after = os.fstat(descriptor)
                if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                    raise EnronPrivateIOError("New private directory changed while setting permissions.")
            finally:
                os.close(descriptor)
        else:
            raise EnronPrivateIOError("Follow-safe private directory permissions are unavailable.")
    except BaseException:
        # No portable POSIX primitive removes a directory by verified inode.
        # Leave this newly allocated, payload-empty shell in place rather than
        # risk deleting a same-UID substitute after a name swap.
        raise


def _stat_at(parent_fd: int, parent_path: Path, name: str) -> os.stat_result:
    if os.stat in os.supports_dir_fd:
        return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    return (parent_path / name).lstat()


def _private_directory_identity(info: os.stat_result) -> tuple[int, int]:
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid()
        or not is_owner_only_private_mode(stat.S_IMODE(info.st_mode))
    ):
        raise EnronPrivateIOError("Private staging directory identity is unsafe.")
    return int(info.st_dev), int(info.st_ino)


def _require_directory_entry_identity(
    parent_fd: int,
    parent_path: Path,
    name: str,
    expected_identity: tuple[int, int],
) -> None:
    try:
        info = _stat_at(parent_fd, parent_path, name)
    except OSError:
        raise EnronPrivateIOError("Private staging directory entry is unavailable.") from None
    if _private_directory_identity(info) != expected_identity:
        raise EnronPrivateIOError("Private staging directory entry changed identity.")


def _unlink_at(parent_fd: int, parent_path: Path, name: str) -> None:
    if os.unlink in os.supports_dir_fd:
        os.unlink(name, dir_fd=parent_fd)
    else:
        os.unlink(parent_path / name)


def _rmdir_at(parent_fd: int, parent_path: Path, name: str) -> None:
    if os.rmdir in os.supports_dir_fd:
        os.rmdir(name, dir_fd=parent_fd)
    else:
        os.rmdir(parent_path / name)


def _require_absent_at(parent_fd: int, parent_path: Path, name: str) -> None:
    try:
        _stat_at(parent_fd, parent_path, name)
    except FileNotFoundError:
        return
    raise EnronPrivateIOError("Private output target already exists.")


def _sync_private_tree(directory_fd: int, directory_path: Path, *, root: bool) -> None:
    try:
        names = sorted(os.listdir(directory_fd if os.listdir in os.supports_fd else directory_path))
    except OSError:
        raise EnronPrivateIOError("Private staging directory could not be inspected safely.") from None
    if root and _COMMIT_MARKER in names:
        raise EnronPrivateIOError("Private commit marker must be created by commit.")
    os.fchmod(directory_fd, _DIRECTORY_MODE)
    for name in names:
        try:
            before = _stat_at(directory_fd, directory_path, name)
            if stat.S_ISLNK(before.st_mode):
                raise EnronPrivateIOError("Private staging data must not contain symlinks.")
            if stat.S_ISDIR(before.st_mode):
                child_fd = _open_directory_at(directory_fd, directory_path, name)
                try:
                    _sync_private_tree(child_fd, directory_path / name, root=False)
                finally:
                    os.close(child_fd)
                continue
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise EnronPrivateIOError("Private staging data must contain only private regular files.")
            file_fd = _open_at(directory_fd, directory_path, name, _regular_read_flags())
            try:
                after = os.fstat(file_fd)
                if (
                    not stat.S_ISREG(after.st_mode)
                    or after.st_nlink != 1
                    or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
                ):
                    raise EnronPrivateIOError("Private file changed while it was opened.")
                os.fchmod(file_fd, _FILE_MODE)
                os.fsync(file_fd)
            finally:
                os.close(file_fd)
        except EnronPrivateIOError:
            raise
        except OSError:
            raise EnronPrivateIOError("Private staging data could not be flushed safely.") from None
    try:
        os.fsync(directory_fd)
    except OSError:
        raise EnronPrivateIOError("Private staging directory could not be flushed safely.") from None


def _write_commit_marker(stage_fd: int, stage_path: Path) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        marker_fd = _open_at(stage_fd, stage_path, _COMMIT_MARKER, flags, _FILE_MODE)
        try:
            os.fchmod(marker_fd, _FILE_MODE)
            remaining = memoryview(_COMMIT_PAYLOAD)
            while remaining:
                written = os.write(marker_fd, remaining)
                if written <= 0:
                    raise OSError(errno.EIO, "short write")
                remaining = remaining[written:]
            os.fsync(marker_fd)
        finally:
            os.close(marker_fd)
    except EnronPrivateIOError:
        raise
    except OSError:
        raise EnronPrivateIOError("Private commit marker could not be written safely.") from None


def _rename_noreplace(parent_fd: int, parent_path: Path, source_name: str, destination_name: str) -> None:
    _rename_noreplace_at(parent_fd, source_name, parent_fd, destination_name)


def _rollback_unverified_promotion(
    parent_fd: int,
    parent_path: Path,
    stage_name: str,
    final_name: str,
) -> None:
    try:
        final_identity = _private_directory_identity(_stat_at(parent_fd, parent_path, final_name))
        _require_absent_at(parent_fd, parent_path, stage_name)
        _rename_noreplace_at(parent_fd, final_name, parent_fd, stage_name)
        os.fsync(parent_fd)
        _require_directory_entry_identity(parent_fd, parent_path, stage_name, final_identity)
        try:
            _stat_at(parent_fd, parent_path, final_name)
        except FileNotFoundError:
            return
    except (EnronPrivateIOError, OSError):
        raise EnronPrivateIOError("Unverified private promotion could not be rolled back safely.") from None
    raise EnronPrivateIOError("Unverified private promotion could not be rolled back safely.")


def _rename_cleanup_entry_at(
    parent_fd: int,
    parent_path: Path,
    source_name: str,
    destination_name: str,
) -> None:
    # Cleanup must never fall back to a check-then-rename sequence: plain POSIX
    # rename may overwrite a same-UID entry raced into the quarantine name.
    # Retaining the wiped original at its current name is safer than deleting a
    # substitute when atomic no-replace support is unavailable.
    _rename_noreplace_at(parent_fd, source_name, parent_fd, destination_name)


def _rollback_cleanup_quarantine(
    parent_fd: int,
    parent_path: Path,
    quarantine_name: str,
    original_name: str,
    expected_identity: tuple[int, int],
    *,
    directory: bool,
) -> None:
    try:
        _require_cleanup_entry_identity(
            parent_fd,
            parent_path,
            quarantine_name,
            expected_identity,
            directory=directory,
        )
        _require_absent_at(parent_fd, parent_path, original_name)
        _rename_cleanup_entry_at(parent_fd, parent_path, quarantine_name, original_name)
        os.fsync(parent_fd)
        _require_cleanup_entry_identity(
            parent_fd,
            parent_path,
            original_name,
            expected_identity,
            directory=directory,
        )
        try:
            _stat_at(parent_fd, parent_path, quarantine_name)
        except FileNotFoundError:
            return
        raise EnronPrivateIOError("Substituted private cleanup entry remained under its quarantine name.")
    except (EnronPrivateIOError, OSError):
        raise EnronPrivateIOError("Substituted private cleanup entry could not be restored safely.") from None


def _require_cleanup_entry_identity(
    parent_fd: int,
    parent_path: Path,
    name: str,
    expected_identity: tuple[int, int],
    *,
    directory: bool,
) -> None:
    info = _stat_at(parent_fd, parent_path, name)
    valid_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if (
        not valid_type
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid()
        or (not directory and info.st_nlink != 1)
        or (info.st_dev, info.st_ino) != expected_identity
    ):
        raise EnronPrivateIOError("Private cleanup entry changed identity.")


def _quarantine_verified_cleanup_entry(
    parent_fd: int,
    parent_path: Path,
    name: str,
    expected_identity: tuple[int, int],
    *,
    directory: bool,
    quarantine_name: str,
) -> str:
    """Move an emptied owned entry out of its public name without deleting it.

    POSIX has no portable unlink-by-inode operation.  The randomized destination
    is therefore retained as a private tombstone after its inode is verified;
    callers must never unlink or rmdir the returned name.
    """

    try:
        _rename_cleanup_entry_at(parent_fd, parent_path, name, quarantine_name)
        info = _stat_at(parent_fd, parent_path, quarantine_name)
        valid_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
        if (
            not valid_type
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid()
            or (not directory and info.st_nlink != 1)
            or (info.st_dev, info.st_ino) != expected_identity
        ):
            substitute_directory = stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
            substitute_regular = stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_nlink == 1
            if info.st_uid != os.geteuid() or not (substitute_directory or substitute_regular):
                raise EnronPrivateIOError("Substituted private cleanup entry is unsafe to restore.")
            _rollback_cleanup_quarantine(
                parent_fd,
                parent_path,
                quarantine_name,
                name,
                (int(info.st_dev), int(info.st_ino)),
                directory=substitute_directory,
            )
            raise EnronPrivateIOError("Private cleanup entry changed before quarantine.")
        return quarantine_name
    except (EnronPrivateIOError, OSError):
        raise EnronPrivateIOError("Private cleanup entry could not be quarantined safely.") from None


def _rename_noreplace_at(
    source_parent_fd: int,
    source_name: str,
    destination_parent_fd: int,
    destination_name: str,
) -> None:
    source = os.fsencode(source_name)
    destination = os.fsencode(destination_name)
    if sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is not None:
            renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
            renameat2.restype = ctypes.c_int
            if renameat2(source_parent_fd, source, destination_parent_fd, destination, 1) == 0:  # RENAME_NOREPLACE
                return
            error = ctypes.get_errno()
            if error not in {errno.ENOSYS, errno.EINVAL, errno.ENOTSUP}:
                raise OSError(error, os.strerror(error))
    elif sys.platform == "darwin":
        libc = ctypes.CDLL(None, use_errno=True)
        renameatx_np = getattr(libc, "renameatx_np", None)
        if renameatx_np is not None:
            renameatx_np.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
            renameatx_np.restype = ctypes.c_int
            if (
                renameatx_np(
                    source_parent_fd,
                    source,
                    destination_parent_fd,
                    destination,
                    0x00000004,
                )
                == 0
            ):  # RENAME_EXCL
                return
            error = ctypes.get_errno()
            if error not in {errno.ENOSYS, errno.EINVAL, errno.ENOTSUP}:
                raise OSError(error, os.strerror(error))

    raise EnronPrivateIOError("Atomic no-replace directory promotion is unavailable on this platform.")


def _clear_pinned_private_directory(directory_fd: int, directory_path: Path) -> bool:
    try:
        names = sorted(os.listdir(directory_fd if os.listdir in os.supports_fd else directory_path))
    except OSError:
        return False
    succeeded = True
    for name in names:
        try:
            before = _stat_at(directory_fd, directory_path, name)
        except OSError:
            succeeded = False
            continue
        if stat.S_ISDIR(before.st_mode) and not stat.S_ISLNK(before.st_mode):
            child_fd: int | None = None
            try:
                if before.st_uid != os.geteuid():
                    raise EnronPrivateIOError("Private staging directory ownership changed during cleanup.")
                child_fd = _open_directory_at(directory_fd, directory_path, name)
                child_info = os.fstat(child_fd)
                if child_info.st_uid != os.geteuid():
                    raise EnronPrivateIOError("Private staging directory ownership changed during cleanup.")
                child_identity = int(child_info.st_dev), int(child_info.st_ino)
                os.fchmod(child_fd, _DIRECTORY_MODE)
                child_cleared = _clear_pinned_private_directory(child_fd, directory_path / name)
                after = os.fstat(child_fd)
                if not child_cleared or (after.st_dev, after.st_ino) != child_identity:
                    succeeded = False
            except (EnronPrivateIOError, OSError):
                succeeded = False
            finally:
                if child_fd is not None:
                    try:
                        os.close(child_fd)
                    except OSError:
                        succeeded = False
            continue
        if stat.S_ISREG(before.st_mode) and not stat.S_ISLNK(before.st_mode):
            file_fd: int | None = None
            try:
                if before.st_uid != os.geteuid():
                    raise EnronPrivateIOError("Private staging file identity is unsafe.")
                flags = (
                    os.O_RDWR
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_BINARY", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_NONBLOCK", 0)
                )
                file_fd = _open_at(directory_fd, directory_path, name, flags)
                opened = os.fstat(file_fd)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or opened.st_uid != os.geteuid()
                    or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
                ):
                    raise EnronPrivateIOError("Private staging file changed during cleanup.")
                os.fchmod(file_fd, _FILE_MODE)
                os.ftruncate(file_fd, 0)
                os.fsync(file_fd)
                if os.fstat(file_fd).st_nlink != 1:
                    # The payload is gone, but a newly introduced hard link
                    # means the tree cannot be authenticated as an owned
                    # single-link tombstone.
                    succeeded = False
            except (EnronPrivateIOError, OSError):
                succeeded = False
            finally:
                if file_fd is not None:
                    try:
                        os.close(file_fd)
                    except OSError:
                        succeeded = False
            continue
        succeeded = False
    try:
        os.fsync(directory_fd)
    except OSError:
        succeeded = False
    return succeeded


def _private_tree_payload_is_empty(directory_fd: int, *, depth: int, entries: list[int]) -> bool:
    if depth > _MAX_PRIVATE_TOMBSTONE_DEPTH:
        return False
    try:
        names = sorted(os.listdir(directory_fd))
    except OSError:
        return False
    for name in names:
        entries[0] += 1
        if entries[0] > _MAX_PRIVATE_TOMBSTONE_ENTRIES:
            return False
        child_fd: int | None = None
        try:
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
                if info.st_uid != os.geteuid() or not is_owner_only_private_mode(stat.S_IMODE(info.st_mode)):
                    return False
                child_fd = os.open(name, _directory_open_flags(), dir_fd=directory_fd)
                opened = os.fstat(child_fd)
                if (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino) or not _private_tree_payload_is_empty(
                    child_fd,
                    depth=depth + 1,
                    entries=entries,
                ):
                    return False
                continue
            if (
                not stat.S_ISREG(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.geteuid()
                or not is_owner_only_private_mode(stat.S_IMODE(info.st_mode))
                or info.st_size != 0
            ):
                return False
        except OSError:
            return False
        finally:
            if child_fd is not None:
                try:
                    os.close(child_fd)
                except OSError:
                    return False
    return True


def _count_registered_private_files(
    directory_fd: int,
    *,
    expected: set[tuple[int, int]],
    counts: dict[tuple[int, int], int],
    depth: int,
    entries: list[int],
    root: bool,
) -> bool:
    if depth > _MAX_PRIVATE_TOMBSTONE_DEPTH:
        return False
    try:
        names = sorted(os.listdir(directory_fd))
    except OSError:
        return False
    for name in names:
        entries[0] += 1
        if entries[0] > _MAX_PRIVATE_TOMBSTONE_ENTRIES:
            return False
        child_fd: int | None = None
        file_fd: int | None = None
        try:
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
                if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != _DIRECTORY_MODE:
                    return False
                child_fd = os.open(name, _directory_open_flags(), dir_fd=directory_fd)
                opened = os.fstat(child_fd)
                if (
                    (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino)
                    or opened.st_uid != os.geteuid()
                    or stat.S_IMODE(opened.st_mode) != _DIRECTORY_MODE
                    or not _count_registered_private_files(
                        child_fd,
                        expected=expected,
                        counts=counts,
                        depth=depth + 1,
                        entries=entries,
                        root=False,
                    )
                ):
                    return False
                continue
            if (
                not stat.S_ISREG(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != _FILE_MODE
            ):
                return False
            file_fd = os.open(name, _regular_read_flags(), dir_fd=directory_fd)
            opened = os.fstat(file_fd)
            if (
                (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino)
                or not stat.S_ISREG(opened.st_mode)
                or opened.st_uid != os.geteuid()
                or opened.st_nlink != 1
                or stat.S_IMODE(opened.st_mode) != _FILE_MODE
            ):
                return False
            identity = int(opened.st_dev), int(opened.st_ino)
            if identity in expected:
                counts[identity] += 1
            elif not root or name != _COMMIT_MARKER or opened.st_size != len(_COMMIT_PAYLOAD):
                return False
            else:
                try:
                    if os.pread(file_fd, len(_COMMIT_PAYLOAD) + 1, 0) != _COMMIT_PAYLOAD:
                        return False
                except OSError:
                    return False
        except OSError:
            return False
        finally:
            if file_fd is not None:
                try:
                    os.close(file_fd)
                except OSError:
                    return False
            if child_fd is not None:
                try:
                    os.close(child_fd)
                except OSError:
                    return False
    return True


def _private_tree_matches_cleanup_inventory(
    directory_fd: int,
    expected: set[tuple[int, int]],
) -> bool:
    """Return whether a pinned private tree contains the complete registered inventory."""

    if len(expected) > _MAX_PINNED_CLEANUP_FILES or any(
        not isinstance(identity, tuple)
        or len(identity) != 2
        or any(type(value) is not int or value < 0 for value in identity)
        for identity in expected
    ):
        return False
    counts = {identity: 0 for identity in expected}
    return _count_registered_private_files(
        directory_fd,
        expected=expected,
        counts=counts,
        depth=0,
        entries=[0],
        root=True,
    ) and all(count == 1 for count in counts.values())


def _collect_cleanup_inventory_descriptors(
    directory_fd: int,
    directory_path: Path,
    *,
    expected: set[tuple[int, int]],
    retained: dict[tuple[int, int], int],
    depth: int,
    entries: list[int],
    root: bool,
) -> bool:
    if depth > _MAX_PINNED_CLEANUP_TREE_DEPTH:
        raise EnronPrivateIOError("Private cleanup inventory exceeds its depth limit.")
    try:
        names = sorted(os.listdir(directory_fd))
    except OSError:
        raise EnronPrivateIOError("Private cleanup inventory could not be inspected safely.") from None
    complete = True
    for name in names:
        entries[0] += 1
        if entries[0] > _MAX_PINNED_CLEANUP_TREE_ENTRIES:
            raise EnronPrivateIOError("Private cleanup inventory exceeds its entry limit.")
        child_fd: int | None = None
        file_fd: int | None = None
        try:
            before = _stat_at(directory_fd, directory_path, name)
            if stat.S_ISLNK(before.st_mode):
                raise EnronPrivateIOError("Private cleanup inventory must not contain symlinks.")
            if stat.S_ISDIR(before.st_mode):
                _require_exact_private_directory(before)
                child_fd = _open_directory_at(directory_fd, directory_path, name)
                opened = os.fstat(child_fd)
                _require_exact_private_directory(opened)
                if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                    raise EnronPrivateIOError("Private cleanup inventory directory changed while it was opened.")
                complete = (
                    _collect_cleanup_inventory_descriptors(
                        child_fd,
                        directory_path / name,
                        expected=expected,
                        retained=retained,
                        depth=depth + 1,
                        entries=entries,
                        root=False,
                    )
                    and complete
                )
                continue
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.geteuid()
                or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != _FILE_MODE
            ):
                raise EnronPrivateIOError("Private cleanup inventory contains an unsafe file.")
            identity = int(before.st_dev), int(before.st_ino)
            flags = (
                (os.O_RDWR if identity in expected else os.O_RDONLY)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
            )
            if identity in expected:
                if identity in retained:
                    complete = False
                    continue
                _open_cleanup_descriptor_at(
                    directory_fd,
                    directory_path,
                    name,
                    flags,
                    expected_identity=identity,
                    target=retained,
                )
                retained_descriptor = retained[identity]
                opened = os.fstat(retained_descriptor)
                if (
                    (opened.st_dev, opened.st_ino) != identity
                    or not stat.S_ISREG(opened.st_mode)
                    or opened.st_uid != os.geteuid()
                    or opened.st_nlink != 1
                    or stat.S_IMODE(opened.st_mode) != _FILE_MODE
                    or opened.st_size != before.st_size
                ):
                    raise EnronPrivateIOError("Private cleanup inventory file changed while it was opened.")
                continue
            file_fd = _open_at(directory_fd, directory_path, name, flags)
            opened = os.fstat(file_fd)
            if (
                (opened.st_dev, opened.st_ino) != identity
                or not stat.S_ISREG(opened.st_mode)
                or opened.st_uid != os.geteuid()
                or opened.st_nlink != 1
                or stat.S_IMODE(opened.st_mode) != _FILE_MODE
                or opened.st_size != before.st_size
            ):
                raise EnronPrivateIOError("Private cleanup inventory file changed while it was opened.")
            if not root or name != _COMMIT_MARKER or opened.st_size != len(_COMMIT_PAYLOAD):
                complete = False
            elif os.pread(file_fd, len(_COMMIT_PAYLOAD) + 1, 0) != _COMMIT_PAYLOAD:
                complete = False
        except EnronPrivateIOError:
            raise
        except (OSError, ValueError):
            raise EnronPrivateIOError("Private cleanup inventory could not be pinned safely.") from None
        finally:
            if file_fd is not None:
                os.close(file_fd)
            if child_fd is not None:
                os.close(child_fd)
    return complete


def _wipe_and_quarantine_pinned_private_directory(
    directory_fd: int,
    parent_fd: int,
    parent_path: Path,
    entry_name: str,
    expected_identity: tuple[int, int],
    *,
    workspace_root: Path | None,
    allow_unignored_output: bool,
) -> tuple[bool, bool, int]:
    """Wipe a pinned private tree and retain one verified payload-empty tombstone."""

    if (
        type(directory_fd) is not int
        or directory_fd < 0
        or type(parent_fd) is not int
        or parent_fd < 0
        or not isinstance(entry_name, str)
        or not entry_name
        or Path(entry_name).name != entry_name
        or entry_name in {os.curdir, os.pardir}
        or not isinstance(expected_identity, tuple)
        or len(expected_identity) != 2
        or any(type(value) is not int or value < 0 for value in expected_identity)
    ):
        raise EnronPrivateIOError("Pinned private cleanup arguments are invalid.")
    parent = _absolute_path_without_traversal(parent_path, description="Private cleanup parent")
    try:
        parent_opened = os.fstat(parent_fd)
        if (
            not stat.S_ISDIR(parent_opened.st_mode)
            or parent_opened.st_uid != os.geteuid()
            or not is_owner_only_private_mode(stat.S_IMODE(parent_opened.st_mode))
        ):
            raise EnronPrivateIOError("Pinned private cleanup parent is unsafe.")
        opened = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or (opened.st_dev, opened.st_ino) != expected_identity
        ):
            raise EnronPrivateIOError("Pinned private cleanup identity changed.")
        os.fchmod(directory_fd, _DIRECTORY_MODE)
        if not _clear_pinned_private_directory(directory_fd, parent / entry_name) or not _private_tree_payload_is_empty(
            directory_fd,
            depth=0,
            entries=[0],
        ):
            raise EnronPrivateIOError("Pinned private cleanup payload could not be wiped safely.")
        # Check the public parent path only after the pinned payload has been
        # wiped. A same-UID rename/substitution must never preserve sensitive
        # bytes merely because the original parent is no longer at this name.
        parent_current = parent.lstat()
        if (parent_opened.st_dev, parent_opened.st_ino) != (parent_current.st_dev, parent_current.st_ino):
            raise EnronPrivateIOError("Pinned private cleanup parent changed.")
        _require_directory_entry_identity(parent_fd, parent, entry_name, expected_identity)
        quarantine_name = f".nerb-cleanup-{secrets.token_hex(24)}"
        quarantine_path = parent / quarantine_name
        root = _workspace_for_path(parent / entry_name, workspace_root)
        if root is not None and _is_within(quarantine_path, root) and not allow_unignored_output:
            _require_git_ignored(quarantine_path, root)
        _quarantine_verified_cleanup_entry(
            parent_fd,
            parent,
            entry_name,
            expected_identity,
            directory=True,
            quarantine_name=quarantine_name,
        )
        if not _private_tree_payload_is_empty(directory_fd, depth=0, entries=[0]):
            raise EnronPrivateIOError("Pinned private cleanup tombstone payload is not empty.")
        os.fsync(parent_fd)
        return True, False, 1
    except EnronPrivateIOError:
        raise
    except (OSError, ValueError):
        raise EnronPrivateIOError("Pinned private directory could not be wiped safely.") from None


def _wipe_and_quarantine_pinned_private_directory_with_inventory(
    directory_fd: int,
    parent_fd: int,
    parent_path: Path,
    entry_name: str,
    expected_identity: tuple[int, int],
    expected_files: set[tuple[int, int]],
    *,
    workspace_root: Path | None,
    allow_unignored_output: bool,
) -> tuple[bool, bool, int]:
    """Pin, authenticate, and wipe an expected recovery inventory before quarantine."""

    complete = False
    descriptors_wiped = True
    removed = (False, False, 0)
    deferred_control_error: BaseException | None = None
    with _UNRESOLVED_CLEANUP_LOCK:
        if _UNRESOLVED_CLEANUP_FDS:
            raise EnronPrivateIOError("Unresolved private cleanup authority blocks recovery inventory collection.")
        with _CLEANUP_TREE_ADOPTION_LOCK:
            try:
                complete = _collect_cleanup_inventory_descriptors(
                    directory_fd,
                    parent_path / entry_name,
                    expected=expected_files,
                    retained=cast(dict[tuple[int, int], int], _UNRESOLVED_CLEANUP_FDS),
                    depth=0,
                    entries=[0],
                    root=True,
                )
                complete = (
                    complete
                    and set(_UNRESOLVED_CLEANUP_FDS) == expected_files
                    and _private_tree_matches_cleanup_inventory(directory_fd, expected_files)
                )
            except EnronPrivateIOError:
                complete = False
        for key, descriptor in _UNRESOLVED_CLEANUP_FDS.items():
            identity = _cleanup_owner_identity(key)
            if not _wipe_authenticated_cleanup_descriptor(identity, descriptor):
                descriptors_wiped = False
        removed = _wipe_and_quarantine_pinned_private_directory(
            directory_fd,
            parent_fd,
            parent_path,
            entry_name,
            expected_identity,
            workspace_root=workspace_root,
            allow_unignored_output=allow_unignored_output,
        )
        for key, descriptor in tuple(_UNRESOLVED_CLEANUP_FDS.items()):
            identity = _cleanup_owner_identity(key)
            try:
                info = os.fstat(descriptor)
                verified_empty = (int(info.st_dev), int(info.st_ino)) == identity and info.st_size == 0
            except OSError:
                verified_empty = False
            if not verified_empty:
                descriptors_wiped = False
                continue
            try:
                _close_owned_cleanup_descriptor(_UNRESOLVED_CLEANUP_FDS, key)
            except (KeyboardInterrupt, SystemExit) as exc:
                if deferred_control_error is None:
                    deferred_control_error = exc
            except (EnronPrivateIOError, OSError):
                descriptors_wiped = False
        if deferred_control_error is not None:
            raise deferred_control_error
        if _UNRESOLVED_CLEANUP_FDS:
            raise EnronPrivateIOError("Private cleanup inventory authority remains unresolved.")
    return complete and descriptors_wiped and removed[0], removed[1], removed[2]


def _wipe_and_quarantine_pinned_private_file(
    file_fd: int,
    parent_fd: int,
    parent_path: Path,
    entry_name: str,
    expected_identity: tuple[int, int],
    *,
    workspace_root: Path | None,
    allow_unignored_output: bool,
) -> tuple[bool, bool, int]:
    """Wipe a pinned private file and retain one verified empty tombstone."""

    if (
        type(file_fd) is not int
        or file_fd < 0
        or type(parent_fd) is not int
        or parent_fd < 0
        or not isinstance(entry_name, str)
        or not entry_name
        or Path(entry_name).name != entry_name
        or entry_name in {os.curdir, os.pardir}
        or not isinstance(expected_identity, tuple)
        or len(expected_identity) != 2
        or any(type(value) is not int or value < 0 for value in expected_identity)
    ):
        raise EnronPrivateIOError("Pinned private file cleanup arguments are invalid.")
    parent = _absolute_path_without_traversal(parent_path, description="Private cleanup parent")
    try:
        parent_opened = os.fstat(parent_fd)
        if (
            not stat.S_ISDIR(parent_opened.st_mode)
            or parent_opened.st_uid != os.geteuid()
            or not is_owner_only_private_mode(stat.S_IMODE(parent_opened.st_mode))
        ):
            raise EnronPrivateIOError("Pinned private cleanup parent is unsafe.")
        opened = os.fstat(file_fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_ISLNK(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or (opened.st_dev, opened.st_ino) != expected_identity
        ):
            raise EnronPrivateIOError("Pinned private cleanup file identity changed.")
        os.fchmod(file_fd, _FILE_MODE)
        os.ftruncate(file_fd, 0)
        os.fsync(file_fd)
        if os.fstat(file_fd).st_size != 0:
            raise EnronPrivateIOError("Pinned private cleanup file payload was not wiped.")

        parent_current = parent.lstat()
        if (parent_opened.st_dev, parent_opened.st_ino) != (parent_current.st_dev, parent_current.st_ino):
            raise EnronPrivateIOError("Pinned private cleanup parent changed.")
        current = _stat_at(parent_fd, parent, entry_name)
        if (
            not stat.S_ISREG(current.st_mode)
            or stat.S_ISLNK(current.st_mode)
            or current.st_nlink != 1
            or current.st_uid != os.geteuid()
            or (current.st_dev, current.st_ino) != expected_identity
        ):
            raise EnronPrivateIOError("Pinned private cleanup file entry changed.")
        quarantine_name = f".nerb-cleanup-{secrets.token_hex(24)}"
        quarantine_path = parent / quarantine_name
        root = _workspace_for_path(parent / entry_name, workspace_root)
        if root is not None and _is_within(quarantine_path, root) and not allow_unignored_output:
            _require_git_ignored(quarantine_path, root)
        _quarantine_verified_cleanup_entry(
            parent_fd,
            parent,
            entry_name,
            expected_identity,
            directory=False,
            quarantine_name=quarantine_name,
        )
        tombstone = _stat_at(parent_fd, parent, quarantine_name)
        if tombstone.st_size != 0:
            raise EnronPrivateIOError("Pinned private cleanup tombstone payload is not empty.")
        os.fsync(parent_fd)
        return True, False, 1
    except EnronPrivateIOError:
        raise
    except (OSError, ValueError):
        raise EnronPrivateIOError("Pinned private file could not be wiped safely.") from None


def _open_regular_input(path: Path) -> int:
    _require_transaction_capabilities()
    if path.anchor == "" or len(path.parts) < 2:
        raise EnronPrivateIOError("Private input path must identify a regular file.")
    current_path = Path(path.anchor)
    current_fd: int | None = None
    try:
        current_fd = os.open(current_path, _directory_open_flags())
        for component in path.parts[1:-1]:
            next_fd = _open_directory_at(current_fd, current_path, component)
            os.close(current_fd)
            current_fd = next_fd
            current_path /= component
        before = _stat_at(current_fd, current_path, path.name)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise EnronPrivateIOError("Private input must be a regular non-symlink file.")
        descriptor = _open_at(current_fd, current_path, path.name, _regular_read_flags())
        after = os.fstat(descriptor)
        if not stat.S_ISREG(after.st_mode) or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            os.close(descriptor)
            raise EnronPrivateIOError("Private input changed while it was opened.")
        return descriptor
    except EnronPrivateIOError:
        raise
    except (OSError, ValueError):
        raise EnronPrivateIOError("Private input could not be opened safely.") from None
    finally:
        if current_fd is not None:
            os.close(current_fd)


__all__ = [
    "EnronPrivateIOError",
    "PrivateRun",
    "ensure_private_output_allowed",
    "find_workspace_root",
    "is_owner_only_private_mode",
    "iter_strict_jsonl",
    "open_private_binary_input",
]
