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
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any, BinaryIO, TextIO

_COMMIT_MARKER = "COMMITTED"
_COMMIT_PAYLOAD = b"nerb.enron.private-run.v2\n"
_DIRECTORY_MODE = 0o700
_FILE_MODE = 0o600
_JSONL_BUFFER_BYTES = 64 * 1024
_MAX_JSON_INTEGER_DIGITS = 256
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
    ) -> None:
        self._requested_final_dir = Path(final_dir)
        self._requested_workspace_root = workspace_root
        self._allow_unignored_output = allow_unignored_output
        self._final_dir: Path | None = None
        self._stage_dir: Path | None = None
        self._stage_name: str | None = None
        self._parent_fd: int | None = None
        self._stage_fd: int | None = None
        self._open_handles: list[BinaryIO | TextIO] = []
        self._entered = False
        self._committed = False
        self._promoted = False

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

    def __enter__(self) -> PrivateRun:
        if self._entered:
            raise EnronPrivateIOError("Private run cannot be entered more than once.")
        self._entered = True
        try:
            _require_transaction_capabilities()
            final = ensure_private_output_allowed(
                self._requested_final_dir,
                workspace_root=self._requested_workspace_root,
                allow_unignored_output=self._allow_unignored_output,
            )
            root = _workspace_for_path(final, self._requested_workspace_root)
            parent_fd = _open_or_create_private_directory(final.parent)
            self._final_dir = final
            self._parent_fd = parent_fd
            _require_absent_at(parent_fd, final.parent, final.name)

            for _ in range(128):
                stage_name = f".{final.name}.stage-{secrets.token_hex(12)}"
                stage = final.parent / stage_name
                if root is not None and _is_within(stage, root) and not self._allow_unignored_output:
                    _require_git_ignored(stage, root)
                try:
                    _mkdir_at(parent_fd, final.parent, stage_name, _DIRECTORY_MODE)
                except FileExistsError:
                    continue
                self._stage_name = stage_name
                self._stage_dir = stage
                stage_fd = _open_directory_at(parent_fd, final.parent, stage_name)
                self._stage_fd = stage_fd
                os.fchmod(stage_fd, _DIRECTORY_MODE)
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
        if self._committed:
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

    def commit(self) -> Path:
        """Flush, mark, and atomically promote the complete private run."""

        self._require_active()
        if self._committed:
            raise EnronPrivateIOError("Private run has already been committed.")
        try:
            if any(not handle.closed for handle in self._open_handles):
                raise EnronPrivateIOError("All private output files must be closed before commit.")
            assert self._stage_fd is not None
            assert self._stage_name is not None
            assert self._parent_fd is not None
            assert self._final_dir is not None
            assert self._stage_dir is not None

            _sync_private_tree(self._stage_fd, self._stage_dir, root=True)
            _write_commit_marker(self._stage_fd, self._stage_dir)
            os.fsync(self._stage_fd)
            _require_absent_at(self._parent_fd, self._final_dir.parent, self._final_dir.name)
            _rename_noreplace(
                self._parent_fd,
                self._final_dir.parent,
                self._stage_name,
                self._final_dir.name,
            )
            self._promoted = True
            os.fsync(self._parent_fd)
            stage_fd = self._stage_fd
            parent_fd = self._parent_fd
            self._stage_fd = None
            self._parent_fd = None
            try:
                os.close(stage_fd)
            except OSError:
                pass
            try:
                os.close(parent_fd)
            except OSError:
                pass
            self._committed = True
            return self._final_dir
        except BaseException as exc:
            self._cleanup()
            if isinstance(exc, (EnronPrivateIOError, KeyboardInterrupt, SystemExit)):
                raise
            raise EnronPrivateIOError("Private run could not be committed safely.") from None

    def _create_output_file(self, relative: Path | str) -> int:
        self._require_active()
        if self._committed:
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
                os.O_WRONLY
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

    def _require_active(self) -> None:
        if not self._entered or self._stage_fd is None or self._parent_fd is None:
            raise EnronPrivateIOError("Private run is not active.")

    def _cleanup(self) -> None:
        for handle in self._open_handles:
            if not handle.closed:
                try:
                    handle.close()
                except OSError:
                    pass
        self._open_handles.clear()
        if self._stage_fd is not None:
            try:
                os.close(self._stage_fd)
            except OSError:
                pass
            self._stage_fd = None
        cleanup_error: OSError | None = None
        if self._parent_fd is not None:
            name = self._final_dir.name if self._promoted and self._final_dir is not None else self._stage_name
            if name is not None:
                try:
                    _remove_entry_at(self._parent_fd, self._final_dir.parent if self._final_dir else Path.cwd(), name)
                    os.fsync(self._parent_fd)
                except FileNotFoundError:
                    pass
                except OSError as exc:
                    cleanup_error = exc
            try:
                os.close(self._parent_fd)
            except OSError as exc:
                cleanup_error = cleanup_error or exc
            self._parent_fd = None
        if cleanup_error is not None:
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
        try:
            _rmdir_at(parent_fd, parent_path, name)
        except OSError:
            pass
        raise


def _stat_at(parent_fd: int, parent_path: Path, name: str) -> os.stat_result:
    if os.stat in os.supports_dir_fd:
        return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    return (parent_path / name).lstat()


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


def _remove_entry_at(parent_fd: int, parent_path: Path, name: str) -> None:
    info = _stat_at(parent_fd, parent_path, name)
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        _unlink_at(parent_fd, parent_path, name)
        return
    child_fd = _open_directory_at(parent_fd, parent_path, name)
    child_path = parent_path / name
    try:
        names = os.listdir(child_fd if os.listdir in os.supports_fd else child_path)
        for child_name in names:
            _remove_entry_at(child_fd, child_path, child_name)
    finally:
        os.close(child_fd)
    _rmdir_at(parent_fd, parent_path, name)


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
