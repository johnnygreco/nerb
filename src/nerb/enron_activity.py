"""Shared deterministic liveness cadence for Enron corpus work."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager

# Capacity accepts phases at 100 records/second and requires an accepted
# progress signal at least every 30 seconds.  One thousand work units therefore
# leaves a 20-second margin for scheduling, resource sampling, and I/O without
# changing the separate 10,000-record semantic checkpoint cadence.
ACTIVITY_RECORD_INTERVAL = 1_000
SQLITE_ACTIVITY_VM_STEP_INTERVAL = 100_000
_SQLITE_ACTIVITY_HANDLER_REMOVAL_ATTEMPTS = 3


class _SQLiteActivityCleanupError(RuntimeError):
    """Raised when SQLite liveness instrumentation cannot be removed safely."""


@contextmanager
def sqlite_activity(connection: sqlite3.Connection, callback: Callable[[], None] | None) -> Iterator[None]:
    """Report genuine SQLite VM work and preserve callback control errors."""

    if callback is None:
        yield
        return
    pending_callback_error: BaseException | None = None
    operation_error: BaseException | None = None

    def progress() -> int:
        nonlocal pending_callback_error
        if pending_callback_error is not None:
            return 1
        try:
            callback()
        except BaseException as exc:
            pending_callback_error = exc
            return 1
        return 0

    connection.set_progress_handler(progress, SQLITE_ACTIVITY_VM_STEP_INTERVAL)
    try:
        yield
    except BaseException as exc:
        operation_error = exc
    cleanup_error: BaseException | None = None
    handler_removed = False
    for _attempt in range(_SQLITE_ACTIVITY_HANDLER_REMOVAL_ATTEMPTS):
        try:
            connection.set_progress_handler(None, 0)
        except BaseException as exc:
            if cleanup_error is None:
                cleanup_error = exc
        else:
            handler_removed = True
            break
    if not handler_removed:
        raise _SQLiteActivityCleanupError("SQLite activity handler could not be removed safely.") from cleanup_error
    if pending_callback_error is not None:
        if cleanup_error is not None:
            raise pending_callback_error from cleanup_error
        raise pending_callback_error
    if operation_error is not None:
        if cleanup_error is not None:
            raise operation_error from cleanup_error
        raise operation_error
    if cleanup_error is not None:
        raise cleanup_error
