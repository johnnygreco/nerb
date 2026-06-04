from __future__ import annotations

import copy
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import jsonpatch

from .bank import BankError
from .diagnostics import DIAGNOSTIC_ERROR, PATCH_INVALID, Diagnostic, diagnostic
from .validation import validate_bank

__all__ = ["BankPatchError", "apply_bank_patches"]


class BankPatchError(BankError):
    """Raised when RFC 6902 patches are malformed or cannot be applied."""


def _patch_error(message: str) -> Diagnostic:
    return diagnostic(DIAGNOSTIC_ERROR, PATCH_INVALID, "", message)


def apply_bank_patches(
    bank: Any,
    patches: Sequence[dict[str, Any]],
    *,
    level: str = "standard",
    engine: str = "python_re",
    base_path: str | Path | None = None,
) -> dict[str, Any]:
    """Apply RFC 6902 JSON Patch operations and validate the candidate bank."""
    try:
        candidate = jsonpatch.apply_patch(copy.deepcopy(bank), list(patches), in_place=False)
    except (jsonpatch.JsonPatchException, TypeError, ValueError) as exc:
        message = f"Could not apply JSON Patch operations: {exc}."
        raise BankPatchError(message, [_patch_error(message)]) from exc

    return validate_bank(candidate, level=level, engine=engine, base_path=base_path)
