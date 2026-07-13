"""Standard-library-only import guard for the isolated capacity worker."""

from __future__ import annotations

import importlib
import importlib.abc
import importlib.machinery
import importlib.util
import os
import stat
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import ModuleType
from typing import Any

_GUARD_ATTRIBUTE = "_nerb_capacity_import_guard"
_GUARD_SCHEMA = "nerb.enron_capacity.import_guard.v1"
_PRIVATE_MODULE_NAME = "_nerb_capacity_bootstrap_impl"
_SOURCE_MODULES = frozenset(
    {
        "_capacity_bootstrap",
        "bank",
        "benchmarks",
        "cli",
        "config",
        "deanonymization",
        "diagnostics",
        "diff",
        "engine",
        "engines",
        "enron_activity",
        "enron_annotations",
        "enron_bank_builder",
        "enron_bank_workflow",
        "enron_capacity",
        "enron_cleaning",
        "enron_conformance",
        "enron_contract",
        "enron_performance",
        "enron_performance_fixtures",
        "enron_performance_worker",
        "enron_preparation",
        "enron_private_io",
        "enron_quality",
        "enron_splitting",
        "evals",
        "extraction",
        "mcp_server",
        "normalization",
        "patches",
        "records",
        "replacements",
        "replacements_schema",
        "reports",
        "schema",
        "validation",
    }
)


def _bootstrap_error() -> ImportError:
    return ImportError("capacity worker source import is invalid")


def _stable_directory(path: Path) -> Path:
    try:
        before = path.lstat()
        resolved = path.resolve(strict=True)
        after = path.lstat()
    except OSError:
        raise _bootstrap_error() from None
    if (
        not path.is_absolute()
        or not stat.S_ISDIR(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or resolved != path
        or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
    ):
        raise _bootstrap_error()
    return resolved


def _regular_file(path: Path, *, required: bool) -> Path | None:
    try:
        before = path.lstat()
        resolved = path.resolve(strict=True)
        after = path.lstat()
    except FileNotFoundError:
        if not required:
            return None
        raise _bootstrap_error() from None
    except OSError:
        raise _bootstrap_error() from None
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or resolved != path
        or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
    ):
        raise _bootstrap_error()
    return path


def _source_spec(
    fullname: str,
    path: Path,
    *,
    package_directory: Path | None = None,
) -> importlib.machinery.ModuleSpec:
    source = _regular_file(path, required=True)
    if source is None:  # pragma: no cover - required=True is fail-closed
        raise _bootstrap_error()
    loader = importlib.machinery.SourceFileLoader(fullname, os.fspath(source))
    spec = importlib.util.spec_from_file_location(
        fullname,
        source,
        loader=loader,
        submodule_search_locations=None if package_directory is None else [os.fspath(package_directory)],
    )
    if spec is None:
        raise _bootstrap_error()
    return spec


class _ExactNerbSourceFinder(importlib.abc.MetaPathFinder):
    """Resolve project modules from exact source paths before import execution."""

    def __init__(self, source_root: Path) -> None:
        self._source_root = _stable_directory(source_root)
        self._package_root = _stable_directory(self._source_root / "nerb")
        suffix = importlib.machinery.EXTENSION_SUFFIXES[0] if importlib.machinery.EXTENSION_SUFFIXES else None
        if (
            not isinstance(suffix, str)
            or not suffix.startswith(".")
            or len(suffix.encode("utf-8")) > 128
            or os.sep in suffix
            or (os.altsep is not None and os.altsep in suffix)
        ):
            raise _bootstrap_error()
        self._extension_suffix = suffix

    def find_spec(
        self,
        fullname: str,
        path: Sequence[str] | None = None,
        target: ModuleType | None = None,
    ) -> importlib.machinery.ModuleSpec | None:
        del path, target
        if fullname == "nerb":
            return _source_spec(
                fullname,
                self._package_root / "__init__.py",
                package_directory=self._package_root,
            )
        if not fullname.startswith("nerb."):
            return None

        components = fullname.split(".")[1:]
        if len(components) != 1 or not components[0].isidentifier():
            raise _bootstrap_error()
        if components == ["_engine"]:
            extension = _regular_file(
                self._package_root / f"_engine{self._extension_suffix}",
                required=True,
            )
            if extension is None:  # pragma: no cover - required=True is fail-closed
                raise _bootstrap_error()
            loader = importlib.machinery.ExtensionFileLoader(fullname, os.fspath(extension))
            spec = importlib.util.spec_from_file_location(fullname, extension, loader=loader)
            if spec is None:
                raise _bootstrap_error()
            return spec

        module_name = components[0]
        if module_name not in _SOURCE_MODULES:
            raise _bootstrap_error()
        return _source_spec(fullname, self._package_root / f"{module_name}.py")

    def policy_identity(self) -> dict[str, Any]:
        return import_policy_identity()


def import_policy_identity() -> dict[str, Any]:
    suffix = importlib.machinery.EXTENSION_SUFFIXES[0] if importlib.machinery.EXTENSION_SUFFIXES else None
    if not isinstance(suffix, str):
        raise _bootstrap_error()
    return {
        "schema": _GUARD_SCHEMA,
        "flat_source_modules": sorted(_SOURCE_MODULES),
        "native_extension_module": "_engine",
        "native_extension_suffix": suffix,
        "source_file_precedes_package_directory": True,
        "meta_path_first_required": True,
    }


def _private_pycache_root() -> Path:
    value = sys.pycache_prefix
    if os.name != "posix" or not isinstance(value, str):
        raise _bootstrap_error()
    root = _stable_directory(Path(value))
    try:
        info = root.stat()
    except OSError:
        raise _bootstrap_error() from None
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise _bootstrap_error()
    return root


def install(source_root: str) -> None:
    """Install the closed project-module finder before dependency roots are exposed."""

    _private_pycache_root()
    if (
        _GUARD_ATTRIBUTE in vars(sys)
        or any(name == "nerb" or name.startswith("nerb.") for name in sys.modules)
        or __name__ != _PRIVATE_MODULE_NAME
        or getattr(sys.modules.get(_PRIVATE_MODULE_NAME), "install", None) is not install
    ):
        raise _bootstrap_error()
    finder = _ExactNerbSourceFinder(Path(source_root))
    sys.meta_path.insert(0, finder)
    setattr(sys, _GUARD_ATTRIBUTE, finder)


def assert_installed(source_root: str | Path) -> None:
    """Fail if the closed finder or its bound import policy has drifted."""

    root = _stable_directory(Path(source_root))
    guard = getattr(sys, _GUARD_ATTRIBUTE, None)
    if (
        guard is None
        or not sys.meta_path
        or sys.meta_path[0] is not guard
        or type(guard).__module__ != _PRIVATE_MODULE_NAME
        or type(guard).__qualname__ != "_ExactNerbSourceFinder"
        or getattr(guard, "_source_root", None) != root
        or getattr(guard, "_package_root", None) != root / "nerb"
        or getattr(guard, "_extension_suffix", None) != import_policy_identity()["native_extension_suffix"]
        or getattr(guard, "policy_identity", None) is None
    ):
        raise _bootstrap_error()
    try:
        actual_policy = guard.policy_identity()
    except (AttributeError, TypeError, ValueError):
        raise _bootstrap_error() from None
    if not isinstance(actual_policy, Mapping) or actual_policy != import_policy_identity():
        raise _bootstrap_error()


def run(source_root: str) -> int:
    """Import and run the capacity worker under an exact canonical module identity."""

    root = _stable_directory(Path(source_root))
    if not sys.path or sys.path[-1] != os.fspath(root):
        raise _bootstrap_error()
    assert_installed(root)
    module = importlib.import_module("nerb.enron_capacity")
    assert_installed(root)
    worker_main = getattr(module, "_production_worker_main", None)
    if not callable(worker_main):
        raise _bootstrap_error()
    result = worker_main()
    assert_installed(root)
    if type(result) is not int:
        raise _bootstrap_error()
    return result
