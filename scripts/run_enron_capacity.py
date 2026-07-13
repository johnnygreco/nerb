#!/usr/bin/env python3
"""Start the production Enron capacity command without processing Python site hooks.

Invoke this file with ``python -I -S -B``.  It intentionally uses only the
standard library until the isolated import roots and private pycache prefix are
installed.
"""

from __future__ import annotations

import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import NoReturn

_BOOTSTRAP_ATTRIBUTE = "_nerb_capacity_bootstrap"
_BOOTSTRAP_SCHEMA = "nerb.enron_capacity.bootstrap.v1"


def _fail(message: str) -> NoReturn:
    raise SystemExit(f"Enron capacity bootstrap refused to start: {message}")


def _validated_directory(path: Path, *, label: str) -> Path:
    """Return one stable, absolute, non-symlink directory."""

    if not path.is_absolute():
        _fail(f"{label} is not absolute")
    try:
        before = path.lstat()
        resolved = path.resolve(strict=True)
        after = path.lstat()
    except OSError:
        _fail(f"{label} is unavailable")
    if (
        not stat.S_ISDIR(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
        or resolved != path
    ):
        _fail(f"{label} is not a stable real directory")
    return resolved


def _validated_source_root() -> Path:
    launcher = Path(__file__).resolve(strict=True)
    root = launcher.parent.parent
    source = _validated_directory(root / "src", label="source root")
    package = _validated_directory(source / "nerb", label="nerb package root")
    try:
        capacity = (package / "enron_capacity.py").lstat()
        cli = (package / "cli.py").lstat()
    except OSError:
        _fail("tracked capacity sources are unavailable")
    if any(not stat.S_ISREG(item.st_mode) or stat.S_ISLNK(item.st_mode) for item in (capacity, cli)):
        _fail("tracked capacity sources are not regular files")
    return source


def _validated_dependency_roots() -> tuple[Path, ...]:
    """Locate a POSIX venv without importing or invoking :mod:`site`."""

    executable = Path(sys.executable)
    if os.name != "posix" or not executable.is_absolute() or executable.parent.name != "bin":
        _fail("the interpreter is not a POSIX virtual-environment interpreter")
    environment = executable.parent.parent
    try:
        config = (environment / "pyvenv.cfg").lstat()
    except OSError:
        _fail("the interpreter virtual environment has no pyvenv.cfg")
    if not stat.S_ISREG(config.st_mode) or stat.S_ISLNK(config.st_mode):
        _fail("the interpreter virtual environment has an unsafe pyvenv.cfg")

    version = f"python{sys.version_info.major}.{sys.version_info.minor}"
    roots: list[Path] = []
    for library in ("lib", "lib64"):
        candidate = environment / library / version / "site-packages"
        try:
            candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            _fail("a dependency root is unavailable")
        try:
            resolved_candidate = candidate.resolve(strict=True)
        except OSError:
            _fail("a dependency root is unavailable")
        root = _validated_directory(resolved_candidate, label="dependency root")
        if root not in roots:
            roots.append(root)
    if not roots:
        _fail("the interpreter virtual environment has no dependency root")
    return tuple(roots)


def main() -> None:
    if not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode):
        _fail("invoke with python -I -S -B")
    if _BOOTSTRAP_ATTRIBUTE in vars(sys):
        _fail("bootstrap state already exists")

    source_root = _validated_source_root()
    dependency_roots = _validated_dependency_roots()
    baseline_path = tuple(sys.path)
    if any(not value or not Path(value).is_absolute() for value in baseline_path):
        _fail("the isolated interpreter path contains a relative entry")

    with tempfile.TemporaryDirectory(prefix="nerb-capacity-launcher-pycache-") as directory:
        pycache_root = _validated_directory(Path(directory).resolve(strict=True), label="pycache root")
        os.chmod(pycache_root, 0o700)
        sys.pycache_prefix = os.fspath(pycache_root)
        explicit_roots = (source_root, *dependency_roots)
        sys.path[:] = [*(os.fspath(path) for path in explicit_roots), *baseline_path]
        setattr(
            sys,
            _BOOTSTRAP_ATTRIBUTE,
            {
                "schema": _BOOTSTRAP_SCHEMA,
                "source_root": os.fspath(source_root),
                "dependency_roots": [os.fspath(path) for path in dependency_roots],
                "baseline_path": list(baseline_path),
                "pycache_root": os.fspath(pycache_root),
            },
        )
        supported_commands = {"run-enron-capacity", "verify-enron-capacity", "export-enron-capacity"}
        if len(sys.argv) < 2 or sys.argv[1] not in supported_commands:
            sys.argv[1:1] = ["run-enron-capacity"]
        from nerb.cli import main as cli_main

        cli_main()


if __name__ == "__main__":
    main()
