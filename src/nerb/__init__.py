__version__ = "0.0.1"

# HACK: Allows setup.py to fetch the version.
try:
    __NERB_SETUP__ # type: ignore  # noqa
except NameError:
    __NERB_SETUP__ = False

if not __NERB_SETUP__:
    from . import utils
    from .regex_builder import NERB
    from .named_entities import NamedEntity, NamedEntityList

    from pathlib import Path
    package_path: Path = Path(__file__).parent
    repo_path: Path = package_path.parent.parent
