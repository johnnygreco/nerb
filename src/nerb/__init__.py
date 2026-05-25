from pathlib import Path

from .named_entities import NamedEntity, NamedEntityList
from .regex_builder import NERB
from .utils import load_yaml_config

__version__ = "0.0.5"

package_path: Path = Path(__file__).parent
repo_path: Path = package_path.parent.parent

__all__ = [
    "NERB",
    "NamedEntity",
    "NamedEntityList",
    "__version__",
    "load_yaml_config",
    "package_path",
    "repo_path",
]
