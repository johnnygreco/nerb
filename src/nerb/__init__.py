from . import utils
from .regex_builder import NERB
from .named_entities import NamedEntity, NamedEntityList

from pathlib import Path
package_path: Path = Path(__file__).parent
repo_path: Path = package_path.parent.parent
