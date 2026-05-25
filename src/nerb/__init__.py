from pathlib import Path

from .config import (
    DEFAULT_CONFIG_ENV_VAR,
    DEFAULT_CONFIG_FILENAME,
    FLAGS_KEY,
    ConfigError,
    PatternConfig,
    add_entity_pattern,
    load_config,
    load_yaml_config,
    remove_entity_pattern,
    resolve_default_config_path,
    save_config,
    validate_pattern_config,
    validate_regex_flags,
)
from .extraction import (
    extract_named_entities,
    extract_named_entities_records,
    extract_named_entity,
    extract_named_entity_records,
)
from .named_entities import NamedEntity, NamedEntityList
from .regex_builder import NERB

__version__ = "0.0.5"

package_path: Path = Path(__file__).parent
repo_path: Path = package_path.parent.parent

__all__ = [
    "ConfigError",
    "DEFAULT_CONFIG_ENV_VAR",
    "DEFAULT_CONFIG_FILENAME",
    "FLAGS_KEY",
    "NERB",
    "NamedEntity",
    "NamedEntityList",
    "PatternConfig",
    "__version__",
    "add_entity_pattern",
    "extract_named_entities",
    "extract_named_entities_records",
    "extract_named_entity",
    "extract_named_entity_records",
    "load_config",
    "load_yaml_config",
    "package_path",
    "repo_path",
    "remove_entity_pattern",
    "resolve_default_config_path",
    "save_config",
    "validate_pattern_config",
    "validate_regex_flags",
]
