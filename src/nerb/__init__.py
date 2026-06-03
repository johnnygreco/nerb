from pathlib import Path

from .bank import BankError, BankLoadError, BankSchemaError, bank_stats, canonicalize_bank, hash_bank, load_bank
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
from .engines import clear_compiled_bank_cache, compiled_bank_cache_info
from .extraction import (
    ExtractionError,
    extract_batch,
    extract_file,
    extract_named_entities,
    extract_named_entities_records,
    extract_named_entity,
    extract_named_entity_records,
    extract_text,
)
from .named_entities import NamedEntity, NamedEntityList
from .patches import BankPatchError, apply_bank_patches
from .regex_builder import NERB
from .schema import BANK_SCHEMA, ID_PATTERN, REGEX_FLAG_ORDER, SCHEMA_VERSION, validate_bank_schema
from .validation import validate_bank

__version__ = "0.0.5"

package_path: Path = Path(__file__).parent
repo_path: Path = package_path.parent.parent

__all__ = [
    "BANK_SCHEMA",
    "ID_PATTERN",
    "REGEX_FLAG_ORDER",
    "SCHEMA_VERSION",
    "BankError",
    "BankLoadError",
    "BankPatchError",
    "BankSchemaError",
    "ConfigError",
    "DEFAULT_CONFIG_ENV_VAR",
    "DEFAULT_CONFIG_FILENAME",
    "FLAGS_KEY",
    "NERB",
    "NamedEntity",
    "NamedEntityList",
    "PatternConfig",
    "ExtractionError",
    "__version__",
    "add_entity_pattern",
    "apply_bank_patches",
    "bank_stats",
    "canonicalize_bank",
    "clear_compiled_bank_cache",
    "compiled_bank_cache_info",
    "extract_batch",
    "extract_file",
    "extract_named_entities",
    "extract_named_entities_records",
    "extract_named_entity",
    "extract_named_entity_records",
    "extract_text",
    "hash_bank",
    "load_bank",
    "load_config",
    "load_yaml_config",
    "package_path",
    "repo_path",
    "remove_entity_pattern",
    "resolve_default_config_path",
    "save_config",
    "validate_bank_schema",
    "validate_bank",
    "validate_pattern_config",
    "validate_regex_flags",
]
