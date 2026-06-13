from pathlib import Path

from .bank import BankError, BankLoadError, BankSchemaError, bank_stats, canonicalize_bank, hash_bank, load_bank
from .benchmarks import benchmark_bank, benchmark_fixture_profiles, make_benchmark_fixture_profile, regress_bank
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
from .deanonymization import anonymize_file, anonymize_text, deanonymize_file, deanonymize_text
from .diff import diff_banks
from .engine import Bank, bank_cache_info, clear_bank_cache
from .evals import eval_bank
from .extraction import (
    ExtractionError,
    explain_match,
    extract_batch,
    extract_file,
    extract_report,
    extract_report_batch,
    extract_report_file,
    extract_text,
)
from .patches import BankPatchError, apply_bank_patches
from .schema import BANK_SCHEMA, ID_PATTERN, REGEX_FLAG_ORDER, SCHEMA_VERSION, validate_bank_schema
from .validation import validate_bank

__version__ = "0.0.6"

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
    "Bank",
    "benchmark_bank",
    "benchmark_fixture_profiles",
    "ConfigError",
    "DEFAULT_CONFIG_ENV_VAR",
    "DEFAULT_CONFIG_FILENAME",
    "FLAGS_KEY",
    "PatternConfig",
    "ExtractionError",
    "__version__",
    "add_entity_pattern",
    "apply_bank_patches",
    "anonymize_file",
    "anonymize_text",
    "bank_stats",
    "bank_cache_info",
    "canonicalize_bank",
    "clear_bank_cache",
    "diff_banks",
    "deanonymize_file",
    "deanonymize_text",
    "extract_batch",
    "extract_file",
    "extract_report",
    "extract_report_batch",
    "extract_report_file",
    "extract_text",
    "eval_bank",
    "explain_match",
    "hash_bank",
    "load_bank",
    "load_config",
    "load_yaml_config",
    "make_benchmark_fixture_profile",
    "package_path",
    "repo_path",
    "remove_entity_pattern",
    "regress_bank",
    "resolve_default_config_path",
    "save_config",
    "validate_bank_schema",
    "validate_bank",
    "validate_pattern_config",
    "validate_regex_flags",
]
