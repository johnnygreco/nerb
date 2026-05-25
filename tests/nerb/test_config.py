# Standard library
import re

# Third-party
import pytest

# Project
from nerb import (
    NERB,
    ConfigError,
    add_entity_pattern,
    load_config,
    remove_entity_pattern,
    resolve_default_config_path,
    save_config,
    validate_regex_flags,
)
from nerb.config import DEFAULT_CONFIG_ENV_VAR


def test_load_config_valid_yaml(tmp_path):
    config_path = tmp_path / "entities.yaml"
    config_path.write_text(
        "ARTIST:\n"
        "  Coheed: 'Coheed(?:\\s(?:and|\\&)\\sCambria)?'\n"
        "GENRE:\n"
        "  _flags: IGNORECASE\n"
        "  Jazz: '(?:smooth\\s)?jazz'\n",
        encoding="utf-8",
    )

    assert load_config(config_path) == {
        "ARTIST": {"Coheed": r"Coheed(?:\s(?:and|\&)\sCambria)?"},
        "GENRE": {"_flags": "IGNORECASE", "Jazz": r"(?:smooth\s)?jazz"},
    }


def test_load_config_rejects_malformed_yaml(tmp_path):
    config_path = tmp_path / "entities.yaml"
    config_path.write_text("ARTIST:\n  Coheed: [unterminated\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="Could not parse YAML"):
        load_config(config_path)


def test_load_config_rejects_schema_errors(tmp_path):
    config_path = tmp_path / "entities.yaml"
    config_path.write_text("ARTIST:\n  Coheed: 123\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="must be a regex string"):
        load_config(config_path)


def test_add_entity_pattern_returns_updated_copy():
    config = {"ARTIST": {"Coheed": r"Coheed(?:\sand\sCambria)?"}}

    updated = add_entity_pattern(config, "ARTIST", "Rush", "Rush")

    assert updated == {"ARTIST": {"Coheed": r"Coheed(?:\sand\sCambria)?", "Rush": "Rush"}}
    assert config == {"ARTIST": {"Coheed": r"Coheed(?:\sand\sCambria)?"}}


def test_add_entity_pattern_refuses_and_replaces_duplicates():
    config = {"ARTIST": {"Coheed": "Coheed"}}

    with pytest.raises(ConfigError, match="already exists"):
        add_entity_pattern(config, "ARTIST", "Coheed", "Coheed and Cambria")

    updated = add_entity_pattern(config, "ARTIST", "Coheed", r"Coheed(?:\sand\sCambria)?", replace=True)

    assert updated == {"ARTIST": {"Coheed": r"Coheed(?:\sand\sCambria)?"}}
    assert config == {"ARTIST": {"Coheed": "Coheed"}}


def test_remove_entity_pattern_returns_updated_copy():
    config = {
        "ARTIST": {
            "Coheed": r"Coheed(?:\sand\sCambria)?",
            "Rush": "Rush",
        }
    }

    updated = remove_entity_pattern(config, "ARTIST", "Rush")

    assert updated == {"ARTIST": {"Coheed": r"Coheed(?:\sand\sCambria)?"}}
    assert config["ARTIST"] == {"Coheed": r"Coheed(?:\sand\sCambria)?", "Rush": "Rush"}


def test_validate_regex_flags():
    assert validate_regex_flags("IGNORECASE") == re.IGNORECASE
    assert validate_regex_flags(["IGNORECASE", "MULTILINE"]) == re.IGNORECASE | re.MULTILINE

    with pytest.raises(ConfigError, match="not a valid regex flag name"):
        validate_regex_flags("NOT_A_FLAG")


def test_resolve_default_config_path_creates_empty_config(monkeypatch, tmp_path):
    config_path = tmp_path / "detectors.yaml"
    monkeypatch.setenv(DEFAULT_CONFIG_ENV_VAR, str(config_path))

    resolved_path = resolve_default_config_path(create=True)

    assert resolved_path == config_path
    assert config_path.exists()
    assert load_config(config_path) == {}


def test_saved_config_round_trips_through_nerb(tmp_path, music_pattern_config, prog_rock_wiki):
    config_path = save_config(music_pattern_config, tmp_path / "saved_entities.yaml")

    original_nerb = NERB(music_pattern_config, add_word_boundaries=True)
    saved_nerb = NERB(config_path, add_word_boundaries=True)

    assert saved_nerb.ARTIST.pattern == original_nerb.ARTIST.pattern
    assert saved_nerb.GENRE.pattern == original_nerb.GENRE.pattern
    assert list(saved_nerb.extract_named_entity("ARTIST", prog_rock_wiki)) == list(
        original_nerb.extract_named_entity("ARTIST", prog_rock_wiki)
    )
    assert list(saved_nerb.extract_named_entity("GENRE", prog_rock_wiki)) == list(
        original_nerb.extract_named_entity("GENRE", prog_rock_wiki)
    )
