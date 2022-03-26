from __future__ import annotations

# Standard library
from pathlib import Path

# Third-party
import pytest

# Project
from nerb import repo_path


@pytest.fixture
def test_data_path() -> Path:
    """Fixture to Fetch reports for unit testing."""
    return repo_path / 'tests' / 'data'


@pytest.fixture
def music_pattern_config() -> dict[str, dict[str, str]]:
    pattern_config = dict(
        music={
            'ARTIST': r'coheed(?:\sand\scambria)?|foo\sfighters|incubus|miles\sdavis|'
                      r'john\smayer|theloniou\smonk|jay\sz|eminem',
            'GENRE': r'(?:progressive|alternative|punk)rock|pop|jazz|rap'
        }
    )
    return pattern_config
