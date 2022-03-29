from __future__ import annotations

# Standard library
from pathlib import Path

# Third-party
import pytest

# Project
from nerb import repo_path


@pytest.fixture
def music_pattern_config() -> dict[str, dict[str, str]]:
    pattern_config = dict(
        ARTIST={
            'Coheed': r'coheed(?:\s(?:and|\&)\scambria)?',
            'Foo Fighters': r'foo\sfighters',
            'Jay Z': r'jay\sz',
            'Mars Volta': r'mars\svolta',
            'Miles Davis': r'miles\sdavis',
            'Thelonious Monk': r'thelonious\smonk'

        },
        GENRE={
            'Hip Hop': r'rap|hip\shop',
            'Jazz': r'(?:smooth\s)?jazz',
            'Pop': r'pop(?:ular)?',
            'Rock': r'(?:(?:prog(:?ressive)?|alternative|punk)\s)?rock|rock\s(?:and|\&|n)\sroll'
        }
    )
    return pattern_config


@pytest.fixture()
def prog_rock_wiki(test_data_path):
    with open(test_data_path / 'prog_rock_wiki.txt', 'r') as file:
        content = file.read()
    return content


@pytest.fixture
def test_data_path() -> Path:
    """Fixture to Fetch reports for unit testing."""
    return repo_path / 'tests' / 'data'
