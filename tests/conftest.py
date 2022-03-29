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
            'Coheed': r'Coheed(?:\s(?:and|\&)\sCambria)?',
            'The Doors': r'[Tt]he\Doors',
            'Dream Theater': r'Dream\sTheater',
            'Foo Fighters': r'Foo\sFighters',
            'The Grateful Dead': r'(?:[Tt]he\s)?Grateful\sDead|[Tt]he\sWarlocks',
            'Jay Z': r'Jay(?:\s|-)Z|Shawn(?:\sCorey\s)?\sCarter',
            'Mars Volta': r'Mars\sVolta',
            'Miles Davis': r'Miles\sDavis',
            'Pink Floyd': r'Pink\sFloyd',
            'Thelonious Monk': r'Thelonious\sMonk',
            'The Who': r'[Tt]he\sWho'

        },
        GENRE={
            '_flags': 'IGNORECASE',
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
