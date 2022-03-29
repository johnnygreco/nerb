# Third-party
import pytest

# Project
from nerb import NERB


@pytest.fixture
def nerb_regex(music_pattern_config) -> NERB:
    """Fixture for creating a NERB instance."""
    return NERB(music_pattern_config)


class TestRegexBuilder:
    """Class for testing methods of the NERB regex builder."""

    def test_nerb_init(self, nerb_regex):
        """Test that the NERB instance is instantiated correctly"""
        assert len(nerb_regex.pattern_config) == 2
        assert nerb_regex.entity_list == ['ARTIST', 'GENRE']
        assert nerb_regex.GENRE_names == ['Hip Hop', 'Jazz', 'Pop', 'Rock']
        assert nerb_regex.ARTIST_names == ['Coheed', 'Foo Fighters', 'Jay Z', 'Mars Volta',
                                           'Miles Davis', 'Thelonious Monk']

    def test_nerb_from_yaml(self, test_data_path, nerb_regex):
        """Test that a NERB instance created from a yaml file works as expected."""

        nerb_regex_yaml = NERB(test_data_path / 'music.yaml')
        assert len(nerb_regex_yaml.pattern_config) == 2
        assert nerb_regex_yaml.entity_list == ['ARTIST', 'GENRE']
        assert nerb_regex_yaml.GENRE_names == ['Hip Hop', 'Jazz', 'Pop', 'Rock']
        assert nerb_regex_yaml.ARTIST_names == ['Coheed', 'Foo Fighters', 'Jay Z', 'Mars Volta',
                                                'Miles Davis', 'Thelonious Monk']
        assert nerb_regex.ARTIST.pattern == nerb_regex_yaml.ARTIST.pattern
        assert nerb_regex.GENRE.pattern == nerb_regex_yaml.GENRE.pattern

    def test_extract_named_entity(self, nerb_regex, prog_rock_wiki):
        """Test the extract named entity method."""

        artist = nerb_regex.extract_named_entity('ARTIST', prog_rock_wiki)
        assert len(artist) == 2
        assert artist.get_unique_names() == {'Coheed', 'Mars Volta'}
        assert prog_rock_wiki[artist[0].span[0]: artist[0].span[1]] == artist[0].string
        assert artist[1].string == 'Mars Volta'

        genre = nerb_regex.extract_named_entity('GENRE', prog_rock_wiki)
        assert len(genre) == 198
        assert genre.get_unique_names() == {'Jazz', 'Pop', 'Rock'}

    def test_isolate_named_capture_group(self, nerb_regex):
        """Test that we correctly isolate the named capture group and return the appropriate regex result."""

        kw = dict(
            entity='ARTIST',
            text='Miles Davis is my favorite jazz artist. '
                 'Foo Fighters are great, but I like progressive rock and '
                 'am a big fan of Coheed because Coheed and Cambria rock!'
        )

        result = nerb_regex.isolate_named_capture_group(name='Miles Davis', method='search', **kw)
        assert result.lastgroup == 'Miles_Davis'
        assert result.group() == 'Miles Davis'

        result = nerb_regex.isolate_named_capture_group(name='Coheed', method='finditer', **kw)
        assert len(result) == 2
        assert result[0].group() == 'Coheed'
        assert result[1].group() == 'Coheed and Cambria'

        result = nerb_regex.isolate_named_capture_group(name='Foo Fighters', method='findall', **kw)
        assert len(result) == 1
        assert result[0][1] == 'Foo Fighters'
