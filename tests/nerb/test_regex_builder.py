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

        artists = [
            'Coheed', 'The Doors', 'Dream Theater', 'Foo Fighters', 'The Grateful Dead', 'Jay Z',
            'Mars Volta', 'Miles Davis', 'Pink Floyd', 'Thelonious Monk', 'The Who'
        ]
        assert len(nerb_regex.pattern_config) == 2
        assert nerb_regex.entity_list == ['ARTIST', 'GENRE']
        assert nerb_regex.GENRE_names == ['Hip Hop', 'Jazz', 'Pop', 'Rock']
        assert nerb_regex.ARTIST_names == artists

    def test_nerb_from_yaml(self, test_data_path, nerb_regex):
        """Test that a NERB instance created from a yaml file works as expected."""

        nerb_regex_yaml = NERB(test_data_path / 'music_entities.yaml')
        assert len(nerb_regex_yaml.pattern_config) == 2
        assert nerb_regex_yaml.entity_list == nerb_regex.entity_list
        assert nerb_regex_yaml.ARTIST.pattern == nerb_regex.ARTIST.pattern
        assert nerb_regex_yaml.GENRE.pattern == nerb_regex.GENRE.pattern
        assert nerb_regex_yaml.ARTIST_names == nerb_regex.ARTIST_names
        assert nerb_regex_yaml.GENRE_names == nerb_regex.GENRE_names

    def test_extract_named_entity(self, nerb_regex, prog_rock_wiki):
        """Test the extract named entity method on the Progressive Rock Wikipedia page."""

        artist = nerb_regex.extract_named_entity('ARTIST', prog_rock_wiki)
        assert len(artist) == 17
        assert artist.get_unique_names() == {'Coheed', 'Dream Theater', 'Mars Volta',
                                             'Pink Floyd', 'The Grateful Dead', 'The Who'}
        assert prog_rock_wiki[artist[0].span[0]: artist[0].span[1]] == artist[0].string

        genre = nerb_regex.extract_named_entity('GENRE', prog_rock_wiki)
        assert len(genre) == 198
        assert genre.get_unique_names() == {'Jazz', 'Pop', 'Rock'}

    def test_set_flags(self, nerb_regex):
        """Test that flags are set when they are passed using the '_flags' config option."""
        text = 'thelonious monk is my favorite JaZz artist.'
        assert nerb_regex.ARTIST.search(text) == None
        assert nerb_regex.GENRE.search(text).group() == 'JaZz'

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
        assert result[0][3] == 'Foo Fighters'
