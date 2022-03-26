# Project
from nerb import Nerb


class TestRegexBuilder:
    """
    Class for testing general functionality of the RegexBuilder.
    """

    def test_isolate_named_capture_group(self, music_pattern_config):
        """Test that we correctly isolate the named capture group and return the appropriate regex result."""

        regex = Nerb(music_pattern_config)

        kw = dict(
            regex_name='music',
            group_name='ARTIST',
            text='Miles Davis is my favorite jazz artist. '
                 'Incubus is great, but I like progressive rock and am a big fan of Coheed.'
        )

        result = regex.isolate_named_capture_group(method='search', **kw)
        assert result.lastgroup == 'ARTIST'
        assert result.group() == 'Miles Davis'

        result = regex.isolate_named_capture_group(method='finditer', **kw)
        assert len(result) == 3
        assert result[0].group() == 'Miles Davis'
        assert result[1].group() == 'Incubus'
        assert result[2].group() == 'Coheed'

        result = regex.isolate_named_capture_group(method='findall', **kw)
        assert len(result) == 3
        assert result[0][0] == 'Miles Davis'
        assert result[1][0] == 'Incubus'
