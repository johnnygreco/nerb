from __future__ import annotations

# Standard library
import re
from copy import deepcopy
from pathlib import Path
from typing import Optional

# Project
from . import utils
from .named_entities import NamedEntity, NamedEntityList


__all__ = ['NERB']


class NERB:
    """
    Named Entity Regex Builder (NERB): Streamlined named catupre groups.

    Parameters
    ----------
    pattern_config : Path or str or dict
        Configuration with the named entities and regex patterns. If
        Path or str, must be the full path to a yaml config file.
    flags : re.RegexFlag or int, optional
        Regular Expresion flags to be applied to all
        compiled regex (default: re.IGNORECASE).
    add_word_boundaries : bool, optional
        If True, add word boundaries to all terms in the regex
        patterns (default: True).

    Examples
    --------
    A pattern_config dict for a music document might look like this:

        pattern_config = dict(
            ARTIST = {
                'Coheed': r'coheed(?:\sand\scambria)?',
                'Thelonious Monk': r'thelonious\smonk',
            },
            GENRE = {
                'Rock': r'(?:(?:progressive|alternative|punk)\s)?rock|rock\s(?:and\s)roll',
                'Jazz': r'(?:smooth\s)?jazz',
                'Hip Hop': r'rap|hip\shop',
                'Pop': r'pop(?:ular)?'
            }
        )

    This pattern config will create a NERB instance with ARTIST and GENRE entities, which
    are accessible via compiled regex attributes composed of named capture groups.
    """

    def __init__(
        self,
        pattern_config: Path | str | dict[str, dict[str, str]],
        add_word_boundaries: bool = True
    ):

        self.add_word_boundaries = add_word_boundaries

        if isinstance(pattern_config, (Path, str)):
            self.pattern_config = utils.load_yaml_config(pattern_config)

        elif isinstance(pattern_config, dict):
            self.pattern_config = deepcopy(pattern_config)

        else:
            raise TypeError(
                f'{type(pattern_config)} is not a valid type for pattern_config. '
                'Must be of type Path, str, or dict.'
            )

        self._build_regex()

    @staticmethod
    def _add_word_boundaries(pattern: str) -> str:
        """
        Add word boundaries to every term within the given pattern.

        Parameters
        ----------
        pattern : str
            Regex pattern with terms that need word boundaries.

        Returns
        -------
        pattern : str
            Modified regex pattern with word boundaries around every term.
        """
        pattern = re.sub(r'\|(?![^(]*\))', r'\\b|\\b', pattern)
        pattern = r'{b}{r}{b}'.format(b=r'\b', r=pattern)
        return pattern

    def _build_regex(self):
        """Build and compile vocab regex patterns."""

        for entity in self.pattern_config.keys():

            # Get flags. Pop '_flags' keyword if it exists.
            flags = self._generate_regex_flags(entity)

            term_dict = {}
            setattr(self, f'{entity}_names', list(self.pattern_config[entity].keys()))

            for name, pattern in self.pattern_config[entity].items():
                # Add word boundaries to all terms.
                pattern = self._add_word_boundaries(pattern) if self.add_word_boundaries else fr'{pattern}'
                term_dict[name.replace(' ', '_')] = pattern

            # Build final pattern and compile regex.
            pattern = '|'.join([fr'(?P<{k}>{v})' for k, v in term_dict.items()])
            setattr(self, entity, re.compile(pattern, flags=flags))

    def _generate_regex_flags(self, entity: str) -> re.RegexFlag:
        """Generate regex flags from input config if the '_flags' parameter is given."""
        flags = self.pattern_config[entity].pop('_flags', 0)
        if not isinstance(flags, int):
            flags = flags if isinstance(flags, list) else [flags]
            combined_flags = getattr(re, flags[0].upper())
            for flag in flags[1:]:
                combined_flags |= getattr(re, flag.upper())
            flags = combined_flags
        return flags

    @property
    def entity_list(self):
        return list(self.pattern_config.keys())

    def extract_named_entity(self, entity: str, text: str) -> NamedEntityList:
        """
        Extract names of the given entity group from the given text.

        Parameters
        ----------
        entity : str
            Entity to extract from text.
        text : str
            Text from which to extract the given entity.

        Returns
        -------
        named_entity_list: NamedEntityList
            List of extracted named entities.
        """

        if not hasattr(self, entity):
            raise AttributeError(f'This NERB instance does not have a compiled regex called {entity}.')
        regex = getattr(self, entity)

        named_entity_list = NamedEntityList()
        for match in regex.finditer(text):
            name = match.lastgroup.replace('_', ' ')
            named_entity_list.append(
                NamedEntity(entity=entity, name=name, string=match.group(), span=match.span())
            )

        return named_entity_list

    def isolate_named_capture_group(
        self, 
        entity: str,
        name: str,
        text: str,
        method: str = 'search'
    ) -> Optional[re.Match | list[re.Match] | list[tuple[str]]]:
        """
        Apply regex method to the given compiled regex attribute, isolating the results for the
        given named capture group.
        
        Parameters
        ----------
        entity : str
            Entity compiled regex attribute that contains the named capture group.
        name : str
            Named capture group to be isolated.
        text : str
            The regex method will be applied to this text.
        method : str, optional
            Regex method to be applied to the given text (search, finditer, or findall).
            
        Returns
        -------
        result : match object, list of match objects, list of tuples, or None
            Result from applying the given regex method. If no match is found, 
            None will be returned.
            
        Note
        ----
        Normally, `finditer` returns an iterator. However, if you select this method here, 
        we need to loop over all the matches, so the results will be returned as a list.
        """
        
        result = None
        regex = getattr(self, entity)
        named_groups = list(regex.groupindex.keys())
        name = name.replace(' ', '_')

        if name not in named_groups:
            raise KeyError(f"'{name}' is not a valid group name for '{entity}'. "
                           f'Allowed values: {named_groups}.')
        
        if method == 'search':
            # The search method returns the first occurrence of the pattern.
            for m in regex.finditer(text):
                if m.lastgroup == name:
                    result = m
                    break
                
        elif method == 'finditer':
            matches = [m for m in regex.finditer(text) if m.lastgroup == name]
            if len(matches) > 0:
                result = matches
                
        elif method == 'findall':
            group_idx = regex.groupindex[name] - 1
            matches = [m for m in regex.findall(text) if m[group_idx] != '']
            if len(matches) > 0:
                result = matches
                
        else:
            raise NameError(
                f"'{method}' is not a valid regex method. Allowed values: search, finditer, or findall."
            )
              
        return result

    def __repr__(self):
        return f'{self.__class__.__name__}(entities: {self.entity_list.__repr__()})'
