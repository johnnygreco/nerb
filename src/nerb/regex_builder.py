from __future__ import annotations

# Standard library
import re
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
        Configuration with the entity groups and regex patterns. If
        Path or str, must be the full path to a yaml config file.
    flags : re.RegexFlag or int, optional
        Regular Expresion flags to be applied to all
        compiled regex (default: re.IGNORECASE).

    Examples
    --------
    A pattern_config dict with an entity group called 'music', which is
    composed of entities 'ARTIST' and 'GENRE', might look like this:

        pattern_config = dict(
            music={
                'ARTIST': r'coheed(?:\sand\scambria)?}|thelonious\smonk',
                'GENRE': r'(?:progressive|alternative|punk)rock|pop|jazz|rap'
            }
        )

    This pattern config will create a `NERB` instance with a `music` compiled
    regex attribute with 'ARTIST' and 'GENRE' named capture groups.
    """

    def __init__(
        self,
        pattern_config: Path | str | dict[str, str],
        flags: re.RegexFlag | int = re.IGNORECASE
    ):

        if isinstance(pattern_config, (Path, str)):
            self.pattern_config = utils.load_yaml_config(pattern_config)

        elif isinstance(pattern_config, dict):
            self.pattern_config = pattern_config

        else:
            raise TypeError(
                f'{type(pattern_config)} is not a valid type for pattern_config. '
                'Must be of type Path, str, or dict.'
            )

        self.flags = flags
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

        for entity_group in self.pattern_config.keys():

            term_dict = {}
            setattr(self, f'{entity_group}_entities', list(self.pattern_config[entity_group].keys()))

            for name, regex in self.pattern_config[entity_group].items():
                # Add word boundaries to all terms.
                term_dict[name] = self._add_word_boundaries(regex)

            # Build final pattern and compile regex.
            pattern = '|'.join([fr'(?P<{k}>{v})' for k, v in term_dict.items()])
            setattr(self, entity_group, re.compile(pattern, flags=self.flags))

    def extract_named_entities(self, entity_group: str, text: str) -> NamedEntityList:
        """
        Extract entities of the given entity group from the given text.

        Parameters
        ----------
        entity_group : str
            Name of compiled regex attribute that contains the named capture group.
        text : str
            The regex method will be applied to this text.

        Returns
        -------
        entity_list: NamedEntityList
            List of extracted named entities.
        """

        if not hasattr(self, entity_group):
            raise AttributeError(f'This NERB instance does not have a compiled regex named {entity_group}.')
        regex = getattr(self, entity_group)

        entity_list = NamedEntityList()
        for match in regex.finditer(text):
            entity = NamedEntity(name=match.group(), entity=match.lastgroup, span=match.span())
            entity_list.append(entity)

        return entity_list

    def isolate_named_capture_group(
        self, 
        entity_group: str,
        entity: str,
        text: str,
        method: str = 'search'
    ) -> Optional[re.Match | list[re.Match] | list[tuple[str]]]:
        """
        Apply regex method to the given compiled regex attribute, isolating the results for the
        given named capture group.
        
        Parameters
        ----------
        entity_group : str
            Name of compiled regex attribute that contains the named capture group.
        entity : str
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
        regex = getattr(self, entity_group)
        named_groups = list(regex.groupindex.keys())
        
        if entity not in named_groups:
            raise KeyError(f"'{entity}' is not a valid group name for '{entity_group}'. "
                           f'Allowed values: {named_groups}.')
        
        if method == 'search':
            # The search method returns the first occurrence of the pattern.
            for m in regex.finditer(text):
                if m.lastgroup == entity:
                    result = m
                    break
                
        elif method == 'finditer':
            matches = [m for m in regex.finditer(text) if m.lastgroup == entity]
            if len(matches) > 0:
                result = matches
                
        elif method == 'findall':
            group_idx = regex.groupindex[entity] - 1
            matches = [m for m in regex.findall(text) if m[group_idx] != '']
            if len(matches) > 0:
                result = matches
                
        else:
            raise NameError(
                f"'{method}' is not a valid regex method. Allowed values: search, finditer, or findall."
            )
              
        return result
