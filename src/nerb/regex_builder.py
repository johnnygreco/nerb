from __future__ import annotations

# Standard library
import re
from pathlib import Path
from typing import Optional

# Project
from . import utils


__all__ = ['Nerb']


class Nerb:
    """Class for building regex using yaml configuration files."""

    def __init__(self, pattern_config: Path | str | dict[str, str]):

        if isinstance(pattern_config, (Path, str)):
            self.pattern_config = utils.load_yaml_config()

        elif isinstance(pattern_config, dict):
            self.pattern_config = pattern_config

        else:
            raise TypeError(
                f'{type(pattern_config)} is not a valid type for pattern_config. Must be of type Path, str, or dict.'
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

        for regex_name in self.pattern_config.keys():

            term_dict = {}
            setattr(self, f'{regex_name}_group_names', list(self.pattern_config[regex_name].keys()))

            for name, regex in self.pattern_config[regex_name].items():
                # Add word boundaries to all terms.
                term_dict[name] = self._add_word_boundaries(regex)

            # Build final pattern and compile regex.
            pattern = '|'.join([fr'(?P<{k}>{v})' for k, v in term_dict.items()])
            setattr(self, regex_name, re.compile(pattern, re.I))
    
    def isolate_named_capture_group(
        self, 
        text: str, 
        regex_name: str, 
        group_name: str, 
        method: str = 'search'
    ) -> Optional[re.Match | list[re.Match] | list[tuple[str]]]:
        """
        Apply regex method to the given compiled regex attribute, isolating the results for the
        given named capture group.
        
        Parameters
        ----------
        text : str
            The regex method will be applied to this text.
        regex_name : str
            Name of compiled regex attribute that contains the named capture group.
        group_name : str
            Named capture group to be isolated.
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
        regex = getattr(self, regex_name)
        named_groups = list(regex.groupindex.keys())
        
        if group_name not in named_groups:
            raise KeyError(f"'{group_name}' is not a valid group name for '{regex_name}'. "
                           f'Allowed values: {named_groups}.')
        
        if method == 'search':
            # The search method returns the first occurrence of the pattern.
            for m in regex.finditer(text):
                if m.lastgroup == group_name:
                    result = m
                    break
                
        elif method == 'finditer':
            matches = [m for m in regex.finditer(text) if m.lastgroup == group_name]
            if len(matches) > 0:
                result = matches
                
        elif method == 'findall':
            group_idx = regex.groupindex[group_name] - 1
            matches = [m for m in regex.findall(text) if m[group_idx] != '']
            if len(matches) > 0:
                result = matches
                
        else:
            raise NameError(f"'{method}' is not a valid regex method. Allowed values: search, finditer, or findall.")  
              
        return result
