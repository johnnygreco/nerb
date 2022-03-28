from __future__ import annotations

# Standard library
import re
from copy import deepcopy
from dataclasses import dataclass
from typing import Callable, Optional


__all__ = ['NamedEntity', 'NamedEntityList']


@dataclass(frozen=True)
class NamedEntity:
    name: str
    entity: str
    span: tuple[int, int]


class NamedEntityList:
    """Named entity list class."""

    def __init__(self, init_list: Optional[list] = None):
        init_list = [] if init_list is None else init_list
        self._list = init_list

    def append(self, entity: NamedEntity):
        """Append entity to this list, where the element must be of type NamedEntity."""
        if not isinstance(entity, NamedEntity):
            raise TypeError(
                f'{self.__class__.__name__} holds {NamedEntity} objects. You gave {type(entity)}.')
        self._list.append(entity)

    def copy(self):
        return deepcopy(self)

    def extend(self, entity_list: NamedEntityList | list[NamedEntity]):
        """Extend list. Similar to the standard python list object, extend takes an iterable as an argument."""
        if not isinstance(entity_list, (NamedEntityList, list)):
            raise TypeError(
                f'Expected object of type {self.__class__.__name__} or list. You gave {type(entity_list)}.'
            )

        for elem in entity_list:
            self.append(elem)

    def get_unique_entities(self) -> set[str]:
        """Return set of the unique entities in this NamedEntityList."""
        return set([entity.entity for entity in self])

    def get_unique_names(self) -> set[str]:
        """Return set of the unique names of the named entities in this NamedEntityList."""
        return set([entity.name for entity in self])

    def sort(self, key: Callable, *, reverse: bool = False) -> None:
        """
        Sort the list according to the given key. The sort is executed in-place.

        Parameters
        ----------
        key : callable (e.g., a lambda function)
            Function that defines how the list should be sorted.
        reverse : bool, optional
            If True, sort in descending order.
        """
        self._list.sort(key=key, reverse=reverse)

    def __add__(self, other: NamedEntityList):
        """Define what it means to add two list objects together."""
        concatenated_list = list(self) + list(other)
        return self.__class__(concatenated_list)

    def __getitem__(self, item):
        if isinstance(item, list):
            return self.__class__([self._list[i] for i in item])
        elif isinstance(item, slice):
            return self.__class__(self._list[item])
        else:
            return self._list[item]

    def __iter__(self):
        return iter(self._list)

    def __len__(self):
        return len(self._list)

    def __repr__(self):
        repr = '\n'.join([f'[{i}] {p.__repr__()}' for i, p in enumerate(self)])
        repr = re.sub(r'^', ' ' * 4, repr, flags=re.M)
        repr = f'(\n{repr}\n)' if len(self) > 0 else f'([])'
        return f'{self.__class__.__name__}{repr}'
