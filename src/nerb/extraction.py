from __future__ import annotations

# Standard library
from typing import Any

# Project
from .named_entities import NamedEntity, NamedEntityList

__all__ = [
    "extract_named_entities",
    "extract_named_entities_records",
    "extract_named_entity",
    "extract_named_entity_records",
]


def _sort_key(entity: NamedEntity) -> tuple[int, int, str, str, str]:
    return (entity.span[0], entity.span[1], entity.entity, entity.name, entity.string)


def extract_named_entity(extractor: Any, entity: str, text: str) -> NamedEntityList:
    """
    Extract one configured entity from text.

    Results preserve the regex engine's deterministic left-to-right match order.
    """
    if not hasattr(extractor, entity):
        raise AttributeError(f"This NERB instance does not have a compiled regex called {entity}.")

    regex = getattr(extractor, entity)
    named_entity_list = NamedEntityList()

    for match in regex.finditer(text):
        if match.lastgroup is None:
            continue

        name = match.lastgroup.replace("_", " ")
        named_entity_list.append(NamedEntity(entity=entity, name=name, string=match.group(), span=match.span()))

    return named_entity_list


def extract_named_entities(extractor: Any, text: str) -> NamedEntityList:
    """
    Extract all configured entities from text.

    Results are sorted by start offset, end offset, entity, name, and matched string so
    callers receive deterministic document-order output across entity groups.
    """
    named_entity_list = NamedEntityList()

    for entity in extractor.entity_list:
        named_entity_list.extend(extract_named_entity(extractor, entity, text))

    named_entity_list.sort(key=_sort_key)
    return named_entity_list


def extract_named_entity_records(extractor: Any, entity: str, text: str) -> list[dict[str, Any]]:
    """Extract one configured entity and serialize the matches as records."""
    return extract_named_entity(extractor, entity, text).to_records()


def extract_named_entities_records(extractor: Any, text: str) -> list[dict[str, Any]]:
    """Extract all configured entities and serialize the matches as records."""
    return extract_named_entities(extractor, text).to_records()
