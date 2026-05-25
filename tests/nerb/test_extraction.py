from __future__ import annotations

# Project
from nerb import NERB, NamedEntity, NamedEntityList, extract_named_entities, extract_named_entities_records


def test_empty_named_entity_list_serializes_to_empty_records():
    assert NamedEntityList().to_records() == []


def test_named_entity_list_serializes_records():
    entities = NamedEntityList()
    entities.append(NamedEntity(entity="ARTIST", name="Coheed", string="Coheed", span=(10, 16)))
    entities.append(NamedEntity(entity="GENRE", name="Rock", string="rock", span=(24, 28)))

    assert entities.to_records() == [
        {
            "entity": "ARTIST",
            "name": "Coheed",
            "string": "Coheed",
            "start": 10,
            "end": 16,
        },
        {
            "entity": "GENRE",
            "name": "Rock",
            "string": "rock",
            "start": 24,
            "end": 28,
        },
    ]


def test_named_entity_serializes_span_as_start_and_end():
    entity = NamedEntity(entity="ARTIST", name="Coheed", string="Coheed", span=(10, 16))

    assert entity.to_dict() == {
        "entity": "ARTIST",
        "name": "Coheed",
        "string": "Coheed",
        "start": 10,
        "end": 16,
    }


def test_extract_named_entities_with_fixture_config_and_document(music_pattern_config, prog_rock_wiki):
    nerb = NERB(music_pattern_config, add_word_boundaries=True)

    entities = extract_named_entities(nerb, prog_rock_wiki)
    entity_sort_keys = [
        (entity.span[0], entity.span[1], entity.entity, entity.name, entity.string) for entity in entities
    ]

    assert len(entities) == 215
    assert len(entities) == len(nerb.extract_named_entity("ARTIST", prog_rock_wiki)) + len(
        nerb.extract_named_entity("GENRE", prog_rock_wiki)
    )
    assert {entity.entity for entity in entities} == {"ARTIST", "GENRE"}
    assert entity_sort_keys == sorted(entity_sort_keys)
    assert nerb.extract_named_entities(prog_rock_wiki).to_records() == entities.to_records()
    assert extract_named_entities_records(nerb, prog_rock_wiki) == entities.to_records()
