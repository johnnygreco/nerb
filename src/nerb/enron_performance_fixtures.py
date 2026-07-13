"""Deterministic, privacy-safe fixtures for Enron performance evidence.

The generators in this module are deliberately in-memory.  Callers decide if
and where to persist the returned immutable byte artifacts, normally through a
``PrivateRun`` transaction.  Public descriptors contain aggregate composition,
sizes, and hashes only; controlled matcher tokens remain private to the fixture
objects.

The 100k fixture preserves the evaluated native-entity-to-pattern ratio by using
318 native matcher shards grouped under two semantic taxonomy classes, with at
most 502 patterns per shard.  A non-promotable five-native-shard feasibility
probe exceeded 5 GiB and did not complete, so this fixture does not establish a
100k small-shard-topology claim.  The higher shard count is an empirical
resource-safety choice, not an expansion of Rust's formal 50k-pattern per-entity
limit.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from .engine import Bank
from .enron_contract import (
    PERFORMANCE_SCALE_PATTERNS,
    hash_enron_performance_bank,
    hash_enron_performance_input,
    hash_enron_performance_inventory,
    summarize_enron_performance_inventory,
)

__all__ = [
    "EnronPerformanceBankFixture",
    "EnronPerformanceFixtureError",
    "EnronPerformanceInputFixture",
    "EnronPerformanceInventoryRow",
    "make_enron_performance_bank_fixture",
    "make_enron_performance_bank_fixtures",
    "make_enron_performance_input_fixtures",
]

_GENERATOR_VERSION = "1.0.0"
_GENERATOR_SEED = "nerb-enron-performance"
_BANK_GENERATOR_ID = "nerb_enron_performance_scale_bank"
_INPUT_GENERATOR_ID = "nerb_enron_performance_controlled_input"
_EXPECTED_ENTITY_CLASSES = ("contact", "person")
_MAX_PATTERNS_PER_ENTITY = 50_000
_MAX_TOTAL_PATTERNS = 100_000
_MAX_TOTAL_PATTERN_BYTES = 10_000_000
_MAX_NATIVE_SOURCE_BYTES = 64 * 1024 * 1024
_CONTROLLED_DOCUMENTS = 100
_CONTROLLED_SIZE_BYTES = {
    "small": 512,
    "medium": 10_240,
    "large": 65_536,
    "huge": 300_000,
}
_SAFE_PADDING = b"nerb synthetic benchmark padding "
_BANK_SPEC = {
    "schema_version": "nerb.enron_performance_scale_bank_spec.v1",
    "scale_axis": "active_matcher_patterns",
    "scales": list(PERFORMANCE_SCALE_PATTERNS),
    "allocation": "integer_largest_remainder",
    "catalog_aliases_are_matcher_independent": True,
    "entity_classes": list(_EXPECTED_ENTITY_CLASSES),
    "native_format": "jsonl",
    "max_patterns_per_entity": _MAX_PATTERNS_PER_ENTITY,
    "max_total_patterns": _MAX_TOTAL_PATTERNS,
    "max_total_pattern_bytes": _MAX_TOTAL_PATTERN_BYTES,
    "max_native_source_bytes": _MAX_NATIVE_SOURCE_BYTES,
    "entity_count_semantics": "native_matcher_shards",
    "entity_allocation": "per_taxon_evaluated_native_entity_to_pattern_ratio_rounded_with_native_bounds",
    "catalog_namespace": "NERB_PERF_Tnnn_[CA]nnnnnn",
    "matcher_namespace": "NERBtnnnnn",
}
_INPUT_SPEC = {
    "schema_version": "nerb.enron_performance_controlled_input_spec.v1",
    "documents": _CONTROLLED_DOCUMENTS,
    "density_records_per_document": {"negative": 0, "sparse": "one_total", "normal": 1, "dense": 3},
    "size_bytes": _CONTROLLED_SIZE_BYTES,
    "artifact_format": "raw_concatenated_utf8_documents",
    "inventory_format": "canonical_json_array_of_bytes_records",
}


class EnronPerformanceFixtureError(ValueError):
    """Raised when a controlled performance fixture cannot be built safely."""


@dataclass(frozen=True)
class EnronPerformanceInventoryRow:
    """One immutable input boundary and aggregate expected-record count."""

    byte_count: int
    record_count: int

    def to_dict(self) -> dict[str, int]:
        return {"bytes": self.byte_count, "records": self.record_count}


@dataclass(frozen=True)
class EnronPerformanceBankFixture:
    """Immutable native/canonical bank artifacts plus an aggregate descriptor."""

    id: str
    source_artifact_id: str
    source_filename: str
    canonical_artifact_id: str
    canonical_filename: str
    source_bytes: bytes = field(repr=False)
    canonical_bytes: bytes = field(repr=False)
    source_sha256: str
    bank_hash: str
    canonical_sha256: str
    descriptor_bytes: bytes = field(repr=False)
    preflight_record_count: int
    _hit_tokens: tuple[bytes, ...] = field(repr=False)

    @property
    def descriptor(self) -> dict[str, Any]:
        """Return a fresh mutable copy of the contract-shaped descriptor."""

        return _decode_object(self.descriptor_bytes)

    @property
    def source_artifact(self) -> dict[str, Any]:
        """Return the content-addressed native-source reference."""

        return {"id": self.source_artifact_id, "sha256": self.source_sha256, "bytes": len(self.source_bytes)}

    @property
    def canonical_artifact(self) -> dict[str, Any]:
        """Return the content-addressed canonical-bank reference."""

        return {
            "id": self.canonical_artifact_id,
            "sha256": self.canonical_sha256,
            "bytes": len(self.canonical_bytes),
        }


@dataclass(frozen=True)
class EnronPerformanceInputFixture:
    """Immutable controlled documents, inventory, and aggregate descriptor."""

    id: str
    artifact_id: str
    artifact_filename: str
    inventory_id: str
    inventory_filename: str
    artifact_bytes: bytes = field(repr=False)
    inventory_bytes: bytes = field(repr=False)
    documents: tuple[bytes, ...] = field(repr=False)
    inventory_rows: tuple[EnronPerformanceInventoryRow, ...]
    descriptor_bytes: bytes = field(repr=False)

    @property
    def descriptor(self) -> dict[str, Any]:
        """Return a fresh mutable copy of the contract-shaped descriptor."""

        return _decode_object(self.descriptor_bytes)

    @property
    def artifact(self) -> dict[str, Any]:
        """Return the exact raw-document artifact reference."""

        return {
            "id": self.artifact_id,
            "sha256": _sha256(self.artifact_bytes),
            "bytes": len(self.artifact_bytes),
        }

    @property
    def inventory_ref(self) -> dict[str, Any]:
        """Return the exact canonical-inventory artifact reference."""

        return {
            "id": self.inventory_id,
            "sha256": _sha256(self.inventory_bytes),
            "bytes": len(self.inventory_bytes),
        }

    def inventory(self) -> list[dict[str, int]]:
        """Return fresh contract inventory rows in document order."""

        return [row.to_dict() for row in self.inventory_rows]


@dataclass(frozen=True)
class _TaxonAllocation:
    entity_class: str
    entities: int
    canonical_names: int
    aliases: int
    literal_patterns: int
    regex_patterns: int

    @property
    def names(self) -> int:
        return self.canonical_names + self.aliases

    @property
    def patterns(self) -> int:
        return self.literal_patterns + self.regex_patterns

    def to_dict(self) -> dict[str, int | str]:
        return {
            "entity_class": self.entity_class,
            "entities": self.entities,
            "canonical_names": self.canonical_names,
            "aliases": self.aliases,
            "literal_patterns": self.literal_patterns,
            "regex_patterns": self.regex_patterns,
        }


@dataclass(frozen=True)
class _InputPayload:
    artifact_id: str
    artifact_filename: str
    inventory_id: str
    inventory_filename: str
    artifact_bytes: bytes = field(repr=False)
    inventory_bytes: bytes = field(repr=False)
    documents: tuple[bytes, ...] = field(repr=False)
    inventory_rows: tuple[EnronPerformanceInventoryRow, ...]


def make_enron_performance_bank_fixture(
    *, active_patterns: int, evaluated_bank: Mapping[str, Any]
) -> EnronPerformanceBankFixture:
    """Build one exact matcher-scale bank while preserving evaluated aggregate composition.

    ``active_aliases`` is scaled independently from ``active_patterns``.  The
    generated JSONL therefore has exactly one row per matcher pattern while its
    descriptor retains the smaller, truthful catalog-alias population.
    """

    if type(active_patterns) is not int or active_patterns not in PERFORMANCE_SCALE_PATTERNS:
        raise EnronPerformanceFixtureError("Performance scale must be one of the frozen active-pattern counts.")
    evaluated = _evaluated_composition(evaluated_bank)
    allocation = _scale_composition(active_patterns, evaluated)
    source_bytes, pattern_bytes, hit_tokens = _native_jsonl_source(allocation, active_patterns)
    if len(source_bytes) >= _MAX_NATIVE_SOURCE_BYTES:
        raise EnronPerformanceFixtureError("Synthetic native bank source exceeds its strict byte limit.")
    if pattern_bytes >= _MAX_TOTAL_PATTERN_BYTES:
        raise EnronPerformanceFixtureError("Synthetic matcher patterns exceed their strict cumulative byte limit.")

    try:
        bank = Bank.from_source_bytes(source_bytes, format_hint="jsonl", use_cache=False)
        metadata = bank.metadata()
        canonical_bytes = bank.to_canonical_json_bytes()
        preflight_records = bank.scan_bytes(b" ".join(hit_tokens))
    except (MemoryError, OSError, RuntimeError, TypeError, ValueError) as error:
        raise EnronPerformanceFixtureError(
            "Synthetic performance bank failed native compile/scan preflight."
        ) from error
    expected_entities = sum(item.entities for item in allocation)
    if (
        metadata.get("entity_count") != expected_entities
        or metadata.get("pattern_count") != active_patterns
        or len(preflight_records) != len(hit_tokens)
    ):
        raise EnronPerformanceFixtureError("Synthetic performance bank failed aggregate native preflight checks.")

    identifier = f"scale_{active_patterns}"
    canonical_sha256 = _sha256(canonical_bytes)
    bank_hash = metadata.get("bank_hash")
    if type(bank_hash) is not str or not bank_hash.startswith("sha256:"):
        raise EnronPerformanceFixtureError("Synthetic canonical bank metadata is missing its stable hash.")
    canonical_artifact_id = f"{identifier}_canonical_bank"
    descriptor: dict[str, Any] = {
        "id": identifier,
        "kind": "synthetic_scale",
        "bank_hash": bank_hash,
        "artifact": {
            "id": canonical_artifact_id,
            "sha256": canonical_sha256,
            "bytes": len(canonical_bytes),
        },
        "generator": {
            "id": _BANK_GENERATOR_ID,
            "version": _GENERATOR_VERSION,
            "source_sha256": _generator_source_sha256(),
            "spec_sha256": _canonical_sha256(_BANK_SPEC),
            "seed": _GENERATOR_SEED,
        },
        "composition": {"taxonomy": [item.to_dict() for item in allocation]},
        "descriptor_sha256": "",
        "active_entities": expected_entities,
        "active_names": sum(item.names for item in allocation),
        "active_aliases": sum(item.aliases for item in allocation),
        "active_patterns": active_patterns,
        "canonical_json_bytes": len(canonical_bytes),
        "native_source_bytes": len(source_bytes),
    }
    descriptor["descriptor_sha256"] = hash_enron_performance_bank(descriptor)
    return EnronPerformanceBankFixture(
        id=identifier,
        source_artifact_id=f"{identifier}_native_source",
        source_filename=f"banks/{identifier}.native.jsonl",
        canonical_artifact_id=canonical_artifact_id,
        canonical_filename=f"banks/{identifier}.canonical.json",
        source_bytes=source_bytes,
        canonical_bytes=canonical_bytes,
        source_sha256=_sha256(source_bytes),
        bank_hash=bank_hash,
        canonical_sha256=canonical_sha256,
        descriptor_bytes=_canonical_payload(descriptor),
        preflight_record_count=len(preflight_records),
        _hit_tokens=hit_tokens,
    )


def make_enron_performance_bank_fixtures(
    *, evaluated_bank: Mapping[str, Any]
) -> tuple[EnronPerformanceBankFixture, ...]:
    """Build the complete frozen 1k/10k/25k/100k matcher-scale family."""

    return tuple(
        make_enron_performance_bank_fixture(active_patterns=active_patterns, evaluated_bank=evaluated_bank)
        for active_patterns in PERFORMANCE_SCALE_PATTERNS
    )


def make_enron_performance_input_fixtures(
    bank_fixtures: Sequence[EnronPerformanceBankFixture],
) -> tuple[EnronPerformanceInputFixture, ...]:
    """Build the frozen scale, density, and size controls for synthetic scans.

    The four scale cells bind the same negative/medium raw bytes and inventory.
    That shared anchor is also the negative/medium intersection of the density
    and size sweeps, avoiding an accidental content confound.
    """

    banks = _scale_bank_family(bank_fixtures)
    anchor = banks[PERFORMANCE_SCALE_PATTERNS[0]]
    shared_negative_medium = _make_input_payload(
        artifact_stem="controlled_negative_medium",
        byte_count=_CONTROLLED_SIZE_BYTES["medium"],
        record_counts=(0,) * _CONTROLLED_DOCUMENTS,
        hit_tokens=(),
    )
    fixtures = [
        _bind_input_fixture(identifier=f"scale_{scale}_input", bank=banks[scale], payload=shared_negative_medium)
        for scale in PERFORMANCE_SCALE_PATTERNS
    ]

    density_records = {
        "sparse": (1,) + (0,) * (_CONTROLLED_DOCUMENTS - 1),
        "normal": (1,) * _CONTROLLED_DOCUMENTS,
        "dense": (3,) * _CONTROLLED_DOCUMENTS,
    }
    for density in ("sparse", "normal", "dense"):
        fixtures.append(
            _bind_input_fixture(
                identifier=f"density_{density}_input",
                bank=anchor,
                payload=_make_input_payload(
                    artifact_stem=f"controlled_{density}_medium",
                    byte_count=_CONTROLLED_SIZE_BYTES["medium"],
                    record_counts=density_records[density],
                    hit_tokens=anchor._hit_tokens,
                ),
            )
        )

    for size in ("small", "large", "huge"):
        fixtures.append(
            _bind_input_fixture(
                identifier=f"size_{size}_input",
                bank=anchor,
                payload=_make_input_payload(
                    artifact_stem=f"controlled_negative_{size}",
                    byte_count=_CONTROLLED_SIZE_BYTES[size],
                    record_counts=(0,) * _CONTROLLED_DOCUMENTS,
                    hit_tokens=(),
                ),
            )
        )
    return tuple(sorted(fixtures, key=lambda item: item.id))


def _evaluated_composition(evaluated_bank: Mapping[str, Any]) -> tuple[_TaxonAllocation, ...]:
    try:
        taxonomy = evaluated_bank["composition"]["taxonomy"]
    except (KeyError, TypeError):
        raise EnronPerformanceFixtureError("Evaluated bank is missing its aggregate taxonomy composition.") from None
    if type(taxonomy) not in (list, tuple):
        raise EnronPerformanceFixtureError("Evaluated bank taxonomy must be an ordered sequence.")
    parsed: list[_TaxonAllocation] = []
    for item in taxonomy:
        if type(item) is not dict or set(item) != {
            "entity_class",
            "entities",
            "canonical_names",
            "aliases",
            "literal_patterns",
            "regex_patterns",
        }:
            raise EnronPerformanceFixtureError("Evaluated bank taxonomy rows have an invalid aggregate shape.")
        entity_class = item["entity_class"]
        if type(entity_class) is not str or entity_class not in _EXPECTED_ENTITY_CLASSES:
            raise EnronPerformanceFixtureError("Evaluated bank taxonomy must contain only contact and person classes.")
        counts = [item[field_name] for field_name in item if field_name != "entity_class"]
        if any(type(value) is not int or value < 0 for value in counts):
            raise EnronPerformanceFixtureError("Evaluated bank taxonomy counts must be nonnegative integers.")
        parsed.append(
            _TaxonAllocation(
                entity_class=entity_class,
                entities=item["entities"],
                canonical_names=item["canonical_names"],
                aliases=item["aliases"],
                literal_patterns=item["literal_patterns"],
                regex_patterns=item["regex_patterns"],
            )
        )
    parsed.sort(key=lambda item: item.entity_class)
    if tuple(item.entity_class for item in parsed) != _EXPECTED_ENTITY_CLASSES:
        raise EnronPerformanceFixtureError("Evaluated bank taxonomy must contain one contact row and one person row.")
    totals = {
        "active_entities": sum(item.entities for item in parsed),
        "active_names": sum(item.names for item in parsed),
        "active_aliases": sum(item.aliases for item in parsed),
        "active_patterns": sum(item.patterns for item in parsed),
    }
    if any(evaluated_bank.get(field_name) != value for field_name, value in totals.items()):
        raise EnronPerformanceFixtureError("Evaluated bank composition does not reconcile with its aggregate totals.")
    if (
        not 0 < totals["active_entities"] <= totals["active_patterns"]
        or not 0 < totals["active_names"] <= totals["active_patterns"]
        or totals["active_aliases"] > totals["active_names"]
        or any(item.patterns == 0 or item.entities == 0 or item.names == 0 for item in parsed)
    ):
        raise EnronPerformanceFixtureError("Evaluated bank composition cannot be represented by native matcher rows.")
    return tuple(parsed)


def _scale_composition(active_patterns: int, evaluated: Sequence[_TaxonAllocation]) -> tuple[_TaxonAllocation, ...]:
    evaluated_patterns = sum(item.patterns for item in evaluated)
    evaluated_names = sum(item.names for item in evaluated)
    evaluated_aliases = sum(item.aliases for item in evaluated)
    evaluated_regex = sum(item.regex_patterns for item in evaluated)

    active_names = _scaled_count(active_patterns, evaluated_names, evaluated_patterns)
    active_aliases = _scaled_count(active_names, evaluated_aliases, evaluated_names)
    regex_patterns = _scaled_count(active_patterns, evaluated_regex, evaluated_patterns)
    aliases = _largest_remainder(active_aliases, [item.aliases for item in evaluated])
    canonical_names = _largest_remainder(active_names - active_aliases, [item.canonical_names for item in evaluated])
    regexes = _largest_remainder(regex_patterns, [item.regex_patterns for item in evaluated])
    literals = _largest_remainder(active_patterns - regex_patterns, [item.literal_patterns for item in evaluated])
    patterns_by_taxon = [literal + regex for literal, regex in zip(literals, regexes, strict=True)]
    minimum_entities = [
        (pattern_count + _MAX_PATTERNS_PER_ENTITY - 1) // _MAX_PATTERNS_PER_ENTITY if pattern_count else 0
        for pattern_count in patterns_by_taxon
    ]
    entities = [
        min(
            pattern_count,
            max(minimum_entities[index], _scaled_count(active_patterns, item.entities, evaluated_patterns)),
        )
        for index, (item, pattern_count) in enumerate(zip(evaluated, patterns_by_taxon, strict=True))
    ]

    result = tuple(
        _TaxonAllocation(
            entity_class=item.entity_class,
            entities=entities[index],
            canonical_names=canonical_names[index],
            aliases=aliases[index],
            literal_patterns=literals[index],
            regex_patterns=regexes[index],
        )
        for index, item in enumerate(evaluated)
    )
    if any(
        (item.patterns == 0 and (item.entities != 0 or item.names != 0))
        or (item.patterns > 0 and (item.entities == 0 or item.names == 0 or item.names > item.patterns))
        for item in result
    ):
        raise EnronPerformanceFixtureError("Scaled catalog names cannot be assigned truthfully to matcher rows.")
    if any(
        item.entities > item.patterns
        or (item.entities > 0 and (item.patterns + item.entities - 1) // item.entities > _MAX_PATTERNS_PER_ENTITY)
        for item in result
    ):
        raise EnronPerformanceFixtureError("Scaled entity sharding exceeds the native per-entity pattern limit.")
    return result


def _native_jsonl_source(
    allocation: Sequence[_TaxonAllocation], active_patterns: int
) -> tuple[bytes, int, tuple[bytes, ...]]:
    output = bytearray()
    pattern_bytes = 0
    hit_tokens: list[bytes] = []
    row_count = 0
    for taxon_index, taxon in enumerate(allocation):
        name_slots = [
            (f"NERB_PERF_T{taxon_index:03d}_C{name_index:06d}", False) for name_index in range(taxon.canonical_names)
        ]
        name_slots.extend(
            (f"NERB_PERF_T{taxon_index:03d}_A{name_index:06d}", True) for name_index in range(taxon.aliases)
        )
        for pattern_index in range(taxon.patterns):
            surface_name, is_alias = name_slots[pattern_index % len(name_slots)]
            match_text = f"NERB{taxon_index}{pattern_index:05d}"
            is_literal = pattern_index < taxon.literal_patterns
            regex = match_text if is_literal else _residual_regex(match_text)
            canonical_name = f"NERB_PERF_T{taxon_index:03d}_ALIAS_TARGET" if is_alias else surface_name
            entity_index = pattern_index % taxon.entities
            row = {
                "canonical_name": canonical_name,
                "entity": f"nerb_perf_t{taxon_index:03d}_s{entity_index:04d}",
                "regex": regex,
                "surface_name": surface_name,
            }
            encoded = _canonical_payload(row) + b"\n"
            output.extend(encoded)
            pattern_bytes += len(regex.encode("utf-8"))
            row_count += 1
            if len(hit_tokens) < 3:
                hit_tokens.append(match_text.encode("ascii"))
    if row_count != active_patterns or len(hit_tokens) != 3:
        raise EnronPerformanceFixtureError("Synthetic native bank row allocation did not reconcile.")
    return bytes(output), pattern_bytes, tuple(hit_tokens)


def _residual_regex(match_text: str) -> str:
    """Return a nonempty multi-string regex that still matches ``match_text``.

    Grouping an exact token is normalized to literal HIR by the native engine,
    so it does not exercise the residual-regex layer.  Generalizing the final
    decimal digit to a two-member class preserves every controlled hit while
    guaranteeing that the parsed HIR contains a class rather than only literal
    nodes.  The alternate is synthetic and cannot resemble corpus PII.
    """

    final = match_text[-1:]
    if len(match_text) < 2 or final not in "0123456789":
        raise EnronPerformanceFixtureError("Synthetic residual-regex token has an invalid shape.")
    return f"{match_text[:-1]}[{final}X]"


def _scale_bank_family(
    fixtures: Sequence[EnronPerformanceBankFixture],
) -> dict[int, EnronPerformanceBankFixture]:
    if type(fixtures) not in (list, tuple):
        raise EnronPerformanceFixtureError("Scale bank fixtures must be an ordered sequence.")
    result: dict[int, EnronPerformanceBankFixture] = {}
    for fixture in fixtures:
        if not isinstance(fixture, EnronPerformanceBankFixture):
            raise EnronPerformanceFixtureError("Scale bank fixture sequence contains an invalid item.")
        descriptor = fixture.descriptor
        active_patterns = descriptor.get("active_patterns")
        if type(active_patterns) is not int or active_patterns in result:
            raise EnronPerformanceFixtureError("Scale bank fixtures contain an invalid or duplicate pattern count.")
        if descriptor.get("id") != fixture.id or descriptor.get("bank_hash") != fixture.bank_hash:
            raise EnronPerformanceFixtureError("Scale bank fixture descriptor does not bind its immutable artifacts.")
        result[active_patterns] = fixture
    if set(result) != set(PERFORMANCE_SCALE_PATTERNS):
        raise EnronPerformanceFixtureError("Controlled inputs require the complete frozen matcher-scale family.")
    return result


def _make_input_payload(
    *, artifact_stem: str, byte_count: int, record_counts: Sequence[int], hit_tokens: Sequence[bytes]
) -> _InputPayload:
    if len(record_counts) != _CONTROLLED_DOCUMENTS:
        raise EnronPerformanceFixtureError("Controlled input record plan has an invalid document count.")
    if len(hit_tokens) < max(record_counts, default=0):
        raise EnronPerformanceFixtureError("Controlled input record plan exceeds the available safe matcher tokens.")
    documents = tuple(
        _controlled_document(byte_count, tuple(hit_tokens[:record_count])) for record_count in record_counts
    )
    inventory_rows = tuple(
        EnronPerformanceInventoryRow(byte_count=len(document), record_count=record_count)
        for document, record_count in zip(documents, record_counts, strict=True)
    )
    artifact_bytes = b"".join(documents)
    inventory_bytes = _canonical_payload([row.to_dict() for row in inventory_rows])
    return _InputPayload(
        artifact_id=f"{artifact_stem}_documents",
        artifact_filename=f"inputs/{artifact_stem}.raw",
        inventory_id=f"{artifact_stem}_inventory",
        inventory_filename=f"inputs/{artifact_stem}.inventory.json",
        artifact_bytes=artifact_bytes,
        inventory_bytes=inventory_bytes,
        documents=documents,
        inventory_rows=inventory_rows,
    )


def _controlled_document(byte_count: int, hit_tokens: Sequence[bytes]) -> bytes:
    prefix = b" ".join(hit_tokens)
    if prefix:
        prefix += b" "
    if len(prefix) > byte_count:
        raise EnronPerformanceFixtureError("Controlled document is too small for its safe matcher plan.")
    remaining = byte_count - len(prefix)
    repeats = (remaining + len(_SAFE_PADDING) - 1) // len(_SAFE_PADDING)
    document = prefix + (_SAFE_PADDING * repeats)[:remaining]
    try:
        document.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise EnronPerformanceFixtureError("Controlled document generator produced invalid UTF-8.") from error
    return document


def _bind_input_fixture(
    *, identifier: str, bank: EnronPerformanceBankFixture, payload: _InputPayload
) -> EnronPerformanceInputFixture:
    inventory = [row.to_dict() for row in payload.inventory_rows]
    if _canonical_payload(inventory) != payload.inventory_bytes:
        raise EnronPerformanceFixtureError("Controlled input inventory bytes are not canonical.")
    summary = summarize_enron_performance_inventory(inventory)
    artifact_sha256 = _sha256(payload.artifact_bytes)
    inventory_sha256 = hash_enron_performance_inventory(inventory)
    if inventory_sha256 != _sha256(payload.inventory_bytes):
        raise EnronPerformanceFixtureError("Controlled input inventory hash did not reconcile.")
    descriptor: dict[str, Any] = {
        "id": identifier,
        "kind": "synthetic_input",
        "bank_id": bank.id,
        "bank_hash": bank.bank_hash,
        "artifact": {
            "id": payload.artifact_id,
            "sha256": artifact_sha256,
            "bytes": len(payload.artifact_bytes),
        },
        "inventory_ref": {
            "id": payload.inventory_id,
            "sha256": inventory_sha256,
            "bytes": len(payload.inventory_bytes),
        },
        "generator": {
            "id": _INPUT_GENERATOR_ID,
            "version": _GENERATOR_VERSION,
            "source_sha256": _generator_source_sha256(),
            "spec_sha256": _canonical_sha256(_INPUT_SPEC),
            "seed": _GENERATOR_SEED,
        },
        **summary,
        "descriptor_sha256": "",
    }
    descriptor["descriptor_sha256"] = hash_enron_performance_input(descriptor)
    if descriptor["bytes"] != len(payload.artifact_bytes):
        raise EnronPerformanceFixtureError("Controlled input inventory does not reconcile with its raw byte artifact.")
    return EnronPerformanceInputFixture(
        id=identifier,
        artifact_id=payload.artifact_id,
        artifact_filename=payload.artifact_filename,
        inventory_id=payload.inventory_id,
        inventory_filename=payload.inventory_filename,
        artifact_bytes=payload.artifact_bytes,
        inventory_bytes=payload.inventory_bytes,
        documents=payload.documents,
        inventory_rows=payload.inventory_rows,
        descriptor_bytes=_canonical_payload(descriptor),
    )


def _scaled_count(target: int, numerator: int, denominator: int) -> int:
    if denominator <= 0 or numerator < 0 or numerator > denominator:
        raise EnronPerformanceFixtureError("Aggregate composition ratio is outside supported bounds.")
    quotient, remainder = divmod(target * numerator, denominator)
    return quotient + int(remainder * 2 >= denominator)


def _largest_remainder(total: int, weights: Sequence[int]) -> list[int]:
    if total < 0 or not weights or any(type(weight) is not int or weight < 0 for weight in weights):
        raise EnronPerformanceFixtureError("Largest-remainder allocation received invalid aggregate counts.")
    weight_total = sum(weights)
    if total == 0:
        return [0] * len(weights)
    if weight_total == 0:
        raise EnronPerformanceFixtureError("Positive aggregate allocation requires positive source support.")
    floors = [(total * weight) // weight_total for weight in weights]
    remainders = [(total * weight) % weight_total for weight in weights]
    for index in sorted(range(len(weights)), key=lambda item: (-remainders[item], item))[: total - sum(floors)]:
        floors[index] += 1
    return floors


def _canonical_payload(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _canonical_sha256(value: Any) -> str:
    return _sha256(_canonical_payload(value))


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _generator_source_sha256() -> str:
    try:
        return _sha256(Path(__file__).read_bytes())
    except OSError as error:
        raise EnronPerformanceFixtureError("Performance fixture generator source cannot be fingerprinted.") from error


def _decode_object(value: bytes) -> dict[str, Any]:
    decoded = json.loads(value)
    if type(decoded) is not dict:
        raise EnronPerformanceFixtureError("Immutable fixture descriptor is not a JSON object.")
    return cast(dict[str, Any], decoded)
