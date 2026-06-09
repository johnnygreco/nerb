from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Sequence
from typing import Any

BANK_TIMESTAMP = "2026-06-09T00:00:00Z"


def build_enron_entity_bank(
    address_counts: Counter[str],
    domain_counts: Counter[str],
    *,
    max_addresses: int = 5_000,
    max_domains: int = 500,
    min_address_count: int = 2,
    min_domain_count: int = 2,
    created_at: str = BANK_TIMESTAMP,
) -> dict[str, Any]:
    addresses = _top_items(address_counts, max_items=max_addresses, min_count=min_address_count)
    domains = _top_items(domain_counts, max_items=max_domains, min_count=min_domain_count)
    entities: dict[str, Any] = {}
    if addresses:
        entities["email_address"] = _literal_entity(
            "Email addresses mined from training-set message headers and bodies.",
            addresses,
            pattern_description="Exact email address literal.",
        )
    if domains:
        entities["email_domain"] = _literal_entity(
            "Email domains mined from training-set message headers and bodies.",
            domains,
            pattern_description="Exact email domain literal.",
        )
    if not entities:
        raise ValueError("Cannot build Enron entity bank because no eligible addresses or domains were mined.")

    return {
        "schema_version": "nerb.bank.v1",
        "id": "enron_corpus_entities",
        "name": "Enron Corpus Entities",
        "description": "Deterministic entity bank mined from the Enron email training split for NERB benchmarking.",
        "version": "2026.06.09",
        "status": "active",
        "created_at": created_at,
        "updated_at": created_at,
        "unicode_normalization": "none",
        "default_regex_flags": ["IGNORECASE"],
        "entities": entities,
        "metadata": {
            "source": "nerb.enron_bank_builder.build_enron_entity_bank",
            "address_candidates": len(addresses),
            "domain_candidates": len(domains),
            "min_address_count": min_address_count,
            "min_domain_count": min_domain_count,
        },
    }


def _literal_entity(description: str, values: Sequence[str], *, pattern_description: str) -> dict[str, Any]:
    names: dict[str, Any] = {}
    for priority, value in enumerate(values):
        name_id = _id_from_value(value)
        names[name_id] = {
            "canonical": value,
            "description": "Corpus-mined literal.",
            "status": "active",
            "patterns": {
                "primary": {
                    "kind": "literal",
                    "value": value,
                    "description": pattern_description,
                    "status": "active",
                    "priority": priority,
                    "case_sensitive": False,
                    "normalize_whitespace": False,
                    "left_boundary": "none",
                    "right_boundary": "none",
                    "metadata": {},
                }
            },
            "metadata": {},
        }
    return {"description": description, "status": "active", "regex_flags": [], "names": names, "metadata": {}}


def _top_items(counts: Counter[str], *, max_items: int, min_count: int) -> list[str]:
    candidates = [item for item, count in counts.items() if count >= min_count]
    candidates.sort(key=lambda item: (-counts[item], item))
    return candidates[:max_items]


def _id_from_value(value: str) -> str:
    return "v_" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
