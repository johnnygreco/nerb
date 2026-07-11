"""Train-only construction of privacy-first Enron intelligence banks.

The v2 builder consumes only the sealed split workflow's development reader.
Candidate surfaces and the resulting real bank are private artifacts; public
results are aggregate cards and commitments.  Validation can choose among
predeclared policies, but validation surfaces are never eligible candidates.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import unicodedata
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, cast

from .bank import bank_stats, hash_bank
from .enron_quality import DEFAULT_MAX_QUALITY_PREDICTIONS_TOTAL

BANK_BUILD_POLICY_VERSION = "nerb.enron_bank_build_policy.v2"
CANDIDATE_SCHEMA_VERSION = "nerb.enron_bank_candidate.v2"
CANDIDATE_FUNNEL_SCHEMA_VERSION = "nerb.enron_candidate_funnel.v2"
BANK_CARD_SCHEMA_VERSION = "nerb.enron_bank_card.v2"
BANK_BUILD_MANIFEST_SCHEMA_VERSION = "nerb.enron_bank_build_manifest.v2"
BANK_BUILD_ITERATION_SCHEMA_VERSION = "nerb.enron_bank_build_iteration.v2"
BANK_BUILD_TIMESTAMP = "2026-07-10T00:00:00Z"

_SHA256_PREFIX = "sha256:"
_EMAIL_RE = re.compile(
    r"^[a-z0-9_][a-z0-9.!#$%&'*+/=?^_`{|}~-]*@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)
_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)
_NAME_TOKEN_RE = re.compile(r"[^\W\d_]+(?:['’-][^\W\d_]+)*", re.UNICODE)
_LOCAL_TOKEN_RE = re.compile(r"[a-z]+")
_ID_SAFE_RE = re.compile(r"^[a-z][a-z0-9_]{0,79}$")
_GENERIC_EMAIL_REGEX = (
    r"(?i)\b[a-z0-9_][a-z0-9.!#$%&'*+/=?^_`{|}~-]*@"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\b"
)
_GENERIC_PHONE_REGEX = (
    r"\b(?:1[ .-])?(?:[2-9][0-9]{2}[ .-][0-9]{3}[ .-][0-9]{4}|"
    r"[2-9][0-9]{2}\)[ .-]?[0-9]{3}[ .-][0-9]{4})"
    r"(?:[ ]*(?:x|ext[.]?)[ ]*[0-9]{1,6})?\b"
)
_ROLE_NAME_TOKENS = frozenset(
    {
        "admin",
        "administrator",
        "alerts",
        "billing",
        "desk",
        "distribution",
        "enron",
        "help",
        "helpdesk",
        "info",
        "mail",
        "marketing",
        "notifications",
        "office",
        "operations",
        "ops",
        "sales",
        "service",
        "support",
        "team",
        "trading",
    }
)


class EnronBankBuildError(ValueError):
    """Raised when a bank cannot be built without weakening the v2 contract."""


@dataclass(frozen=True, slots=True)
class EnronBankPolicy:
    """Frozen train-only curation thresholds and resource limits."""

    internal_domains: tuple[str, ...] = ("enron.com",)
    minimum_contact_groups: int = 2
    minimum_person_alias_groups: int = 2
    minimum_domain_groups: int = 2
    max_active_contacts: int = 500
    max_active_people: int = 500
    max_active_person_aliases: int = 500
    max_active_domains: int = 500
    max_draft_per_class: int = 2_000
    max_active_patterns: int = 25_000
    max_pattern_utf8_bytes: int = 5 * 1024 * 1024
    max_bank_json_bytes: int = 32 * 1024 * 1024
    max_train_records: int = 600_000
    max_train_artifact_bytes: int = 512 * 1024 * 1024
    max_validation_records: int = 10_000
    max_validation_artifact_bytes: int = 96 * 1024 * 1024
    max_validation_entries: int = 250_000
    max_validation_spans: int = 150_000
    max_validation_text_utf8_bytes: int = 64 * 1024 * 1024
    max_development_memberships_bytes: int = 48 * 1024 * 1024
    max_development_samples_bytes: int = 24 * 1024 * 1024
    max_quality_predictions: int = DEFAULT_MAX_QUALITY_PREDICTIONS_TOTAL
    max_header_entries_per_document: int = 8_192
    max_observations: int = 2_000_000
    max_unique_candidates: int = 50_000
    max_candidate_value_bytes: int = 4_096

    def descriptor(self) -> dict[str, Any]:
        return {
            "schema_version": BANK_BUILD_POLICY_VERSION,
            "identity_anchor": "normalized_structured_header_address",
            "support_unit": "distinct_train_leakage_group",
            "candidate_source": "train_structured_headers_plus_sender_body_confirmed_local_parts",
            "validation_source": "validation_structured_headers_only_no_literal_promotion",
            "person_alias_policy": (
                "recurring_match_distinct_observed_surface_unique_address_owner_exact_normalized_full_identity_"
                "local_part_compatible_resolvable_contact_anchor_no_unobserved_aliases"
            ),
            "contact_policy": "recurring_valid_exact_address",
            "organization_policy": "recurring_exact_at_domain_surface",
            "generic_email_policy": "bounded_rust_regex_lowest_contact_priority",
            "generic_phone_policy": "draft_without_independent_negative_evidence",
            "identity_normalization": "NFKC_casefold_name_tokens_with_last_first_reordering",
            "person_pattern_equivalence": "unicode_simple_casefold_collapsed_whitespace_without_reordering",
            "internal_domains": list(self.internal_domains),
            "thresholds": {
                "minimum_contact_groups": self.minimum_contact_groups,
                "minimum_person_alias_groups": self.minimum_person_alias_groups,
                "minimum_domain_groups": self.minimum_domain_groups,
            },
            "capacity": {
                "max_active_contacts": self.max_active_contacts,
                "max_active_people": self.max_active_people,
                "max_active_person_aliases": self.max_active_person_aliases,
                "max_active_domains": self.max_active_domains,
                "max_draft_per_class": self.max_draft_per_class,
                "max_active_patterns": self.max_active_patterns,
                "max_pattern_utf8_bytes": self.max_pattern_utf8_bytes,
                "max_bank_json_bytes": self.max_bank_json_bytes,
                "max_train_records": self.max_train_records,
                "max_train_artifact_bytes": self.max_train_artifact_bytes,
                "max_validation_records": self.max_validation_records,
                "max_validation_artifact_bytes": self.max_validation_artifact_bytes,
                "max_validation_entries": self.max_validation_entries,
                "max_validation_spans": self.max_validation_spans,
                "max_validation_text_utf8_bytes": self.max_validation_text_utf8_bytes,
                "max_development_memberships_bytes": self.max_development_memberships_bytes,
                "max_development_samples_bytes": self.max_development_samples_bytes,
                "max_quality_predictions": self.max_quality_predictions,
                "max_header_entries_per_document": self.max_header_entries_per_document,
                "max_observations": self.max_observations,
                "max_unique_candidates": self.max_unique_candidates,
                "max_candidate_value_bytes": self.max_candidate_value_bytes,
            },
        }

    @property
    def sha256(self) -> str:
        return _canonical_hash(self.descriptor())


@dataclass(frozen=True, slots=True)
class CandidateEvidence:
    kind: Literal["contact", "person_alias", "organization_domain"]
    normalized_value: str
    surfaces: tuple[tuple[str, int], ...]
    related_counts: tuple[tuple[str, int], ...]
    source_types: tuple[tuple[str, int], ...]
    observation_count: int
    document_count: int
    leakage_group_count: int
    first_seen: str | None
    last_seen: str | None
    unknown_date_documents: int
    evidence_sha256: str

    @property
    def primary_surface(self) -> str:
        return min(self.surfaces, key=lambda item: (-item[1], item[0]))[0]

    @property
    def related_values(self) -> tuple[str, ...]:
        return tuple(value for value, _count in self.related_counts)


@dataclass(frozen=True, slots=True)
class CandidatePool:
    contacts: tuple[CandidateEvidence, ...]
    person_aliases: tuple[CandidateEvidence, ...]
    organization_domains: tuple[CandidateEvidence, ...]
    train_records: int
    observations: int
    source_sha256: str
    ledger_sha256: str


@dataclass(frozen=True, slots=True)
class IterationPolicy:
    id: str
    parent_id: str | None
    activate_generic_email: bool
    activate_phone: bool
    selection_intent: str

    @property
    def sha256(self) -> str:
        return _canonical_hash(
            {
                "schema_version": BANK_BUILD_ITERATION_SCHEMA_VERSION,
                "id": self.id,
                "parent_id": self.parent_id,
                "activate_generic_email": self.activate_generic_email,
                "activate_phone": self.activate_phone,
                "selection_intent": self.selection_intent,
            }
        )


ITERATION_POLICIES = (
    IterationPolicy(
        id="iteration_01_catalog",
        parent_id=None,
        activate_generic_email=False,
        activate_phone=False,
        selection_intent="measure_recurring_catalog_without_unknown_format_fallbacks",
    ),
    IterationPolicy(
        id="iteration_02_email_recall",
        parent_id="iteration_01_catalog",
        activate_generic_email=True,
        activate_phone=False,
        selection_intent="cover_unknown_structured_email_with_bounded_low_precedence_fallback",
    ),
    IterationPolicy(
        id="iteration_03_phone_experiment",
        parent_id="iteration_02_email_recall",
        activate_generic_email=True,
        activate_phone=True,
        selection_intent="test_broader_phone_fallback_without_promoting_unsupported_utility",
    ),
)


@dataclass(slots=True)
class _EvidenceAccumulator:
    kind: str
    normalized_value: str
    observation_count: int = 0
    documents: set[str] = field(default_factory=set)
    groups: set[str] = field(default_factory=set)
    surfaces: Counter[str] = field(default_factory=Counter)
    related: Counter[str] = field(default_factory=Counter)
    source_types: Counter[str] = field(default_factory=Counter)
    first_seen: str | None = None
    last_seen: str | None = None
    unknown_date_documents: set[str] = field(default_factory=set)
    digest: Any = field(default_factory=hashlib.sha256)

    def add(
        self,
        *,
        surface: str,
        related: str,
        source_type: str,
        document_id: str,
        group_id: str,
        observed_at: str | None,
        occurrences: int,
    ) -> None:
        self.observation_count += occurrences
        self.documents.add(document_id)
        self.groups.add(group_id)
        self.surfaces[surface] += occurrences
        if related:
            self.related[related] += occurrences
        self.source_types[source_type] += occurrences
        if observed_at is None:
            self.unknown_date_documents.add(document_id)
        else:
            self.first_seen = (
                observed_at if self.first_seen is None or observed_at < self.first_seen else self.first_seen
            )
            self.last_seen = observed_at if self.last_seen is None or observed_at > self.last_seen else self.last_seen
        self.digest.update(
            _canonical_json_bytes(
                {
                    "document_id": document_id,
                    "group_id": group_id,
                    "observed_at": observed_at,
                    "occurrences": occurrences,
                    "related": related,
                    "surface": surface,
                    "source_type": source_type,
                }
            )
        )

    def finish(self) -> CandidateEvidence:
        return CandidateEvidence(
            kind=cast(Any, self.kind),
            normalized_value=self.normalized_value,
            surfaces=tuple(sorted(self.surfaces.items())),
            related_counts=tuple(sorted(self.related.items())),
            source_types=tuple(sorted(self.source_types.items())),
            observation_count=self.observation_count,
            document_count=len(self.documents),
            leakage_group_count=len(self.groups),
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            unknown_date_documents=len(self.unknown_date_documents),
            evidence_sha256=_SHA256_PREFIX + self.digest.hexdigest(),
        )


def mine_enron_candidates(
    records_and_memberships: Iterable[tuple[Mapping[str, Any], Mapping[str, Any]]],
    *,
    sqlite_path: Path,
    train_artifact_sha256: str,
    policy: EnronBankPolicy,
) -> CandidatePool:
    """Stream verified train records into a bounded private SQLite spool."""

    _validate_policy(policy)
    sqlite_path = Path(sqlite_path)
    try:
        connection = sqlite3.connect(sqlite_path)
    except sqlite3.Error:
        raise EnronBankBuildError("Candidate mining spool could not be opened safely.") from None
    records = 0
    observations = 0
    unique_candidates = 0
    try:
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA temp_store=FILE")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            """
            CREATE TABLE candidate_values (
                kind TEXT NOT NULL,
                normalized_value TEXT NOT NULL,
                PRIMARY KEY (kind, normalized_value)
            ) WITHOUT ROWID
            """
        )
        connection.execute(
            """
            CREATE TABLE observations (
                kind TEXT NOT NULL,
                normalized_value TEXT NOT NULL,
                surface TEXT NOT NULL,
                related TEXT NOT NULL,
                source_type TEXT NOT NULL,
                document_id TEXT NOT NULL,
                group_id TEXT NOT NULL,
                observed_at TEXT,
                occurrences INTEGER NOT NULL,
                PRIMARY KEY (kind, normalized_value, surface, related, source_type, document_id)
            ) WITHOUT ROWID
            """
        )
        connection.execute(
            """
            CREATE TABLE source_projections (
                document_id TEXT NOT NULL PRIMARY KEY,
                payload BLOB NOT NULL
            ) WITHOUT ROWID
            """
        )
        connection.execute("BEGIN IMMEDIATE")
        for record, membership in records_and_memberships:
            records += 1
            if records > policy.max_train_records:
                raise EnronBankBuildError("Train record count exceeds the bank-build limit.")
            document_id, group_id, observed_at, entries, body_aliases = _train_record_projection(
                record, membership, policy
            )
            source_projection = _canonical_json_bytes(
                {
                    "document_id": document_id,
                    "group_id": group_id,
                    "observed_at": observed_at,
                    "structured_entries": len(entries),
                    "sender_body_aliases": len(body_aliases),
                }
            )
            try:
                connection.execute(
                    "INSERT INTO source_projections(document_id, payload) VALUES (?, ?)",
                    (document_id, source_projection),
                )
            except sqlite3.IntegrityError:
                raise EnronBankBuildError("Train split contains a duplicate document identifier.") from None
            projected: list[tuple[str, str, str, str, str]] = []
            for _field_name, name, address in entries:
                normalized_address = _normalize_email(address)
                if normalized_address:
                    projected.append(("contact", normalized_address, normalized_address, "", "structured_header"))
                    domain = normalized_address.rsplit("@", 1)[1]
                    projected.append(("organization_domain", domain, domain, "", "structured_header"))
                person_surface = _person_literal_surface(name)
                normalized_name = _normalize_person_name(person_surface)
                if normalized_name and normalized_address:
                    projected.append(
                        (
                            "person_alias",
                            _person_literal_catalog_key(person_surface),
                            person_surface,
                            normalized_address,
                            "structured_display_name",
                        )
                    )
            for name, address in body_aliases:
                person_surface = _person_literal_surface(name)
                normalized_name = _normalize_person_name(person_surface)
                normalized_address = _normalize_email(address)
                if normalized_name and normalized_address:
                    projected.append(
                        (
                            "person_alias",
                            _person_literal_catalog_key(person_surface),
                            person_surface,
                            normalized_address,
                            "sender_body_local_link",
                        )
                    )
            for kind, normalized_value, surface, related, source_type in projected:
                observations += 1
                if observations > policy.max_observations:
                    raise EnronBankBuildError("Candidate observations exceed the bank-build limit.")
                if max(len(value.encode("utf-8")) for value in (normalized_value, surface, related)) > (
                    policy.max_candidate_value_bytes
                ):
                    raise EnronBankBuildError("Candidate value exceeds the bank-build byte limit.")
                cursor = connection.execute(
                    "INSERT OR IGNORE INTO candidate_values(kind, normalized_value) VALUES (?, ?)",
                    (kind, normalized_value),
                )
                if cursor.rowcount:
                    unique_candidates += 1
                    if unique_candidates > policy.max_unique_candidates:
                        raise EnronBankBuildError("Unique candidates exceed the bank-build limit.")
                connection.execute(
                    """
                    INSERT INTO observations(
                        kind, normalized_value, surface, related, source_type,
                        document_id, group_id, observed_at, occurrences
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
                    ON CONFLICT(kind, normalized_value, surface, related, source_type, document_id)
                    DO UPDATE SET occurrences = occurrences + 1
                    """,
                    (kind, normalized_value, surface, related, source_type, document_id, group_id, observed_at),
                )
            if records % 10_000 == 0:
                connection.commit()
                connection.execute("BEGIN IMMEDIATE")
        connection.commit()
        if records == 0:
            raise EnronBankBuildError("Train split is empty.")

        candidates = _read_candidate_evidence(connection)
        source_digest = hashlib.sha256(b"nerb/enron/bank-mining-source/v2\0")
        for (payload,) in connection.execute("SELECT payload FROM source_projections ORDER BY document_id"):
            source_digest.update(bytes(payload))
        ledger_sha256 = _candidate_pool_hash(candidates, train_artifact_sha256, policy.sha256)
        by_kind: dict[str, list[CandidateEvidence]] = defaultdict(list)
        for candidate in candidates:
            by_kind[candidate.kind].append(candidate)
        return CandidatePool(
            contacts=tuple(by_kind["contact"]),
            person_aliases=tuple(by_kind["person_alias"]),
            organization_domains=tuple(by_kind["organization_domain"]),
            train_records=records,
            observations=observations,
            source_sha256=_SHA256_PREFIX + source_digest.hexdigest(),
            ledger_sha256=ledger_sha256,
        )
    except (sqlite3.Error, UnicodeError) as exc:
        connection.rollback()
        if isinstance(exc, EnronBankBuildError):
            raise
        raise EnronBankBuildError("Candidate mining failed safely.") from None
    finally:
        connection.close()


def _read_candidate_evidence(connection: sqlite3.Connection) -> tuple[CandidateEvidence, ...]:
    query = connection.execute(
        """
        SELECT kind, normalized_value, surface, related, source_type,
               document_id, group_id, observed_at, occurrences
        FROM observations
        ORDER BY kind, normalized_value, surface, related, source_type, document_id
        """
    )
    finished: list[CandidateEvidence] = []
    current: _EvidenceAccumulator | None = None
    current_key: tuple[str, str] | None = None
    for kind, normalized_value, surface, related, source_type, document_id, group_id, observed_at, occurrences in query:
        key = (str(kind), str(normalized_value))
        if current_key != key:
            if current is not None:
                finished.append(current.finish())
            current = _EvidenceAccumulator(kind=key[0], normalized_value=key[1])
            current_key = key
        assert current is not None
        current.add(
            surface=str(surface),
            related=str(related),
            source_type=str(source_type),
            document_id=str(document_id),
            group_id=str(group_id),
            observed_at=None if observed_at is None else str(observed_at),
            occurrences=int(occurrences),
        )
    if current is not None:
        finished.append(current.finish())
    return tuple(finished)


def _train_record_projection(
    record: Mapping[str, Any], membership: Mapping[str, Any], policy: EnronBankPolicy
) -> tuple[
    str,
    str,
    str | None,
    tuple[tuple[str, str, str], ...],
    tuple[tuple[str, str], ...],
]:
    document_id = record.get("document_id")
    membership_document_id = membership.get("document_id")
    group_id = membership.get("group_id")
    if (
        not isinstance(document_id, str)
        or document_id != membership_document_id
        or membership.get("role") != "train"
        or not isinstance(group_id, str)
    ):
        raise EnronBankBuildError("Train records and memberships are not aligned.")
    date = record.get("date")
    observed_at = date.get("utc") if isinstance(date, Mapping) and isinstance(date.get("utc"), str) else None
    headers = record.get("headers")
    if not isinstance(headers, Mapping):
        raise EnronBankBuildError("Train record headers are invalid.")
    entries: list[tuple[str, str, str]] = []
    for field_name in ("from", "to", "cc", "bcc"):
        field_entries = headers.get(field_name)
        if not isinstance(field_entries, list):
            raise EnronBankBuildError("Train structured header field is invalid.")
        for entry in field_entries:
            if (
                not isinstance(entry, Mapping)
                or not isinstance(entry.get("name"), str)
                or not isinstance(entry.get("address"), str)
            ):
                raise EnronBankBuildError("Train structured header entry is invalid.")
            entries.append((field_name, str(entry["name"]), str(entry["address"])))
            if len(entries) > policy.max_header_entries_per_document:
                raise EnronBankBuildError("Train structured header count exceeds the bank-build limit.")
    body_aliases = _sender_body_aliases(record, entries)
    return document_id, group_id, observed_at, tuple(entries), body_aliases


def _sender_body_aliases(
    record: Mapping[str, Any],
    entries: Sequence[tuple[str, str, str]],
) -> tuple[tuple[str, str], ...]:
    views = record.get("views")
    current_body = views.get("current_body") if isinstance(views, Mapping) else None
    if not isinstance(current_body, str) or not current_body:
        return ()
    tail = "\n".join(current_body[-8_192:].splitlines()[-12:])
    aliases: set[tuple[str, str]] = set()
    for field_name, display_name, address in entries:
        if field_name != "from" or display_name.strip():
            continue
        normalized_address = _normalize_email(address)
        if normalized_address is None:
            continue
        candidate = _local_part_person_name(normalized_address)
        if candidate is None:
            continue
        tokens = candidate.split()
        expression = r"(?<!\w)" + r"\s+".join(re.escape(token) for token in tokens) + r"(?!\w)"
        match = re.search(expression, tail, flags=re.IGNORECASE)
        if match is not None:
            aliases.add((_person_literal_surface(match.group(0)), normalized_address))
    return tuple(sorted(aliases))


def _local_part_person_name(address: str) -> str | None:
    local = address.rsplit("@", 1)[0].split("+", 1)[0].casefold()
    tokens = tuple(token for token in re.split(r"[._-]+", local) if token)
    if (
        not 2 <= len(tokens) <= 4
        or any(not token.isascii() or not token.isalpha() or len(token) < 2 for token in tokens)
        or any(token in _ROLE_NAME_TOKENS for token in tokens)
    ):
        return None
    return " ".join(tokens)


def _candidate_pool_hash(
    candidates: Sequence[CandidateEvidence], train_artifact_sha256: str, policy_sha256: str
) -> str:
    digest = hashlib.sha256(b"nerb/enron/candidate-ledger/v2\0")
    digest.update(train_artifact_sha256.encode("ascii"))
    digest.update(policy_sha256.encode("ascii"))
    for candidate in candidates:
        digest.update(
            _canonical_json_bytes(
                {
                    "kind": candidate.kind,
                    "normalized_value": candidate.normalized_value,
                    "surfaces": candidate.surfaces,
                    "related_counts": candidate.related_counts,
                    "source_types": candidate.source_types,
                    "observation_count": candidate.observation_count,
                    "document_count": candidate.document_count,
                    "leakage_group_count": candidate.leakage_group_count,
                    "first_seen": candidate.first_seen,
                    "last_seen": candidate.last_seen,
                    "unknown_date_documents": candidate.unknown_date_documents,
                    "evidence_sha256": candidate.evidence_sha256,
                }
            )
        )
    return _SHA256_PREFIX + digest.hexdigest()


@dataclass(frozen=True, slots=True)
class CuratedIteration:
    iteration: IterationPolicy
    bank: dict[str, Any]
    candidates: tuple[dict[str, Any], ...]
    funnel: dict[str, Any]
    collisions: dict[str, Any]


@dataclass(slots=True)
class _CandidateLedger:
    """Accumulate an aggregate funnel without retaining private candidate rows."""

    retain_rows: bool
    rows: list[dict[str, Any]] = field(default_factory=list)
    decisions: Counter[str] = field(default_factory=Counter)
    types: dict[str, Counter[str]] = field(default_factory=lambda: defaultdict(Counter))
    reasons: Counter[str] = field(default_factory=Counter)
    total: int = 0

    def append(self, row: dict[str, Any]) -> None:
        decision = str(row["decision"])
        candidate_type = str(row["candidate_type"])
        reason = str(row["primary_reason_code"])
        self.total += 1
        self.decisions[decision] += 1
        self.types[candidate_type][decision] += 1
        self.reasons[reason] += 1
        if self.retain_rows:
            self.rows.append(row)

    def funnel(self) -> dict[str, Any]:
        return _candidate_funnel_from_counts(
            total=self.total,
            decisions=self.decisions,
            types=self.types,
            reasons=self.reasons,
        )


def curate_enron_iteration(
    pool: CandidatePool,
    *,
    policy: EnronBankPolicy,
    iteration: IterationPolicy,
    source_binding: Mapping[str, Any],
    created_at: str = BANK_BUILD_TIMESTAMP,
    retain_candidate_ledger: bool = True,
) -> CuratedIteration:
    """Create one deterministic bank candidate; optionally retain its private row ledger."""

    if iteration not in ITERATION_POLICIES:
        raise EnronBankBuildError("Unknown bank-build iteration policy.")
    if type(retain_candidate_ledger) is not bool:
        raise EnronBankBuildError("Candidate-ledger retention flag must be boolean.")
    _validate_policy(policy)
    policy_sha256 = policy.sha256
    candidate_rows = _CandidateLedger(retain_rows=retain_candidate_ledger)
    collision_counts: Counter[str] = Counter()
    entities: dict[str, Any] = {}

    fallback_reserve = int(iteration.activate_generic_email) + int(iteration.activate_phone)
    pattern_budget = policy.max_active_patterns - fallback_reserve
    if pattern_budget <= 0:
        raise EnronBankBuildError("Active-pattern limit leaves no room for catalog patterns.")

    contact_names: dict[str, Any] = {}
    retained_contact_values: set[str] = set()
    active_contact_patterns = 0
    draft_contacts = 0
    contacts_ranked = sorted(
        pool.contacts,
        key=lambda item: (-item.leakage_group_count, -item.document_count, item.normalized_value),
    )
    eligible_contact_values = {
        evidence.normalized_value
        for evidence in contacts_ranked
        if evidence.leakage_group_count >= policy.minimum_contact_groups
    }
    active_contact_values: set[str] = set()
    for evidence in contacts_ranked:
        if (
            evidence.leakage_group_count >= policy.minimum_contact_groups
            and active_contact_patterns < policy.max_active_contacts
            and active_contact_patterns < pattern_budget
        ):
            decision = "active"
            reason = "recurring_valid_contact"
            active_contact_patterns += 1
            active_contact_values.add(evidence.normalized_value)
        elif draft_contacts < policy.max_draft_per_class:
            decision = "draft"
            reason = (
                "insufficient_distinct_group_support"
                if evidence.leakage_group_count < policy.minimum_contact_groups
                else "active_pattern_capacity"
            )
            draft_contacts += 1
        else:
            decision = "rejected"
            reason = "draft_capacity"
        name_id = _opaque_id("contact", evidence.normalized_value)
        metadata = _evidence_metadata(
            evidence,
            policy_sha256=policy_sha256,
            source_binding=source_binding,
            review_status=decision,
            reason_code=reason,
            privacy_class="email_address",
            extra={"contact_scope": _contact_scope(evidence.normalized_value, policy)},
        )
        pattern_id = "exact_email"
        bank_ref = None
        if decision != "rejected":
            pattern = _literal_pattern(
                evidence.normalized_value,
                status=decision,
                priority=active_contact_patterns - 1 if decision == "active" else policy.max_active_patterns + 1,
                description="Observed structured-header email address.",
                normalize_whitespace=False,
                left_boundary="word",
                right_boundary="word",
                metadata=metadata,
            )
            contact_names[name_id] = {
                "canonical": evidence.primary_surface,
                "description": "Train-observed contact address.",
                "status": decision,
                "patterns": {pattern_id: pattern},
                "metadata": metadata,
            }
            retained_contact_values.add(evidence.normalized_value)
            bank_ref = {"entity_id": "contact", "name_id": name_id, "pattern_ids": [pattern_id]}
        candidate_rows.append(_candidate_row(evidence, decision, reason, bank_ref))

    fallback_status = "active" if iteration.activate_generic_email else "draft"
    fallback_reason = "bounded_structured_email_fallback" if iteration.activate_generic_email else "iteration_deferred"
    fallback_metadata = _fallback_metadata(
        policy_sha256,
        source_binding,
        privacy_class="email_address",
        review_status=fallback_status,
        reason_code=fallback_reason,
        evidence_scope="synthetic_adversarial_and_structured_weak",
    )
    contact_names["unknown_email_contact"] = {
        "canonical": "Unknown email contact",
        "description": "Generic unknown structured email fallback.",
        "status": fallback_status,
        "patterns": {
            "structured_email": _regex_pattern(
                _GENERIC_EMAIL_REGEX,
                status=fallback_status,
                priority=policy.max_active_patterns - 1,
                description="Bounded RFC-like email fallback for otherwise unknown contacts.",
                metadata=fallback_metadata,
            )
        },
        "metadata": fallback_metadata,
    }
    candidate_rows.append(
        _fallback_candidate_row(
            "contact_fallback",
            fallback_status,
            fallback_reason,
            {"entity_id": "contact", "name_id": "unknown_email_contact", "pattern_ids": ["structured_email"]},
        )
    )
    entities["contact"] = {
        "description": "Known contact addresses and a separately labeled unknown-email fallback.",
        "status": "active",
        "regex_flags": [],
        "names": contact_names,
        "metadata": {
            "charter_role": "structured_contact_discovery_and_canonical_address_identity",
            "label_source": "train_structured_headers",
            "unknown_fallback_evidence": "structured_weak_plus_synthetic_adversarial",
        },
    }

    person_identity_owners: dict[str, set[str]] = defaultdict(set)
    for evidence in pool.person_aliases:
        if len(evidence.related_values) == 1:
            identity_value = _person_identity_value(evidence)
            if identity_value is not None:
                person_identity_owners[identity_value].add(evidence.related_values[0])

    aliases_by_address: dict[str, list[CandidateEvidence]] = defaultdict(list)
    for evidence in pool.person_aliases:
        identity_value = _person_identity_value(evidence)
        if len(evidence.related_values) == 1 and identity_value is not None:
            if len(person_identity_owners[identity_value]) == 1:
                aliases_by_address[evidence.related_values[0]].append(evidence)
            else:
                collision_counts["person_alias_multiple_addresses"] += 1
                candidate_rows.append(
                    _candidate_row(evidence, "rejected", "ambiguous_address_ownership", bank_ref=None)
                )
        else:
            collision_counts["person_alias_multiple_addresses"] += 1
            candidate_rows.append(_candidate_row(evidence, "rejected", "ambiguous_address_ownership", bank_ref=None))

    person_names: dict[str, Any] = {}
    active_person_patterns = 0
    active_people = 0
    draft_person_patterns = 0
    person_priorities = {
        value: index + 20_000
        for index, value in enumerate(
            sorted(
                pool.person_aliases,
                key=lambda item: (-len(item.primary_surface), -item.leakage_group_count, item.normalized_value),
            )
        )
    }
    ranked_identities = sorted(
        aliases_by_address.items(),
        key=lambda item: (
            -sum(alias.leakage_group_count for alias in item[1]),
            item[0],
        ),
    )
    for address, aliases in ranked_identities:
        aliases = sorted(
            aliases,
            key=lambda item: (-item.leakage_group_count, -item.document_count, item.normalized_value),
        )
        recurring = [alias for alias in aliases if alias.leakage_group_count >= policy.minimum_person_alias_groups]
        anchors = [
            alias
            for alias in recurring
            if (identity_value := _person_identity_value(alias)) is not None
            and _name_matches_address(identity_value, address)
        ]
        compatible = (
            _compatible_person_aliases([anchors[0], *(alias for alias in recurring if alias is not anchors[0])])
            if anchors
            else []
        )
        if len(compatible) < len(recurring):
            collision_counts["person_alias_incompatible_same_address"] += len(recurring) - len(compatible)
        remaining_budget = min(
            pattern_budget - active_contact_patterns - active_person_patterns,
            policy.max_active_person_aliases - active_person_patterns,
        )
        can_activate_identity = (
            bool(compatible)
            and active_people < policy.max_active_people
            and remaining_budget > 0
            and address in eligible_contact_values
            and address in retained_contact_values
        )
        active_alias_values = (
            {alias.normalized_value for alias in compatible[: max(0, remaining_budget)]}
            if can_activate_identity
            else set()
        )
        if active_alias_values:
            active_people += 1
            active_person_patterns += len(active_alias_values)
        patterns_by_identity: dict[str, dict[str, Any]] = defaultdict(dict)
        decisions_by_identity: dict[str, list[str]] = defaultdict(list)
        retained_aliases_by_identity: dict[str, list[CandidateEvidence]] = defaultdict(list)
        for alias in aliases:
            identity_value = _person_identity_value(alias)
            if identity_value is None:
                raise EnronBankBuildError("A retained person alias has no unambiguous normalized full identity.")
            person_identity_key = f"{address}\n{identity_value}"
            name_id = _opaque_id("person", person_identity_key)
            if address not in retained_contact_values:
                decision = "rejected"
                reason = "contact_anchor_not_retained"
            elif alias.normalized_value in active_alias_values:
                decision = "active"
                reason = "recurring_unique_full_name_alias"
            elif draft_person_patterns < policy.max_draft_per_class:
                decision = "draft"
                draft_person_patterns += 1
                if alias.leakage_group_count < policy.minimum_person_alias_groups:
                    reason = "insufficient_distinct_group_support"
                elif alias not in compatible:
                    reason = (
                        "address_local_part_incompatible"
                        if identity_value is None or not _name_matches_address(identity_value, address)
                        else "incompatible_alias_set"
                    )
                elif not can_activate_identity:
                    reason = "identity_not_eligible"
                else:
                    reason = "active_pattern_capacity"
            else:
                decision = "rejected"
                reason = "draft_capacity"
            pattern_id = _opaque_id("alias", alias.normalized_value)
            bank_ref = None
            if decision == "rejected":
                collision_counts[
                    "person_contact_anchor_not_retained"
                    if reason == "contact_anchor_not_retained"
                    else "person_alias_draft_capacity"
                ] += 1
                candidate_rows.append(_candidate_row(alias, decision, reason, bank_ref=None))
                continue
            metadata = _evidence_metadata(
                alias,
                policy_sha256=policy_sha256,
                source_binding=source_binding,
                review_status=decision,
                reason_code=reason,
                privacy_class="person_name",
                extra={
                    "identity_ref": _opaque_id("identity", person_identity_key),
                    "contact_ref": _opaque_id("contact", address),
                    "contact_scope": _contact_scope(address, policy),
                },
            )
            patterns_by_identity[identity_value][pattern_id] = _literal_pattern(
                alias.primary_surface,
                status=decision,
                priority=person_priorities[alias],
                description="Observed recurring full-name alias.",
                normalize_whitespace=True,
                left_boundary="word",
                right_boundary="word",
                metadata=metadata,
            )
            bank_ref = {"entity_id": "person", "name_id": name_id, "pattern_ids": [pattern_id]}
            candidate_rows.append(
                _candidate_row(
                    alias,
                    decision,
                    reason,
                    bank_ref,
                )
            )
            decisions_by_identity[identity_value].append(decision)
            retained_aliases_by_identity[identity_value].append(alias)
        for identity_value in sorted(retained_aliases_by_identity):
            retained_aliases = retained_aliases_by_identity[identity_value]
            patterns = patterns_by_identity[identity_value]
            name_status = "active" if "active" in decisions_by_identity[identity_value] else "draft"
            canonical_alias = next(
                (alias for alias in retained_aliases if alias.normalized_value in active_alias_values),
                retained_aliases[0],
            )
            person_identity_key = f"{address}\n{identity_value}"
            name_metadata = _evidence_metadata(
                canonical_alias,
                policy_sha256=policy_sha256,
                source_binding=source_binding,
                review_status=name_status,
                reason_code=("recurring_unique_identity" if name_status == "active" else "identity_not_eligible"),
                privacy_class="person_name",
                extra={
                    "identity_ref": _opaque_id("identity", person_identity_key),
                    "contact_ref": _opaque_id("contact", address),
                    "contact_scope": _contact_scope(address, policy),
                    "alias_count": len(patterns),
                    "active_alias_count": sum(
                        alias.normalized_value in active_alias_values for alias in retained_aliases
                    ),
                    "evidence_scope": "canonical_alias_only",
                    "identity_aggregate_counts_supported": False,
                },
            )
            person_names[_opaque_id("person", person_identity_key)] = {
                "canonical": canonical_alias.primary_surface,
                "description": "Address-anchored train-observed person identity.",
                "status": name_status,
                "patterns": patterns,
                "metadata": name_metadata,
            }

    if not person_names:
        placeholder_metadata = _fallback_metadata(
            policy_sha256,
            source_binding,
            privacy_class="person_name",
            review_status="draft",
            reason_code="no_eligible_person_aliases",
            evidence_scope="train_structured_headers",
        )
        person_names["unresolved_person"] = {
            "canonical": "Unresolved person",
            "description": "Draft placeholder; no source surface is active.",
            "status": "draft",
            "patterns": {
                "unresolved": _literal_pattern(
                    "NERB_UNRESOLVED_PERSON_PLACEHOLDER",
                    status="draft",
                    priority=policy.max_active_patterns + 2,
                    description="Inactive structural placeholder.",
                    normalize_whitespace=False,
                    left_boundary="word",
                    right_boundary="word",
                    metadata=placeholder_metadata,
                )
            },
            "metadata": placeholder_metadata,
        }
    entities["person"] = {
        "description": "Address-anchored people with recurring collision-free full-name aliases.",
        "status": "active" if active_person_patterns else "draft",
        "regex_flags": [],
        "names": person_names,
        "metadata": {
            "charter_role": "canonical_person_identity_and_observed_full_name_aliases",
            "label_source": "train_structured_display_names_and_sender_body_confirmed_local_parts",
            "first_name_aliases": "prohibited",
        },
    }

    domain_names: dict[str, Any] = {}
    draft_domains = 0
    for evidence in sorted(
        pool.organization_domains,
        key=lambda item: (-item.leakage_group_count, -item.document_count, item.normalized_value),
    ):
        if draft_domains >= policy.max_draft_per_class:
            candidate_rows.append(_candidate_row(evidence, "rejected", "draft_capacity", bank_ref=None))
            continue
        draft_domains += 1
        collision_counts["domain_exact_boundary_unavailable"] += 1
        reason = "exact_domain_boundary_not_expressible"
        name_id = _opaque_id("domain", evidence.normalized_value)
        metadata = _evidence_metadata(
            evidence,
            policy_sha256=policy_sha256,
            source_binding=source_binding,
            review_status="draft",
            reason_code=reason,
            privacy_class="organization_domain",
            extra={"affiliation": _domain_affiliation(evidence.normalized_value, policy)},
        )
        pattern_id = "at_domain"
        domain_names[name_id] = {
            "canonical": evidence.primary_surface,
            "description": "Train-observed organization domain awaiting exact-boundary support.",
            "status": "draft",
            "patterns": {
                pattern_id: _literal_pattern(
                    "@" + evidence.normalized_value,
                    status="draft",
                    priority=policy.max_active_patterns + 3,
                    description="Draft full-domain contact suffix.",
                    normalize_whitespace=False,
                    left_boundary="none",
                    right_boundary="word",
                    metadata=metadata,
                )
            },
            "metadata": metadata,
        }
        candidate_rows.append(
            _candidate_row(
                evidence,
                "draft",
                reason,
                {"entity_id": "organization_domain", "name_id": name_id, "pattern_ids": [pattern_id]},
            )
        )
    if not domain_names:
        placeholder_metadata = _fallback_metadata(
            policy_sha256,
            source_binding,
            privacy_class="organization_domain",
            review_status="draft",
            reason_code="no_domain_candidates",
            evidence_scope="train_structured_headers",
        )
        domain_names["unresolved_domain"] = {
            "canonical": "Unresolved organization domain",
            "description": "Draft placeholder; no source surface is active.",
            "status": "draft",
            "patterns": {
                "unresolved": _literal_pattern(
                    "@nerb-unresolved-domain.invalid",
                    status="draft",
                    priority=policy.max_active_patterns + 4,
                    description="Inactive structural placeholder.",
                    normalize_whitespace=False,
                    left_boundary="none",
                    right_boundary="word",
                    metadata=placeholder_metadata,
                )
            },
            "metadata": placeholder_metadata,
        }
    entities["organization_domain"] = {
        "description": "Observed exact domains retained as draft until safe exact boundary semantics are available.",
        "status": "draft",
        "regex_flags": [],
        "names": domain_names,
        "metadata": {
            "charter_role": "organization_and_domain_intelligence",
            "label_source": "train_structured_headers",
            "activation_limit": "exact_domain_boundary_not_expressible_without_span_expansion",
        },
    }

    phone_status = "active" if iteration.activate_phone else "draft"
    phone_reason = "unsupported_independent_negative_evidence" if iteration.activate_phone else "iteration_deferred"
    phone_metadata = _fallback_metadata(
        policy_sha256,
        source_binding,
        privacy_class="phone_number",
        review_status=phone_status,
        reason_code=phone_reason,
        evidence_scope="synthetic_only",
    )
    entities["phone_number"] = {
        "description": "Conservative US phone fallback experiment; selected bank keeps it draft.",
        "status": phone_status,
        "regex_flags": [],
        "names": {
            "unknown_phone": {
                "canonical": "Unknown phone number",
                "description": "Generic structured phone fallback.",
                "status": phone_status,
                "patterns": {
                    "structured_us_phone": _regex_pattern(
                        _GENERIC_PHONE_REGEX,
                        status=phone_status,
                        priority=policy.max_active_patterns - 2,
                        description="Bounded US phone-number experiment.",
                        metadata=phone_metadata,
                    )
                },
                "metadata": phone_metadata,
            }
        },
        "metadata": {
            "charter_role": "unknown_structured_phone_fallback",
            "label_source": "synthetic_only",
            "selected_bank_status": "draft",
        },
    }
    candidate_rows.append(
        _fallback_candidate_row(
            "phone_fallback",
            phone_status,
            phone_reason,
            {"entity_id": "phone_number", "name_id": "unknown_phone", "pattern_ids": ["structured_us_phone"]},
        )
    )

    bank = {
        "schema_version": "nerb.bank.v1",
        "id": "enron_intelligence_v2",
        "name": "Private Enron Intelligence Bank v2",
        "description": "Train-only privacy-first contact and person intelligence with bounded structured fallbacks.",
        "version": "2026.07.10",
        "status": "active",
        "created_at": created_at,
        "updated_at": created_at,
        "unicode_normalization": "none",
        "default_regex_flags": [],
        "entities": entities,
        "metadata": {
            "builder": "nerb.enron_bank_builder.curate_enron_iteration",
            "builder_policy_sha256": policy_sha256,
            "candidate_ledger_sha256": pool.ledger_sha256,
            "iteration_id": iteration.id,
            "iteration_policy_sha256": iteration.sha256,
            "source": dict(source_binding),
            "sealed_test_accessed": False,
            "real_pii_private": True,
        },
    }
    bank_bytes = _canonical_json_bytes(bank)
    active_stats = bank_stats(bank)["active_totals"]
    active_pattern_bytes = 0
    for entity in entities.values():
        if entity["status"] != "active":
            continue
        for name in entity["names"].values():
            if name["status"] != "active":
                continue
            for pattern in name["patterns"].values():
                if pattern["status"] == "active":
                    active_pattern_bytes += len(str(pattern["value"]).encode("utf-8"))
    if active_stats["patterns"] > policy.max_active_patterns:
        raise EnronBankBuildError("Curated bank exceeds the active-pattern limit.")
    if active_pattern_bytes > policy.max_pattern_utf8_bytes:
        raise EnronBankBuildError("Curated bank exceeds the active-pattern byte limit.")
    if len(bank_bytes) > policy.max_bank_json_bytes:
        raise EnronBankBuildError("Curated bank exceeds the canonical JSON byte limit.")

    candidate_rows.rows.sort(key=lambda item: (str(item["candidate_type"]), str(item["candidate_id"])))
    funnel = candidate_rows.funnel()
    collisions = {
        "schema_version": "nerb.enron_bank_collisions.v2",
        "active_exact_identity_collisions": 0,
        "allowed_fallback_shadowing": len(active_contact_values) if iteration.activate_generic_email else 0,
        "by_reason": dict(sorted(collision_counts.items())),
        "passed": True,
    }
    return CuratedIteration(
        iteration=iteration,
        bank=bank,
        candidates=tuple(candidate_rows.rows),
        funnel=funnel,
        collisions=collisions,
    )


def candidate_funnel(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    decisions: Counter[str] = Counter()
    types: dict[str, Counter[str]] = defaultdict(Counter)
    reasons: Counter[str] = Counter()
    for row in rows:
        decision = str(row["decision"])
        candidate_type = str(row["candidate_type"])
        reason = str(row["primary_reason_code"])
        decisions[decision] += 1
        types[candidate_type][decision] += 1
        reasons[reason] += 1
    return _candidate_funnel_from_counts(total=len(rows), decisions=decisions, types=types, reasons=reasons)


def _candidate_funnel_from_counts(
    *,
    total: int,
    decisions: Mapping[str, int],
    types: Mapping[str, Mapping[str, int]],
    reasons: Mapping[str, int],
) -> dict[str, Any]:
    return {
        "schema_version": CANDIDATE_FUNNEL_SCHEMA_VERSION,
        "total_candidates": total,
        "by_decision": {name: decisions[name] for name in ("active", "draft", "rejected")},
        "by_type": {
            name: {
                "total": sum(counts.values()),
                "active": counts["active"],
                "draft": counts["draft"],
                "rejected": counts["rejected"],
            }
            for name, counts in sorted(types.items())
        },
        "by_primary_reason": dict(sorted(reasons.items())),
    }


def _candidate_row(
    evidence: CandidateEvidence,
    decision: str,
    reason_code: str,
    bank_ref: Mapping[str, Any] | None,
) -> dict[str, Any]:
    return {
        "schema_version": CANDIDATE_SCHEMA_VERSION,
        "candidate_id": _opaque_id(evidence.kind, evidence.normalized_value),
        "candidate_type": evidence.kind,
        "normalized_value": evidence.normalized_value,
        "surfaces": [{"value": value, "observations": count} for value, count in evidence.surfaces],
        "related_values": [value for value, _count in evidence.related_counts],
        "decision": decision,
        "primary_reason_code": reason_code,
        "secondary_reason_codes": [],
        "evidence": {
            "observation_count": evidence.observation_count,
            "distinct_document_count": evidence.document_count,
            "distinct_leakage_group_count": evidence.leakage_group_count,
            "first_seen": evidence.first_seen,
            "last_seen": evidence.last_seen,
            "unknown_date_documents": evidence.unknown_date_documents,
            "evidence_sha256": evidence.evidence_sha256,
            "source_types": [name for name, _count in evidence.source_types],
        },
        "bank_ref": None if bank_ref is None else dict(bank_ref),
    }


def _fallback_candidate_row(
    candidate_type: str,
    decision: str,
    reason_code: str,
    bank_ref: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": CANDIDATE_SCHEMA_VERSION,
        "candidate_id": candidate_type,
        "candidate_type": candidate_type,
        "normalized_value": None,
        "surfaces": [],
        "related_values": [],
        "decision": decision,
        "primary_reason_code": reason_code,
        "secondary_reason_codes": [],
        "evidence": {
            "observation_count": 0,
            "distinct_document_count": 0,
            "distinct_leakage_group_count": 0,
            "first_seen": None,
            "last_seen": None,
            "unknown_date_documents": 0,
            "evidence_sha256": _canonical_hash({"candidate_type": candidate_type, "reason": reason_code}),
        },
        "bank_ref": dict(bank_ref),
    }


def _evidence_metadata(
    evidence: CandidateEvidence,
    *,
    policy_sha256: str,
    source_binding: Mapping[str, Any],
    review_status: str,
    reason_code: str,
    privacy_class: str,
    extra: Mapping[str, Any],
) -> dict[str, Any]:
    provenance_sha256 = _canonical_hash(
        {
            "source": source_binding,
            "policy_sha256": policy_sha256,
            "evidence_sha256": evidence.evidence_sha256,
            "counts": [
                evidence.observation_count,
                evidence.document_count,
                evidence.leakage_group_count,
            ],
        }
    )
    confidence = (
        "high" if evidence.leakage_group_count >= 5 else "medium" if evidence.leakage_group_count >= 2 else "low"
    )
    return {
        "source_type": "+".join(name for name, _count in evidence.source_types),
        "split": "train",
        "observation_count": evidence.observation_count,
        "distinct_document_count": evidence.document_count,
        "distinct_leakage_group_count": evidence.leakage_group_count,
        "first_seen": evidence.first_seen,
        "last_seen": evidence.last_seen,
        "unknown_date_documents": evidence.unknown_date_documents,
        "confidence": confidence,
        "review_status": review_status,
        "curation_reason_code": reason_code,
        "privacy_class": privacy_class,
        "label_strength": "structured_weak",
        "evidence_sha256": evidence.evidence_sha256,
        "provenance_sha256": provenance_sha256,
        "builder_policy_sha256": policy_sha256,
        "ambiguity": {
            "status": "clear" if review_status == "active" else "review_required",
            "reason_codes": [] if review_status == "active" else [reason_code],
        },
        **dict(extra),
    }


def _fallback_metadata(
    policy_sha256: str,
    source_binding: Mapping[str, Any],
    *,
    privacy_class: str,
    review_status: str,
    reason_code: str,
    evidence_scope: str,
) -> dict[str, Any]:
    evidence_sha256 = _canonical_hash(
        {
            "policy_sha256": policy_sha256,
            "source": source_binding,
            "privacy_class": privacy_class,
            "evidence_scope": evidence_scope,
        }
    )
    return {
        "source_type": "generic_structured_fallback",
        "split": "train",
        "observation_count": 0,
        "distinct_document_count": 0,
        "distinct_leakage_group_count": 0,
        "first_seen": None,
        "last_seen": None,
        "unknown_date_documents": 0,
        "confidence": "medium" if review_status == "active" else "low",
        "review_status": review_status,
        "curation_reason_code": reason_code,
        "privacy_class": privacy_class,
        "label_strength": "synthetic_conformance",
        "evidence_scope": evidence_scope,
        "evidence_sha256": evidence_sha256,
        "provenance_sha256": evidence_sha256,
        "builder_policy_sha256": policy_sha256,
        "ambiguity": {
            "status": "bounded_format" if review_status == "active" else "review_required",
            "reason_codes": [] if review_status == "active" else [reason_code],
        },
    }


def _literal_pattern(
    value: str,
    *,
    status: str,
    priority: int,
    description: str,
    normalize_whitespace: bool,
    left_boundary: str,
    right_boundary: str,
    metadata: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "kind": "literal",
        "value": value,
        "description": description,
        "status": status,
        "priority": priority,
        "case_sensitive": False,
        "normalize_whitespace": normalize_whitespace,
        "left_boundary": left_boundary,
        "right_boundary": right_boundary,
        "metadata": dict(metadata),
    }


def _regex_pattern(
    value: str,
    *,
    status: str,
    priority: int,
    description: str,
    metadata: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "kind": "regex",
        "value": value,
        "description": description,
        "status": status,
        "priority": priority,
        "regex_flags": [],
        "metadata": dict(metadata),
    }


def _compatible_person_aliases(values: Sequence[CandidateEvidence]) -> list[CandidateEvidence]:
    if not values:
        return []
    first_value = _person_identity_value(values[0])
    if first_value is None:
        return []
    accepted = [values[0]]
    accepted_match_surfaces = {values[0].normalized_value}
    for value in values[1:]:
        identity_value = _person_identity_value(value)
        if identity_value == first_value and value.normalized_value not in accepted_match_surfaces:
            accepted.append(value)
            accepted_match_surfaces.add(value.normalized_value)
    return accepted


def _person_identity_value(evidence: CandidateEvidence) -> str | None:
    values = {
        normalized
        for surface, _count in evidence.surfaces
        if (normalized := _normalize_person_name(surface)) is not None
    }
    if len(values) != 1:
        return None
    return next(iter(values))


def _contact_scope(address: str, policy: EnronBankPolicy) -> str:
    domain = address.rsplit("@", 1)[-1]
    return "internal" if _domain_affiliation(domain, policy) == "internal" else "external"


def _domain_affiliation(domain: str, policy: EnronBankPolicy) -> str:
    normalized_internal = tuple(cast(str, _normalize_domain(item)) for item in policy.internal_domains)
    is_internal = any(domain == item or domain.endswith("." + item) for item in normalized_internal)
    return "internal" if is_internal else "external"


def _normalize_email(value: str) -> str | None:
    normalized = unicodedata.normalize("NFKC", value).strip().casefold()
    if not normalized or len(normalized) > 320 or not _EMAIL_RE.fullmatch(normalized):
        return None
    local, domain = normalized.rsplit("@", 1)
    if len(local) > 64 or len(domain) > 253 or any(len(label) > 63 for label in domain.split(".")):
        return None
    return normalized


def _normalized_surface(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).split())


def _person_literal_surface(value: str) -> str:
    return " ".join(value.split())


def _person_literal_catalog_key(value: str) -> str:
    return "".join(_simple_casefold_scalar(character) for character in _person_literal_surface(value))


def _simple_casefold_scalar(value: str) -> str:
    folded = value.casefold()
    if len(folded) == 1:
        return folded
    lowered = value.lower()
    return lowered if len(lowered) == 1 else value


def _normalize_person_name(value: str) -> str | None:
    surface = _normalized_surface(value).strip(' \t\r\n"<>()[]{}')
    if not surface or "@" in surface or len(surface) > 160:
        return None
    if surface.count(",") == 1:
        last, first = (part.strip() for part in surface.split(",", 1))
        if last and first:
            surface = f"{first} {last}"
    tokens = _NAME_TOKEN_RE.findall(surface)
    if len(tokens) < 2 or len(tokens) > 8:
        return None
    lowered = [unicodedata.normalize("NFKC", token).casefold() for token in tokens]
    if any(token in _ROLE_NAME_TOKENS for token in lowered) or all(len(token) == 1 for token in lowered):
        return None
    return " ".join(lowered)


def _name_matches_address(normalized_name: str, address: str) -> bool:
    local = address.rsplit("@", 1)[0].split("+", 1)[0].casefold()
    local_tokens = _LOCAL_TOKEN_RE.findall(local)
    name_tokens = normalized_name.split()
    if len(name_tokens) < 2 or not local_tokens:
        return False
    first = re.sub(r"[^a-z]", "", name_tokens[0])
    last = re.sub(r"[^a-z]", "", name_tokens[-1])
    compact = "".join(local_tokens)
    return bool(
        first
        and last
        and (
            (first in local_tokens and last in local_tokens)
            or compact in {first + last, last + first}
            or compact.startswith(first[:1] + last)
            or compact.startswith(last + first[:1])
        )
    )


def _validate_policy(policy: EnronBankPolicy) -> None:
    values = (
        policy.minimum_contact_groups,
        policy.minimum_person_alias_groups,
        policy.minimum_domain_groups,
        policy.max_active_contacts,
        policy.max_active_people,
        policy.max_active_person_aliases,
        policy.max_active_domains,
        policy.max_draft_per_class,
        policy.max_active_patterns,
        policy.max_pattern_utf8_bytes,
        policy.max_bank_json_bytes,
        policy.max_train_records,
        policy.max_train_artifact_bytes,
        policy.max_validation_records,
        policy.max_validation_artifact_bytes,
        policy.max_validation_entries,
        policy.max_validation_spans,
        policy.max_validation_text_utf8_bytes,
        policy.max_development_memberships_bytes,
        policy.max_development_samples_bytes,
        policy.max_quality_predictions,
        policy.max_header_entries_per_document,
        policy.max_observations,
        policy.max_unique_candidates,
        policy.max_candidate_value_bytes,
    )
    if any(type(value) is not int or value <= 0 for value in values):
        raise EnronBankBuildError("Bank-build policy limits must be positive integers.")
    if policy.max_quality_predictions != DEFAULT_MAX_QUALITY_PREDICTIONS_TOTAL:
        raise EnronBankBuildError("Bank-build prediction capacity must match the frozen quality evaluator limit.")
    if policy.max_validation_spans > policy.max_quality_predictions:
        raise EnronBankBuildError("Validation span capacity must not exceed the quality prediction capacity.")
    domains = tuple(_normalize_domain(value) for value in policy.internal_domains)
    if not domains or any(value is None for value in domains) or len(set(domains)) != len(domains):
        raise EnronBankBuildError("Internal-domain policy must contain unique valid domains.")


def _normalize_domain(value: str) -> str | None:
    normalized = unicodedata.normalize("NFKC", value).strip().rstrip(".").casefold()
    if len(normalized) > 253 or not _DOMAIN_RE.fullmatch(normalized):
        return None
    return normalized


def _opaque_id(prefix: str, value: str) -> str:
    digest = hashlib.sha256(prefix.encode("utf-8") + b"\0" + value.encode("utf-8")).hexdigest()
    candidate = f"{prefix}_{digest[:20]}"
    if not _ID_SAFE_RE.fullmatch(candidate):  # pragma: no cover - static prefix invariant
        raise EnronBankBuildError("Generated bank identifier is invalid.")
    return candidate


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise EnronBankBuildError("Bank-build value is not canonical finite UTF-8 JSON.") from None


def _canonical_hash(value: Any) -> str:
    return _SHA256_PREFIX + hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


# Historical v1 support remains quarantined inside ``enron_benchmark``.  New
# code must use the development-split v2 workflow in this module.


def summarize_bank(bank: Mapping[str, Any]) -> dict[str, Any]:
    """Return safe structural counts for a private bank."""

    return {"hash": hash_bank(bank), "stats": bank_stats(bank)}
