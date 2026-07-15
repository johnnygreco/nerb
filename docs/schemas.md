# NERB Schema Reference

This document describes the public JSON-compatible contracts for NERB banks, extraction records, replacement databases,
anonymization responses, eval refs, YAML detector configs, and shared diagnostic objects. The runtime source of truth is
the code in `src/nerb/schema.py`, `src/nerb/extraction.py`, `src/nerb/replacements_schema.py`,
`src/nerb/deanonymization.py`, `src/nerb/reports.py`, and `src/nerb/evals.py`. The purpose-specific Enron bank-build
contracts are implemented in `src/nerb/enron_bank_builder.py` and `src/nerb/enron_bank_workflow.py`.

## Shared Rules

IDs use this pattern:

```text
^[a-z][a-z0-9_]{0,79}$
```

IDs apply to bank IDs, entity IDs, name IDs, pattern IDs, and batch `document_id` values. Status values are `draft`,
`active`, `inactive`, and `deprecated`. Regex flag values are `ASCII`, `IGNORECASE`, `MULTILINE`, `DOTALL`, and
`VERBOSE`. Unicode normalization values are `none`, `NFC`, and `NFKC`.

`metadata` fields are JSON objects whose values must be JSON-compatible. Metadata above 16 KiB produces a warning;
metadata above 1 MiB is an error. Descriptions are capped at 2,000 characters. Pattern values are capped at 10,000
characters.

`eval_refs` can appear on a bank, entity, name, or pattern. Each value is a non-empty string. Local eval execution
requires relative paths under the eval base path; absolute paths, parent traversal outside the base path, remote URIs,
non-regular files, and invalid UTF-8 are rejected.

## JSON Bank

A JSON bank is the main agent and service format. It stores authoring metadata plus extractable literal and regex
patterns in one validated object.

### Top-Level Bank

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `schema_version` | string | yes | Must be `nerb.bank.v1`. |
| `id` | ID string | yes | Stable bank ID. |
| `name` | string | yes | Human-readable bank name. |
| `description` | string | yes | Up to 2,000 characters. |
| `version` | string | yes | Bank authoring version, independent from package version. |
| `status` | status string | yes | Extraction includes `active` banks by default. |
| `created_at` | string | yes | Timestamp string; format is not schema-enforced. |
| `updated_at` | string | yes | Timestamp string; format is not schema-enforced. |
| `unicode_normalization` | string | yes | `none`, `NFC`, or `NFKC`. |
| `default_regex_flags` | array of flag strings | yes | Bank-level default regex flags. |
| `entities` | object | yes | At least one entity keyed by entity ID. |
| `metadata` | object | yes | JSON-compatible metadata. |
| `eval_refs` | array of strings | no | Local JSONL eval references. |

Additional top-level properties are rejected.

### Entity

Each entity is stored under `entities.<entity_id>`.

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `description` | string | yes | Up to 2,000 characters. |
| `status` | status string | yes | Extraction includes active entities by default. |
| `regex_flags` | array of flag strings | yes | Entity-level regex flags. |
| `names` | object | yes | At least one name keyed by name ID. |
| `metadata` | object | yes | JSON-compatible metadata. |
| `eval_refs` | array of strings | no | Entity-scoped JSONL eval references. |

Additional entity properties are rejected.

### Name

Each name is stored under `entities.<entity_id>.names.<name_id>`.

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `canonical` | string | yes | Canonical name returned as `canonical_name`. |
| `description` | string | yes | Up to 2,000 characters. |
| `status` | status string | yes | Extraction includes active names by default. |
| `patterns` | object | yes | At least one pattern keyed by pattern ID. |
| `metadata` | object | yes | JSON-compatible metadata. |
| `eval_refs` | array of strings | no | Name-scoped JSONL eval references. |

Additional name properties are rejected.

### Pattern

Each pattern is stored under `entities.<entity_id>.names.<name_id>.patterns.<pattern_id>`.

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `kind` | string | yes | `literal` or `regex`. |
| `value` | string | yes | Non-empty pattern value, up to 10,000 characters. |
| `description` | string | yes | Up to 2,000 characters. |
| `status` | status string | yes | Extraction includes active patterns by default. |
| `priority` | integer | yes | Lower priority wins report overlap resolution. |
| `metadata` | object | yes | JSON-compatible metadata. |
| `eval_refs` | array of strings | no | Pattern-scoped JSONL eval references. |

Literal patterns also require:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `case_sensitive` | boolean | yes | Literal case behavior. |
| `normalize_whitespace` | boolean | yes | Whether literal whitespace is normalized. |
| `left_boundary` | string | yes | `none` or `word`. |
| `right_boundary` | string | yes | `none` or `word`. |

Regex patterns also require:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `regex_flags` | array of flag strings | yes | Pattern-level regex flags. |

Literal patterns must not include `regex_flags`. Regex patterns must not include `case_sensitive`,
`normalize_whitespace`, `left_boundary`, or `right_boundary`. Additional pattern properties are rejected.

### Minimal Complete Bank

```json
{
  "schema_version": "nerb.bank.v1",
  "id": "company_entities",
  "name": "Company Entities",
  "description": "Companies to recognize in internal documents.",
  "version": "2026.06.24",
  "status": "active",
  "created_at": "2026-06-24T00:00:00Z",
  "updated_at": "2026-06-24T00:00:00Z",
  "unicode_normalization": "none",
  "default_regex_flags": ["IGNORECASE"],
  "entities": {
    "company": {
      "description": "Organizations.",
      "status": "active",
      "regex_flags": [],
      "names": {
        "acme_corp": {
          "canonical": "Acme Corp",
          "description": "Primary account.",
          "status": "active",
          "patterns": {
            "primary": {
              "kind": "literal",
              "value": "Acme Corp",
              "description": "Exact company alias.",
              "status": "active",
              "priority": 100,
              "case_sensitive": false,
              "normalize_whitespace": true,
              "left_boundary": "word",
              "right_boundary": "word",
              "metadata": {}
            }
          },
          "metadata": {}
        }
      },
      "metadata": {}
    }
  },
  "metadata": {}
}
```

## Extraction Records

Direct `Bank` scans and config-backed CLI/MCP extraction return Rust-backed records:

| Field | Type | Notes |
| --- | --- | --- |
| `entity` | string | Entity ID or source entity name. |
| `canonical_name` | string | Canonical name for the matched detector. |
| `surface_name` | string | Surface alias for the matched detector. |
| `string` | string | Matched document substring. |
| `start` | integer | Start offset. Byte offset by default. |
| `end` | integer | Exclusive end offset. Byte offset by default. |
| `offset_unit` | string | Usually `byte`; direct `Bank.scan_text(..., offsets="char")` can return `char`. |

JSON-bank extraction enriches each record with source IDs and captures:

| Field | Type | Notes |
| --- | --- | --- |
| `entity_id` | string | JSON-bank entity ID. |
| `name_id` | string | JSON-bank name ID. |
| `pattern_id` | string | JSON-bank pattern ID. |
| `pattern_kind` | string | `literal` or `regex`. |
| `captures` | object | Current extraction records return `{}`. |

Example JSON-bank record:

```json
{
  "entity": "company",
  "canonical_name": "Acme Corp",
  "surface_name": "Acme Corp",
  "string": "Acme Corp",
  "start": 13,
  "end": 22,
  "offset_unit": "byte",
  "entity_id": "company",
  "name_id": "acme_corp",
  "pattern_id": "primary",
  "pattern_kind": "literal",
  "captures": {}
}
```

Direct `Bank` records are sorted deterministically by start offset, end offset, entity, canonical name, surface name, and
matched string. JSON-bank records are sorted by start offset, end offset, `entity_id`, `name_id`, `pattern_id`, and
matched string. Batch flat records add a leading `document_id` field.

## Extraction Responses

Single-document JSON-bank extraction returns:

| Field | Type | Notes |
| --- | --- | --- |
| `bank` | object | Bank metadata: `id`, `version`, `schema_version`, `hash`. |
| `engine` | object | Engine metadata: `name`, `version`, `cache`. |
| `source` | object | Source metadata. Text sources include `type`, `length`, `bytes`; file sources also include `path`. |
| `records` | array | JSON-bank extraction records. |

Batch extraction returns:

| Field | Type | Notes |
| --- | --- | --- |
| `bank` | object | Same bank metadata as single-document extraction. |
| `engine` | object | Same engine metadata as single-document extraction. |
| `source` | object | `{ "type": "batch", "document_count": int, "bytes": int }`. |
| `documents` | array | Per-document objects with `document_id`, `source`, and document-local `records`. |
| `records` | array | Flat records across documents; each record includes `document_id`. |
| `summary` | object | `document_count`, `record_count`, and `documents_with_records`. |

Batch input documents must be objects with a valid `document_id` or `id`, and exactly one of `text` or `file_path`.
Default limits are 100 documents, 10 MiB per document, and 25 MiB combined text.

## Report Responses

`extract_report` returns extraction records plus overlap resolution and context:

| Field | Type | Notes |
| --- | --- | --- |
| `bank` | object | Bank metadata. |
| `engine` | object | Engine metadata. |
| `source` | object | Source metadata. |
| `records` | array | Raw JSON-bank extraction records. |
| `resolved_records` | array | Objects with `record`, `explanation`, and `context`. |
| `overlaps` | array | Overlap groups resolved by priority. |
| `summary` | object | `record_count`, `resolved_record_count`, `entity_counts`, and `name_counts`. |
| `diagnostics` | array | Diagnostic objects, including missing expected-match warnings. |

An overlap object has `id`, `policy`, `span`, `records`, `resolved_record`, and `dropped_records`. The current public
report policy is `priority`. Lower numeric pattern priority wins; ties prefer longer matches, earlier starts, stable
IDs, and matched string ordering.

Report batch responses mirror batch extraction and add flat `resolved_records`, flat `overlaps`, and per-document report
objects.

## Replacement Database

A replacement database is a local JSON object with schema version `nerb.replacements.v1`. It stores default replacement
policy, optional per-entity policy, replacement candidate sets, and assignments. When `store_originals` is true, the
database contains sensitive originals and must be treated as sensitive local state.

### Top-Level Replacement DB

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `schema_version` | string | yes | Must be `nerb.replacements.v1`. |
| `id` | ID string | yes | Local database ID. |
| `description` | string | yes | Up to 2,000 characters. |
| `version` | integer | yes | Positive integer incremented by save operations. |
| `created_at` | string | yes | Timestamp string; format is not schema-enforced. |
| `updated_at` | string | yes | Timestamp string; format is not schema-enforced. |
| `metadata` | object | yes | JSON-compatible metadata. |
| `defaults` | object | yes | Default replacement policy. |
| `entities` | object | yes | Per-entity policy overrides keyed by replacement entity ID. |
| `replacement_sets` | object | yes | Pseudonym candidate sets keyed by replacement set ID. |
| `assignments` | object | yes | Stable assignment rows keyed by opaque assignment key. |

Additional top-level properties are rejected.

### Replacement Policy

`defaults` must contain the base policy fields. `replacement_set_id` is optional for redaction policies, but required in
the effective policy when `replacement_mode` is `pseudonym`. `entities.<entity_id>` may contain any non-empty subset of
the same fields.

| Field | Type | Notes |
| --- | --- | --- |
| `unicode_normalization` | string | `none`, `NFC`, or `NFKC`. |
| `assignment_scope` | string | `name`, `canonical`, or `surface`. JSON banks usually use `name`; config-backed workflows use `canonical` or `surface`. |
| `replacement_mode` | string | `redact` or `pseudonym`. |
| `redaction_template` | string | Format string supporting `{entity}`, `{ENTITY}`, and `{ordinal:04d}`. |
| `collision_policy` | string | Currently `error`. |
| `store_originals` | boolean | Enables reversible de-anonymization when true. |
| `allow_new_assignments` | boolean | When false, unknown entities produce diagnostics instead of assignments. |
| `replacement_set_id` | ID string | Optional for redaction; required for effective pseudonym policies. |

Assignment scopes:

- `name`: uses JSON-bank `entity_id` and `name_id`; aliases share one assignment and de-anonymization restores the
  canonical value.
- `canonical`: uses entity plus normalized `canonical_name`; useful for YAML detector configs.
- `surface`: uses entity plus normalized matched `string`; useful when exact source-surface restoration matters.

### Replacement Sets

Each replacement set contains `description`, `reuse`, `candidates`, and optional `metadata`. Candidates are objects with
`id`, non-empty `value`, and `metadata`. Pseudonym mode allocates from the configured candidate set and rejects exhausted
or ambiguous candidate pools.

### Assignments

Assignment keys use this opaque format:

```text
<entity>|<scope>|sha256:<64 lowercase hex>
```

Assignment rows contain `assignment_key`, `entity_id`, `identity`, `replacement`, `redaction`, timestamps, `use_count`,
and `metadata`. `original` is present only when the effective policy stores originals. Fingerprints, assignment keys,
source IDs, originals, replacement values, and hashes are linkable or sensitive. Default CLI response metadata redacts
them, while the transformed `text` contains replacement values by design. Default Python and MCP anonymization response
metadata include replacement values because those values are also present in the transformed text; they still redact
originals, raw assignment keys, fingerprints, and hashes.

## Anonymization Responses

`anonymize_text`, `anonymize_file`, `anonymize_config_text`, and `anonymize_config_file` return
`nerb.anonymize_response.v1` payloads.

| Field | Type | Notes |
| --- | --- | --- |
| `schema_version` | string | `nerb.anonymize_response.v1`. |
| `bank` | object | Safe metadata with `bank_ref`, `schema_version`, and `version`; hashes/IDs require sensitive metadata. |
| `replacement_db` | object | Safe DB metadata: `replacement_db_ref`, `schema_version`, `version`, `modified`, `saved`. |
| `source` | object | Text/file metadata. File paths are omitted by default and replaced with `source_ref`. |
| `text` | string | Transformed text. |
| `applied_replacements` | array | Per-replacement metadata. |
| `summary` | object | `record_count`, `applied_count`, and `diagnostic_count`. |
| `diagnostics` | array | Non-fatal diagnostics. |

Default Python and MCP `applied_replacements` entries include opaque `assignment_ref`, `entity`, `mode`,
`original_span`, `replacement_span`, and `replacement`. CLI output strips `replacement` unless
`--include-sensitive-metadata` is set. `include_originals` adds original strings. `include_sensitive_metadata` adds raw
assignment keys, source record IDs, DB data, hashes, and file paths where available.

Config-backed anonymization uses Rust `Bank.scan_text()` records from YAML detector configs. It does not run JSON-bank
report resolution. Because config records do not include `name_id`, use `assignment_scope: "canonical"` or
`assignment_scope: "surface"` for config-backed replacement DBs.

## De-Anonymization Responses

`deanonymize_text` and `deanonymize_file` return `nerb.deanonymize_response.v1` payloads.

| Field | Type | Notes |
| --- | --- | --- |
| `schema_version` | string | `nerb.deanonymize_response.v1`. |
| `replacement_db` | object | Safe DB metadata. |
| `source` | object | Text/file metadata. File paths are omitted by default and replaced with `source_ref`. |
| `text` | string | Restored text. |
| `applied_restorations` | array | Per-restoration metadata. |
| `summary` | object | `match_count`, `applied_count`, and `diagnostic_count`. |
| `diagnostics` | array | Non-fatal diagnostics and warnings. |

Redaction tokens are restored by default. Pseudonym restoration requires `restore_pseudonyms=true` or
`--restore-pseudonyms` and emits a warning because it is exact string replacement. If `store_originals` was false or a
replacement maps to multiple originals, de-anonymization returns diagnostics instead of guessing.

## Eval JSONL

Eval references are UTF-8 JSONL files. Blank lines are ignored. Each non-empty line must be one JSON object with one of
these `type` values: `positive`, `negative`, or `provenance`.

Positive records require exact expected matches:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `type` | string | yes | Must be `positive`. |
| `text` | string | yes | UTF-8 text to extract from. |
| `matches` | array | yes | Non-empty array of expected match objects. |
| `metadata` | object | yes | JSON-compatible metadata. |

Positive match objects require `string`, `start`, and `end`. They may also include `entity`, `entity_id`, `name`,
`name_id`, `pattern_id`, `pattern_kind`, and `captures`. `start` and `end` are non-negative byte offsets, `end >= start`,
and `string` must equal the UTF-8 text slice at `[start:end]`. When both `entity` and `entity_id` are present, they must
agree.

Capture objects are keyed by capture name and contain only `string`, `start`, and `end`.

Negative records assert that scoped extraction should return no records:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `type` | string | yes | Must be `negative`. |
| `text` | string | yes | UTF-8 text to extract from. |
| `reason` | string | yes | Human-readable reason for the negative case. |
| `metadata` | object | yes | JSON-compatible metadata. |

Provenance records are counted but do not affect pass/fail:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `type` | string | yes | Must be `provenance`. |
| `source_type` | string | yes | Provenance source category. |
| `observed_at` | string | yes | Timestamp string; format is not schema-enforced. |
| `evidence` | string | yes | Human-readable evidence. |
| `metadata` | object | yes | JSON-compatible metadata. |

Example eval ref:

```jsonl
{"type":"positive","text":"Send this to Acme Corp.","matches":[{"string":"Acme Corp","start":13,"end":22}],"metadata":{"case":"fixture_positive"}}
{"type":"negative","text":"The acme of performance was impressive.","reason":"Common-word false positive guard.","metadata":{}}
{"type":"provenance","source_type":"crm","observed_at":"2026-06-03T00:00:00Z","evidence":"Fixture eval record for Acme Corp.","metadata":{}}
```

## Eval Responses

`eval_bank` returns:

| Field | Type | Notes |
| --- | --- | --- |
| `summary` | object | `evaluated`, `passed`, positive and negative totals, and failure counts. Empty/provenance-only evidence is not evaluated and cannot pass. |
| `by_entity` | object | Counts keyed by entity ID. |
| `by_name` | object | Counts keyed by `entity_id/name_id`. |
| `by_pattern` | object | Counts keyed by `entity_id/name_id/pattern_id`. |
| `provenance` | object | Total provenance count and counts by `source_type`. |
| `evidence` | object | `ref_count` plus a deterministic `suite_sha256` commitment to every attachment scope, eval-ref identity, exact readable content hash, and byte size. |
| `failures` | array | Eval ref, record index, record type, expected/actual data, and diagnostics. |

`nerb eval-bank` exits nonzero when the bank is invalid, no behavioral records were evaluated, or any eval failed.
`nerb regress-bank` exits nonzero when either bank is invalid or any aggregate regression gate fails; JSON is still
printed so CI can retain the evidence. Regression requires old and new `evidence.suite_sha256` values to match, in
addition to unchanged behavioral populations, so replacing an eval suite with equal-sized easier content fails closed.

## Diagnostic Objects

Diagnostics are JSON objects with stable core fields:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `severity` | string | yes | `error`, `warning`, or `info`. |
| `code` | string | yes | Stable diagnostic code such as `schema.required` or `eval.positive_failed`. |
| `path` | string | yes | JSON Pointer-style path or an empty string. |
| `message` | string | yes | Human-readable diagnostic message. |
| `why` | string | no | Optional explanation. |
| `suggested_fix` | string | no | Optional fix guidance. |
| `suggested_patch` | array | no | Optional RFC 6902 JSON Patch operations. |
| `metadata` | object | no | Optional JSON-compatible metadata. |

## Enron benchmark evidence

`nerb.enron_manifest.v2` and `nerb.enron_evidence.v2` use verifier `nerb-enron-contract` version 2.2.0. Bank provenance
keeps the physical content-addressed artifact identity (`artifact_sha256` plus `artifact_bytes`) separate from
`canonical_json_bytes` and `native_source_bytes`. A pretty-printed private bank may therefore have the same canonical
bank hash while its physical file size differs from the canonical serialization size. Performance-bank artifact
references always bind the physical artifact hash and byte count.

`ENRON_PERFORMANCE_OUTPUT_SCHEMA` exposes the same closed performance object embedded in evidence, and
`validate_enron_performance_output` performs standalone structure and schema validation. Full hash, provenance,
sample-reference, bank/input, comparison, breakeven, and promotion semantics still require `validate_enron_evidence`
with its surrounding evidence context.

Performance scale descriptors use active matcher-pattern counts of 1k, 10k, 25k, and 100k. Their native matcher-shard,
name, alias, literal, and regex totals remain independent truthful fields and must preserve the evaluated composition.
The frozen 100k fixture records 318 native matcher shards under two semantic taxonomy classes; it is not a 100k
small-shard-topology claim. One-time
source-profile, source-build, and cold-compile decision cells use 20 samples with median, MAD, and p95; p99 is null.
Helper-cache hit/miss and end-to-end cells use 100 samples. The matrix contains 19 true decision cells; all true direct
whole-input and document cells use 1,000 pooled samples and report p99. One additional 100-sample direct-cache-value
comparison-support cell has `decision_grade: false`, uses median stability, and cannot satisfy a headline, absolute gate,
or break-even role. Every candidate/exact-twin pair is divided into ten frozen paired blocks with a hash-derived balanced
mix of ABBA and BAAB observation order. Reused paths receive a fresh worker session for each twin in each block. Runner
source and tests enforce balanced construction order. Verifier-observable evidence binds sample chronology, per-block PID
reuse or freshness, and disjoint twin PIDs; it does not represent process-creation events. Each 100-sample document block
is one complete pass over the exact frozen 100-document population. Each materialized workload records its stable
observed whole-input record count, so non-equivalent baselines compute their own records/second.

Same-path comparison objects use `direction: "symmetric"`, `noise_method: "exact_block_swap"`, exactly ten blocks, and
one metric per true decision cell: median for setup, helper-cache hit/miss, and end-to-end cells, or p99 for true
direct/document cells. The comparison-support proxy uses median.
They record the balanced block assignment, candidate/control values, absolute log ratio, symmetric relative gap,
diagnostic permutation p-value, 0.05 significance level, 0.05 stability tolerance, and one of `within_tolerance`,
`unstable`, or `inconclusive`. A gap no greater than 5% is `within_tolerance`. Larger gaps enumerate all `2^10`
whole-block swaps and recompute the pooled metric; p <= 0.05 distinguishes `unstable` from `inconclusive`, but both fail
promotion. `within_tolerance` is not a statistical equivalence claim.

Cross-path comparison objects remain a separate directional contract. A dedicated 100-sample direct-cache-value cell,
helper-cache hit/miss, and end-to-end cells use ten Williams-balanced blocks with identical bank, input, work, and
concurrency. The support cell cannot replace the 1,000-sample direct cell used for absolute p99 gates or the direct rate
bound into the break-even model. Only these directional cross-path comparisons use paired-block timing-ratio MAD. Their
noise floor has an unconditional 25% ceiling; a larger value fails promotion independently of the directional result.
Same-path comparisons do not use this noise-floor field or ceiling. The public helpers in `nerb.enron_contract` calculate
canonical inventory summaries, phase-aware sample statistics, symmetric same-path outcomes, directional cross-path
outcomes, and additive breakeven results so evidence producers share the verifier's exact arithmetic. The promoted value
model compares direct reuse against a semantically exact NERB helper-cache-miss alternative on the same bank and input;
each phase has its own exact same-path stability control, and both value paths use the same whole-input population.
Shared curation, profiling, and bank-build costs are recorded identically on both sides and cancel, leaving cold compile
plus the two marginal scan rates to determine the crossing. Breakeven inputs whose bounded component/unit products cannot
remain finite are rejected with `ValueError` rather than leaking an arithmetic overflow from the helper.

The executable workflow adds four private-run contracts around that evidence object:

| Schema | Role | Publication boundary |
| --- | --- | --- |
| `nerb.enron_performance_plan.v1` | Path-free, hashed workload plan with separate smoke and decision profiles. | Structurally public, but copied into a private prepared run until reviewed. |
| `nerb.enron_performance_private_manifest.v1` | Hash, byte-count, kind, and relative-path bindings for evaluated/generated banks, inputs, inventories, plan, and private source locations. | Private. |
| `nerb.enron_performance_run.v1` | Aggregate report containing the closed performance object, raw timing/resource samples, environment, decision summary, privacy status, and `sealed_test_accessed: false`. | Eligible for review only after verification and a privacy scan. |
| `nerb.enron_performance_run_private_manifest.v1` | Transactional bindings for the aggregate report, correctness audit, frozen plan, and inventories. | Private. |

The prepared and measured directories use the private-run commit marker and fail closed on changed hashes, unsafe
relative paths, unexpected shapes, or privacy diagnostics. Inventories contain per-document byte and record counts, not
text or matched surfaces. `verify_enron_performance_run` recomputes statistics, comparisons, break-even arithmetic,
decision status, sample policy, the exact-block assignment, balanced ABBA/BAAB and Williams-block sequences, per-block
fresh/reused process isolation, disjoint twin PIDs, cross-path correctness, and audit bindings
without accepting or opening a preparation-source or sealed-test input.

### Aggregate publication bundle

`nerb.enron_publication` is the closed clean-clone bundle manifest in `evidence/enron/publication.json`. It binds the
benchmark manifest/evidence, portable capacity decision, aggregate performance report and content-addressed inventories,
sanitized bank card, generated Markdown/SVGs, terminal decision, audit chain, bank, measurement commit, and a fixed file
inventory. It deliberately has no compatibility branch or alternate historical behavior.

`nerb verify-enron-evidence --bundle evidence/enron` validates authentic terminal evidence whether the quality decision
passes or fails. `--require-quality-eligible` adds the release policy and fails for the committed do-not-ship result.
`nerb render-enron-evidence` regenerates only `summary.md` and the three SVG figures from committed aggregates. The
verifier rejects extra files, missing inventories, symlinks, stale renders, hash drift, non-finite arithmetic, private
paths, raw text, direct identifiers, bank values, document IDs, and span surfaces.

## Enron bank-build artifacts

The [Enron bank construction workflow](enron-bank-building.md) emits a strict, manifest-bound private run. These
workflow contracts are separate from the general `nerb.bank.v1` schema:

| Schema | Role | Publication boundary |
| --- | --- | --- |
| `nerb.enron_bank_build_manifest.v2` | Source, policy, artifact, and selected-bank commitments for the complete run. | Private; it describes sensitive artifact names and bindings. |
| `nerb.enron_bank_candidate.v2` | One active, draft, or rejected candidate with evidence and bank references. | Private; candidate surfaces and provenance may be identifying. |
| `nerb.enron_candidate_funnel.v2` | Conserved aggregate counts by decision, class, and reason. | Embedded in the scanned bank card; the standalone run file remains private. |
| `nerb.enron_bank_build_iteration.v2` | Parent-linked policy, quality commitments, decision, and reason for one iteration. | Aggregate rows appear in the scanned bank card; private validation bindings remain private. |
| `nerb.enron_bank_card.v2` | Aggregate source commitments, bank statistics, funnel, iterations, limited validation summaries, conformance, and privacy report. | Designed for possible public handoff only after deep verification and independent publication review; always non-promotable at the development stage. |
| `nerb.enron_bank_build_verification.v2` | Aggregate result of replaying the private manifest, bank, iterations, conformance, and optional auxiliary evidence. | Contains no document text or direct identifier, but does not by itself authorize publication or promotion. |

The bank card's structured-weak `labeled_span_recall` is not open-world recall. Unsupported open-world recall,
precision, false-alarm, and over-redaction fields remain `null`. See the construction guide for the complete
private-versus-public artifact policy.

## YAML Detector Config

YAML detector configs are compact maps used by config-backed CLI and MCP extraction:

```yaml
ARTIST:
  _flags: IGNORECASE
  Pink Floyd: 'Pink\sFloyd'
  The Who: '[Tt]he\sWho'

GENRE:
  _flags: [IGNORECASE, MULTILINE]
  Rock: '(?:progressive\s)?rock'
```

The top level must be a mapping of non-empty entity names to mappings. Each entity mapping must contain at least one
detector pattern. `_flags` is reserved for regex flags and may be a flag string or an array of flag strings. All other
keys are non-empty detector names and all pattern values must be regex strings.

Empty top-level configs are valid for config authoring, but every non-empty entity must contain at least one detector
pattern. Config extraction compiles through the same Rust-backed `Bank` scanner and returns the direct record schema
above.
