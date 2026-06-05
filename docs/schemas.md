# NERB Schema Reference

This document describes the public JSON-compatible contracts for NERB banks, extraction records, eval refs, YAML detector
configs, and shared diagnostic objects. The runtime source of truth is the code in `src/nerb/schema.py`,
`src/nerb/extraction.py`, `src/nerb/reports.py`, and `src/nerb/evals.py`.

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
  "version": "2026.06.05",
  "status": "active",
  "created_at": "2026-06-05T00:00:00Z",
  "updated_at": "2026-06-05T00:00:00Z",
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
| `summary` | object | `passed`, positive and negative totals, and failure counts. |
| `by_entity` | object | Counts keyed by entity ID. |
| `by_name` | object | Counts keyed by `entity_id/name_id`. |
| `by_pattern` | object | Counts keyed by `entity_id/name_id/pattern_id`. |
| `provenance` | object | Total provenance count and counts by `source_type`. |
| `failures` | array | Eval ref, record index, record type, expected/actual data, and diagnostics. |

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
