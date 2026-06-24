---
icon: lucide/shield
description: "Use NERB replacement databases for redaction, pseudonym replacement, and deliberate de-anonymization."
---

# Anonymization

NERB can replace extracted entities with stable redaction tokens or pseudonyms. Reversible workflows use an explicit
local replacement database; that database is sensitive when it stores originals.

## Reversible Redaction

```shell
nerb replacement-db init --db replacements.json --reversible
nerb anonymize-text --bank people.json --db replacements.json \
  --text "John Smith joined." --mode redact --save-db
nerb deanonymize-text --db replacements.json --text "[PERSON_0001] joined."
```

Use `--save-db` only when you intentionally want future calls to reuse the same assignments.

## Config-Backed Redaction

YAML detector configs do not have JSON-bank `name_id` values, so initialize or configure the replacement DB with
`canonical` or `surface` assignment scope:

```shell
nerb replacement-db init --db config-replacements.json --reversible --assignment-scope canonical
nerb anonymize-config-text --config detectors.yaml --db config-replacements.json \
  --text "Miles Davis met M. Davis." --mode redact --save-db
```

## Pseudonyms

Pseudonyms require a replacement set and are not restored by default:

```shell
nerb replacement-db init --db pseudonym-replacements.json --reversible
nerb replacement-db add-set --db pseudonym-replacements.json --set person_names \
  --candidate "Mikey Law" --candidate "Nina Vale"
nerb replacement-db set-entity --db pseudonym-replacements.json --entity person \
  --mode pseudonym --set person_names --store-originals
nerb anonymize-text --bank people.json --db pseudonym-replacements.json \
  --text "John Smith joined." --mode pseudonym --save-db
nerb deanonymize-text --db pseudonym-replacements.json --text "Mikey Law joined." --restore-pseudonyms
```

## Sensitive Metadata

Default CLI response metadata omits originals, replacement values, raw assignment keys, fingerprints, bank hashes, and
replacement DB hashes. The transformed `text` still contains replacement values by design.

Python and MCP anonymization response metadata include replacement values because they are already present in the
transformed text, but still omit originals, raw keys, fingerprints, and hashes by default.

Use these flags only when the caller is allowed to receive sensitive data:

```shell
--include-originals
--include-sensitive-metadata
--include-values
```

## Operational Rules

- Treat reversible DBs as sensitive local files, especially when `store_originals` is true.
- Pseudonymization is deterministic replacement, not cryptographic anonymization.
- De-anonymization restores redaction tokens by default.
- Pseudonym restoration is opt-in because exact replacement can also affect naturally occurring pseudonym strings.
- MCP writes are explicit: creating or reading a replacement DB does not imply an in-place save.
