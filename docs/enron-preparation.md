# Enron Preparation

The preparation command turns the pinned parsed Enron email source into deterministic private records and a
privacy-safe aggregate profile. It deliberately does **not** create train, validation, or test roles, build a bank, or
compute quality scores. Leakage grouping and immutable role assignment happen in the implemented
[split and sealing stage](enron-splits.md).

The pinned large-corpus source is `corbt/enron-emails`, split `train`, revision
`cfc06c758093d90993abce1a43668fb7357258a6`. Pin the loader package too:

```shell
uv run --python 3.13 --with datasets==5.0.0 nerb prepare-enron \
  --dataset corbt/enron-emails \
  --dataset-split train \
  --dataset-revision cfc06c758093d90993abce1a43668fb7357258a6 \
  --output-dir .nerb/enron-preparation/enron-v2
```

For the committed synthetic fixture:

```shell
uv run nerb prepare-enron \
  --input-jsonl tests/data/enron_preparation_v2.jsonl \
  --dataset synthetic/enron-preparation \
  --dataset-revision fixture-v2 \
  --output-dir .nerb/enron-preparation/fixture-v2

uv run nerb verify-enron-preparation \
  --run-dir .nerb/enron-preparation/fixture-v2
```

The command streams its source once into a private disk-backed spool. Canonical export order, source commitments, and
full SHA-256 document identities do not depend on source row order. Byte-identical source rows collapse into one record
with an occurrence count; distinct mailbox copies retain distinct document IDs while sharing exact-content,
Message-ID, thread-subject, participant, and near-duplicate features for the grouping stage.
The pinned `file_name` grammar also yields a domain-separated mailbox-owner hash and one frozen coarse folder role
(`inbox`, `sent`, `draft`, `deleted`, `archive`, or `other`). This supports mailbox cohorts without retaining the raw
owner or path; parse/missing/invalid coverage is aggregated.

The source-row commitment is an order-independent bounded-memory multiset commitment. Each canonical row SHA-256 is
domain-separated through SHA-512, occurrence-weighted in a 512-bit additive accumulator, and finalized with the total
occurrence count. Deep verification recomputes it from both prepared and rejected rows, so reordered input has the same
identity while additions, deletions, or changed multiplicities fail verification.

A full run of that exact pinned source must observe its frozen 517,401-row descriptor and at least one usable prepared
record; empty, truncated, or schema-incompatible streams fail transactionally. `--max-rows` is a fixture/debug prefix
mode and does not satisfy the full-source descriptor.

## Views and cleaning

Prepared records retain separate fields instead of creating answer-bearing scan text:

- `full_visible_body`: normalized visible content, including quoted or forwarded regions;
- `current_body`: confidently segmented current content, with signatures and templates retained;
- `subject_current_body`: natural subject plus current body, with no synthetic `From`, `To`, `Addresses`, labels, or
  candidate inventory;
- `current_body_core`: a grouping-only view that may omit strongly identified signature or template tails (its
  near-duplicate feature explicitly falls back to `current_body` when the core is empty); and
- `structured_headers`: normalized source header fields, kept separate for weak supervision.

Cleaning is bounded, versioned, and recall-first. It normalizes LF and Unicode NFC; removes audited bidi controls and
Unicode default-ignorables that can split detector-visible identifiers; and removes ZWNJ/ZWJ only inside ASCII
identifier-like runs while preserving them in supported-language text. HTML extraction retains visible text, safe
natural accessibility/form attributes, Outlook conditional content, `noscript`, and inline SVG text, while excluding
resource URLs, scripts, styles, and ordinary comments.

Explicit MIME handling retains every bounded non-attachment `text/*` subtype, visible multipart preambles and
epilogues, all distinct alternatives, and selected visible/thread headers plus the body of inline `message/rfc822`
parts. Transfer and charset failures have separate unsupported-versus-invalid reason codes. Declared attachments and
unsupported non-text payloads remain outside coverage and are counted. Ambiguous material stays visible. Signatures and
templates stay in recall-bearing views because deleting them would make privacy recall look artificially better.

Dates use a frozen policy hash: ISO-8601 parsing is attempted before RFC-2822 parsing, timezone-naive values are marked
ambiguous and ineligible, and the temporal-eligibility interval is
`[1990-01-01T00:00:00Z, 2011-01-01T00:00:00Z)`. Parseable outliers remain recorded but are not eligible for temporal
splitting.

The production defaults cover the published source's observed maximum body and recipient sizes. Smaller explicit limits
are allowed for adversarial fixtures; every body, subject, or recipient truncation is counted. A promoted quality run
must report truncated/excluded coverage and must not claim recall over bytes it did not evaluate.

## Private transaction and artifacts

The final directory must not already exist. Inside a Git workspace it must be ignored, normally beneath `.nerb/`.
`--allow-unignored-output` is an explicit escape hatch for a private location, but it never disables ancestor-symlink,
no-follow, exclusive-create, or permission checks.

The private transaction currently requires POSIX directory descriptors, no-follow opens, follow-safe chmod, directory
fsync, and a kernel no-replace rename primitive (Linux or macOS). It fails before creating staging data on platforms
that cannot provide the same boundary; the cross-platform cleaner remains usable as a Python API, but a weaker private
writer is not substituted silently.

Preparation builds a random sibling staging directory with mode `0700`, creates files with mode `0600`, flushes and
validates the tree, writes `COMMITTED` last, and atomically promotes the directory without replacement. Failures remove
owned staging data and cannot overwrite a previous run. If the operating system prevents cleanup (for example after a
permission change), the cleanup failure is surfaced even when another exception is active; any residue remains private
but requires explicit operator cleanup.

The committed directory contains:

- `prepared.jsonl`: private PII-bearing records (`nerb.enron_prepared_record.v2`);
- `rejections.jsonl`: private deterministic source digests, safe reason codes, occurrence counts, and
  truncation-before-rejection flags for every excluded source row;
- `profile.json`: deterministic aggregate-only diagnostics (`nerb.enron_preparation_profile.v2`);
- `manifest.json`: hashes and semantic bindings for the canonical artifacts;
- `transport-receipt.json`: noncanonical local byte hash and run timing, intentionally excluded from deterministic
  artifact identity; and
- `COMMITTED`: completion marker written only after validation and synchronization.

`profile.json` and `manifest.json` contain no message text, addresses, message IDs, filenames, absolute paths, or
per-record hashes. They report conservation counts, fixed size histograms, coarse date range/status counts, cleaning
transforms, duplicate-group histograms, feature availability, policy/code hashes, and whole-artifact hashes. The verifier
checks file hashes, canonical ordering, record counts, privacy-safe aggregate structure, and manifest/profile bindings
without returning private prepared text.

Dataset, revision, and split labels are intentionally public provenance and must use bounded identifier tokens; free-form
names or descriptions are rejected rather than copied into aggregate output.

Rejected rows never disappear from the coverage denominator. This includes blank JSONL lines, malformed transport,
schema failures, and cleaning failures. The profile conserves input occurrences as prepared plus rejected, while the
private rejection ledger lets an authorized auditor locate excluded source commitments without putting text,
addresses, filenames, or parser excerpts into aggregate output.

Deep verification treats every artifact schema as closed. It recomputes view commitments, cleaning/date/size/grouping
aggregates, source conservation, rejection reasons and truncation flags, duplicate histograms, and grouping features;
it also binds the exact code, NERB, Python, and Unicode versions. Duplicate verification uses a private disk-backed
hash-only spool so full-corpus verification stays memory-bounded.

Unicode normalization and case folding depend on the runtime Unicode database. The profile therefore records the Python
implementation/version and `unicodedata` version in addition to the preparation implementation hash. Reuse that exact
runtime for deep verification and downstream grouping; changing Python or Unicode data creates a different preparation
environment even when the source revision is unchanged.

Raw source, prepared records, and any later banks remain sensitive even when they are pseudonymous or hashed. Keep the
run under the authorized retention and access policy; do not commit, publish, or use it to contact or profile people.
After this run verifies, use the [immutable split workflow](enron-splits.md) to create the development and separately
controlled steward bundles; do not manually divide or copy prepared rows into roles.
