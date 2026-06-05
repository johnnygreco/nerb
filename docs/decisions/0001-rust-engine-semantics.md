# Rust Engine Semantics Decision Record

Date: 2026-06-04

Status: accepted for the Rust engine migration baseline.

Tracker: <https://github.com/johnnygreco/nerb/issues/45>

Implementation issue: <https://github.com/johnnygreco/nerb/issues/46>

## Context

The Rust engine migration changes NERB into a package with Python as the authoring/control plane and Rust as the matching
data plane. This is a planned breaking migration: the Rust engine behavior is the target, and the removed Python regex
object model does not constrain the design. Silent semantic drift is unacceptable. Every planned engine mode must either
satisfy this record or be documented as a deliberate divergence.

The pre-removal Python surfaces were useful differential oracles during migration. They helped identify and name semantic
changes, but they do not define the target surface.

The Rust engine will store and sort raw byte spans. Python projection can optionally convert to character offsets for
explicit text callers, but that conversion is outside the Rust scan benchmark.

## Decisions

### Document And Offset Model

NERB is a text detector. Native file/path scanning accepts valid UTF-8 and reports byte offsets by default. It fails
clearly on invalid UTF-8 instead of applying lossy decoding. Callers that need a different error policy must decode in
Python first and pass text explicitly.

New public Rust-backed records use this schema:

```json
{
  "entity": "PERSON",
  "canonical_name": "John Doe",
  "surface_name": "JD",
  "string": "JD",
  "start": 1024,
  "end": 1026,
  "offset_unit": "byte"
}
```

Conformance tests compare Rust byte-offset records directly against the planned record schema.

### Attribution

Attribution is part of correctness. Conformance checks must compare entity and detector identity, not just spans. Native
JSON-bank records keep `canonical_name` and `surface_name` explicit.

Detector names with underscores are preserved by the Rust engine because pattern names no longer round-trip through
Python capture group syntax.

### Overlap Contract

Cross-entity overlap is reported. If `PERSON/Sam` and `PROJECT/Samba` both match bytes starting at zero, both records
are part of the correct output.

Within an entity, the production default preserves leftmost-first behavior. Source order is the default priority unless
a canonical bank explicitly sets `priority`. A leftmost-first entity scan reports one winner for an overlapping region
and honors ordered alternation preference inside a pattern.

Within-pattern alternation also follows leftmost-first semantics in the production default. `Sam|Samwise` over
`Samwise` emits `Sam`; `Samwise|Sam` emits `Samwise`.

The default production mode is therefore `entity_independent`: one logical matcher per entity, `LeftmostFirst` within
the entity, cross-entity overlap by running every entity, and deterministic output sorting after raw matches are
collected.

### Non-Default Modes

`all_overlaps` has a different semantic contract. It reports cross-entity overlap, within-entity overlap, and all
matching spans for each detector pattern unless a reconstruction step restores leftmost-first behavior. It does not
preserve branch identity inside one regex; attribution remains at the NERB detector index. Slice 6 showed that a
span-only raw-candidate post-filter is not sufficient to prove exact reconstruction: `MatchKind::All` can expose the
shorter span of one detector such as `Sam` from `Samwise|Sam`, while leftmost-first semantics choose `Samwise` when that
branch appears first. The prototype therefore keeps raw `all_overlaps` output separate from an exact reconstruction
measurement path that reruns the entity-independent shards after measuring raw overlap scan cost. It must remain a
measured prototype until raw semantics, reconstruction cost, and dense-hit match amplification justify a mode strategy
change.

The Slice 6 lower-level DFA prototype rejects Unicode word-boundary assertions such as `\b`. `regex-automata` hybrid DFA
support for Unicode boundaries is heuristic and can quit on valid non-ASCII UTF-8, which is not an acceptable runtime
failure mode for NERB text scans. Raw `all_overlaps` can still use explicit ASCII word-boundary syntax such as
`(?-u:\b)`, while Unicode boundary semantics stay on the `entity_independent` path unless a later issue adds a measured
fallback.

`global_leftmost` is an internal throughput baseline only. It compiles one combined meta matcher in `LeftmostFirst` mode,
collapses cross-entity overlap to one winner per region, and must not become the default extraction behavior without a
separate product decision. Native metadata labels it `internal_benchmark_only` with `production_default: false` and
`internal_only: true`.

### Regex Profile

The Rust regex profile rejects constructs that require a backtracking engine, including backreferences and lookaround.
Earlier Python validation accepted some of these patterns because they were valid Python `re`; those cases are deliberate
migration divergences. ReDoS-shaped patterns and compile-bomb-shaped patterns are fixture categories for the conformance
and validation gates even when the removed Python path could compile them.

Entity-level `_flags` map into per-pattern engine flags during Rust canonicalization. The current direct migration set is
`IGNORECASE`, `MULTILINE`, `DOTALL`, `VERBOSE`, and `ASCII`. `ASCII` lowers only ASCII-sensitive escapes and boundaries
such as `\w`, `\d`, `\s`, and `\b`; the rest of the pattern stays in the UTF-8-safe Unicode regex mode. Unsupported flags
fail validation.

`word_boundaries` remains a first-class `Bank.from_config` and compile-option behavior, and Rust canonicalization applies
it with explicit boundary rules rather than Python-side regex string substitution.

## Entity Cardinality Assumption

No real bank-owner cardinality target is recorded in this repository yet. Current checked-in evidence is small:

- `tests/data/minimal_bank.json`: 1 entity.
- `examples/music_entities.yaml`: 2 entities.

The working assumption for `entity_independent` is order-tens of entities with many patterns per entity. Slice 10 adds
synthetic order-tens evidence, but the real bank-owner target remains unrecorded. If the real bank is expected to grow
beyond the order-tens entity range validated by Slice 10, open a new issue before changing the default mode strategy.

## Slice 10 Gate Decision

Slice 10 gate evidence keeps `entity_independent` as the production default for the current Rust engine path. The routine
gate report in `docs/rust-engine-gates.md` measured a dense two-entity prefix workload where production
`entity_independent` emitted 32 matches, raw `all_overlaps` emitted 31,776 matches, exact `all_overlaps` reconstruction
matched the production raw tuples, and `global_leftmost` emitted 16 matches. That means raw `all_overlaps` amplified
materialized output by 993x, while `global_leftmost` dropped half of the valid cross-entity production matches.

Slice 10 also adds a synthetic entity-cardinality sweep with 2, 8, and 32 entities. With 8 dense prefix detectors per
entity over 256 bytes, `entity_independent` produced 64, 256, and 1,024 matches respectively; raw `all_overlaps`
produced 4,040, 16,160, and 64,640 matches; and `global_leftmost` produced 32 matches in each case because it collapses
cross-entity overlap to one global winner per region. Exact reconstruction matched the production tuples in all sweep
cases. The sweep gates order-tens performance as well: the dense 32-entity `entity_independent` raw scan must stay under
0.01s, and the dense 32-to-2 `entity_independent` scan-time ratio must stay under 40x. A separate sparse no-match
routine-size probe scans the configured target bytes with 2 and 32 entities; its 32-entity `entity_independent` raw scan
must stay under 0.05s, and its 32-to-2 `entity_independent` ratio must stay under 40x.

The mode strategy is therefore locked for the current Rust engine path and the order-tens entity-cardinality assumption:

- `entity_independent` remains the only production-default mode.
- `all_overlaps` remains an internal measured prototype until a future issue proves raw dense output and exact
  reconstruction cost are acceptable for real banks.
- `global_leftmost` remains an internal throughput baseline only and must not be used for production extraction because
  it violates the cross-entity overlap contract.

This decision does not close the missing bank-owner cardinality input. That input must be recorded before changing the
mode strategy or expanding beyond the order-tens range; any target beyond that range requires a new mode-strategy issue.

## Deterministic Output Order

Projected Rust-backed records sort by:

```text
start byte, end byte, entity, canonical_name, surface_name, matched string
```

Raw Rust buffers may also include detector indexes in the internal sort key. Public records do not expose detector
indexes in this baseline schema.

## Required Conformance Fixture Categories

The conformance suite covers these categories as evidence for the Rust-backed matching contract:

- non-ASCII text before a match, proving character-to-byte offset conversion;
- cross-entity overlap;
- within-entity leftmost-first overlap, including source-order priority ties;
- nickname-inside-project overlap;
- ordered alternation ties;
- underscores in detector names as a known Python-oracle divergence;
- word-boundary behavior, including a Unicode boundary fixture that ASCII-only boundaries would fail;
- direct flag migration behavior for `IGNORECASE`, `MULTILINE`, `DOTALL`, `VERBOSE`, and UTF-8-safe `ASCII` lowering;
- unsupported backtracking-only regex syntax;
- ReDoS-shaped regexes;
- compile-bomb-shaped regexes.

## Consequences

The first Rust implementation can stay thin and correct by compiling one matcher per entity. It does not need recursive
walking, chunked streaming, serialized automata, DFA caches, or Hyperscan/Vectorscan. Those remain backlog unless the
benchmark gate proves a concrete gap.
