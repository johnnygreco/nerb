# Rust Engine Semantics Decision Record

Date: 2026-06-04

Status: accepted for the Rust engine migration baseline.

Tracker: <https://github.com/johnnygreco/nerb/issues/45>

Implementation issue: <https://github.com/johnnygreco/nerb/issues/46>

## Context

The Rust engine migration changes NERB from the current Python `re` regex builder into a package with Python as the
authoring/control plane and Rust as the matching data plane. This is a planned breaking migration: the Rust engine
behavior is the target, and the current Python object model does not constrain the design. Silent semantic drift is
unacceptable. Every planned engine mode must either satisfy this record or be documented as a deliberate divergence.

Current Python surfaces expose useful differential oracles. These oracles help identify and name semantic changes; they
do not define the target surface.

- Current `NERB` extraction returns `entity`, `name`, `string`, `start`, and `end` records with Python string offsets.
- JSON-bank extraction returns richer pattern identity, but still reports offsets over Python strings.

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

The conformance oracle converts current Python character offsets to UTF-8 byte offsets in tests only.

### Attribution

Attribution is part of correctness. Conformance checks must compare entity and detector identity, not just spans. For
current Python `NERB` records, the test oracle maps `name` to both `canonical_name` and `surface_name`. Native JSON-bank
records will keep the two concepts separate once Rust canonicalization exists.

Current `NERB` loses information when detector names contain underscores because spaces are converted to underscores for
Python capture groups and then underscores are converted back to spaces on extraction. The Rust engine must not inherit
that limitation. The Slice 0 fixtures mark this as a known Python-oracle divergence instead of behavior to carry forward.

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
Existing Python validation may accept some of these patterns because they are valid Python `re`; those cases are
deliberate migration divergences. ReDoS-shaped patterns and compile-bomb-shaped patterns are fixture categories for the
conformance and validation gates even when the current Python path can compile them.

Entity-level `_flags` map into per-pattern engine flags during Rust canonicalization. The direct migration set is
`IGNORECASE`, `MULTILINE`, `DOTALL`, `VERBOSE`, and `ASCII`; unsupported flags fail validation.

`add_word_boundaries` remains a first-class bank option, but Rust canonicalization must apply it with explicit boundary
rules instead of the current string substitution trick.

## Entity Cardinality Assumption

No real bank-owner cardinality target is recorded in this repository yet. Current checked-in evidence is small:

- `tests/data/minimal_bank.json`: 1 entity.
- `examples/music_entities.yaml`: 2 entities.

The working assumption for `entity_independent` is order-tens of entities with many patterns per entity. Before the
Rust engine becomes the default, the tracker must record expected entity count and growth from the bank owner. If the
real bank is expected to grow beyond order-tens of entity classes, Slice 6 (`all_overlaps`) becomes a prerequisite for
the default strategy rather than an optional optimization.

## Deterministic Output Order

Projected Rust-backed records sort by:

```text
start byte, end byte, entity, canonical_name, surface_name, matched string
```

Raw Rust buffers may also include detector indexes in the internal sort key. Public records do not expose detector
indexes in this baseline schema.

## Required Conformance Fixture Categories

The differential conformance suite must cover these categories before Rust matching can replace Python matching:

- non-ASCII text before a match, proving character-to-byte offset conversion;
- cross-entity overlap;
- within-entity leftmost-first overlap, including source-order priority ties;
- nickname-inside-project overlap;
- ordered alternation ties;
- underscores in detector names as a known Python-oracle divergence;
- word-boundary behavior, including a Unicode boundary fixture that ASCII-only boundaries would fail;
- direct flag migration behavior for `IGNORECASE`, `MULTILINE`, `DOTALL`, `VERBOSE`, and `ASCII`;
- unsupported backtracking-only regex syntax;
- ReDoS-shaped regexes;
- compile-bomb-shaped regexes.

## Consequences

The first Rust implementation can stay thin and correct by compiling one matcher per entity. It does not need recursive
walking, chunked streaming, serialized automata, DFA caches, or Hyperscan/Vectorscan. Those remain backlog unless the
benchmark gate proves a concrete gap.
