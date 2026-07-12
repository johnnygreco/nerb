# Enron Immutable Splits

The split stage turns one committed [Enron preparation run](enron-preparation.md) into two private, immutable bundles:
a development bundle containing train and validation data, and a separately controlled steward bundle containing the
sealed final test. It creates leakage groups, assigns whole groups to roles, derives privacy-safe cohort counts, and
records deterministic diagnostic samples. It does not build a bank, create labels, run quality evaluation, or make a
benchmark result promotable.

For a production split, keep the steward output outside the builder's access boundary:

```shell
uv run nerb split-enron \
  --preparation-run .nerb/enron-preparation/run \
  --development-output-dir .nerb/enron-splits/development \
  --sealed-output-dir /authorized/steward/enron-test \
  --benchmark-version enron-v2 \
  --seed nerb-enron-v2-split-v1
```

Verify both committed bundles from the steward environment:

```shell
uv run nerb verify-enron-splits \
  --development-dir .nerb/enron-splits/development \
  --sealed-dir /authorized/steward/enron-test \
  --seed nerb-enron-v2-split-v1
```

Verification requires the original seed and checks it against the aggregate seed commitment; a custom split seed must
be supplied again to the steward verifier without being published in the development manifest.

For a tiny synthetic fixture, add `--fixture-mode` to `split-enron`. Fixture mode relaxes the production support floors
so leakage and sealing behavior can be tested on small inputs. Its manifests are permanently marked non-promotable and
cannot support a quality, privacy, performance, or product claim.

## Two private bundles

The development and sealed directories are distinct private transactions. Each final directory must not already exist;
inside a Git workspace it must be ignored. They inherit the preparation pipeline's no-follow, exclusive-create,
private-permission, synchronization, and atomic no-replace requirements.

The sealed transaction commits first and the development transaction commits second. Only after both commits succeed
does the splitter create `PAIR_COMMITTED.json` in the sealed root, binding both manifests and the development freeze
receipt. Steward verification and final-test access reject a missing or mismatched pair receipt, so an orphaned sealed
transaction cannot become an access capability after a partial two-directory commit. Pair, claim, and outcome receipts
are written to private staging files inside the pinned bundle, synchronized, inode-checked, and then published atomically
without replacement. This needs write access only to the 0700 bundle, not its parent. A recognizable partial staging
file left by process death is lock-checked and removed before later inventory validation; a published receipt is always
complete.

- The **development bundle** contains train and validation records, their private group membership and cohort material,
  and bounded diagnostic samples. Candidate miners, bank builders, reviewers, and validation experiments may use this
  bundle.
- The **steward bundle** contains final-test records and the private material needed to audit and run the final release
  evaluation. It belongs in a different access-controlled location and, in production, should be held by a different
  account or release steward.

Both bundles contain real communications and remain sensitive even when a field is hashed or pseudonymous. Do not
commit them, publish them, place them in an agent prompt, or copy the steward bundle into a development environment.
Only bounded aggregate counts, policy identities, and whole-artifact commitments are candidates for later public
evidence, and those still require the benchmark privacy verifier.

The separation is an operational and capability boundary, not cryptographic protection from the same operating-system
user. A user who can bypass the API and read both directories can read the sealed bytes. Use filesystem ownership,
least privilege, encryption at rest where practical, and a distinct steward account or machine when the threat model
requires protection from builders. The verifier rejects hard-linked run files, but an ordinary byte-for-byte directory
copy can still create another local claim namespace; an external append-only custody/lineage ledger remains mandatory
when the same OS principal can copy the steward bundle.

## Leakage components

Assignment operates on the transitive closure of leakage edges, never on individual prepared records. If A links to B
and B links to C under any combination of policies, all three records form one indivisible component. The frozen policy
joins records through four evidence families:

1. **Exact content:** matching non-empty prepared-view commitments join duplicate mailbox copies and repeated content.
2. **References:** a normalized message identifier joins the same normalized identifier found in another record's
   bounded `Message-ID`, `In-Reply-To`, or `References` evidence.
3. **Threads:** a matching non-empty frozen thread subject plus at least one shared normalized structured participant
   joins likely reply/forward relatives even when transport identifiers are missing. Subject or identity alone does not.
4. **Radius-3 near duplicates:** the prepared 64-bit SimHash signatures for the current/core and full-visible views are
   divided into five bands and indexed by all ten pairs of band positions. Candidates are joined only when their full
   Hamming distance is at most three and each signature has at least 12 tokens and eight shingles.

The radius is deliberately narrow: it catches answer-sharing edits while bounding accidental giant components and
comparison cost. With at most three changed bits, at least two of five bands remain unchanged, so paired-band indexing
is complete for the declared radius while avoiding the tens of millions of candidates produced by four single-band
keys at this corpus size. Band matches are only an index; the full distance check decides the edge. The verifier
reconstructs the components from the prepared feature commitments and fails if a component crosses train, validation,
and test. A fail-closed candidate budget bounds both raw paired-band join emissions and unique full-distance comparisons;
per-node band-key deduplication makes the raw-emission preflight exact.
Empty features never become shared join keys. A largest component containing 5% or more of unique prepared records is a
production failure rather than permission to split an answer-sharing component.

## Temporal role assignment

The frozen target is 80% train, 10% validation, and 10% final test. Components that contain at least one temporally
eligible record are ordered by their **latest eligible member**. Whole components are assigned from older to newer, so
an old message connected to a later reply moves forward with that reply; the older copy cannot leak its answer into an
earlier role. Boundaries are deterministic component boundaries, not row cutoffs, so exact percentages may move enough
to preserve leakage integrity.

A component with no eligible date cannot support a temporal or future-data claim. Those components follow a separate,
deterministic seeded assignment policy based on their component identity, benchmark version, and split seed. They stay
explicitly ineligible in cohort and audit counts and are never silently included in the dated temporal denominator.
Changing the preparation run, benchmark version, split seed, or split policy creates a different split commitment.
Input row order does not. A version bump by itself is not a fresh final test: most temporal membership can remain the
same. After any final-test access, a successor must bind a genuinely different test population or split policy and the
lineage verifier must reject a repeated test artifact hash.

## Cohorts and samples

Identity recurrence is computed from hashed source identities in **train only**. A validation or test identity does not
become known merely because it occurs elsewhere in a held-out role. Held-out records retain explicit known, novel,
mixed, and unavailable states where applicable. Frequency buckets count distinct train leakage groups: novel is zero,
tail is one, mid is two through nine, and head is at least ten. No final-test frequency is fed back into their
definition. Natural-body and structured-header
availability, mailbox/thread/date challenges, and other declared diagnostics remain separate cohort dimensions.

The source does not provide exhaustive independent labels for sensitive-negative documents. Consequently the split
stage marks the negative-document cohort unsupported. An empty structured header, an absent known identity, or no NERB
prediction is not evidence that a message contains no PII. A later evaluator may add a negative cohort only from an
independently and exhaustively labeled population with a declared annotation scope.

Bounded review samples are diagnostics, not the quality population. The sampler apportions its per-role budget across
declared non-empty base strata with deterministic Hamilton largest-remainder allocation, then selects records by seeded
minimum hash. Before that allocation it reserves deterministic coverage for every non-empty date-status,
identity-frequency, natural/structured-availability, and challenge-family margin. This guarantees rare named cohorts a
review surface without creating a potentially explosive Cartesian stratum. The default ceiling is 10,000 records per
role; a production run fails if that budget cannot cover all required reservations. This makes the sample representative
and row-order independent without exposing arbitrary first rows. It does not authorize sample-only recall, precision,
false-alarm, or promotion claims: quality gates use every applicable document in the frozen full role/cohort population.

## Production support floors

A production run fails closed unless all of the following hold:

- each role contains at least the greater of 5% of unique prepared records or 10,000 records;
- each role contains at least 1,000 leakage components;
- the largest leakage component contains less than 5% of unique prepared records; and
- validation and final test each contain at least 100 records in every required known, novel, head, tail, natural-body,
  and structured-header cohort.

These are split-integrity floors, not evidence that a role is sufficiently or exhaustively labeled. The later quality
contract applies its own support floors. Fixture mode relaxes the split floors only; its non-promotable marker cannot be
removed by accumulating more records or by copying fixture artifacts into a production directory.

## Sealed-test access

Normal split readers expose only train and validation. They reject a request for the final-test role; a filesystem path
or role string is not a test-access capability. Verification may validate commitments and aggregate split invariants in
the steward environment, but it must not return test records, identities, memberships, samples, or per-document
diagnostics to development callers.

Final-test bytes are available only through the explicit steward release-access path for a fully frozen benchmark
target, including the exact final-test artifact hash. That path durably creates the one-shot access claim **before**
yielding the first test byte. A crash, exception, partial read, or caller cancellation after the claim still counts as
the benchmark's single access. There is no retry for that benchmark version, because retry semantics would turn
failures into selective test access. An aborted or failed outcome enters the append-only benchmark lineage; further
tuning requires a disclosed successor benchmark version and a newly sealed test whose artifact hash has not already
appeared in the trusted lineage.

If a steward process dies after the valid claim is durable but before an outcome is written, the claim still consumes
the one permitted access. `finalize_aborted_enron_final_test_access` can append an `aborted` outcome after validating the
claim and pair receipt; it never opens the test artifact and cannot authorize a retry.

Run `verify-enron-splits` before freezing the bank, evaluator, thresholds, claims, and workload for release. Once the
frozen target has been bound and access is claimed, treat every result as final-test evidence rather than development
feedback. See the [Enron charter](enron-benchmark.md#sealed-train-validation-and-test-policy) for the quality and
promotion rules that apply after splitting.

Before any release freeze, a builder may pass only the development bundle to the
[train-only bank construction workflow](enron-bank-building.md). That command has no sealed-test path or role selector.
