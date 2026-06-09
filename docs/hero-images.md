# Benchmark-Grounded Hero Image Direction

These hero concepts position NERB as a local intelligence cache for LLM agents: a compact, reusable entity bank built
from large source data, validated by a held-out benchmark, and improved through a measured autoresearch loop.

The images are intentionally abstract. They must not show raw Enron email text, names, addresses, screenshots, code
snippets, or in-image performance numbers. When a page needs numeric claims, put those claims in adjacent copy that cites
the benchmark or tracker evidence rather than encoding them into the artwork.

## Assets

Committed JPEG previews live under `examples/artifacts/hero-images/`:

- `nerb-intelligence-cache.jpg`
- `corpus-to-entity-bank.jpg`
- `autoresearch-loop.jpg`

They were generated on 2026-06-09 with the built-in image generation tool and converted to JPEG with:

```shell
sips -s format jpeg -s formatOptions 88 <source.png> --out examples/artifacts/hero-images/<asset>.jpg
```

The committed files are 1672x941 hero-background previews, suitable for docs, PR review, and later site composition.

## Concept 1: Intelligence Cache Beside The Model

Asset: `examples/artifacts/hero-images/nerb-intelligence-cache.jpg`

Audience: developers and agent builders deciding where entity memory should live in an LLM workflow.

Message: NERB is a local, explainable, reusable entity-memory layer that sits beside model reasoning instead of hiding
inside a prompt or remote service.

Composition: a compact crystalline entity bank slightly left of center, connected by deterministic extraction lanes to
an abstract reasoning core. The right side keeps enough open space for future hero copy.

Factual benchmark anchor: NERB builds validated JSON banks, scans locally with a Rust-backed engine, and reuses compiled
banks through process-local cache behavior measured by the Enron construction benchmark.

Recommended use: primary landing or README hero when the page headline is about NERB as an intelligence cache for
agents.

Prompt:

```text
Use case: ads-marketing
Asset type: website hero background, 16:9 landscape, high-resolution bitmap
Primary request: Create a polished hero image for NERB, a local named-entity regex bank tool positioned as an intelligence cache for LLM agents. Show a compact glowing structured entity bank/cache module beside a large abstract AI reasoning core, with deterministic extraction paths flowing between them. The scene should communicate local, explainable, reusable entity memory and fast retrieval without showing real text.
Scene/backdrop: modern technical workspace, dark neutral interface environment with subtle glass panels and hardware-like cache elements, cinematic but restrained.
Subject: a compact crystalline data bank with organized entity nodes, connected to an abstract LLM core represented by layered luminous circuits and memory lanes.
Composition: wide hero composition with strong first-viewport subject, primary object slightly left of center, open negative space for future headline overlay on the right, no card frame, no split layout.
Style: sophisticated product visualization, realistic 3D render with crisp details, restrained palette using graphite, white, teal, amber accents; avoid one-note purple/blue gradients.
Factual anchor: optimized NERB construction and cached entity-bank reuse; represent as aggregate flows and reusable memory, not numeric claims.
Avoid: no readable text, no logos, no raw email screenshots, no personal names, no fake UI copy, no watermark, no cluttered dashboards, no humanoid robots.
```

## Concept 2: Corpus Stream To Entity Bank

Asset: `examples/artifacts/hero-images/corpus-to-entity-bank.jpg`

Audience: data, ML, and platform engineers evaluating large-corpus workflows.

Message: a large private corpus can be transformed into aggregate, reusable entity-bank structure without committing raw
source text.

Composition: blurred document and envelope shapes stream from the left through deterministic lanes into a compact bank
on the right. The image emphasizes compression, filtering, and structured reuse rather than individual records.

Factual benchmark anchor: the Enron benchmark prepares deterministic train/test splits, keeps raw and cleaned corpus
artifacts out of git, and commits only scripts, tiny fixtures, aggregate metrics, benchmark summaries, and generated
visuals.

Recommended use: benchmark or data-prep pages where the story is "large source to reusable entity memory" and privacy
guardrails are important.

Prompt:

```text
Use case: ads-marketing
Asset type: website hero background, 16:9 landscape, high-resolution bitmap
Primary request: Create a hero image for NERB showing a large anonymous email corpus being transformed into a compact structured entity bank. Communicate Enron-scale email stream cleaning, deterministic train/test split, aggregate quality checks, and privacy-safe entity memory without displaying any readable email text.
Scene/backdrop: abstract data refinery for documents, with thousands of pale paper-like shards and envelopes entering from the far left as blurred shapes, passing through clean deterministic lanes, and compressing into a precise compact bank of entity tokens on the right.
Subject: a privacy-safe transformation pipeline from raw document volume into an organized reusable entity-memory block.
Composition: cinematic wide banner, strong diagonal flow left-to-right, central compression/funnel moment, right side has clear compact bank object; leave upper-left negative space for future copy overlay.
Style: editorial technical visualization, premium 3D/photoreal hybrid, quiet enterprise product feel, graphite and soft white base with teal and amber accents; avoid purple gradients and stock-photo people.
Factual anchor: raw/private corpus stays abstract, committed artifacts are aggregate metrics and bank structures; no unsupported performance numbers in image.
Avoid: no readable text, no real emails, no names, no addresses, no screenshots, no UI labels, no logos, no watermark, no people, no messy spam imagery.
```

## Concept 3: Autoresearch Evaluation Loop

Asset: `examples/artifacts/hero-images/autoresearch-loop.jpg`

Audience: teams using coding agents to improve infrastructure while keeping benchmark and review discipline.

Message: candidate bank-construction changes are scored against a fixed evaluator, logged, and kept or discarded before
normal PR review.

Composition: a circular evaluation track around an immutable evaluator core, with accepted candidates flowing toward a
structured entity-bank cache and rejected candidates fading out safely. Abstract ledger tiles imply JSONL results without
readable text.

Factual benchmark anchor: the NERB autoresearch harness runs a fixed candidate command, extracts a scalar score, appends
aggregate-only JSONL rows, enforces editable/frozen path gates, and treats green CI plus independent review as merge
requirements.

Recommended use: pages or posts about agentic optimization, measured construction improvements, and safe keep/discard
experimentation.

Prompt:

```text
Use case: ads-marketing
Asset type: website hero background, 16:9 landscape, high-resolution bitmap
Primary request: Create a hero image for NERB's autoresearch loop: an autonomous coding agent evaluates bank-construction experiments against a frozen benchmark, logs a result, then keeps or discards the candidate. The visual should show a measured optimization loop with safeguards, not a chaotic robot scene.
Scene/backdrop: clean technical lab with a circular evaluation track, checkpoint marker, immutable evaluator core, compact result ledger, and branching paths for keep/discard decisions.
Subject: an elegant loop of luminous experiment capsules moving around a fixed evaluator core, with one candidate capsule being accepted into a structured entity-bank cache and another fading out safely.
Composition: wide 16:9 hero, evaluator core centered but not crowded, loop arcs around it, foreground has subtle ledger tiles with abstract marks only, leave top-right negative space for overlay text.
Style: premium product/technical render, restrained dark graphite background with white, teal, and amber accents, precise and trustworthy, no cartoon robots, no busy dashboard.
Factual anchor: fixed evaluator, scalar score, JSONL result logging, keep/discard mechanics, green CI/review gates; communicate as abstract controls and paths, not literal text.
Avoid: no readable text, no numbers, no code snippets, no email data, no people, no robots, no logos, no watermark, no fake product claims.
```

## Usage Guidance

- Use each image as a full-bleed or wide hero background with restrained overlay copy; do not place the image inside a
  decorative card.
- Keep factual copy near the image tied to `docs/enron-benchmark.md`, `docs/autoresearch.md`, or merged PR evidence.
- Prefer aggregate terms such as "entity bank", "held-out benchmark", "local cache", and "keep/discard loop" over claims
  that imply broad model intelligence or unsupported production performance.
- If a future generated variant includes readable text, names, addresses, code, or numbers, discard it or edit it before
  committing.
