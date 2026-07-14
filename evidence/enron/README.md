# Enron benchmark evidence

`capacity-decision.json` is the privacy-scanned, aggregate-only result of the full-source capacity prerequisite for the
Enron benchmark. It binds the complete 517,401-row source run, the seven-receipt attempt chain, the measured Git and
native identities, all resource observations, deterministic deep replay, and the sealed-access state.

This is deliberately a `pre_terminal_non_decision` artifact. It proves that the frozen construction and validation
workflow completes at representative scale within its preregistered resource gates. It does **not** contain sealed-test
quality results and does not support a final ship/no-ship decision. The sealed test remained `sealed_unbound` and
unopened throughout this run.

## Verify from a clean clone

Keep complete Git history so the measured commit remains reachable, then run:

```shell
uv run nerb verify-portable-enron-capacity \
  --artifact evidence/enron/capacity-decision.json
```

The verifier checks closed report arithmetic and hashes, the full attempt chain and terminal cross-bindings, the
measured commit and root tree, tracked source blobs, the reader lock, and the native build-source commitment.

## Frozen identities

| Identity | Value |
| --- | --- |
| Measured commit | `bd573361010fbb87198480eb2ed36a824e332c73` |
| Measured root tree | `d3990c8d9fa01b36c490713569f3dbd40d2c9317` |
| Artifact file SHA-256 | `441d90fc64d45d6febdd2a8ee13d9db25c712d195f4414ca6acb9bf1268ddca2` |
| Portable decision SHA-256 | `sha256:6f49646db68c767471ddc0d58bc429febba75085460c06c98f7c2a7626447919` |
| Capacity report SHA-256 | `sha256:7ff338badbfefcd7ad9202ed47bb049fb0e317612532488d09c97859a8407af1` |
| Terminal attempt SHA-256 | `sha256:2e2a6f1f2dca87004b82ad0e7fd71515260668854efd07d32bc17e1fb6374c1a` |

## Capacity result

| Metric | Measured | Frozen gate |
| --- | ---: | ---: |
| Source rows accounted | 517,401 | exactly 517,401 |
| Total report wall time | 5,888.611 s | at most 14,400 s |
| Peak process-tree RSS | 3,122,921,472 bytes | at most 6,442,450,944 bytes |
| Owned-disk high-water | 16,424,824,832 bytes | at most 20 GiB |
| Minimum runtime free disk | 23,774,683,136 bytes | at least 5 GiB |
| Maximum resource acquisition | 92.436 ms | at most 500 ms |
| Maximum resource-observation gap | 193.056 ms | at most 500 ms |
| Report resource observations | 54,738 | continuous monitoring required |
| Resource acquisition retries | 0 | aggregate evidence only |
| Privacy-scan violations | 0 | exactly 0 |

Every phase cleared the frozen 100 records/s floor:

| Phase | Records | Elapsed | Throughput |
| --- | ---: | ---: | ---: |
| Preparation | 517,401 | 2,288.518 s | 226.085 records/s |
| Split | 517,179 | 2,371.578 s | 218.073 records/s |
| Bank build | 413,752 | 535.471 s | 772.688 records/s |
| Streaming validation | 51,723 | 46.614 s | 1,109.611 records/s |
| Deep replay | 465,475 | 642.474 s | 724.504 records/s |

All closed gates passed, including source conservation, runtime/RSS/disk limits, observation and verified-work cadence,
commitment-chain integrity, deterministic replay equality, private-tombstone bounds, and sealed-access stability.

## Privacy and verification boundary

The artifact contains no raw messages, candidate values, detector values, document IDs, correctness rows, private paths,
or private payloads. It contains only aggregate counts, timings, resource samples, hashes, and closed receipts.

The clean-clone verifier does not recreate the original private payload, independently prove the recorded timing/RSS/disk
observations, re-attest the original promoted inode, or reproduce the native binary bytes. Those limitations are encoded
and hash-bound in `verification_scope`. Regenerate this artifact only from a fresh, successful production capacity run;
do not edit it by hand.
