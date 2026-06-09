from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path

import pytest

from nerb import validate_bank_schema
from nerb.enron_benchmark import (
    BANK_TIMESTAMP,
    DEFAULT_MAX_BASELINE_BENCHMARK_BYTES,
    PrepOptions,
    _gold_span_keys,
    _load_json_mapping,
    _parse_args,
    clean_email_text,
    main,
    prepare_enron_benchmark,
)


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> Path:
    path.write_text("\n".join(json.dumps(row, separators=(",", ":")) for row in rows) + "\n", encoding="utf-8")
    return path


def _options(input_jsonl: Path, output_dir: Path, *, created_at: str = "2026-06-09T00:00:00Z") -> PrepOptions:
    return PrepOptions(
        output_dir=output_dir,
        dataset_id="fixture/enron",
        dataset_split="train",
        dataset_revision="fixture",
        input_jsonl=input_jsonl,
        row_limit=None,
        sample_fraction=1.0,
        test_fraction=0.35,
        seed="fixture-seed",
        max_body_chars=1_000,
        max_addresses=20,
        max_domains=10,
        min_address_count=1,
        min_domain_count=1,
        benchmark_documents=5,
        quality_documents=5,
        benchmark_iterations=1,
        created_at=created_at,
        baseline_benchmark_json=None,
        max_cold_compile_seconds_ratio=None,
        max_warm_cached_compile_seconds_ratio=None,
        min_target_bytes_per_second_ratio=None,
    )


def test_clean_email_text_removes_headers_quotes_controls_and_reply_tail() -> None:
    raw = (
        "Message-ID: <1>\r\n"
        "Hello\x00  team,\n"
        "> quoted text\n"
        "\n"
        "Please review.\n"
        "-----Original Message-----\n"
        "From: hidden@example.com\n"
    )

    assert clean_email_text(raw) == "Hello team,\n\nPlease review."


def test_gold_span_keys_require_alphabetic_domain_tld() -> None:
    text = "Use version 1.2 on 2026.06.09, skip IP 10.20.30.40, email a@example.com, and visit research.example.org."

    spans = _gold_span_keys({"document_id": "doc", "text": text})
    surfaces = {(entity, text[start:end], normalized) for _document_id, entity, start, end, normalized in spans}

    assert ("email_address", "a@example.com", "a@example.com") in surfaces
    assert ("email_domain", "example.com", "example.com") in surfaces
    assert ("email_domain", "research.example.org", "research.example.org") in surfaces
    assert all(surface not in {"1.2", "2026.06.09", "10.20.30.40"} for _entity, surface, _normalized in surfaces)


def test_prepare_enron_benchmark_writes_deterministic_manifest_and_valid_bank(tmp_path: Path) -> None:
    rows: list[dict[str, object]] = [
        {
            "message_id": f"<fixture-{index}>",
            "subject": f"Deal {index}",
            "from": f"sender{index % 3}@enron.com",
            "to": [f"desk{index % 4}@enron.com", "outside@example.net"],
            "cc": [""],
            "bcc": [""],
            "body": f"Please send updates to desk{index % 4}@enron.com for Deal {index}.",
            "file_name": f"fixture/{index}",
        }
        for index in range(24)
    ]
    rows.append(dict(rows[0]))
    input_jsonl = _write_jsonl(tmp_path / "fixture.jsonl", rows)

    first = prepare_enron_benchmark(_options(input_jsonl, tmp_path / "first"))
    second = prepare_enron_benchmark(_options(input_jsonl, tmp_path / "second"))

    assert first["manifest"]["prep_summary"]["input_records"] == 25
    assert first["manifest"]["prep_summary"]["dropped_duplicate_message_id"] == 1
    assert first["manifest"]["prep_summary"]["selected_records"] == 24
    assert first["manifest"]["prep_summary"]["train_records"] > 0
    assert first["manifest"]["prep_summary"]["test_records"] > 0
    assert first["bank"]["schema_valid"] is True
    assert first["bank"]["stats"]["active_totals"]["patterns"] > 0
    assert first["quality"]["test"]["documents_with_records"] > 0
    assert first["quality"]["test"]["precision"] == 1.0
    assert first["quality"]["test"]["recall"] == 1.0
    assert first["quality"]["test"]["f1"] == 1.0
    assert first["quality"]["test"]["true_positive"] == first["quality"]["test"]["gold_count"]
    assert first["quality"]["test"]["false_positive"] == 0
    assert first["quality"]["test"]["false_negative"] == 0
    assert first["summary"]["test_f1"] == first["quality"]["test"]["f1"]
    assert first["benchmark"]["summary"]["cache_hit_verified"] is True
    assert first["benchmark"]["environment"]["python"]
    assert first["benchmark"]["environment"]["executable_name"]
    assert "executable" not in first["benchmark"]["environment"]
    assert first["manifest"]["environment"]["executable_name"]
    assert "executable" not in first["manifest"]["environment"]
    assert first["benchmark"]["bank"]["size"]["canonical_json_bytes"] > 0
    assert "compile_construction" in first["benchmark"]["stages"]
    assert first["gate"]["configured"] is False

    assert first["manifest"]["artifact_hashes"]["train"] == second["manifest"]["artifact_hashes"]["train"]
    assert first["manifest"]["artifact_hashes"]["test"] == second["manifest"]["artifact_hashes"]["test"]
    assert first["manifest"]["artifact_hashes"]["bank"] == second["manifest"]["artifact_hashes"]["bank"]
    assert first["manifest"]["artifact_sizes"]["train"] > 0
    assert first["manifest"]["artifact_sizes"]["test"] > 0
    assert first["manifest"]["artifact_sizes"]["bank"] > 0
    assert first["manifest"]["dataset"]["id"] == "fixture/enron"

    with open(Path(first["paths"]["bank"]), encoding="utf-8") as file:
        bank = json.load(file)
    assert validate_bank_schema(bank)["valid"] is True

    if os.name != "nt":
        assert (tmp_path / "first").stat().st_mode & 0o777 == 0o700
        assert Path(first["paths"]["train"]).stat().st_mode & 0o777 == 0o600
        assert Path(first["paths"]["test"]).stat().st_mode & 0o777 == 0o600
        assert Path(first["paths"]["bank"]).stat().st_mode & 0o777 == 0o600


def test_prepare_enron_benchmark_compares_against_stored_baseline_gate(tmp_path: Path) -> None:
    rows: list[dict[str, object]] = [
        {
            "message_id": f"<fixture-{index}>",
            "subject": f"Deal {index}",
            "from": f"sender{index % 3}@enron.com",
            "to": [f"desk{index % 4}@enron.com", "outside@example.net"],
            "body": f"Please send updates to desk{index % 4}@enron.com for Deal {index}.",
        }
        for index in range(24)
    ]
    input_jsonl = _write_jsonl(tmp_path / "fixture.jsonl", rows)
    baseline = prepare_enron_benchmark(_options(input_jsonl, tmp_path / "baseline"))
    baseline_path = Path(baseline["paths"]["benchmark"])

    candidate = prepare_enron_benchmark(
        replace(
            _options(input_jsonl, tmp_path / "candidate"),
            baseline_benchmark_json=baseline_path,
            max_cold_compile_seconds_ratio=100.0,
            max_warm_cached_compile_seconds_ratio=100.0,
            min_target_bytes_per_second_ratio=0.000001,
        )
    )

    assert candidate["gate"]["configured"] is True
    assert candidate["gate"]["passed"] is True
    assert candidate["gate"]["evaluator"]["passed"] is True
    assert {check["name"] for check in candidate["gate"]["quality"]["checks"]} == {
        "test_f1_delta",
        "test_precision_delta",
        "test_recall_delta",
    }
    assert {check["name"] for check in candidate["gate"]["performance"]["checks"]} == {
        "cold_compile_seconds_ratio",
        "warm_cached_compile_seconds_ratio",
        "target_bytes_per_second_ratio",
    }

    lower_quality = prepare_enron_benchmark(
        replace(
            _options(input_jsonl, tmp_path / "lower-quality-candidate"),
            baseline_benchmark_json=baseline_path,
            max_addresses=1,
            max_domains=1,
        )
    )

    assert lower_quality["gate"]["passed"] is False
    assert lower_quality["gate"]["evaluator"]["passed"] is True
    assert lower_quality["gate"]["quality"]["checks"][0]["name"] == "test_f1_delta"
    assert lower_quality["gate"]["quality"]["checks"][0]["actual"] < 0

    non_numeric_metric_baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    non_numeric_metric_baseline["benchmark"]["summary"]["cold_compile_seconds"] = "inf"
    non_numeric_metric_path = tmp_path / "non-numeric-metric-baseline.json"
    non_numeric_metric_path.write_text(json.dumps(non_numeric_metric_baseline), encoding="utf-8")

    non_numeric_metric = prepare_enron_benchmark(
        replace(
            _options(input_jsonl, tmp_path / "non-numeric-metric-candidate"),
            baseline_benchmark_json=non_numeric_metric_path,
            max_cold_compile_seconds_ratio=100.0,
        )
    )

    assert non_numeric_metric["gate"]["passed"] is False
    assert non_numeric_metric["gate"]["performance"]["checks"][0]["name"] == "cold_compile_seconds_ratio"
    assert non_numeric_metric["gate"]["performance"]["checks"][0]["actual"] is None

    negative_metric_baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    negative_metric_baseline["benchmark"]["summary"]["cold_compile_seconds"] = -1
    negative_metric_path = tmp_path / "negative-metric-baseline.json"
    negative_metric_path.write_text(json.dumps(negative_metric_baseline), encoding="utf-8")

    negative_metric = prepare_enron_benchmark(
        replace(
            _options(input_jsonl, tmp_path / "negative-metric-candidate"),
            baseline_benchmark_json=negative_metric_path,
            max_cold_compile_seconds_ratio=100.0,
        )
    )

    assert negative_metric["gate"]["passed"] is False
    assert negative_metric["gate"]["performance"]["checks"][0]["name"] == "cold_compile_seconds_ratio"
    assert negative_metric["gate"]["performance"]["checks"][0]["actual"] is None

    oversized_integer_metric_baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    oversized_integer_metric_baseline["benchmark"]["summary"]["cold_compile_seconds"] = 10**309
    oversized_integer_metric_path = tmp_path / "oversized-integer-metric-baseline.json"
    oversized_integer_metric_path.write_text(json.dumps(oversized_integer_metric_baseline), encoding="utf-8")

    oversized_integer_metric = prepare_enron_benchmark(
        replace(
            _options(input_jsonl, tmp_path / "oversized-integer-metric-candidate"),
            baseline_benchmark_json=oversized_integer_metric_path,
            max_cold_compile_seconds_ratio=100.0,
        )
    )

    assert oversized_integer_metric["gate"]["passed"] is False
    assert oversized_integer_metric["gate"]["performance"]["checks"][0]["name"] == "cold_compile_seconds_ratio"
    assert oversized_integer_metric["gate"]["performance"]["checks"][0]["actual"] is None

    missing_metric_baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    del missing_metric_baseline["benchmark"]["summary"]["cold_compile_seconds"]
    missing_metric_path = tmp_path / "missing-metric-baseline.json"
    missing_metric_path.write_text(json.dumps(missing_metric_baseline), encoding="utf-8")
    with pytest.raises(ValueError, match="benchmark.summary.cold_compile_seconds"):
        prepare_enron_benchmark(
            replace(
                _options(input_jsonl, tmp_path / "missing-metric-candidate"),
                baseline_benchmark_json=missing_metric_path,
                max_cold_compile_seconds_ratio=100.0,
            )
        )

    malformed_baseline_path = tmp_path / "malformed-baseline.json"
    malformed_baseline_path.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="manifest.dataset"):
        prepare_enron_benchmark(
            replace(
                _options(input_jsonl, tmp_path / "malformed-candidate"),
                baseline_benchmark_json=malformed_baseline_path,
            )
        )

    coerced_record_count_baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    coerced_record_count_baseline["quality"]["test"]["record_count"] = "1"
    coerced_record_count_path = tmp_path / "coerced-record-count-baseline.json"
    coerced_record_count_path.write_text(json.dumps(coerced_record_count_baseline), encoding="utf-8")
    with pytest.raises(ValueError, match="record_count.*nonnegative integer"):
        prepare_enron_benchmark(
            replace(
                _options(input_jsonl, tmp_path / "coerced-record-count-candidate"),
                baseline_benchmark_json=coerced_record_count_path,
            )
        )

    coerced_entity_counts_baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    coerced_entity_counts_baseline["quality"]["test"]["entity_counts"] = {"email_address": 1.0}
    coerced_entity_counts_path = tmp_path / "coerced-entity-counts-baseline.json"
    coerced_entity_counts_path.write_text(json.dumps(coerced_entity_counts_baseline), encoding="utf-8")
    with pytest.raises(ValueError, match="entity_counts.*nonnegative integers"):
        prepare_enron_benchmark(
            replace(
                _options(input_jsonl, tmp_path / "coerced-entity-counts-candidate"),
                baseline_benchmark_json=coerced_entity_counts_path,
            )
        )

    mismatched_baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    mismatched_baseline["manifest"]["sampling"]["seed"] = "different-evaluator"
    mismatched_path = tmp_path / "mismatched-baseline.json"
    mismatched_path.write_text(json.dumps(mismatched_baseline), encoding="utf-8")

    failed = prepare_enron_benchmark(
        replace(
            _options(input_jsonl, tmp_path / "failed-candidate"),
            baseline_benchmark_json=mismatched_path,
            max_cold_compile_seconds_ratio=1.0,
        )
    )

    assert failed["gate"]["configured"] is True
    assert failed["gate"]["passed"] is False
    assert failed["gate"]["evaluator"]["passed"] is False
    assert failed["gate"]["quality"]["skipped"] is True
    assert failed["gate"]["performance"]["skipped"] is True
    assert failed["gate"]["performance"]["checks"] == []


def test_main_exits_nonzero_when_configured_gate_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rows: list[dict[str, object]] = [
        {
            "message_id": f"<fixture-{index}>",
            "subject": f"Deal {index}",
            "from": f"sender{index % 3}@enron.com",
            "to": [f"desk{index % 4}@enron.com", "outside@example.net"],
            "body": f"Please send updates to desk{index % 4}@enron.com for Deal {index}.",
        }
        for index in range(24)
    ]
    input_jsonl = _write_jsonl(tmp_path / "fixture.jsonl", rows)
    baseline = prepare_enron_benchmark(_options(input_jsonl, tmp_path / "baseline"))

    with pytest.raises(SystemExit) as exc_info:
        main(
            [
                "--input-jsonl",
                str(input_jsonl),
                "--output-dir",
                str(tmp_path / "candidate"),
                "--sample-fraction",
                "1.0",
                "--test-fraction",
                "0.35",
                "--seed",
                "fixture-seed",
                "--created-at",
                "2026-06-09T00:00:00Z",
                "--min-address-count",
                "1",
                "--min-domain-count",
                "1",
                "--benchmark-documents",
                "5",
                "--quality-documents",
                "5",
                "--benchmark-iterations",
                "1",
                "--baseline-benchmark-json",
                str(baseline["paths"]["benchmark"]),
                "--max-addresses",
                "1",
                "--max-domains",
                "1",
            ]
        )

    assert exc_info.value.code == 1
    output = json.loads(capsys.readouterr().out)
    assert output["gate"]["configured"] is True
    assert output["gate"]["passed"] is False


@pytest.mark.parametrize(
    ("flag", "value"),
    [
        ("--max-cold-compile-seconds-ratio", "nan"),
        ("--max-warm-cached-compile-seconds-ratio", "inf"),
        ("--min-target-bytes-per-second-ratio", "-inf"),
    ],
)
def test_parse_args_rejects_non_finite_gate_thresholds(tmp_path: Path, flag: str, value: str) -> None:
    input_jsonl = tmp_path / "fixture.jsonl"
    input_jsonl.write_text("{}\n", encoding="utf-8")
    baseline_json = tmp_path / "baseline.json"
    baseline_json.write_text("{}", encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        _parse_args(["--input-jsonl", str(input_jsonl), "--baseline-benchmark-json", str(baseline_json), flag, value])

    assert exc_info.value.code == 2


def test_parse_args_rejects_gate_threshold_without_baseline(tmp_path: Path) -> None:
    input_jsonl = tmp_path / "fixture.jsonl"
    input_jsonl.write_text("{}\n", encoding="utf-8")

    with pytest.raises(SystemExit):
        _parse_args(["--input-jsonl", str(input_jsonl), "--max-cold-compile-seconds-ratio", "1.05"])


def test_prepare_enron_benchmark_rejects_gate_threshold_without_baseline(tmp_path: Path) -> None:
    input_jsonl = _write_jsonl(
        tmp_path / "fixture.jsonl",
        [
            {
                "message_id": f"<fixture-{index}>",
                "subject": f"Deal {index}",
                "from": f"sender{index}@enron.com",
                "to": ["desk@example.net"],
                "body": f"Please send updates to sender{index}@enron.com.",
            }
            for index in range(8)
        ],
    )

    with pytest.raises(ValueError, match="baseline-benchmark-json"):
        prepare_enron_benchmark(
            replace(_options(input_jsonl, tmp_path / "candidate"), max_cold_compile_seconds_ratio=1.05)
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_cold_compile_seconds_ratio", float("nan")),
        ("max_warm_cached_compile_seconds_ratio", float("inf")),
        ("min_target_bytes_per_second_ratio", 0.0),
        ("max_cold_compile_seconds_ratio", -1.0),
    ],
)
def test_prepare_enron_benchmark_rejects_invalid_direct_gate_thresholds(
    tmp_path: Path,
    field: str,
    value: float,
) -> None:
    input_jsonl = tmp_path / "fixture.jsonl"
    input_jsonl.write_text("{}\n", encoding="utf-8")

    with pytest.raises(ValueError, match=field):
        prepare_enron_benchmark(
            replace(
                _options(input_jsonl, tmp_path / "candidate"),
                baseline_benchmark_json=tmp_path / "baseline.json",
                **{field: value},
            )
        )


def test_load_json_mapping_rejects_unsafe_baseline_paths(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="regular file"):
        _load_json_mapping(tmp_path)

    too_large = tmp_path / "too-large.json"
    with too_large.open("wb") as file:
        file.truncate(DEFAULT_MAX_BASELINE_BENCHMARK_BYTES + 1)
    with pytest.raises(ValueError, match="exceeds the configured limit"):
        _load_json_mapping(too_large)

    non_finite = tmp_path / "non-finite.json"
    non_finite.write_text('{"threshold": NaN}', encoding="utf-8")
    with pytest.raises(ValueError, match="non-finite value NaN"):
        _load_json_mapping(non_finite)

    overflow_float = tmp_path / "overflow-float.json"
    overflow_float.write_text('{"threshold": 1e999}', encoding="utf-8")
    with pytest.raises(ValueError, match="non-finite value 1e999"):
        _load_json_mapping(overflow_float)

    duplicate_key = tmp_path / "duplicate-key.json"
    duplicate_key.write_text('{"quality": {}, "quality": {}}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate key 'quality'"):
        _load_json_mapping(duplicate_key)

    target = tmp_path / "baseline.json"
    target.write_text("{}", encoding="utf-8")
    symlink = tmp_path / "baseline-link.json"
    try:
        symlink.symlink_to(target)
    except OSError:
        return
    with pytest.raises(ValueError, match="must not be a symlink"):
        _load_json_mapping(symlink)


def test_prepare_enron_benchmark_rejects_empty_held_out_split(tmp_path: Path) -> None:
    rows: list[dict[str, object]] = [
        {
            "message_id": f"<fixture-{index}>",
            "subject": f"Deal {index}",
            "from": f"sender{index}@enron.com",
            "to": ["desk@example.net"],
            "cc": [""],
            "bcc": [""],
            "body": f"Please send updates to sender{index}@enron.com.",
        }
        for index in range(8)
    ]
    input_jsonl = _write_jsonl(tmp_path / "fixture.jsonl", rows)
    options = _options(input_jsonl, tmp_path / "empty-test")
    options = replace(options, test_fraction=0.0)

    with pytest.raises(ValueError, match="held-out test documents"):
        prepare_enron_benchmark(options)


def test_parse_args_preserves_local_source_provenance_and_fixed_bank_timestamp(tmp_path: Path) -> None:
    input_jsonl = tmp_path / "fixture.jsonl"
    input_jsonl.write_text("{}\n", encoding="utf-8")

    options = _parse_args(["--input-jsonl", str(input_jsonl)])

    assert options.dataset_id == "local-jsonl"
    assert options.created_at == BANK_TIMESTAMP


def test_prepare_enron_benchmark_requires_huggingface_revision(tmp_path: Path) -> None:
    options = PrepOptions(
        output_dir=tmp_path / "hf",
        dataset_id="corbt/enron-emails",
        dataset_split="train",
        dataset_revision=None,
        input_jsonl=None,
        row_limit=1,
        sample_fraction=1.0,
        test_fraction=0.5,
        seed="fixture",
        max_body_chars=1_000,
        max_addresses=20,
        max_domains=10,
        min_address_count=1,
        min_domain_count=1,
        benchmark_documents=1,
        quality_documents=1,
        benchmark_iterations=1,
        created_at=BANK_TIMESTAMP,
        baseline_benchmark_json=None,
        max_cold_compile_seconds_ratio=None,
        max_warm_cached_compile_seconds_ratio=None,
        min_target_bytes_per_second_ratio=None,
    )

    with pytest.raises(ValueError, match="dataset-revision"):
        prepare_enron_benchmark(options)
