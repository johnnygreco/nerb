from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path

import pytest

from nerb import validate_bank_schema
from nerb.enron_benchmark import BANK_TIMESTAMP, PrepOptions, _parse_args, clean_email_text, prepare_enron_benchmark


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
        benchmark_iterations=1,
        created_at=created_at,
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
    assert first["benchmark"]["summary"]["cache_hit_verified"] is True

    assert first["manifest"]["artifact_hashes"]["train"] == second["manifest"]["artifact_hashes"]["train"]
    assert first["manifest"]["artifact_hashes"]["test"] == second["manifest"]["artifact_hashes"]["test"]
    assert first["manifest"]["artifact_hashes"]["bank"] == second["manifest"]["artifact_hashes"]["bank"]
    assert first["manifest"]["dataset"]["id"] == "fixture/enron"

    with open(Path(first["paths"]["bank"]), encoding="utf-8") as file:
        bank = json.load(file)
    assert validate_bank_schema(bank)["valid"] is True

    if os.name != "nt":
        assert (tmp_path / "first").stat().st_mode & 0o777 == 0o700
        assert Path(first["paths"]["train"]).stat().st_mode & 0o777 == 0o600
        assert Path(first["paths"]["test"]).stat().st_mode & 0o777 == 0o600
        assert Path(first["paths"]["bank"]).stat().st_mode & 0o777 == 0o600


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
        benchmark_iterations=1,
        created_at=BANK_TIMESTAMP,
    )

    with pytest.raises(ValueError, match="dataset-revision"):
        prepare_enron_benchmark(options)
