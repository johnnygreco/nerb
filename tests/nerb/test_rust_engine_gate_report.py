from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_gate_report_module():
    module_path = Path(__file__).parents[2] / "scripts" / "rust_engine_gate_report.py"
    spec = importlib.util.spec_from_file_location("rust_engine_gate_report", module_path)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_rust_engine_gate_report_quick_mode_returns_passing_json_compatible_shape():
    gate_report = _load_gate_report_module()

    report = gate_report.gate_report(iterations=1, target_bytes=10_000, dense_bytes=128)

    assert report["overall"]["passed"] is True
    assert report["conformance"]["passed"] is True
    assert report["performance"]["passed"] is True
    assert report["mode_strategy"]["passed"] is True
    assert report["memory"]["passed"] is True
    assert report["distribution"]["passed"] is True
    assert report["mode_strategy"]["decision"] == "entity_independent remains the production default"
    assert report["performance"]["literal_heavy"]["python_rust_records_equal"] is True
    assert report["performance"]["regex_heavy"]["python_rust_records_equal"] is True
