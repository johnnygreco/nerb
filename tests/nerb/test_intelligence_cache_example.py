from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_fictitious_intelligence_cache_example_runs_end_to_end() -> None:
    repository_root = Path(__file__).parents[2]
    result = subprocess.run(
        [sys.executable, "examples/intelligence_cache/run.py"],
        cwd=repository_root,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    payload = json.loads(result.stdout)

    assert [(item["entity"], item["canonical_name"]) for item in payload["records"]] == [
        ("person", "Avery Stone"),
        ("contact", "Avery Stone work email"),
        ("organization", "Northstar Logistics"),
    ]
    assert payload["redacted_text"] == (
        "Please ask [PERSON_0001] at [CONTACT_0001] to route the [ORGANIZATION_0001] review to Rowan Birch."
    )
    assert "Rowan Birch remains" in payload["note"]
