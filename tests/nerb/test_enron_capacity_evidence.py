from __future__ import annotations

import hashlib
from pathlib import Path

from nerb.enron_capacity import verify_portable_capacity_decision

_REPOSITORY_ROOT = Path(__file__).parents[2]
_CAPACITY_EVIDENCE = _REPOSITORY_ROOT / "evidence" / "enron" / "capacity-decision.json"
_CAPACITY_EVIDENCE_SHA256 = "441d90fc64d45d6febdd2a8ee13d9db25c712d195f4414ca6acb9bf1268ddca2"


def test_committed_full_source_capacity_evidence_verifies_portably() -> None:
    payload = _CAPACITY_EVIDENCE.read_bytes()
    assert hashlib.sha256(payload).hexdigest() == _CAPACITY_EVIDENCE_SHA256

    artifact = verify_portable_capacity_decision(_CAPACITY_EVIDENCE, require_production=False)

    assert artifact["decision_sha256"] == ("sha256:6f49646db68c767471ddc0d58bc429febba75085460c06c98f7c2a7626447919")
    assert artifact["terminal_attempt"]["outcome"] == "passed"
    assert artifact["terminal_attempt"]["production_evidence"] is True
    assert artifact["report"]["execution"]["executable_git_commit"] == ("bd573361010fbb87198480eb2ed36a824e332c73")
    assert artifact["report"]["totals"]["source_rows_accounted"] == 517_401
    assert artifact["report"]["gates"]["passed"] is True
    assert artifact["report"]["privacy"]["sealed_test_accessed"] is False
    assert artifact["privacy"]["privacy_scan_violation_count"] == 0
