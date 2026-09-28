from __future__ import annotations

from app.correlation.attack_chain import TACTIC_ORDER
from app.correlation.risk_score import compute_risk_score


def _technique(confidence: float) -> dict:
    return {"attack_id": "T0000", "max_confidence_score": confidence}


def _chain(tactics: list[str]) -> list[dict]:
    return [{"tactic": t, "techniques": []} for t in tactics]


def test_empty_incident_scores_zero_and_low():
    result = compute_risk_score([], [])
    assert result["score"] == 0
    assert result["severity"] == "Low"
    assert result["breakdown"]["tactic_coverage"] == 0
    assert result["breakdown"]["high_risk_tactic_bonus"] == 0


def test_full_coverage_high_confidence_scores_100_and_critical():
    deduped = [_technique(1.0) for _ in range(10)]
    chain = _chain(TACTIC_ORDER)  # tum 15 fazi kapsar, high-risk taktiklerin hepsi dahil
    result = compute_risk_score(deduped, chain)
    assert result["score"] == 100
    assert result["severity"] == "Critical"


def test_high_risk_tactic_bonus_capped_at_thirty():
    chain = _chain(["Credential Access", "Lateral Movement", "Impact", "Command and Control", "Exfiltration"])
    result = compute_risk_score([], chain)
    assert result["breakdown"]["high_risk_tactic_bonus"] == 30


def test_technique_volume_capped_at_twenty():
    deduped = [_technique(0.0) for _ in range(50)]
    result = compute_risk_score(deduped, [])
    assert result["breakdown"]["technique_volume"] == 20


def test_severity_thresholds_are_monotonic_with_score():
    low = compute_risk_score([], [])
    high_risk_chain = _chain(["Credential Access", "Lateral Movement"])
    medium = compute_risk_score([_technique(0.6) for _ in range(5)], high_risk_chain)
    assert low["score"] < medium["score"]
    assert medium["severity"] in {"Medium", "High"}
