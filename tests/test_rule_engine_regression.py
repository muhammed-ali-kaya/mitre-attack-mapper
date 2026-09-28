"""Regresyon: 2026-08-06 tarihli 51 satirlik gercek QRadar export'u.

Bu veri seti, benzerlik tabanli eslestirmenin neden terk edildigini gosteren
kanittir. Eski sistem bu dosyadan 44 teknik, 10 taktik ve "Kritik / 85"
puanli bir olay uretmisti. Veri setinde:
  - Guvenlik duvari DEGISIKLIGI olayi (4946-4954, 5025) hic yok -- buna
    ragmen T1686.003 'Windows Host Firewall' 14 kez uretilmisti; kaynak,
    guvenlik duvarinin CALISTIGINI gosteren 5156 "permitted a connection"
    satirlariydi.
  - 4688 (surec olusturma) hic yok -- buna ragmen Execution taktigi doluydu.
  - 51 satirin yalnizca 18'inde Account Name var ve uc farkli principal'e
    ait; buna ragmen tum zincir tek hesaba atfedilmisti.

Dogru cikti: sifir teknik, kurulmamis zincir, iki 'incelenmeli' bulgu."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.batch.qradar_adapter import try_convert_qradar_export
from app.mapping.polarity import Polarity, classify
from app.mapping.rule_engine import evaluate_review_rules, evaluate_rules

from tests.private_data import QRADAR_CSV, requires_qradar_export

FIXTURE = QRADAR_CSV

# Modulun tamami gercek export'a bagli: veri yoksa hepsi atlanir.
pytestmark = requires_qradar_export


@pytest.fixture(scope="module")
def rows() -> list[dict]:
    parsed = try_convert_qradar_export(FIXTURE.read_bytes())
    assert parsed is not None, "QRadar export'u taninamadi"
    return parsed


def test_fixture_parses_to_51_rows(rows):
    assert len(rows) == 51


def test_dataset_contains_no_firewall_change_events(rows):
    """Kuralin dayandigi olgu: bu veride guvenlik duvari degisikligi yok."""
    present = {str(r["EventID"]) for r in rows}
    firewall_change_ids = {"4946", "4947", "4948", "4949", "4950", "4954", "5025"}
    assert not (present & firewall_change_ids)


def test_no_high_confidence_techniques_are_produced(rows):
    """Regresyonun kalbi: bu veriden hicbir teknik uretilmemeli."""
    findings = evaluate_rules(rows)
    high = [f for f in findings if f.confidence == "high"]
    assert high == [], f"beklenmedik high-confidence teknik: {[f.technique_id for f in high]}"


def test_no_techniques_at_all_are_produced(rows):
    findings = evaluate_rules(rows)
    assert findings == [], f"beklenmedik teknik: {[f.technique_id for f in findings]}"


def test_firewall_audit_rows_can_never_prove_impair_defenses(rows):
    """5156/5158 'permitted' satirlari kontrolun CALISTIGI kanitidir."""
    firewall_rows = [r for r in rows if str(r["EventID"]) in {"5156", "5158"}]
    assert len(firewall_rows) == 32
    assert all(classify(r["Message"]) is Polarity.ENFORCING for r in firewall_rows)


def test_exactly_two_review_findings(rows):
    findings = evaluate_review_rules(rows)
    assert len(findings) == 2, [f.id for f in findings]
    assert {f.id for f in findings} == {
        "powershell_hidden_bypass",
        "binary_in_user_writable_path",
    }


def test_review_findings_point_at_the_right_rows(rows):
    by_id = {f.id: f for f in evaluate_review_rules(rows)}

    powershell = by_id["powershell_hidden_bypass"]
    assert powershell.evidence_row_ids == [45]
    assert "Enforce-LabTaskAlwaysOn.ps1" in rows[45]["Message"]

    binary = by_id["binary_in_user_writable_path"]
    assert binary.evidence_row_ids == [48]
    assert "tdrfagent.exe" in rows[48]["Message"].lower()


def test_every_finding_carries_evidence(rows):
    """Kanit kapisi: kanitsiz bulgu uretilemez."""
    for finding in evaluate_rules(rows) + evaluate_review_rules(rows):
        assert finding.evidence_row_ids, f"{finding} kanitsiz uretildi"


def test_account_attribution_is_not_uniform(rows):
    """Tum zinciri tek hesaba atfetmek yanlisti -- veri bunu desteklemiyor."""
    users = {r.get("SubjectUserName") for r in rows if r.get("SubjectUserName")}
    assert users == {"Administrator", "LOCAL SERVICE", "WINHOST-01$"}
    without_user = [r for r in rows if not r.get("SubjectUserName")]
    assert len(without_user) == 33
