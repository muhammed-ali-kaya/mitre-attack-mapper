from __future__ import annotations

from app.agents.base import Verdict
from app.agents.deterministic import (
    DETERMINISTIC_AGENTS,
    FirewallChangeAgent,
    LsassAccessAgent,
    ScheduledTaskAgent,
)
from app.agents.runner import run_agents
from app.mapping.rule_engine import Finding


def _finding(technique_id, confidence="high"):
    return Finding(
        technique_id=technique_id, tactic="TA0002",
        confidence=confidence, evidence_row_ids=[0], name=technique_id,
    )


def _rows(message):
    return [{"EventID": "4688", "Message": message}]


# ---------------------------------------------------------------- T1053.005

def test_remote_task_creation_is_confirmed():
    decision = ScheduledTaskAgent().review(
        _finding("T1053.005"),
        _rows("schtasks /create /s 10.10.20.15 /tn UpdateCheck /tr powershell.exe"),
    )
    assert decision.verdict is Verdict.CONFIRM
    assert "uzak makinede" in decision.reason


def test_known_good_task_binary_is_rejected():
    decision = ScheduledTaskAgent().review(
        _finding("T1053.005"),
        _rows("schtasks /create /tn Defrag /tr C:\\Windows\\System32\\defrag.exe"),
    )
    assert decision.verdict is Verdict.REJECT
    assert "bilinen-iyi" in decision.reason


def test_unknown_task_binary_leads_to_abstain_not_rejection():
    """Taninmayan ikili 'zararsiz' demek degildir -- ajan karar vermez."""
    decision = ScheduledTaskAgent().review(
        _finding("T1053.005"),
        _rows("schtasks /create /tn X /tr C:\\Temp\\bilinmeyen.exe"),
    )
    assert decision.verdict is Verdict.ABSTAIN


# ---------------------------------------------------------------- T1003.001

def test_edr_process_accessing_lsass_is_rejected():
    decision = LsassAccessAgent().review(
        _finding("T1003.001"),
        _rows("Process Name: C:\\ProgramData\\Microsoft\\Windows Defender\\MsMpEng.exe "
              "Object Name: \\Device\\HarddiskVolume3\\Windows\\System32\\lsass.exe"),
    )
    assert decision.verdict is Verdict.REJECT
    assert "EDR" in decision.reason


def test_memory_read_access_mask_is_confirmed():
    decision = LsassAccessAgent().review(
        _finding("T1003.001"),
        _rows("Object Name: lsass.exe Access Mask: 0x1410"),
    )
    assert decision.verdict is Verdict.CONFIRM


def test_lsass_handle_without_read_mask_is_downgraded_not_rejected():
    """Handle acilisi tek basina dokum kaniti degil ama yok da sayilmaz."""
    decision = LsassAccessAgent().review(
        _finding("T1003.001"),
        _rows("Object Name: lsass.exe Access Mask: 0x40"),
    )
    assert decision.verdict is Verdict.DOWNGRADE
    assert decision.downgrade_to == "medium"


def test_lsass_downgrade_is_a_ceiling_not_an_absolute_target():
    """REGRESYON -- olcumde 3 senaryoyu dusuren hata.

    Bulgu zaten 'low' ise 'medium'a dusurmek YUKSELTME olur; runner bunu
    sozlesme ihlali sayip istisna firlatiyordu (subtech-001, multi-002,
    crosslang-002). Yapacak sey kalmadiysa dogru davranis cekimserlik."""
    decision = LsassAccessAgent().review(
        _finding("T1003.001", confidence="low"),
        _rows("Object Name: lsass.exe Access Mask: 0x40"),
    )
    assert decision.verdict is Verdict.ABSTAIN
    assert "düşürülecek seviye yok" in decision.reason


# ---------------------------------------------------------------- T1686.003

def test_firewall_permitted_record_is_rejected_by_the_second_line_of_defence():
    """Projenin en pahali hatasi -- ikinci savunma hatti da yakalamali."""
    decision = FirewallChangeAgent().review(
        _finding("T1686.003"),
        _rows("The Windows Filtering Platform has permitted a connection."),
    )
    assert decision.verdict is Verdict.REJECT
    assert "denetim kaydı" in decision.reason


def test_firewall_rule_deletion_is_confirmed():
    decision = FirewallChangeAgent().review(
        _finding("T1686.003"),
        _rows("A rule was deleted from the Windows Firewall exception list."),
    )
    assert decision.verdict is Verdict.CONFIRM


# ---------------------------------------------------------------- entegrasyon

def test_agents_never_grow_the_finding_set():
    findings = [_finding("T1053.005"), _finding("T1003.001"), _finding("T1686.003")]
    rows = _rows("The Windows Filtering Platform has permitted a connection.")

    result = run_agents(findings, rows, DETERMINISTIC_AGENTS)

    before = {f.technique_id for f in findings}
    after = {f.technique_id for f in result.findings}
    assert after <= before


def test_every_decision_carries_a_reason():
    findings = [_finding("T1053.005"), _finding("T1003.001"), _finding("T1686.003")]
    result = run_agents(findings, _rows("schtasks /create /tn X /tr y.exe"), DETERMINISTIC_AGENTS)
    assert all(d.reason.strip() for d in result.decisions)


def test_rejected_findings_are_preserved_with_their_reason():
    findings = [_finding("T1686.003")]
    rows = _rows("The Windows Filtering Platform has permitted a connection.")

    result = run_agents(findings, rows, DETERMINISTIC_AGENTS)

    assert result.findings == []
    assert result.rejected_technique_ids == ["T1686.003"]
    assert "denetim kaydı" in result.rejected[0][1].reason


def test_agents_are_deterministic_across_runs():
    findings = [_finding("T1003.001")]
    rows = _rows("Object Name: lsass.exe Access Mask: 0x1410")

    first = run_agents(findings, rows, DETERMINISTIC_AGENTS)
    second = run_agents([_finding("T1003.001")], rows, DETERMINISTIC_AGENTS)

    assert [d.verdict for d in first.decisions] == [d.verdict for d in second.decisions]
    assert [d.reason for d in first.decisions] == [d.reason for d in second.decisions]
