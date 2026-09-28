"""Ajan sozlesmesinin makine tarafindan zorlandigini kanitlar.

Bu dosyadaki testler mimarinin bel kemigi: ajan katmani teknik EKLEYEMEZ ve
guven YUKSELTEMEZ. Bir gun biri 'ajan da teknik onersin' diye kod yazarsa
burasi kirmizi yanar."""

from __future__ import annotations

import pytest

from app.agents.base import AgentDecision, Verdict, is_weakening
from app.agents.runner import (
    AgentContractViolation,
    apply_decisions,
    run_agents,
)
from app.mapping.rule_engine import Finding


def _finding(technique_id="T1053.005", confidence="high", rows=(0,)):
    return Finding(
        technique_id=technique_id,
        tactic="TA0002",
        confidence=confidence,
        evidence_row_ids=list(rows),
        name=technique_id,
    )


def _decision(technique_id="T1053.005", verdict=Verdict.CONFIRM, to=None, reason="gerekce"):
    return AgentDecision(
        agent_id="test-agent",
        technique_id=technique_id,
        verdict=verdict,
        reason=reason,
        downgrade_to=to,
    )


class _Agent:
    def __init__(self, technique_id, decision):
        self.agent_id = "sahte-ajan"
        self.technique_id = technique_id
        self._decision = decision

    def review(self, finding, rows):
        return self._decision


# ------------------------------------------------------------------ temel davranis

def test_confirm_leaves_the_finding_untouched():
    finding = _finding()
    result = apply_decisions([finding], [_decision()])
    assert [f.technique_id for f in result.findings] == ["T1053.005"]
    assert result.findings[0].confidence == "high"
    assert result.rejected == []


def test_reject_removes_the_finding_but_keeps_it_with_its_reason():
    """Elenen bulgu KAYBOLMAZ -- gerekcesiyle raporda durur."""
    finding = _finding()
    decision = _decision(verdict=Verdict.REJECT, reason="onayli degisiklik penceresi")
    result = apply_decisions([finding], [decision])

    assert result.findings == []
    assert result.rejected_technique_ids == ["T1053.005"]
    assert result.rejected[0][1].reason == "onayli degisiklik penceresi"


def test_downgrade_weakens_confidence():
    finding = _finding(confidence="high")
    result = apply_decisions([finding], [_decision(verdict=Verdict.DOWNGRADE, to="medium")])
    assert result.findings[0].confidence == "medium"


def test_abstain_changes_nothing():
    finding = _finding(confidence="high")
    result = apply_decisions([finding], [_decision(verdict=Verdict.ABSTAIN)])
    assert result.findings[0].confidence == "high"


def test_finding_without_any_agent_passes_untouched():
    """'Ajan yok' bir reddetme sebebi degildir."""
    finding = _finding("T1078")
    result = run_agents([finding], [{}], agents=[])
    assert result.findings == [finding]


# ------------------------------------------------------------------ SOZLESME

def test_agent_cannot_raise_confidence():
    finding = _finding(confidence="medium")
    with pytest.raises(AgentContractViolation, match="yukseltmeye"):
        apply_decisions([finding], [_decision(verdict=Verdict.DOWNGRADE, to="high")])


def test_agent_cannot_add_a_technique():
    """Karar listesinde olmayan bir teknik ciktiya giremez."""
    finding = _finding("T1053.005")
    result = apply_decisions([finding], [_decision(technique_id="T1059.001")])
    assert {f.technique_id for f in result.findings} == {"T1053.005"}


def test_agent_reviewing_wrong_technique_is_a_violation():
    agent = _Agent("T1053.005", _decision(technique_id="T1059.001"))
    with pytest.raises(AgentContractViolation, match="hakkinda karar dondurdu"):
        run_agents([_finding("T1053.005")], [{}], [agent])


def test_output_technique_set_is_always_a_subset_of_input():
    findings = [_finding("T1053.005"), _finding("T1059.001"), _finding("T1003.001")]
    decisions = [
        _decision("T1053.005", Verdict.REJECT),
        _decision("T1059.001", Verdict.DOWNGRADE, to="low"),
        _decision("T1003.001", Verdict.CONFIRM),
    ]
    result = apply_decisions(findings, decisions)

    before = {f.technique_id for f in findings}
    after = {f.technique_id for f in result.findings}
    assert after <= before


def test_decision_without_reason_is_rejected_at_construction():
    """Gerekcesiz eleme = sessizce kaybolan bulgu."""
    with pytest.raises(ValueError, match="gerekcesiz"):
        AgentDecision(
            agent_id="a", technique_id="T1", verdict=Verdict.REJECT, reason="   "
        )


def test_downgrade_needs_a_valid_target_level():
    with pytest.raises(ValueError, match="gecersiz"):
        AgentDecision(
            agent_id="a", technique_id="T1", verdict=Verdict.DOWNGRADE,
            reason="x", downgrade_to="cok-dusuk",
        )


# ------------------------------------------------------------------ cakisan kararlar

def test_strictest_verdict_wins_when_agents_disagree():
    """Bir ajan onaylarken digeri somut gerekceyle eliyorsa, eleme gecerlidir."""
    finding = _finding()
    result = apply_decisions([finding], [
        _decision(verdict=Verdict.CONFIRM),
        _decision(verdict=Verdict.REJECT, reason="bilinen-iyi ikili"),
    ])
    assert result.findings == []
    assert result.rejected_technique_ids == ["T1053.005"]


def test_multiple_downgrades_take_the_weakest():
    finding = _finding(confidence="high")
    result = apply_decisions([finding], [
        _decision(verdict=Verdict.DOWNGRADE, to="medium"),
        _decision(verdict=Verdict.DOWNGRADE, to="low"),
    ])
    assert result.findings[0].confidence == "low"


def test_is_weakening_helper():
    assert is_weakening("high", "medium")
    assert is_weakening("medium", "low")
    assert not is_weakening("medium", "high")
    assert not is_weakening("high", "high")


# ------------------------------------------------------------------ PROPERTY
# Asagidaki tarama, tek tek ajan duzeltmenin yerine gecer.
#
# Gecmisi: LsassAccessAgent kosulsuz "medium'a dusur" donduruyordu. Bulgu
# zaten "low" ise bu bir YUKSELTME olur, apply_decisions haklı olarak
# AgentContractViolation firlatir ve ANALIZ TAMAMEN DUSER -- 60 senaryoluk
# olcumde 3 senaryo boyle oldu. Hata ajanin kendisinde degil, "dusur"
# ifadesini MUTLAK HEDEF sanan her ajanda tekrarlanabilir bir kalipta.
#
# Bu yuzden tek ajani duzeltmek yeterli degil: her ajan, HER guven
# seviyesindeki bir bulgu icin sozlesmeye uygun karar uretmek zorunda.
# Yeni bir ajan eklendiginde bu test onu otomatik kapsar.

def _all_agents():
    """Depodaki tum kontrol ajanlari. LLM'li olanlara sahte model baglanir --
    sozlesme testi Ollama'nin ayakta olmasina bagli olamaz."""
    import json

    from app.agents.deterministic import DETERMINISTIC_AGENTS
    from app.agents.general import DetectionEvidenceAgent
    from app.agents.hybrid import build_hybrid_agents

    # Model, sozlesmeyi zorlamaya calisan EN AGRESIF cevabi versin.
    def hostile_llm(system, user):
        return json.dumps({
            "reason": "modelin sozlesmeyi zorlama denemesi",
            "evidence": "weak",
            "weakened_to": "high",   # gecersiz: yukseltme talebi
        })

    knowledge = {
        tid: {"name": tid, "detection": "Monitor for suspicious activity.",
              "platforms": ["Windows"], "data_sources": ["Process"]}
        for tid in ("T1053.005", "T1003.001", "T1686.003", "T1059.001", "T1078")
    }
    return [
        *DETERMINISTIC_AGENTS,
        *build_hybrid_agents(llm_fn=hostile_llm),
        DetectionEvidenceAgent(knowledge=knowledge, llm_fn=hostile_llm),
    ]


_ADVERSARIAL_ROWS = [
    {"EventID": "4656", "Message": "Object Name: lsass.exe Access Mask: 0x40"},
    {"EventID": "4688", "Message": "schtasks /create /tn X /tr C:\\Temp\\x.exe"},
    {"EventID": "5156", "Message": "The Windows Filtering Platform has permitted a connection."},
    {"EventID": "4104", "Message": "powershell -w hidden -enc SQBFAFgA"},
]


@pytest.mark.parametrize("confidence", ["high", "medium", "low"])
def test_no_agent_ever_attempts_to_raise_confidence(confidence):
    """SOZLESME TARAMASI: hicbir ajan, hicbir guven seviyesinde, hicbir
    girdide yukseltme yonunde karar dondurmemeli."""
    for agent in _all_agents():
        technique_id = agent.technique_id or "T1078"
        finding = _finding(technique_id, confidence=confidence)
        for row in _ADVERSARIAL_ROWS:
            decision = agent.review(finding, [row])

            assert decision.technique_id == technique_id, (
                f"{agent.agent_id}: baska teknik hakkinda karar dondurdu"
            )
            if decision.verdict is Verdict.DOWNGRADE:
                assert is_weakening(confidence, decision.downgrade_to), (
                    f"{agent.agent_id}: {confidence} -> {decision.downgrade_to} "
                    "yukseltme girisimi"
                )


@pytest.mark.parametrize("confidence", ["high", "medium", "low"])
def test_applying_every_agent_decision_never_raises(confidence):
    """Ayni tarama uctan uca: kararlar apply_decisions'tan gecerken
    AgentContractViolation cikmamali. Bir istisna, analizin tamamen
    dusmesi demek."""
    for agent in _all_agents():
        technique_id = agent.technique_id or "T1078"
        for row in _ADVERSARIAL_ROWS:
            finding = _finding(technique_id, confidence=confidence)
            result = run_agents([finding], [row], [agent])

            after = {f.technique_id for f in result.findings}
            assert after <= {technique_id}


def test_every_agent_decision_carries_a_reason():
    for agent in _all_agents():
        technique_id = agent.technique_id or "T1078"
        finding = _finding(technique_id)
        for row in _ADVERSARIAL_ROWS:
            assert agent.review(finding, [row]).reason.strip(), (
                f"{agent.agent_id}: gerekcesiz karar"
            )
