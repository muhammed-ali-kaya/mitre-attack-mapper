"""Ajanlari calistirir ve kararlari bulgulara uygular.

Bu modulun asil isi ajan cagirmak DEGIL, sozlesmeyi ZORLAMAK. apply_decisions
kararlari uygularken cikti kumesini denetler: teknik eklenmedigini ve hicbir
guvenin yukselmedigini kodun kendisi garanti eder. Bir ajan sozlesmeyi ihlal
eden bir karar dondurse bile burada yakalanir.

Neden ajana guvenmiyoruz: ajanlarin bir kismi hibrit calisiyor, yani icinde
dil modeli var (bkz. app/agents/hybrid.py). Modelin sozlesmeye uymasini
UMUT ETMEK bir tasarim degildir; uymadiginda ne olacagini kodlamak tasarimdir."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.agents.base import AgentDecision, ControlAgent, Verdict, is_weakening
from app.mapping.rule_engine import Finding


class AgentContractViolation(RuntimeError):
    """Bir ajan yetkisinin disina cikti. Sessizce duzeltmiyoruz -- bu bir
    kod hatasidir ve gorunmesi gerekir."""


@dataclass
class VerificationResult:
    """Ajan katmaninin ciktisi.

    findings: dogrulamadan GECEN bulgular (guveni dusurulmus olabilir)
    rejected: elenen bulgular -- KAYBOLMAZLAR, gerekcesiyle raporda dururlar
    decisions: her ajanin her bulgu icin verdigi karar (denetim izi)"""
    findings: list[Finding] = field(default_factory=list)
    rejected: list[tuple[Finding, AgentDecision]] = field(default_factory=list)
    decisions: list[AgentDecision] = field(default_factory=list)

    @property
    def rejected_technique_ids(self) -> list[str]:
        return [f.technique_id for f, _ in self.rejected]


def apply_decisions(
    findings: list[Finding], decisions: list[AgentDecision]
) -> VerificationResult:
    """Kararlari uygular ve sozlesmeyi dogrular.

    Ayni teknik icin birden fazla karar gelirse EN SERT olan kazanir:
    reject > downgrade > confirm/abstain. Gerekce: kontroller birbirini
    zayiflatmamali -- bir ajan 'bu supheli degil' derken digeri somut bir
    gerekce ile eliyorsa, eleme gecerlidir."""
    by_technique: dict[str, list[AgentDecision]] = {}
    for decision in decisions:
        by_technique.setdefault(decision.technique_id, []).append(decision)

    kept: list[Finding] = []
    rejected: list[tuple[Finding, AgentDecision]] = []

    for finding in findings:
        relevant = by_technique.get(finding.technique_id, [])

        reject = next((d for d in relevant if d.verdict is Verdict.REJECT), None)
        if reject is not None:
            rejected.append((finding, reject))
            continue

        for decision in relevant:
            if decision.verdict is not Verdict.DOWNGRADE:
                continue
            target = decision.downgrade_to
            # SOZLESME: yalnizca zayiflatma. Ajan 'medium -> high' derse
            # karar yok sayilmaz, hata olarak yukselir.
            if target == finding.confidence:
                continue
            if not is_weakening(finding.confidence, target):
                raise AgentContractViolation(
                    f"{decision.agent_id}: {finding.technique_id} guvenini "
                    f"{finding.confidence} -> {target} yukseltmeye calisti"
                )
            finding.confidence = target

        kept.append(finding)

    _assert_no_technique_added(findings, kept)
    return VerificationResult(findings=kept, rejected=rejected, decisions=decisions)


def _assert_no_technique_added(before: list[Finding], after: list[Finding]) -> None:
    added = {f.technique_id for f in after} - {f.technique_id for f in before}
    if added:
        raise AgentContractViolation(
            f"ajan katmani teknik EKLEDI: {sorted(added)} -- yetki disi"
        )


def run_agents(
    findings: list[Finding],
    rows: list[dict[str, Any]],
    agents: list[ControlAgent],
) -> VerificationResult:
    """Her bulguyu, onu denetleyecek ajanlara gonderir.

    IKI YONLENDIRME VAR (bkz. base.ControlAgent):
      technique_id is None -> GENEL ajan, HER bulguya gider. Katmanin
          kapsami buradan gelir: 858 teknigin hepsinde calisir.
      technique_id = "T…"  -> UZMAN ajan, yalnizca o teknige gider.

    Hicbir ajan bulguyla ilgilenmezse bulgu DOKUNULMADAN gecer -- 'ajan yok'
    bir reddetme sebebi degildir."""
    general: list[ControlAgent] = []
    by_technique: dict[str, list[ControlAgent]] = {}
    for agent in agents:
        if agent.technique_id is None:
            general.append(agent)
        else:
            by_technique.setdefault(agent.technique_id, []).append(agent)

    decisions: list[AgentDecision] = []
    for finding in findings:
        for agent in [*general, *by_technique.get(finding.technique_id, [])]:
            decision = agent.review(finding, rows)
            if decision.technique_id != finding.technique_id:
                raise AgentContractViolation(
                    f"{agent.agent_id}: {finding.technique_id} incelenirken "
                    f"{decision.technique_id} hakkinda karar dondurdu"
                )
            decisions.append(decision)

    return apply_decisions(findings, decisions)
