"""Kapsam beyani: veri setinde HANGI olay ID'lerinin BULUNMADIGI ve bunun
hangi taktikleri degerlendirilemez kildigi.

Neden gerekli: "Execution taktiginde bulgu yok" ile "Execution taktigini
degerlendirecek veri yok" bambaska iki ifadedir. Ilki bir tespit sonucudur,
ikincisi bir korluk beyani. Gercek bir kosuda veri setinde 4688 (surec
olusturma) hic yokken sistem Execution taktigini dolu gostermisti; tersi de
en az o kadar yaniltici olurdu -- "temiz" diyen bir rapor, aslinda bakmadigi
yeri temiz ilan etmis olur.

Kapsam, kural katalogundan TURETILIR: her kuralin required.event_ids'i, o
kuralin taktigi icin "bu taktigi gorebilecegimiz olaylar" kumesini olusturur.
Boylece kataloga yeni kural eklendiginde kapsam beyani kendiliginde guncellenir."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.correlation.tactic_labels import tactic_name
from app.mapping.rule_engine import Rule, load_rules


@dataclass(frozen=True)
class TacticCoverage:
    tactic: str                     # TA00xx
    tactic_name: str | None
    assessable: bool
    present_event_ids: tuple[str, ...]
    missing_event_ids: tuple[str, ...]

    @property
    def statement(self) -> str:
        """Rapora dogrudan yazilabilecek tek cumle."""
        label = self.tactic_name or self.tactic
        if self.assessable:
            return (
                f"{label}: değerlendirildi "
                f"(mevcut olay ID'leri: {', '.join(self.present_event_ids)})"
            )
        return (
            f"{', '.join(self.missing_event_ids)} yok → {label} taktiği değerlendirilemedi"
        )


@dataclass(frozen=True)
class CoverageReport:
    dataset_event_ids: tuple[str, ...]
    tactics: tuple[TacticCoverage, ...]

    @property
    def unassessable(self) -> tuple[TacticCoverage, ...]:
        return tuple(t for t in self.tactics if not t.assessable)

    @property
    def assessable(self) -> tuple[TacticCoverage, ...]:
        return tuple(t for t in self.tactics if t.assessable)

    def statements(self) -> list[str]:
        return [t.statement for t in self.tactics]


def _event_ids_in(rows: list[dict[str, Any]]) -> set[str]:
    return {str(r.get("EventID")).strip() for r in rows if r.get("EventID") is not None}


def build_coverage_report(
    rows: list[dict[str, Any]], rules: list[Rule] | None = None
) -> CoverageReport:
    """Veri setindeki olay ID'lerini kural katalogunun bekledikleriyle karsilastirir."""
    if rules is None:
        rules = load_rules()

    present = _event_ids_in(rows)

    expected_by_tactic: dict[str, set[str]] = {}
    for rule in rules:
        if not rule.required_event_ids:
            # Olay ID'si sart kosmayan kural (yalnizca metin kosullu) bir
            # taktigin "gorulebilirligi" hakkinda bilgi tasimaz.
            continue
        expected_by_tactic.setdefault(rule.tactic, set()).update(rule.required_event_ids)

    coverage = []
    for tactic in sorted(expected_by_tactic):
        expected = expected_by_tactic[tactic]
        found = expected & present
        coverage.append(
            TacticCoverage(
                tactic=tactic,
                tactic_name=tactic_name(tactic),
                assessable=bool(found),
                present_event_ids=tuple(sorted(found)),
                missing_event_ids=tuple(sorted(expected - present)),
            )
        )

    return CoverageReport(
        dataset_event_ids=tuple(sorted(present)),
        tactics=tuple(coverage),
    )
