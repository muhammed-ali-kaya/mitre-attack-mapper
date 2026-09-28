"""Teknik bazli kontrol ajanlarinin sozlesmesi.

DEGISMEZ KURAL (mimarinin tamami buna dayaniyor):
    Bir ajan bir bulguyu ONAYLAR, GUVENINI DUSURUR veya ELER.
    Yeni teknik URETEMEZ. Guveni YUKSELTEMEZ.

Neden bu kadar kati: bu projede teknik secimi bilerek dil modelinden alinip
deterministik kural motoruna verildi (bkz. app/mapping/rule_engine.py) --
cunku benzerlik tabanli secim, guvenlik duvarinin CALISTIGINI gosteren bir
kaydi "Impair Defenses" diye raporlayabiliyordu. Ajan katmanina ekleme
yetkisi vermek, o kapiyi arka taraftan geri acmak olurdu.

Yetki yalnizca AZALTMA yonunde oldugu icin katmanin en kotu hatasi yanlis
NEGATIFTIR: bir bulguyu haksiz yere eler. Bu hata sessiz degildir -- her
karar gerekcesiyle birlikte saklanir ve raporda gorunur. Yanlis pozitif
uretme ihtimali ise sifirdir, cunku ajan bulgu yaratamaz.

Sozlesmenin makine tarafindan zorlanmasi icin bkz. app/agents/runner.py
::apply_decisions ve tests/test_agent_contract.py."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from app.mapping.rule_engine import CONFIDENCE_LEVELS, Finding

# Guven seviyeleri, en gucluden en zayifa. Indeksi buyuyen yon = zayiflama.
_CONFIDENCE_RANK = {level: i for i, level in enumerate(CONFIDENCE_LEVELS)}


class Verdict(str, Enum):
    CONFIRM = "confirm"        # bulgu oldugu gibi kalir
    DOWNGRADE = "downgrade"    # bulgu kalir, guveni duser
    REJECT = "reject"          # bulgu listeden cikar
    ABSTAIN = "abstain"        # ajan karar veremedi -> bulgu DEGISMEZ


@dataclass(frozen=True)
class AgentDecision:
    """Bir ajanin tek bir bulgu hakkindaki karari.

    reason ZORUNLU: gerekcesiz bir eleme, sessizce kaybolan bir bulgudur.
    Bir olay raporunda "sistem bunu eledi ama neden bilmiyoruz" savunulamaz."""
    agent_id: str
    technique_id: str
    verdict: Verdict
    reason: str
    downgrade_to: str | None = None

    def __post_init__(self) -> None:
        if not self.reason.strip():
            raise ValueError(f"{self.agent_id}: gerekcesiz karar verilemez")
        if self.verdict is Verdict.DOWNGRADE:
            if self.downgrade_to not in _CONFIDENCE_RANK:
                raise ValueError(
                    f"{self.agent_id}: downgrade_to {self.downgrade_to!r} gecersiz"
                )


def is_weakening(current: str, target: str) -> bool:
    """target, current'tan DAHA ZAYIF mi? Esitlik zayiflama sayilmaz."""
    return _CONFIDENCE_RANK.get(target, -1) > _CONFIDENCE_RANK.get(current, -1)


@runtime_checkable
class ControlAgent(Protocol):
    """Bir bulguyu denetleyen kontrol ajani.

    IKI TUR AJAN VAR ve ayrimi technique_id belirler:

    technique_id = "T1003.001"  UZMAN ajan. Yalnizca o teknige bakar ve
        teknige ozel bir soru sorar (access mask gercekten bellek okuma mi?).
        Ucuz, kesin, tekrarlanabilir -- ama yalnizca yazildigi teknikte.

    technique_id = None         GENEL ajan. HER bulguda calisir. Teknige
        ozel bilgiyi kendi tasimaz; olcutunu tekniğin ATT&CK detection
        metninden alir (bkz. app/agents/general.py). Boylece kapsam,
        elle yazilan ajan sayisiyla degil ATT&CK verisiyle olceklenir.

    Mimari onceligi GENEL ajanlardadir; uzman ajanlar, deterministik bir
    kuralin dil modelinden kesin olarak daha iyi oldugu birkac yerde
    duran istisnalardir.

    Ortak olan tek sey sozlesme: girdi bir bulgu, cikti bir karar, ve
    karar asla ekleme yonunde olamaz."""

    agent_id: str
    technique_id: str | None

    def review(self, finding: Finding, rows: list[dict[str, Any]]) -> AgentDecision:
        ...


def evidence_rows(finding: Finding, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Bulgunun dayandigi ham satirlar -- ajanlarin ortak yardimcisi."""
    return [rows[i] for i in finding.evidence_row_ids if 0 <= i < len(rows)]


def joined_text(finding: Finding, rows: list[dict[str, Any]], field: str = "Message") -> str:
    """Kanit satirlarinin ilgili alanini tek metinde birlestirir."""
    return "\n".join(
        str(row.get(field) or "") for row in evidence_rows(finding, rows)
    )
