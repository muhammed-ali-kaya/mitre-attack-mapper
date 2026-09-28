"""Incident Risk Score (0-100): seffaf, kural tabanli bir formul -- LLM
kullanilmaz. app/validation/confidence.py'deki 'bilesenlere ayrilmis skor'
desenini takip eder (UI'da ayni sekilde bir 'neden bu skor' expander'i
gosterilebilir, bkz. app/ui/render.py 'Guven Skoru Bilesenleri').

Bilesenler (toplamda maksimum 100):
- tactic_coverage      (0-30): incident kac farkli ATT&CK taktik fazina
                        yayilmis (Reconnaissance..Impact, 15 faz).
- high_risk_tactic_bonus (0-30): Credential Access / Lateral Movement / Impact /
                        Command and Control / Exfiltration fazlarindan her biri
                        icin +15, en fazla 30 (yuksek etkili taktikler orantisiz
                        agirlik alsin diye).
- technique_volume     (0-20): farkli teknik sayisi (teknik basina +3, tavan 20).
- confidence_factor    (0-20): incident'teki tekniklerin ortalama guven skoru * 20.

Esikler: <25 Low, 25-49 Medium, 50-74 High, 75-100 Critical."""

from __future__ import annotations

from typing import Any

from app.correlation.attack_chain import TACTIC_ORDER

HIGH_RISK_TACTICS = {"Credential Access", "Lateral Movement", "Impact", "Command and Control", "Exfiltration"}
HIGH_RISK_BONUS_PER_TACTIC = 15
HIGH_RISK_BONUS_CAP = 30
TECHNIQUE_VOLUME_PER_TECHNIQUE = 3
TECHNIQUE_VOLUME_CAP = 20

# Bilesen anahtarlarinin ekranda/raporda gorunecek Turkce karsiliklari.
# Ham JSON ('tactic_coverage': 22.0) bir olay raporunda okunabilir bir gerekce
# degil; skorun neden o oldugunu anlatan tek yer burasi oldugu icin her
# bilesen ne olctugunu da soyluyor.
BREAKDOWN_LABELS_TR: dict[str, str] = {
    "tactic_coverage": "Taktik yayılımı (0-30) — olay kaç ATT&CK fazına yayılmış",
    "high_risk_tactic_bonus": "Yüksek riskli taktik bonusu (0-30)",
    "high_risk_tactics_present": "Tespit edilen yüksek riskli taktikler",
    "technique_volume": "Teknik çeşitliliği (0-20) — farklı teknik sayısı",
    "confidence_factor": "Güven katsayısı (0-20) — tekniklerin ortalama güven skoru",
    "tactics_present": "Olayda görülen taktikler",
    "excluded_low_confidence": "Skora dahil EDİLMEYEN düşük güvenli teknik sayısı",
}


def _severity(score: float) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def compute_risk_score(
    deduped_techniques: list[dict[str, Any]],
    attack_chain: list[dict[str, Any]],
    *,
    excluded_low_confidence: int = 0,
) -> dict[str, Any]:
    """deduped_techniques YALNIZCA guclu teknikleri icermelidir (bkz.
    app/correlation/dedup.py::split_by_confidence).

    Neden: skorun uc bileseni de teknik sayimina bakiyor. Tek kanita dayanan
    0.25 skorlu bir eslesme, hem technique_volume'u hem tactic_coverage'i
    yukseltip ortalama guveni dusuruyordu -- yani zayif bir sinyal skoru
    hem sisiriyor hem de kalitesini bozuyordu. excluded_low_confidence
    yalnizca raporlanir, hesaba girmez: okuyucu kac bulgunun disarida
    kaldigini skorun yaninda gormeli."""
    tactics_present = [phase["tactic"] for phase in attack_chain]
    total_tactics = len(TACTIC_ORDER) or 1
    tactic_coverage = (len(tactics_present) / total_tactics) * 30

    high_risk_present = [t for t in tactics_present if t in HIGH_RISK_TACTICS]
    high_risk_tactic_bonus = min(len(high_risk_present) * HIGH_RISK_BONUS_PER_TACTIC, HIGH_RISK_BONUS_CAP)

    technique_volume = min(len(deduped_techniques) * TECHNIQUE_VOLUME_PER_TECHNIQUE, TECHNIQUE_VOLUME_CAP)

    if deduped_techniques:
        avg_confidence = sum(t.get("max_confidence_score") or 0.0 for t in deduped_techniques) / len(deduped_techniques)
    else:
        avg_confidence = 0.0
    confidence_factor = avg_confidence * 20

    raw_total = tactic_coverage + high_risk_tactic_bonus + technique_volume + confidence_factor
    score = max(0, min(100, round(raw_total)))

    return {
        "score": score,
        "severity": _severity(score),
        "breakdown": {
            "tactic_coverage": round(tactic_coverage, 2),
            "high_risk_tactic_bonus": high_risk_tactic_bonus,
            "high_risk_tactics_present": high_risk_present,
            "technique_volume": technique_volume,
            "confidence_factor": round(confidence_factor, 2),
            "tactics_present": tactics_present,
            "excluded_low_confidence": excluded_low_confidence,
        },
    }


# --- GOSTERIM (Gorev 25) --------------------------------------------------
# Buradan asagisi SKORU HESAPLAMAZ. compute_risk_score'un urettigi
# `breakdown` sozlugunu okuyup her sayinin NEREDEN geldigini bir cumleye
# ceviriyor. Sikayet buydu: "tactic_coverage 4.0" analiste hicbir sey
# soylemiyor.
#
# HICBIR DEGER YENIDEN HESAPLANMAZ -- her cumledeki katki, breakdown'daki
# degerin ta kendisidir (bkz. tests/test_risk_breakdown_sentences.py).

THRESHOLD_SENTENCE = "Eşikler: <25 Düşük · 25-49 Orta · 50-74 Yüksek · 75+ Kritik"


def _tr(value: float) -> str:
    """Turkce ondalik ayraci. 4.0 -> '4', 13.08 -> '13,08'."""
    text = f"{value:.2f}".rstrip("0").rstrip(".")
    return text.replace(".", ",") or "0"


def _signed(value: float) -> str:
    return f"+{_tr(value)}"


def breakdown_sentences(
    risk: dict[str, Any], *, technique_count: int | None = None
) -> list[tuple[str, str, str]]:
    """(bilesen adi, gerekce cumlesi, katki) uclulerinin listesi.

    technique_count verilmezse technique_volume'dan geri hesaplanir; tavana
    dayanmis bir skorda bu sayi GERCEK teknik sayisindan kucuk cikabilecegi
    icin cagiran taraf biliyorsa vermelidir."""
    breakdown = risk.get("breakdown") or {}
    tactics_present = breakdown.get("tactics_present") or []
    high_risk = breakdown.get("high_risk_tactics_present") or []
    volume = breakdown.get("technique_volume") or 0
    confidence = breakdown.get("confidence_factor") or 0.0
    excluded = breakdown.get("excluded_low_confidence") or 0
    phases = len(TACTIC_ORDER)

    if technique_count is None:
        technique_count = int(volume // TECHNIQUE_VOLUME_PER_TECHNIQUE)

    rows: list[tuple[str, str, str]] = []

    rows.append((
        "Taktik yayılımı",
        f"{phases} ATT&CK fazından {len(tactics_present)} tanesi görüldü"
        + (f" ({', '.join(tactics_present)})" if tactics_present else ""),
        _signed(breakdown.get("tactic_coverage") or 0.0),
    ))

    if high_risk:
        capped = " — tavan uygulandı" if len(high_risk) * HIGH_RISK_BONUS_PER_TACTIC > HIGH_RISK_BONUS_CAP else ""
        gerekce = (
            f"{len(high_risk)} yüksek riskli taktik ({', '.join(high_risk)}) "
            f"× {HIGH_RISK_BONUS_PER_TACTIC}{capped}"
        )
    else:
        gerekce = (
            "Yüksek riskli taktiklerin hiçbiri görülmedi "
            f"({', '.join(sorted(HIGH_RISK_TACTICS))})"
        )
    rows.append(("Yüksek riskli taktik bonusu", gerekce, _signed(breakdown.get("high_risk_tactic_bonus") or 0)))

    capped = " (tavan)" if volume >= TECHNIQUE_VOLUME_CAP else ""
    rows.append((
        "Teknik çeşitliliği",
        f"{technique_count} doğrulanmış teknik × {TECHNIQUE_VOLUME_PER_TECHNIQUE}{capped}",
        _signed(volume),
    ))

    rows.append((
        "Güven katsayısı",
        f"Bu tekniklerin ortalama güven skoru {_tr(confidence / 20)} × 20",
        _signed(confidence),
    ))

    rows.append((
        "Skora girmeyen bulgular",
        f"{excluded} düşük güvenli teknik hesaba KATILMADI — silinmediler, "
        "'Doğrulama Gerektiren Zayıf Sinyaller' bölümünde duruyorlar",
        "0",
    ))

    return rows
