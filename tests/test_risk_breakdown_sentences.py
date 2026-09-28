"""Gorev 25 — risk skoru gerekce cumlelerinin sozlesmesi.

TEK ONEMLI MADDE: bu katman HICBIR SEY HESAPLAMAZ. Ekranda gorunen her
katki, compute_risk_score'un urettigi `breakdown` degerinin ta kendisi
olmali. Cumle uretici bir sayiyi kendi hesaplarsa, ekran skorla
celisebilir ve bunu kimse fark etmez."""

from __future__ import annotations

from app.correlation.attack_chain import TACTIC_ORDER
from app.correlation.risk_score import (
    HIGH_RISK_BONUS_CAP,
    HIGH_RISK_BONUS_PER_TACTIC,
    TECHNIQUE_VOLUME_CAP,
    THRESHOLD_SENTENCE,
    breakdown_sentences,
    compute_risk_score,
)


def _teknik(attack_id, score):
    return {"attack_id": attack_id, "max_confidence_score": score}


def _risk(techniques, tactics, excluded=0):
    return compute_risk_score(
        techniques,
        [{"tactic": t} for t in tactics],
        excluded_low_confidence=excluded,
    )


def test_katkilar_breakdown_degerlerinin_TA_KENDISI():
    """Gercek kosunun sayilari: 4.0 / 0 / 9 / 13.08 (risk 26)."""
    risk = _risk(
        [_teknik("T1134.002", 0.63), _teknik("T1205.002", 0.67), _teknik("T1546.003", 0.66)],
        ["Persistence", "Privilege Escalation"],
        excluded=22,
    )
    rows = breakdown_sentences(risk, technique_count=3)
    katkilar = {ad: katki for ad, _, katki in rows}
    b = risk["breakdown"]

    assert risk["score"] == 26 and risk["severity"] == "Medium"
    assert katkilar["Taktik yayılımı"] == "+4"
    assert katkilar["Yüksek riskli taktik bonusu"] == "+" + str(b["high_risk_tactic_bonus"])
    assert katkilar["Teknik çeşitliliği"] == "+" + str(b["technique_volume"])
    assert katkilar["Güven katsayısı"].replace(",", ".") == "+" + str(b["confidence_factor"])


def test_katkilarin_toplami_skora_esit():
    risk = _risk(
        [_teknik("T1", 0.9), _teknik("T2", 0.8)],
        ["Credential Access", "Impact", "Persistence"],
    )
    toplam = 0.0
    for _, _, katki in breakdown_sentences(risk):
        toplam += float(katki.replace("+", "").replace(",", "."))

    assert round(toplam) == risk["score"]


def test_gerekce_sayilari_breakdown_ile_TUTARLI():
    risk = _risk([_teknik("T1", 0.5)], ["Persistence", "Impact"])
    rows = {ad: gerekce for ad, gerekce, _ in breakdown_sentences(risk, technique_count=1)}

    assert str(len(TACTIC_ORDER)) + " ATT&CK fazından 2 tanesi" in rows["Taktik yayılımı"]
    assert "1 doğrulanmış teknik" in rows["Teknik çeşitliliği"]
    assert "Impact" in rows["Yüksek riskli taktik bonusu"]


def test_yuksek_riskli_taktik_yokken_HANGILERI_arandigi_yazilir():
    """Bonus 0 tek basina bilgi degil; analist hangi taktiklerin aranmis
    oldugunu bilmeli."""
    risk = _risk([_teknik("T1", 0.5)], ["Persistence"])
    gerekce = dict((ad, g) for ad, g, _ in breakdown_sentences(risk))["Yüksek riskli taktik bonusu"]

    assert "Credential Access" in gerekce and "Impact" in gerekce


def test_tavana_dayanan_bilesenler_ISARETLENIR():
    coklu = [_teknik("T" + str(i), 0.9) for i in range(10)]
    risk = _risk(coklu, ["Credential Access", "Impact", "Lateral Movement", "Persistence"])
    rows = dict((ad, g) for ad, g, _ in breakdown_sentences(risk, technique_count=10))

    assert risk["breakdown"]["technique_volume"] == TECHNIQUE_VOLUME_CAP
    assert "tavan" in rows["Teknik çeşitliliği"]
    assert risk["breakdown"]["high_risk_tactic_bonus"] == HIGH_RISK_BONUS_CAP
    assert "tavan" in rows["Yüksek riskli taktik bonusu"]


def test_skora_girmeyen_bulgular_ayri_satirda_ve_KATKISIZ():
    risk = _risk([_teknik("T1", 0.6)], ["Persistence"], excluded=22)
    ad, gerekce, katki = [r for r in breakdown_sentences(risk) if r[0] == "Skora girmeyen bulgular"][0]

    assert "22" in gerekce
    assert "silinmediler" in gerekce
    assert katki == "0"


def test_technique_count_verilmezse_hacimden_geri_hesaplanir():
    risk = _risk([_teknik("T1", 0.6), _teknik("T2", 0.6)], ["Persistence"])
    rows = dict((ad, g) for ad, g, _ in breakdown_sentences(risk))

    assert "2 doğrulanmış teknik" in rows["Teknik çeşitliliği"]


def test_esik_cumlesi_dort_sinirin_HEPSINI_sayiyla_yazar():
    for sinir in ("25", "49", "50", "74", "75"):
        assert sinir in THRESHOLD_SENTENCE
    for etiket in ("Düşük", "Orta", "Yüksek", "Kritik"):
        assert etiket in THRESHOLD_SENTENCE


def test_bos_incident_cokmez():
    risk = _risk([], [])
    rows = breakdown_sentences(risk)

    assert len(rows) == 5
    assert risk["score"] == 0


def test_bonus_carpani_koddan_okunur():
    """Cumledeki carpan elle yazilmis olsaydi sabit degisince yalan olurdu."""
    risk = _risk([_teknik("T1", 0.6)], ["Impact"])
    gerekce = dict((ad, g) for ad, g, _ in breakdown_sentences(risk))["Yüksek riskli taktik bonusu"]

    assert "× " + str(HIGH_RISK_BONUS_PER_TACTIC) in gerekce
