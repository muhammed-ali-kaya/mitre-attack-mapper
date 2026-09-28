"""Cok olayli girdinin HAT uzerindeki yolu (Gorev 14).

NE OLCULUYOR: `run_improved_query`'nin bolme + birlestirme yarisi. LLM ve
indeks devrede DEGIL -- tek-olay analizi (`_analyze_event`) sahteleniyor.
Gerekce: bu testin sorusu "model dogru teknigi buluyor mu" degil, "bolunen
olaylarin sonuclari BIRLESTIRILIRKEN bir sey kayboluyor mu".

NEDEN AYRI DOSYA: burasi hattin sozlesmesini olcuyor, karar katmanininkini
degil. Karar katmani tests/test_merge_vulnerability.py'de.
"""
from __future__ import annotations

from typing import Any

import pytest

from app.retrieval import improved_pipeline
from app.validation.decision import (
    INSUFFICIENT_DATA,
    SUFFICIENT_BENIGN,
    SUFFICIENT_SUSPICIOUS,
)

EV1 = "{Event ID=4657, Object Name=\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\A, Process Name=TrustedInstaller.exe, Account Name=corp\\attacker}"
EV2 = "{Event ID=4624, Logon Type=5, Account Name=SYSTEM}"


def _sahte_sonuc(
    karar: str,
    teknikler: list[str],
    *,
    sure: float = 1.0,
    token: int = 10,
) -> dict[str, Any]:
    return {
        "input_summary": {
            "raw_input": "x",
            "platform_filter": None,
            "detected_platform": "Windows",
            "detected_tools": ["reg.exe"],
            "is_remote": False,
            "observed_actions_heuristic": ["bir sey oldu"],
        },
        "decision": {
            "decision": karar,
            "label": karar,
            "reason": f"{karar} gerekcesi",
            "reason_chain": [f"{karar} zinciri"],
            "inputs": {"dogrulanmis_kanit": 1},
            "paths": {"A": True, "B": False},
            "suppression": {"aile": "service"} if karar == SUFFICIENT_BENIGN else None,
        },
        "benign_signals_display": ["sinyal"],
        "observed_behaviors": ["davranis"],
        "filtered_observed_behaviors": [],
        "mappings": [{"attack_id": t, "name": t, "confidence_level": "medium"} for t in teknikler],
        "mappings_before_agents": [{"attack_id": t} for t in teknikler],
        "mappings_after_first_pass": [],
        "rejected_mappings": [],
        "agent_rejected_mappings": [],
        "agent_decisions": [{"agent_id": "g", "attack_id": t} for t in teknikler],
        "alternative_candidates": [],
        "additional_data_needed": ["daha fazla log"],
        "evidence_summary": {"detected": ["kanit"], "not_detected": []},
        "attack_version": "19.2",
        "retrieved_chunk_ids": ["c1"],
        "retrieval_candidates": [{"attack_id": teknikler[0] if teknikler else "T0"}],
        "retrieval_candidates_first_pass": [],
        "loop_passes": 1,
        "loop_trace": ["tur 1"],
        "timings": {"total_seconds": sure},
        "token_usage": {"total_tokens": token},
        "system": "improved",
    }


@pytest.fixture
def sahte_analiz(monkeypatch: pytest.MonkeyPatch):
    """Her cagriyi kaydeder ve sirayla hazir sonuc dondurur."""
    cagrilar: list[str] = []
    kuyruk: list[dict[str, Any]] = []

    def _fake(user_input: str, platform: str | None = None) -> dict[str, Any]:
        cagrilar.append(user_input)
        return kuyruk[len(cagrilar) - 1]

    monkeypatch.setattr(improved_pipeline, "_analyze_event", _fake)
    return cagrilar, kuyruk


def test_her_olay_KENDI_cagrisini_aliyor(sahte_analiz) -> None:
    """Toplu modun yaptigi seyin ayni: satir basina bir analiz."""
    cagrilar, kuyruk = sahte_analiz
    kuyruk += [
        _sahte_sonuc(SUFFICIENT_SUSPICIOUS, ["T1543.003"]),
        _sahte_sonuc(INSUFFICIENT_DATA, []),
    ]

    improved_pipeline.run_improved_query(EV1 + "\n" + EV2)

    assert len(cagrilar) == 2
    assert cagrilar[0].startswith("{Event ID=4657")
    assert cagrilar[1].startswith("{Event ID=4624")
    # Birlestirilmis metin HICBIR cagriya girmiyor -- acigin kok nedeni buydu.
    assert not any("4657" in c and "4624" in c for c in cagrilar)


def test_alarm_karari_EN_SERT_eventten(sahte_analiz) -> None:
    cagrilar, kuyruk = sahte_analiz
    kuyruk += [
        _sahte_sonuc(SUFFICIENT_BENIGN, []),
        _sahte_sonuc(SUFFICIENT_SUSPICIOUS, ["T1543.003"]),
    ]

    sonuc = improved_pipeline.run_improved_query(EV1 + "\n" + EV2)
    karar = sonuc["decision"]

    assert karar["decision"] == SUFFICIENT_SUSPICIOUS
    assert karar["belirleyen_event"] == 1
    assert karar["dagilim"][SUFFICIENT_BENIGN] == 1
    # Bastirma event seviyesinde kaldi, alarma yayilmadi.
    assert karar["event_kararlari"][0]["suppression"]
    assert sonuc["split"]["event_count"] == 2


def test_mappingler_teknik_basina_TEKLESIYOR_ve_kaynagi_tasiyor(sahte_analiz) -> None:
    """`mappings` her yerde TEKNIK LISTESI olarak okunuyor (metrics, UI,
    QRadar taslagi); ayni ID'yi iki kez koymak bir teknigi iki bulgu gibi
    saydirirdi."""
    cagrilar, kuyruk = sahte_analiz
    kuyruk += [
        _sahte_sonuc(SUFFICIENT_SUSPICIOUS, ["T1543.003", "T1112"]),
        _sahte_sonuc(INSUFFICIENT_DATA, ["T1112"]),
    ]

    sonuc = improved_pipeline.run_improved_query(EV1 + "\n" + EV2)
    idler = [m["attack_id"] for m in sonuc["mappings"]]

    assert idler == ["T1543.003", "T1112"]
    t1112 = next(m for m in sonuc["mappings"] if m["attack_id"] == "T1112")
    assert t1112["source_event_indices"] == [0, 1]
    assert t1112["source_event_index"] == 0


def test_sayisal_alanlar_TOPLANIYOR(sahte_analiz) -> None:
    """Alarm iki event'e bolunduyse harcanan sure ikisinin toplamidir;
    birini raporlamak maliyeti yariya gosterirdi."""
    cagrilar, kuyruk = sahte_analiz
    kuyruk += [
        _sahte_sonuc(INSUFFICIENT_DATA, [], sure=2.0, token=100),
        _sahte_sonuc(INSUFFICIENT_DATA, [], sure=3.0, token=250),
    ]

    sonuc = improved_pipeline.run_improved_query(EV1 + "\n" + EV2)

    assert sonuc["timings"]["total_seconds"] == pytest.approx(5.0)
    assert sonuc["token_usage"]["total_tokens"] == 350


def test_cikti_sozlesmesi_KORUNUYOR(sahte_analiz) -> None:
    """Toplu mod, arayuz ve degerlendirme betikleri bu anahtarlara bagli."""
    cagrilar, kuyruk = sahte_analiz
    kuyruk += [
        _sahte_sonuc(SUFFICIENT_SUSPICIOUS, ["T1543.003"]),
        _sahte_sonuc(INSUFFICIENT_DATA, []),
    ]

    tekli_anahtarlar = set(_sahte_sonuc(INSUFFICIENT_DATA, []))
    coklu = improved_pipeline.run_improved_query(EV1 + "\n" + EV2)

    eksik = tekli_anahtarlar - set(coklu)
    assert not eksik, f"cok olayli ciktida eksik anahtar: {sorted(eksik)}"
    assert coklu["system"] == "improved"
    assert coklu["input_summary"]["raw_input"] == EV1 + "\n" + EV2


def test_TEK_olayli_girdi_ayni_yoldan_geciyor(sahte_analiz) -> None:
    """Dallanma yok: tek olayli girdi de bolme + birlestirmeden gecer, ama
    sonuc tek event'in sonucudur ve zincire hicbir sey EKLENMEZ.

    Gecmis olcumlerle karsilastirilabilirligin sarti bu."""
    cagrilar, kuyruk = sahte_analiz
    kuyruk += [_sahte_sonuc(SUFFICIENT_SUSPICIOUS, ["T1543.003"])]

    sonuc = improved_pipeline.run_improved_query(EV1)

    assert len(cagrilar) == 1
    assert sonuc["decision"]["decision"] == SUFFICIENT_SUSPICIOUS
    assert sonuc["decision"]["reason_chain"] == [f"{SUFFICIENT_SUSPICIOUS} zinciri"]
    assert sonuc["decision"]["reason"] == f"{SUFFICIENT_SUSPICIOUS} gerekcesi"
    assert sonuc["decision"]["belirleyen_event"] == 0
    assert sonuc["split"]["event_count"] == 1
    # Tekli ciktinin geri kalani AYNEN korunuyor.
    assert sonuc["mappings"][0]["attack_id"] == "T1543.003"
    assert sonuc["timings"]["total_seconds"] == pytest.approx(1.0)


def test_bolunemeyen_girdide_UYARI_karar_zincirine_yaziliyor(sahte_analiz) -> None:
    """Kalan risk gorunur kaliyor: bolunemeyen cok olayli girdide alanlar
    hala birlesiyor, ama durum sessiz degil."""
    cagrilar, kuyruk = sahte_analiz
    kuyruk += [_sahte_sonuc(INSUFFICIENT_DATA, [])]

    ham = (
        "EventID=4688 NewProcessName=powershell.exe followed by "
        "EventID=4688 NewProcessName=schtasks.exe"
    )
    sonuc = improved_pipeline.run_improved_query(ham)

    assert sonuc["split"]["warning"]
    assert any("BÖLÜNEMEDİ" in adim for adim in sonuc["decision"]["reason_chain"])
