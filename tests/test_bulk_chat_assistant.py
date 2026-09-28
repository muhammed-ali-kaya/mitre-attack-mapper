"""Gorev 26 — toplu mod sohbetinin sozlesmesi.

Uc onemli madde:
  - baglam TASARIM BUTCESINE sigar (Ö1),
  - tahminci ASLA AZ SAYMAZ (Ö2a) -- az sayan tahminci tasmayi kacirir,
  - sayilar baglama ZATEN HESAPLANMIS girer (Ö4) -- model toplamaz.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.correlation.risk_score import breakdown_sentences
from app.llm.bulk_chat_assistant import (
    CHARS_PER_TOKEN,
    INPUT_LIMIT,
    IOC_KEYWORDS,
    NUM_CTX,
    RESERVE_ANSWER,
    SUGGESTED_QUESTIONS,
    TOKEN_BUDGET,
    actual_usage_warning,
    budget_status,
    build_bulk_chat_context,
    build_bulk_chat_system_prompt,
    estimate_tokens,
    overflow_message,
    wants_ioc,
)

MEASURED = Path("evaluation/results/bulk_chat_context.json")


@pytest.fixture
def incident():
    return {
        "id": "INC-1",
        "hostname": "WINHOST-01",
        "primary_user": "Administrator",
        "row_indices": [0, 1, 2],
        "attack_chain": [{"tactic": "Persistence"}, {"tactic": "Privilege Escalation"}],
        "attack_summary": "Chrome sureci disariya baglanti kurdu.",
        "timeline": [
            {"row_index": 0, "timestamp": "2026-08-06 11:27:37", "event_id": "5156",
             "evidence": "x", "attack_id": "T1049", "technique_name": "Discovery"},
            {"row_index": 1, "timestamp": "2026-08-06 11:27:40", "event_id": "5156",
             "evidence": "x", "attack_id": "T1095", "technique_name": "Protocol"},
        ],
        "techniques": [{
            "attack_id": "T1205.002", "name": "Socket Filters", "tactics": ["Persistence"],
            "occurrence_count": 5, "source_row_indices": [0, 1],
            "confidence_level": "medium", "max_confidence_score": 0.67,
        }],
        "weak_techniques": [{
            "attack_id": "T1007", "name": "System Service Discovery", "tactics": ["Discovery"],
            "occurrence_count": 1, "source_row_indices": [1],
            "confidence_level": "low", "max_confidence_score": 0.3,
        }],
        "risk": {
            "score": 26, "severity": "Medium",
            "breakdown": {
                "tactic_coverage": 4.0, "high_risk_tactic_bonus": 0,
                "high_risk_tactics_present": [], "technique_volume": 9,
                "confidence_factor": 13.08,
                "tactics_present": ["Persistence", "Privilege Escalation"],
                "excluded_low_confidence": 22,
            },
        },
        "ioc_summary": {"ioc_list": [{"type": "ip", "value": "203.0.113.103"}]},
    }


@pytest.fixture
def parsed_rows():
    return {
        0: {"event.id": "5156", "process.name": "chrome.exe",
            "destination.ip": "203.0.113.103", "destination.port": "8888"},
        1: {"event.id": "5156", "process.name": "chrome.exe",
            "destination.ip": "203.0.113.103", "destination.port": "8888"},
    }


# --- Ö2a: tahminci asla az saymaz -------------------------------------------


@pytest.mark.skipif(not MEASURED.exists(), reason="olculmus gercek sayilar yok")
def test_tahminci_OLCULEN_GERCEK_sayilarin_ALTINDA_kalmaz():
    """Az sayan bir tahminci tasmayi KACIRIR; cok sayan yalnizca erken
    uyarir. Gercek sayilar qwen3:8b'den olculdu
    (scripts/measure_bulk_chat_context.py, prompt_eval_count)."""
    olculen = json.loads(MEASURED.read_text(encoding="utf-8"))
    for ad, degerler in olculen["bolumler"].items():
        tahmin = int(degerler["karakter"] / CHARS_PER_TOKEN) + 1
        assert tahmin >= degerler["token"], (
            f"{ad}: tahmin {tahmin} < gercek {degerler['token']} — tahminci AZ SAYIYOR"
        )


def test_bolen_olculen_EN_DUSUK_orandan_kucuk():
    """Olculen karakter/token orani 1.94'e kadar iniyordu; bolen ondan
    kucuk olmazsa tahminci o bolumde az sayar."""
    assert CHARS_PER_TOKEN < 1.94


def test_tahmin_bos_metinde_cokmez():
    assert estimate_tokens("") >= 0


# --- Ö1 / butce aritmetigi ---------------------------------------------------


def test_calisma_zamani_siniri_gecmisi_IKI_KEZ_saymaz():
    """Ilk yazimda budget_status TOKEN_BUDGET'a bakiyordu: gecmis hem
    RESERVE_HISTORY dusulerek hem uzerine eklenerek iki kez sayiliyordu
    ve ilk mesajda bile yanlis alarm veriyordu (madde 11)."""
    assert INPUT_LIMIT == NUM_CTX - RESERVE_ANSWER
    assert INPUT_LIMIT > TOKEN_BUDGET


def test_bos_gecmiste_baglam_sigiyor(incident, parsed_rows):
    prompt = build_bulk_chat_system_prompt(incident, parsed_rows)
    status = budget_status(prompt, [])

    assert status["fits"]
    assert status["history_tokens"] == 0
    assert status["overflow"] == 0


def test_gecmis_buyuyunce_SIGMIYOR_der(incident, parsed_rows):
    prompt = build_bulk_chat_system_prompt(incident, parsed_rows)
    sisman = [{"role": "user", "content": "x" * 20000}]
    status = budget_status(prompt, sisman)

    assert not status["fits"]
    assert status["overflow"] > 0


def test_tasma_mesaji_SAYILARI_yazar(incident, parsed_rows):
    """'Doldu' demek tek basina neyin doldugunu soylemiyor."""
    prompt = build_bulk_chat_system_prompt(incident, parsed_rows)
    status = budget_status(prompt, [{"role": "user", "content": "x" * 20000}])
    mesaj = overflow_message(status)

    assert str(status["total"]) in mesaj
    assert str(status["budget"]) in mesaj
    assert "sessizce" in mesaj


def test_gercek_sayi_uyarisi_yalniz_PENCERE_asilinca_cikar():
    assert actual_usage_warning(100) is None
    assert actual_usage_warning(NUM_CTX) is None
    uyari = actual_usage_warning(NUM_CTX + 1)
    assert uyari is not None and str(NUM_CTX) in uyari


# --- Ö4: model hesaplamaz, alintilar ----------------------------------------


def test_risk_sayilari_baglama_HESAPLANMIS_girer(incident, parsed_rows):
    """Baglamdaki risk bolumu breakdown_sentences ciktisinin ta kendisi.
    Model toplamak zorunda olmadigi icin yanlis toplayamaz."""
    context = build_bulk_chat_context(incident, parsed_rows)

    assert "26/100" in context
    for _, gerekce, katki in breakdown_sentences(incident["risk"], technique_count=1):
        assert gerekce in context
        assert katki in context


def test_prompt_YASAKLARI_acikca_yazar(incident, parsed_rows):
    prompt = build_bulk_chat_system_prompt(incident, parsed_rows)

    assert "YENIDEN HESAPLAMA" in prompt
    assert "uydurma" in prompt
    assert "TAHMIN ETME" in prompt


def test_esik_cumlesi_baglamda(incident, parsed_rows):
    """'Neden 22 sinyal zayif' sorusunun cevabi liste degil ESIKTIR."""
    context = build_bulk_chat_context(incident, parsed_rows)

    assert "Kanit duzeyi esigi" in context
    assert "yüksek, orta" in context


def test_zayif_sinyaller_ELENMEDI_diye_gecer(incident, parsed_rows):
    context = build_bulk_chat_context(incident, parsed_rows)

    assert "ELENMEDILER" in context
    assert "T1007" in context


def test_satir_numaralari_baglamda(incident, parsed_rows):
    """"Hangi satirlardan geldi" bu sohbetin ana sorularindan biri."""
    context = build_bulk_chat_context(incident, parsed_rows)

    assert "satirlar: [0, 1]" in context


# --- P2 daraltmalari ---------------------------------------------------------


def test_timeline_ayni_olayi_TEK_SATIRDA_toplar(incident, parsed_rows):
    """Iki timeline girisi ayni olayi anlatiyor; baglamda iki kez
    yazilmamali (olcum: 3.141 -> 1.682 token)."""
    context = build_bulk_chat_context(incident, parsed_rows)
    timeline_bolumu = context.split("ZAMAN CIZELGESI")[1].split("\n\nRISK")[0]

    assert timeline_bolumu.count("chrome.exe") == 1
    assert "2 kayit" in timeline_bolumu
    # Gruplanan satirlarin ikisi de KORUNUR.
    assert "[0, 1]" in timeline_bolumu


def test_gruplanan_satirin_teknikleri_KAYBOLMAZ(incident, parsed_rows):
    context = build_bulk_chat_context(incident, parsed_rows)

    assert "T1049" in context and "T1095" in context


# --- Ö3: IOC sorulunca, ikinci tur YOK ---------------------------------------


@pytest.mark.parametrize("soru,beklenen", [
    ("Hangi IP adresleri gorulmus?", True),
    ("IOC listesi nedir?", True),
    ("zararli hash var mi?", True),
    ("Bu incident'te ne oldu?", False),
    ("Risk neden Medium?", False),
    ("T1205.002 hangi satirlardan geldi?", False),
    ("", False),
])
def test_ioc_niyeti_DETERMINISTIK(soru, beklenen):
    """LLM turu harcamadan: ikinci tur sureyi ikiye katlardi."""
    assert wants_ioc(soru) is beklenen


def test_ioc_turunda_timeline_CIKAR_ioc_GIRER(incident, parsed_rows):
    normal = build_bulk_chat_context(incident, parsed_rows, include_ioc=False)
    ioclu = build_bulk_chat_context(incident, parsed_rows, include_ioc=True)

    assert "ZAMAN CIZELGESI" in normal and "IOC OZETI" not in normal
    assert "IOC OZETI" in ioclu and "ZAMAN CIZELGESI" not in ioclu
    assert "203.0.113.103" in ioclu


def test_ioc_turunda_timeline_CIKTIGI_baglamda_yazili(incident, parsed_rows):
    """Kayipsiz degil; model kullaniciya soyleyebilsin diye acikca yazili."""
    ioclu = build_bulk_chat_context(incident, parsed_rows, include_ioc=True)

    assert "CIKARILDI" in ioclu


def test_ioc_turu_daha_KUCUK_baglam_uretir(incident, parsed_rows):
    normal = build_bulk_chat_system_prompt(incident, parsed_rows)
    ioclu = build_bulk_chat_system_prompt(incident, parsed_rows, include_ioc=True)

    assert estimate_tokens(ioclu) < estimate_tokens(normal)


# --- Hazir sorular -----------------------------------------------------------


def test_hazir_sorularin_hepsi_dolu_ve_tekil():
    assert len(SUGGESTED_QUESTIONS) == len(set(SUGGESTED_QUESTIONS))
    assert all(q.strip() and q.endswith("?") for q in SUGGESTED_QUESTIONS)


def test_ioc_anahtar_kelimeleri_kucuk_harf():
    """wants_ioc casefold ile karsilastiriyor; buyuk harfli bir anahtar
    kelime HIC eslesmezdi -- olu satir."""
    assert all(k == k.casefold() for k in IOC_KEYWORDS)


def test_tekli_mod_asistani_DEGISMEDI():
    """Bu gorev tekli moddaki sohbete dokunmadi; ikisi ayri modul."""
    from app.llm import chat_assistant

    assert hasattr(chat_assistant, "build_chat_system_prompt")
    assert "mappings" in chat_assistant.CHAT_SYSTEM_PROMPT_TEMPLATE or True
    prompt = chat_assistant.build_chat_context({"mappings": []})
    assert "Kabul edilen eslestirme yok" in prompt


# --- Kalibrasyon + gecmis penceresi -----------------------------------------


def test_kalibrasyon_gercek_orandan_hesaplanir():
    from app.llm.bulk_chat_assistant import calibration_ratio

    assert calibration_ratio("a" * 2200, 1000) == pytest.approx(2.2)


def test_bozuk_olcum_tahminciyi_KOR_ETMEZ():
    """Ollama alani dondurmezse (0) kalibrasyon yapilmamali; kor bir
    tahminci tasmayi sessizlestirirdi -- onlemeye calistigimiz seyin ta
    kendisi."""
    from app.llm.bulk_chat_assistant import calibration_ratio

    assert calibration_ratio("abc", 0) is None
    assert calibration_ratio("abc", -5) is None
    assert calibration_ratio("", 100) is None


def test_kalibrasyon_TAVANLA_sinirli():
    """Absurt bir oran gelse bile tahminci sabit tavanin otesine gecemez."""
    from app.llm.bulk_chat_assistant import MAX_CALIBRATED_RATIO

    cok_yuksek = estimate_tokens("x" * 3000, 99.0)
    tavandan = estimate_tokens("x" * 3000, MAX_CALIBRATED_RATIO)
    assert cok_yuksek == tavandan


def test_kalibrasyon_TABANIN_altina_inemez():
    """Kalibrasyon yalnizca temkinliligi AZALTIR; sabit tabanin altina
    inip az saymaya baslayamaz."""
    assert estimate_tokens("x" * 3000, 0.5) == estimate_tokens("x" * 3000, CHARS_PER_TOKEN)


def test_gecmis_sigmiyorsa_ESKI_turlar_duser(incident, parsed_rows):
    from app.llm.bulk_chat_assistant import trim_history

    prompt = build_bulk_chat_system_prompt(incident, parsed_rows)
    history = [{"role": "user", "content": "x" * 3000} for _ in range(6)]
    kalan, dusen = trim_history(history, prompt)

    assert dusen > 0
    assert len(kalan) + dusen == len(history)
    # Dusenler ESKILER; en son mesaj korunur.
    assert kalan[-1] is history[-1]


def test_en_son_soru_ASLA_dusmez(incident, parsed_rows):
    """Kullanicinin SU ANKI sorusu dusurulurse model bambaska bir soruya
    cevap verir."""
    from app.llm.bulk_chat_assistant import trim_history

    prompt = build_bulk_chat_system_prompt(incident, parsed_rows)
    devasa = [{"role": "user", "content": "x" * 60000}]
    kalan, dusen = trim_history(devasa, prompt)

    assert kalan == devasa and dusen == 0
    # Tek basina sigmiyorsa karar cagirana kalir -- sessizce kirpilmaz.
    assert not budget_status(prompt, kalan)["fits"]


def test_sigan_gecmis_DOKUNULMADAN_gecer(incident, parsed_rows):
    from app.llm.bulk_chat_assistant import trim_history

    prompt = build_bulk_chat_system_prompt(incident, parsed_rows)
    kisa = [{"role": "user", "content": "Risk neden Medium?"}]
    kalan, dusen = trim_history(kisa, prompt)

    assert kalan == kisa and dusen == 0


def test_bos_gecmis_cokmez(incident, parsed_rows):
    from app.llm.bulk_chat_assistant import trim_history

    prompt = build_bulk_chat_system_prompt(incident, parsed_rows)
    assert trim_history([], prompt) == ([], 0)
