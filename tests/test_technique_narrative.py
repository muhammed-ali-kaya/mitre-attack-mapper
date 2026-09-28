"""Gorev 25 — "ne oldu" cumlesinin sozlesmesi.

En onemli iki madde: cumle UYDURULMAZ (veri yoksa None) ve alan secimi
`config/event_semantics.yaml`ten gelir, bu modulde ikinci bir tablo
YOKTUR."""

from __future__ import annotations

from datetime import datetime

import pytest

from app.correlation.technique_narrative import (
    ACTOR_FIELDS,
    TARGET_FIELDS,
    VALUE_LENGTH_LIMIT,
    base_name,
    technique_sentence,
    technique_sentences,
)
from app.normalization.event_semantics import event_semantics


def _tech(indices=(0,), timestamp="2026-08-06 11:27:37", attack_id="T1205.002"):
    return {
        "attack_id": attack_id,
        "source_row_indices": list(indices),
        "first_seen_timestamp": timestamp,
    }


def test_gercek_5156_kaydi_analistin_istedigi_cumleyi_uretir():
    """Kullanicinin verdigi ornek: saat, surec, hedef, olayin anlami, ID."""
    row = {
        "event.id": "5156",
        "process.name": r"\device\harddiskvolume3\program files\google\chrome\application\chrome.exe",
        "source.ip": "198.51.100.185",
        "destination.ip": "203.0.113.103",
        "destination.port": "8888",
    }
    sentence = technique_sentence(_tech(), {0: row})

    assert sentence is not None
    assert sentence.startswith("11:27 · chrome.exe → 203.0.113.103:8888")
    assert sentence.endswith("(5156)")
    # Anlam KATALOGTAN gelir, burada yazili degildir.
    assert event_semantics("5156")["anlam"] in sentence


def test_alan_secimi_katalogtan_gelir_modulde_ikinci_tablo_yok():
    """anlamli_alanlar DISINDAKI bir alan dolu olsa bile cumleye girmez.

    Bu, madde 7'nin ("ayni isi yapan baska kac yol var?") testi: alan
    secimi tek bir yerde, event_semantics.yaml'de tanimli."""
    row = {
        "event.id": "5156",
        "process.name": "chrome.exe",
        "destination.ip": "203.0.113.103",
        "destination.port": "8888",
        # 5156'nin anlamli_alanlar listesinde YOK:
        "object.name": r"\REGISTRY\MACHINE\SYSTEM\CurrentControlSet",
        "target.user.name": "kurban",
    }
    sentence = technique_sentence(_tech(), {0: row})

    assert "REGISTRY" not in sentence
    assert "kurban" not in sentence
    assert "5156" in sentence


def test_katalogda_olmayan_olay_icin_cumle_UYDURULMAZ():
    """Gercek kosuda olculdu: 4690 ve 403 katalogda yok (Ö1)."""
    row = {"event.id": "4690", "process.name": "chrome.exe", "account.name": "SYSTEM"}
    assert event_semantics("4690") is None, "test onculu: 4690 katalogda olmamali"
    assert technique_sentence(_tech(), {0: row}) is None


def test_anlamli_alanlarin_hicbiri_dolu_degilse_cumle_yok():
    row = {"event.id": "5156", "unknown.Foo": "dolu ama anlamsiz"}
    assert technique_sentence(_tech(), {0: row}) is None


def test_bos_parca_icin_yer_tutucu_BASILMAZ():
    """Gorev 24'un `- -` dersi: iceriksiz isaret basmak yerine parca duser."""
    row = {"event.id": "4673", "process.name": "chrome.exe"}
    sentence = technique_sentence(_tech(), {0: row})

    assert sentence is not None
    assert "→" not in sentence, "hedef yokken ok basilmamali"
    assert "-," not in sentence and ", -" not in sentence


def test_taban_ad_turetimi_TEK_TARAFLI():
    """Gorev 24'un kurali: yol -> ad turetilir; ad yol sayilmaz."""
    assert base_name(r"C:\Program Files\Google\Chrome\chrome.exe") == "chrome.exe"
    assert base_name(r"\device\harddiskvolume3\windows\system32\svchost.exe") == "svchost.exe"
    # Dizinsiz deger oldugu gibi kalir -- yol UYDURULMAZ.
    assert base_name("chrome.exe") == "chrome.exe"


def test_kaydedilmis_sonuctaki_STRING_zaman_damgasi_okunur():
    """Demo diske kaydedilmis sonuctan aciliyor; result_store json.dumps
    default=str ile yaziyor, yani datetime STRING olarak geri geliyor."""
    row = {"event.id": "5156", "process.name": "chrome.exe", "destination.ip": "10.0.0.1"}

    from_string = technique_sentence(_tech(timestamp="2026-08-06 11:27:37"), {0: row})
    from_datetime = technique_sentence(
        _tech(timestamp=datetime(2026, 8, 6, 11, 27, 37)), {0: row}
    )

    assert from_string == from_datetime
    assert from_string.startswith("11:27 · ")


def test_zaman_damgasi_cozulemezse_cumle_yine_kurulur():
    row = {"event.id": "5156", "process.name": "chrome.exe", "destination.ip": "10.0.0.1"}
    sentence = technique_sentence(_tech(timestamp="bozuk-damga"), {0: row})

    assert sentence is not None
    assert "·" not in sentence
    assert "chrome.exe → 10.0.0.1" in sentence


def test_ipv6_adresi_koseli_ayracla_birlesir():
    """Gercek 5158 kaydinda source.ip '::' -- duz birlestirme ':::54770'
    uretiyordu ve okunmuyordu."""
    row = {"event.id": "5158", "process.name": "chrome.exe", "source.ip": "::", "source.port": "54770"}
    sentence = technique_sentence(_tech(), {0: row})

    assert "[::]:54770" in sentence
    assert ":::" not in sentence


def test_uzun_deger_kirpildigini_ISARETLER():
    uzun = r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\WSearchIdxPi\Performance\Cok\Uzun\Yol"
    row = {"event.id": "4656", "object.name": uzun, "process.name": "svchost.exe"}
    sentence = technique_sentence(_tech(), {0: row})

    assert "…" in sentence, "sessizce kirpmak, tam deger gosterildigi izlenimi verir"
    assert uzun not in sentence


def test_satir_bulunamazsa_None():
    assert technique_sentence(_tech(indices=(99,)), {0: {"event.id": "5156"}}) is None
    assert technique_sentence(_tech(indices=()), {}) is None


def test_legacy_EventID_de_okunur():
    """text_to_row IKI namespace'i birden yaziyor (Gorev 24); yalnizca
    birine bakmak iki kez yanlis sayi uretmisti."""
    row = {"EventID": "5156", "process.name": "chrome.exe", "destination.ip": "10.0.0.1"}
    assert technique_sentence(_tech(), {0: row}) is not None


def test_cumlesiz_teknik_sozlukte_YER_ALMAZ():
    rows = {0: {"event.id": "5156", "process.name": "chrome.exe", "destination.ip": "10.0.0.1"},
            1: {"event.id": "4690", "process.name": "chrome.exe"}}
    out = technique_sentences(
        [_tech(indices=(0,), attack_id="T1"), _tech(indices=(1,), attack_id="T2")], rows
    )

    assert "T1" in out
    assert "T2" not in out, "cumle kurulamayan teknik sessizce '-' ile doldurulmamali"


@pytest.mark.parametrize("field", [f for f in ACTOR_FIELDS] + [f for f, _ in TARGET_FIELDS])
def test_her_gosterim_alani_en_az_bir_olayin_anlamli_alani(field):
    """Gosterim tablosunda, hicbir olayin anlamli saymadigi bir alan
    bulunmamali -- oyle bir satir OLU kod olurdu ve tabloyu buyuturdu."""
    events = __import__("app.normalization.event_semantics", fromlist=["_load"])
    catalog = events._load(events.EVENT_FILE, "events")["events"]
    kullanilan = {
        alan
        for olay in catalog.values()
        for alan in (olay.get("anlamli_alanlar") or [])
    }
    assert field in kullanilan, f"{field} hicbir olayda anlamli degil -- olu satir"


def test_kirpma_siniri_tek_satira_sigacak_kadar_kisa():
    assert 40 <= VALUE_LENGTH_LIMIT <= 120
