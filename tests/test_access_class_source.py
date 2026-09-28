"""Gorev 19 -- erisim sinifi KAYNAGI (maske / Accesses metni).

Beklenti: docs/beklenti_19_accesses_metni.md

Iki gercek QRadar logu ayni belirtiyi (gerekce zincirinde "salt okuma")
IKI FARKLI sebeple uretiyordu. Bu dosya ikisini AYRI AYRI kilitler --
ayni testte toplanirsa biri duzeltilip digeri yerinde kalabilir.
"""
from __future__ import annotations

import json
import pathlib

import pytest

from app.normalization.event_semantics import decode_access_mask, describe
from app.normalization.input_parser import normalize_input
from app.validation.decision import decide

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "access_class_source_logs.json"
LOGS = {g["id"]: g for g in json.loads(FIXTURE.read_text(encoding="utf-8"))["logs"]}


def _ozet(log_id: str) -> dict:
    n = normalize_input(LOGS[log_id]["raw"])
    p = n["parsed_fields"]

    def v(ad):
        f = p.get(ad)
        return getattr(f, "value", None)

    return describe(v("event.id") or n.get("event_id"), v("access.mask"),
                    v("object.type"), v("access.list"))


# ------------------------------------------- birim: metin tek basina sinif verir

def test_accesses_metni_maske_YOKKEN_sinif_uretir():
    """Gorev 19'un cekirdegi. Eskiden `if not mask: return None` idi."""
    d = decode_access_mask(None, "Key", "Set key value")
    assert d is not None
    assert d.classes == {"write"}
    assert d.access_class == "write"
    assert d.source == "text"
    assert d.raw is None


def test_taninmayan_erisim_adi_sinif_UYDURMAZ():
    """Uydurulmus bir sinif, olmayan bir siniftan kotudur.

    GOREV 20'DE DEGISTI. Once `None` donuyordu ve bu SESSIZ bir yanlisti:
    cagiran olayin varsayilanina dusuyor, 4663 icin `read` cikiyordu --
    yani cozulemeyen bir YAZMA adi okuma sayiliyordu. Artik cozulemeyen ad
    raporlaniyor ve sinif `unknown`.

    Testin ASIL iddiasi degismedi ve hala sinaniyor: sinif UYDURULMUYOR."""
    d = decode_access_mask(None, "Key", "Tanimsiz Erisim Adi")
    assert d is not None
    assert d.classes == set()            # sinif uydurulmadi
    assert d.access_class == "unknown"   # ama sessiz de kalmadi
    assert d.unresolved == ["Tanimsiz Erisim Adi"]


def test_maske_varken_kaynak_maske_kalir_ve_celiski_RAPORLANIR():
    """Gorev 3'un celiski politikasi: ikisi de raporlanir, biri sessizce
    secilmez."""
    d = decode_access_mask("0x20006", "Key", "Set key value")
    assert d.access_class == "write"
    assert d.source == "mask+text"
    assert d.inconsistent_with_text is True
    assert "keycreatesubkey" in d.mask_only


# ------------------------------------------- L1: 4656 TALEP ayrimi KORUNUR

def test_L1_4656_maskede_yazma_biti_olsa_da_TALEPTIR():
    """GOREV 18 KORUNUYOR. Bu test dusesiye kadar 19, 18'i bozmamis demektir."""
    r = _ozet("L1")
    assert r["access_class"] == LOGS["L1"]["expected_access_class"] == "read"
    assert r["requested_class"] == "write"
    assert r["access_realized"] is False


def test_L1_gerekce_metni_TALEBI_soyler_salt_okuma_demekle_yetinmez():
    """Kusurun kendisi buydu: maskesinde iki yazma biti olan bir kayit icin
    analiste 'salt okuma' demek yanlis sey soylemektir."""
    karar = decide(normalize_input(LOGS["L1"]["raw"]), [], None)
    assert karar.decision == LOGS["L1"]["expected_decision"]
    govde = " ".join(karar.reason_chain) + " " + karar.reason
    assert LOGS["L1"]["_beklenen_metin"] in govde
    assert karar.inputs["talep_edilen_erisim"] == "write"


# ------------------------------------------- L2: metin-tek yol

def test_L2_4663_metin_tek_yazma_uretir():
    r = _ozet("L2")
    assert r["access_class"] == "write"
    assert r["access_class_source"] == "text"
    assert r["requested_class"] is None


def test_L2_gurultu_anahtarina_YAZMA_benign_sayilmaz():
    """Duzeltmeden once SUFFICIENT_BENIGN idi ('salt okuma' dali)."""
    karar = decide(normalize_input(LOGS["L2"]["raw"]), [], None)
    assert karar.decision == LOGS["L2"]["expected_decision"] == "INSUFFICIENT_DATA"


# ------------------------------------------- L3: kacan alarm

def test_L3_KRITIK_varlikta_alarm_ARTIK_KACMIYOR():
    """Riskin kendisi. Duzeltmeden once INSUFFICIENT_DATA donuyordu: SAM
    hive'a yazma, Yol B hic ateslenmeden geciyordu."""
    log = LOGS["L3"]
    karar = decide(normalize_input(log["raw"]), [], None)
    assert karar.inputs["kritiklik"] == "critical"
    assert karar.inputs["erisim_sinifi"] == "write"
    assert karar.decision == log["expected_decision"] == "SUFFICIENT_SUSPICIOUS"
    assert karar.paths == log["expected_paths"]


def test_L3_alarmin_varligi_kaynagin_maskeyi_yazmasina_BAGLI_DEGIL():
    """Ayni olay, iki farkli kaynak bicimi, AYNI karar cikmali.

    Kusurun ozu buydu: alarm, kaynagin hex maskeyi loglayip loglamamasina
    bagliydi. Bu test o bagimliligi kilitler."""
    metinli = decide(normalize_input(LOGS["L3"]["raw"]), [], None)
    maskeli_ham = LOGS["L3"]["raw"].replace(
        "Accesses:  Set key value", "Accesses:  Set key value  Access Mask:  0x20006"
    )
    maskeli = decide(normalize_input(maskeli_ham), [], None)
    assert metinli.decision == maskeli.decision == "SUFFICIENT_SUSPICIOUS"
    assert metinli.paths == maskeli.paths


@pytest.mark.parametrize("log_id", ["L1", "L2", "L3"])
def test_fixture_beklentileri_kod_ile_ayrismiyor(log_id: str):
    """Fixture'daki beklenti ile uretilen deger tek kaynak olmali."""
    log = LOGS[log_id]
    r = _ozet(log_id)
    assert r["access_class"] == log["expected_access_class"]
    assert r["requested_class"] == log["expected_requested_class"]
    assert r["access_class_source"] == log["expected_access_class_source"]
