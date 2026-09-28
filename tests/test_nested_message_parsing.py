"""Gorev 15 -- sarmalanan Message govdesinin ayristirilmasi.

Beklenti: docs/beklenti_15_kv_alan_kaybi.md
Olcum   : scripts/measure_kv_field_loss.py

Uc kusur birden kapaniyor ve UCU DE BIRBIRINE BAGLI:
    K-A  yuvalama       -- bir log, iki bicim (dis space_kv, ic windows_message)
    K-B  kacis asimetri -- serilestirme kacirir, ayristirma geri almazdi
    K-C  etiket siniri  -- keyfi 28 karakter, gercek etiketi kaciriyordu

Herhangi biri tek basina duzeltilseydi sonuc "dogru duzeltme, calismayan
sonuc" olurdu; bu yuzden her birinin AYRI testi var.
"""

from __future__ import annotations

import pytest

from app.batch.serialize import row_to_kv_string
from app.normalization.event_semantics import decode_access_mask, describe
from app.normalization.formats import parse_fields, unescape_serialized
from app.normalization.input_parser import normalize_input
from app.validation.decision import erisim_sinifi, varlik_kritikligi

BS = chr(92)

# Gercek bir 4656 registry govdesinin cekirdegi (tests/fixtures/
# qradar_2026-08-06_51rows.csv, G-007). 'Privileges Used for Access Check'
# 32 karakter -- eski 28'lik sinir onu goremiyordu.
GOVDE = (
    "A handle to an object was requested."
    "  Subject:  Security ID:  NT AUTHORITY" + BS + "LOCAL SERVICE"
    "  Account Name:  WINHOST-01$  Logon ID:  0x3E5"
    "  Object:  Object Server:  Security  Object Type:  Key"
    "  Object Name:  " + BS + "REGISTRY" + BS + "MACHINE" + BS + "SYSTEM"
    + BS + "ControlSet001" + BS + "Services" + BS + "tapisrv" + BS + "Performance"
    "  Handle ID:  0x0"
    "  Process Information:  Process ID:  0x1b34"
    "  Process Name:  C:" + BS + "Windows" + BS + "System32" + BS + "svchost.exe"
    "  Access Request Information:  Transaction ID:  {00000000-0000-0000-0000-000000000000}"
    "  Accesses:  READ_CONTROL     Query key value     Set key value"
    "  Access Reasons:  -"
    "  Access Mask:  0x2001F"
    "  Privileges Used for Access Check: -"
    "  Restricted SID Count: 4"
)

SATIR = {"EventID": 4656, "Hostname": "WINHOST-01", "Message": GOVDE}


def _kv_alanlari(satir: dict) -> dict:
    alanlar, _ = parse_fields(row_to_kv_string(satir))
    return alanlar


# -- K-A: yuvalanmis govde ayristiriliyor ------------------------------------

def test_sarmalanan_govdenin_alt_alanlari_kv_yolunda_gorunur():
    """Uretimin toplu modda hatta verdigi metin, ham govdenin alanlarini
    KAYBETMEZ. Kayip 51 satirda 84 alandi (docs/beklenti_15 SS1)."""
    alanlar = _kv_alanlari(SATIR)
    for ad in ("access.mask", "access.list", "object.name", "object.type",
               "process.id", "handle.id"):
        assert ad in alanlar, f"{ad} KV yolunda kayboldu"


def test_donen_bicim_adi_DIS_bicimdir():
    """Ic ayristirma bir kurtarma adimidir, bir bicim degil. 'Bu log hangi
    bicimde' sorusunun tek cevabi olmali."""
    _, bicim = parse_fields(row_to_kv_string(SATIR))
    assert bicim == "space_kv"


def test_dis_alan_ic_govdeyi_yener():
    """YETKI SIRASI SOZLESMESI: dis alanlar kaynagin ACIK kolonlaridir,
    ic govde best-effort'tur. Sira degisirse bu test kirilir -- varsayim
    sessizce donmesin (HANDOFF dersi 8)."""
    satir = dict(SATIR, NewProcessName="C:" + BS + "gercek.exe")
    alanlar = _kv_alanlari(satir)
    assert alanlar["process.name"].text == "C:" + BS + "gercek.exe"


def test_ic_govde_yalnizca_tek_seviye_iniyor():
    """Govde icinde yine bir Message= alani varsa sonsuz inis olmamali."""
    ic_ice = dict(SATIR, Message='Message="Object Name:  X"  Object Type:  Key')
    alanlar = _kv_alanlari(ic_ice)  # patlamamali
    assert "event.message" in alanlar


def test_bilgi_tasimayan_deger_ic_govdeden_KURTARILMAZ():
    """Boslugu bos bir degerle doldurmak bosluktan kotudur.

    Somut zarar: decision._alan yalnizca 'N/A'yi yokluk sayiyor, '-' saymiyor.
    Ic govdeden gelen object.name='-' iyi olan file.path'i GOLGELERDI."""
    satir = {
        "EventID": 4656,
        "FilePath": BS + "REGISTRY" + BS + "MACHINE" + BS + "SAM",
        "Message": "A handle was requested.  Object Name:  -  Object Type:  Key",
    }
    alanlar = _kv_alanlari(satir)
    assert "object.name" not in alanlar

    seviye, aile, yol = varlik_kritikligi({"parsed_fields": alanlar})
    assert yol == BS + "REGISTRY" + BS + "MACHINE" + BS + "SAM"
    assert seviye == "critical"


# -- K-B: kacis gidis-donusu -------------------------------------------------

@pytest.mark.parametrize("deger", [
    "reg.exe save HKLM" + BS + "SAM C:" + BS + "Users" + BS + "Public" + BS + "sam.hiv",
    "reg.exe export " + BS + BS + "REGISTRY" + BS + BS + "MACHINE" + BS + BS + "SAM C:" + BS + "o.reg",
    'cmd.exe /c "echo merhaba"',
    "powershell.exe -File C:" + BS + "Program Files" + BS + "a.ps1",
])
def test_kacis_gidis_donusu_degeri_korur(deger):
    """row_to_kv_string tirnaklarken kacis uygular; ayristirma geri almali.

    Eski test (test_batch_serialize) ne ters bolu ne tirnak iceren bir komut
    satiri kullaniyordu, yani bu asimetriyi GOREMIYORDU -- HANDOFF dersi 9."""
    alanlar, _ = parse_fields(row_to_kv_string({"EventID": 4688, "CommandLine": deger}))
    assert alanlar["process.command_line"].text == deger


def test_kacis_geri_alma_DAR_tutulur():
    """Yalnizca serilestirmenin URETTIGI iki dizi geri alinir.

    Genel bir r'\\\\(.)' kurali ucuncu taraf loglarindaki tirnak ici
    'C:\\Users\\...' yollarindan ters boluyu SILERDI."""
    assert unescape_serialized("C:" + BS + "Users" + BS + "Public") == "C:" + BS + "Users" + BS + "Public"
    assert unescape_serialized("C:" + BS + BS + "Users") == "C:" + BS + "Users"
    assert unescape_serialized(BS + '"alinti' + BS + '"') == '"alinti"'


def test_kacis_kritikligi_bozuyordu():
    """Regresyon capasi: K-B tek basina birakilsaydi K-A'nin kurtardigi
    registry yollari 'unknown'a duserdi."""
    satir = {
        "EventID": 4688,
        "CommandLine": "reg.exe save HKLM" + BS + "SAM C:" + BS + "Users" + BS + "Public" + BS + "s.hiv",
    }
    normalized = normalize_input(row_to_kv_string(satir))
    seviye, aile, _ = varlik_kritikligi(normalized)
    assert (seviye, aile) == ("critical", "credential-hive")


# -- K-C: etiket siniri uzunluktan degil, degismezden --------------------

def test_uzun_etiket_taniniyor():
    """'Privileges Used for Access Check' 32 karakter; eski 28'lik sinir
    onu goremiyor ve metnini access.mask'in DEGERINE yapistiriyordu."""
    alanlar = _kv_alanlari(SATIR)
    assert alanlar["access.mask"].text == "0x2001F"


def test_iki_bosluk_iceren_dize_etiket_SAYILMAZ():
    """Sinir uzunluk olsaydi buyutmek bu kez degeri etiket sanardi:
    'Notify about changes to keys       Access Reasons' bir etiket DEGILDIR,
    cunku 2+ ardisik bosluk zaten etiket/deger ayracidir."""
    alanlar = _kv_alanlari(SATIR)
    bozuk = [ad for ad in alanlar if "  " in ad]
    assert bozuk == []


def test_maske_cozulebiliyor_ve_yazma_erisimi_gorunuyor():
    """UCUNUN BIRLIKTE calistiginin kaniti -- ve Yol B'nin ateslenebilmesinin
    on kosulu. G kolunda bu 0/5 idi (docs/sonuc_13_g_kolu.md SS2)."""
    alanlar = _kv_alanlari(SATIR)
    cozum = decode_access_mask(alanlar["access.mask"].text, "Key")
    assert cozum is not None
    assert "write" in cozum.classes

    # GOREV 18: bu satir bir 4656, yani handle TALEBI. Maske cozuluyor ve
    # yazma biti GORUNUYOR -- bu testin asil iddiasi buydu ve ayakta. Ama
    # talep artik gerceklesen erisim sayilmiyor: yazma, requested_class
    # olarak raporlaniyor. Yol B'nin on kosulu "maske okunabiliyor"dur;
    # "her handle talebi yazmadir" degil.
    d = describe(alanlar["event.id"].value, alanlar["access.mask"].value, "Key", None)
    assert d["requested_class"] == "write"
    assert d["access_realized"] is False
    assert erisim_sinifi({"parsed_fields": alanlar}) == "read"
