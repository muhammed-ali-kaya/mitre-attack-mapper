"""Gorev 20 -- erisim adi kapsami, ayrac ve taninmayan ad politikasi.

Beklenti: docs/beklenti_20_erisim_adi_kapsami.md

Gorev 19 `Accesses` metnini erisim sinifina soktu ama takma ad tablosu
dokuz elle yazilmis girdiydi. Olculdu: 22 Windows goruntu adinin 9'u
cozuluyordu (%40) ve KACANLARIN 7'SI YAZMA idi -- yani duzeltilen bug
baska bir yazimla tekrarlanabiliyordu.

BU DOSYA TABLOYU DEGIL KURALI SINAR. Beklenen sinif hicbir yerde elle
yazilmadi; her adin karsilik geldigi bitin config/access_mask.yaml'daki
sinifindan aliniyor. Tabloya yeni bir bit eklenirse bu testler onu da
kapsar.
"""
from __future__ import annotations

import pathlib

import pytest
import yaml

from app.normalization.event_semantics import (
    _classes_from_text,
    _table_for,
    decode_access_mask,
    describe,
)
from app.normalization.input_parser import normalize_input
from app.validation.decision import decide

MASK_FILE = pathlib.Path(__file__).parent.parent / "config" / "access_mask.yaml"
_MASKS = yaml.safe_load(MASK_FILE.read_text(encoding="utf-8"))

#: bit adi -> sinif, TEK KAYNAK: config/access_mask.yaml
SINIF = {
    spec["ad"]: spec["sinif"]
    for aile, tablo in _MASKS.items()
    if isinstance(tablo, dict) and aile != "object_type_map"
    for spec in tablo.values()
}

#: Windows'un `Accesses` alanina bastigi GORUNTU adlari -> karsilik gelen bit.
#: Kaynak: winnt.h erisim haklari + guvenlik olayi mesaj tablosu.
#: Beklenen SINIF burada YOK -- SINIF sozlugunden geliyor.
GORUNTU_ADLARI = [
    ("Key", "Query key value", "KEY_QUERY_VALUE"),
    ("Key", "Set key value", "KEY_SET_VALUE"),
    ("Key", "Create sub-key", "KEY_CREATE_SUB_KEY"),
    ("Key", "Enumerate sub-keys", "KEY_ENUMERATE_SUB_KEYS"),
    ("Key", "Notify about changes to keys", "KEY_NOTIFY"),
    ("Key", "Create link", "KEY_CREATE_LINK"),
    ("Key", "DELETE", "DELETE"),
    ("Key", "READ_CONTROL", "READ_CONTROL"),
    ("Key", "WRITE_DAC", "WRITE_DAC"),
    ("Key", "WRITE_OWNER", "WRITE_OWNER"),
    ("Key", "SYNCHRONIZE", "SYNCHRONIZE"),
    ("File", "ReadData (or ListDirectory)", "FILE_READ_DATA"),
    ("File", "WriteData (or AddFile)", "FILE_WRITE_DATA"),
    ("File", "AppendData (or AddSubdirectory or CreatePipeInstance)", "FILE_APPEND_DATA"),
    ("File", "Execute/Traverse", "FILE_EXECUTE"),
    ("File", "DeleteChild", "FILE_DELETE_CHILD"),
    ("File", "ReadAttributes", "FILE_READ_ATTRIBUTES"),
    ("File", "WriteAttributes", "FILE_WRITE_ATTRIBUTES"),
    ("Process", "VM read", "PROCESS_VM_READ"),
    ("Process", "VM write", "PROCESS_VM_WRITE"),
    ("Process", "VM operation", "PROCESS_VM_OPERATION"),
    ("Process", "Query process information", "PROCESS_QUERY_INFORMATION"),
]

B = chr(92)
SAM = B + "REGISTRY" + B + "MACHINE" + B + "SAM"

#: G kolunun GERCEK QRadar satirlarinda gecen bicim: ogeler COKLU BOSLUKLA
#: paketlenmis tek dize. Bu satir 5 gercek kayittan alindi.
GERCEK_COKLU = (
    "READ_CONTROL     Query key value     Set key value     "
    "Create sub-key     Enumerate sub-keys     Notify about changes to keys"
)


def _log(accesses: str, event_id: str = "4663", obj: str = SAM, tip: str = "Key") -> str:
    return (
        'Timestamp="2026-09-02 10:00:00" EventID=' + event_id + ' Hostname=WINHOST-01 '
        'Message="An attempt was made to access an object.  Subject:  Security ID:  '
        "NT AUTHORITY" + B + "SYSTEM  Account Name:  svc-x  Object:  Object Type:  "
        + tip + "  Object Name:  " + obj + "  Handle ID:  0x2f4  Process Information:  "
        "Process ID:  0x2b8  Process Name:  C:" + B + "Windows" + B + "System32"
        + B + 'svchost.exe  Access Request Information:  Accesses:  ' + accesses + '"'
    )


# ------------------------------------------------------------- kapsam

@pytest.mark.parametrize("tip,goruntu,bit", GORUNTU_ADLARI,
                         ids=[f"{t}-{b}" for t, _, b in GORUNTU_ADLARI])
def test_her_goruntu_adi_dogru_bite_baglanir(tip: str, goruntu: str, bit: str) -> None:
    """Kapsam olculdu: duzeltmeden once 9/22 (%40), kacanlarin 7'si YAZMA."""
    bitler, siniflar, cozulemeyen = _classes_from_text(goruntu, _table_for(tip))
    assert bit in bitler, f"{goruntu!r} -> {bitler} (cozulemeyen: {cozulemeyen})"
    assert SINIF[bit] in siniflar


def test_hicbir_YAZMA_adi_kacmiyor() -> None:
    """Asil risk burada: okuma adinin kacmasi zararsiz, yazma adinin
    kacmasi ALARM KACIRIR."""
    kacan = [
        goruntu for tip, goruntu, bit in GORUNTU_ADLARI
        if SINIF[bit] == "write"
        and "write" not in _classes_from_text(goruntu, _table_for(tip))[1]
    ]
    assert kacan == []


def test_takma_ad_tablosu_ELLE_BUYUTULMEDI() -> None:
    """Kapsam turetilmis eslesmeden gelmeli, elle yazilmis listeden degil.

    Dokuzu yirmi ikiye cikarmak ayni kusuru bir sonraki ada ertelerdi.
    Bu test tabloyu KUCUK tutmayi sozlesme yapiyor: bir ad buraya ancak
    mekanik kural onu cozemedigi icin girer."""
    from app.normalization.event_semantics import _ACCESS_ALIASES

    assert len(_ACCESS_ALIASES) <= 2, (
        "Takma ad tablosu buyuyor. Yeni ad eklemeden once mekanik kuralin "
        "neden cozemedigi yazilmali (beklenti_20 §2.1)."
    )


# ------------------------------------------------------------- ayrac

def test_gercek_QRadar_coklu_bosluk_bicimi_cozulur() -> None:
    """G'nin 5 gercek satiri ve S'in 3'u bu bicimde geliyordu ve TEK AD
    saniliyordu -- icinde 'Set key value' OLMASINA RAGMEN cozulmuyordu.

    Ayrac Gorev 15'in K-C degismezi: 2+ ardisik bosluk."""
    bitler, siniflar, cozulemeyen = _classes_from_text(GERCEK_COKLU, _table_for("Key"))
    assert cozulemeyen == []
    assert siniflar == {"read", "write"}
    assert "KEY_SET_VALUE" in bitler


def test_TEK_bosluktan_BOLUNMEZ() -> None:
    """Adlarin kendisi tek bosluk iceriyor; tek bosluktan bolmek
    'Set key value'yi uc parcaya ayirir ve hicbiri cozulmez."""
    bitler, _, cozulemeyen = _classes_from_text("Set key value", _table_for("Key"))
    assert bitler == ["KEY_SET_VALUE"]
    assert cozulemeyen == []


# ------------------------------------------------- belirsizlik / uydurma

@pytest.mark.parametrize("ad", ["Read", "Write", "Frobnicate widget", "Data"])
def test_belirsiz_ya_da_bilinmeyen_ad_SINIF_UYDURMAZ(ad: str) -> None:
    """Belirsizken bir sinif SECMEK, uydurmak demektir.

    'Read' tek basina FILE_READ_DATA, FILE_READ_ATTRIBUTES ve
    PROCESS_VM_READ'in hepsinin alt kumesi -- tek aday yok, cozulmez."""
    _, siniflar, cozulemeyen = _classes_from_text(ad, _table_for("File"))
    assert siniflar == set()
    assert cozulemeyen == [ad]


def test_tam_esitlik_alt_kumeden_ONCE_sorulur() -> None:
    """DELETE hem DELETE ile (esitlik) hem FILE_DELETE_CHILD ile (alt kume)
    eslesir. Esitlik once sorulmazsa belirsiz kalir ve cozulmezdi."""
    bitler, siniflar, _ = _classes_from_text("DELETE", _table_for("File"))
    assert bitler == ["DELETE"]
    assert siniflar == {"write"}


# ------------------------------------------- unknown politikasi (Gorev 4)

def test_cozulemeyen_ad_unknown_uretir_sessiz_read_DEGIL() -> None:
    """Kusurun ozu buydu: cozulemeyen ad sinifi olayin varsayilanina
    dusuruyordu (4663 -> read), yani cozulemeyen bir YAZMA adi okuma
    sayiliyordu."""
    r = describe("4663", None, "Key", "Frobnicate widget")
    assert r["access_class"] == "unknown"
    assert r["unresolved_access_names"] == ["Frobnicate widget"]


def test_unknown_BENIGN_uretemez_ve_YolB_tetiklemez() -> None:
    """Gorev 4'un karari: unknown != noise. Bilinmeyenden yazma iddia
    edilmez (Yol B kapali) ama bilinmeyen okuma da sayilmaz (BENIGN kapali)."""
    karar = decide(normalize_input(_log("Frobnicate widget")), [], None)
    assert karar.inputs["erisim_sinifi"] == "unknown"
    assert karar.paths["B"] is False
    assert karar.decision == "INSUFFICIENT_DATA"


def test_cozulemeyen_ad_GEREKCE_ZINCIRINDE_yazili() -> None:
    """Karar sinifi eskiden de INSUFFICIENT_DATA cikiyordu -- ama YANLIS
    SEBEPLE. Sinif dogru cikip gerekce yanlis olabilir; bu projede tam bu
    desen defalarca olcum kirletti."""
    karar = decide(normalize_input(_log("Frobnicate widget")), [], None)
    govde = " ".join(karar.reason_chain)
    assert "Frobnicate widget" in govde
    assert "çözülemedi" in govde


# ------------------------------------------------- ucdan uca: kacan alarm

@pytest.mark.parametrize("accesses", ["Set key value", "Create link", GERCEK_COKLU])
def test_KRITIK_varlikta_yazma_adi_ALARM_URETIR(accesses: str) -> None:
    """Duzeltmeden once 'Create link' ve gercek coklu dize INSUFFICIENT_DATA
    donuyordu: Gorev 19'un kapattigi kacan alarm, baska bir yazimla."""
    karar = decide(normalize_input(_log(accesses)), [], None)
    assert karar.inputs["erisim_sinifi"] == "write"
    assert karar.paths["B"] is True
    assert karar.decision == "SUFFICIENT_SUSPICIOUS"


def test_GOREV_18_KORUNUYOR_4656_hala_talep() -> None:
    """4656'da metinden turetilen sinif da TALEPTIR; access_class'i
    yukseltmez. Bu test dusesiye kadar 20, 18'i bozmamis demektir."""
    karar = decide(normalize_input(_log("Create link", event_id="4656")), [], None)
    assert karar.inputs["erisim_sinifi"] == "read"
    assert karar.inputs["talep_edilen_erisim"] == "write"
    assert karar.paths["B"] is False


def test_maske_varken_hala_MASKE_kazanir() -> None:
    """Gorev 3'un politikasi degismedi."""
    d = decode_access_mask("0x00000001", "Key", "Set key value")
    assert d.access_class == "read"      # maske yalnizca QUERY_VALUE
    assert d.source == "mask+text"
    assert d.inconsistent_with_text is True
