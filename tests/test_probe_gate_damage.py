"""Kanit kapisi hasar metriginin kendi testi.

Neden testi var: metrik "kapi girdide VAR OLAN bir gozlemi sildi mi" sorusunu
cevapliyor ve buna bakip kapiya guvenip guvenmeyecegimize karar veriyoruz.
Yanlis guven veren bir metrik, hic metrik olmamasindan kotudur.

Ilk yaziminda iki kusuru vardi ve ikisi de burada kilitleniyor:
  - deger tek basina aranıyordu: "New Value: 1" icin deger "1"dir ve ham
    logda 0x2b1c gibi onlarca yerde gecer -> her zaman eslesme
  - iki nokta icermeyen (Turkce duzyazi) davranislar tek token sayiliyordu
    -> hicbir zaman eslesmeme; oysa kapinin en cok zarar verdigi yer orasi
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from run_probe_diagnostics import _gate_damage  # noqa: E402

# T3'un gercek logundan ilgili parca.
T3_RAW = (
    "{Process Path=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe, "
    "Event ID=4657, Process Name=powershell.exe, Account Name=administrator, "
    "Object Name=\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender, "
    "Object Value Name=DisableAntiSpyware, Operation Type=Existing registry value modified, "
    "Old Value Type=REG_DWORD, Old Value=0, New Value Type=REG_DWORD, New Value=1, "
    "Handle ID=0x2b1c, Process ID=0x1e40, Logon ID=0x8a3f2}"
)

# Bozuk parser'in urettigi fact tablosu (duzelmeden onceki hali).
T3_FACTS = {
    "Name": "N/A,", "Path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe,",
    "Domain": "CORP,", "ID": "4657,", "Workstation": "SRV-APP02,", "Type": "Key,",
    "Value": "0,", "Class": "N/A,",
}


def _wrong(items, facts=None, raw=T3_RAW):
    return [d for d in _gate_damage(items, facts or T3_FACTS, raw) if d["gate_was_wrong"]]


# ---------------------------------------------------------------- olculmus vaka

def test_the_measured_t3_case_is_flagged_as_wrong_removal():
    """OLCULMUS VAKA: kapi 'New Value: 1' ve 'Old Value: 0' maddelerini eledi.

    Logda 'New Value=1' aynen var ve bu, Defender'in kapatildiginin TEK
    kanitiydi. Fark yalnizca iki nokta ile esittir isaretiydi."""
    wrong = _wrong(["Old Value: 0", "New Value: 1"])
    assert len(wrong) == 2, "kapi girdide var olan iki gozlemi sildi, metrik bunu gormeli"
    assert {d["value"] for d in wrong} == {"0", "1"}


def test_short_values_require_the_field_name_to_match_too():
    """Kisa deger tek basina kanit degil: '1' ham logda 0x2b1c icinde de gecer.

    Alan adi girdide YOKSA eslesme sayilmamali -- aksi halde metrik her
    kisa degerli maddeyi 'yanlis eleme' ilan eder."""
    wrong = _wrong(["Imaginary Field: 1"])
    assert wrong == [], "alan adi girdide yokken kisa deger eslesme saymamali"


def test_a_field_that_really_exists_with_a_long_value_is_flagged():
    wrong = _wrong(["Object Value Name: DisableAntiSpyware"])
    assert len(wrong) == 1
    assert wrong[0]["form"] == "field_value"


def test_a_value_absent_from_the_input_is_not_flagged():
    """Kapi UYDURMA bir gozlemi eledi ise dogru is yapmistir."""
    assert _wrong(["Object Name: \\REGISTRY\\MACHINE\\SAM"]) == []


# ---------------------------------------------------------------- duzyazi bicimi

def test_turkish_prose_behaviour_is_measured_by_token_overlap():
    """Kapinin en cok zarar verdigi bicim: LLM Turkce yazar, log Ingilizcedir.

    Iki nokta yoktur; tum cumleyi tek token saymak her zaman 'eslesmedi'
    verir ve metrik bu vakalari hic gormezdi."""
    item = "DisableAntiSpyware degeri REG_DWORD olarak powershell.exe tarafindan degistirildi"
    result = _gate_damage([item], T3_FACTS, T3_RAW)[0]

    assert result["form"] == "prose"
    assert result["overlap_ratio"] > 0.0
    assert "disableantispyware" in result["matched_tokens"]


def test_prose_with_no_grounding_is_not_flagged():
    """Girdiyle ilgisi olmayan bir cumle elendiyse kapi dogru davranmistir."""
    item = "Saldirgan uzaktaki bir sunucuya sifrelenmis veri sizdirdi"
    result = _gate_damage([item], T3_FACTS, T3_RAW)[0]

    assert result["form"] == "prose"
    assert result["gate_was_wrong"] is False


def test_empty_filter_list_produces_no_damage():
    assert _gate_damage([], T3_FACTS, T3_RAW) == []
