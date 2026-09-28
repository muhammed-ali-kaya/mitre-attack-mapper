"""Komut satiri yol sinirinin sozlesme testleri.

Beklenen degerler KOD YAZILMADAN ONCE tests/fixtures/
command_line_path_boundary.json dosyasina yazildi. Test o dosyayi okur --
beklentiyi test icinde yeniden yazmak, koda bakip 'evet boyle olmali'
demenin kibar hali olurdu.
"""
from __future__ import annotations

import json
import pathlib

import pytest

from app.normalization.asset_criticality import siniflandir
from app.normalization.command_line_paths import extract_registry_paths

FIXTURE = (
    pathlib.Path(__file__).resolve().parent
    / "fixtures"
    / "command_line_path_boundary.json"
)
VAKALAR = json.loads(FIXTURE.read_text(encoding="utf-8"))["vakalar"]
IDLER = [v["id"] for v in VAKALAR]


@pytest.mark.parametrize("vaka", VAKALAR, ids=IDLER)
def test_yol_siniri(vaka: dict) -> None:
    assert extract_registry_paths(vaka["command_line"]) == vaka["expected_paths"], (
        f"{vaka['id']} ({vaka['baslik']}) -- kural: {vaka['kural']}"
    )


@pytest.mark.parametrize("vaka", VAKALAR, ids=IDLER)
def test_cikan_yol_siniflanabiliyor(vaka: dict) -> None:
    """Sinir dogru olsa bile kritiklik cikmiyorsa is bitmemistir.

    V1 tam olarak boyle kaybediliyordu: yol cikiyordu ama 'HKLM\\SAM C'
    oldugu icin siniflandir 'unknown' diyordu."""
    beklenen = vaka["expected_criticality"]
    yollar = extract_registry_paths(vaka["command_line"])
    if beklenen is None:
        assert not yollar
        return
    k = siniflandir(yollar[0])
    assert not k.bilinmiyor, f"{vaka['id']} -- yol cikti ama siniflanamadi: {yollar[0]!r}"
    assert k.seviye == beklenen, f"{vaka['id']} -- {yollar[0]!r}"


def test_amiral_gemisi_regresyonu() -> None:
    """V1 ayrica tek basina kilitlenir -- kabul olcutu bu.

    reg.exe save HKLM\\SAM ... SAM hirsizliginin komut satiri bicimidir
    (T1003.002). Naif desen 'HKLM\\SAM C' uretip kritikligi 'unknown'a
    dusuruyordu; vaka boylece sessizce kayboluyordu."""
    cmd = r"reg.exe save HKLM\SAM C:\Users\Public\sam.hive"
    assert extract_registry_paths(cmd) == [r"HKLM\SAM"]
    assert siniflandir(r"HKLM\SAM").seviye == "critical"


def test_duzyazi_bu_modulun_isi_degil() -> None:
    """Gorev 5 §6: kritiklik duzyazidan OKUNMAZ.

    Modul bir cumleden yol cikarabilir -- bu bir kusur degil, cunku kural
    cagiran tarafta zorlanir. Test bunu BELGELER: buradaki cikti, kaynak
    secimi kararinin yerini almaz."""
    cumle = r"Saldirgan HKCU\Software\Microsoft\Windows\CurrentVersion\Run altina yazdi."
    assert extract_registry_paths(cumle), "cikarim calisir; kaynak karari cagiranda"


def test_bos_girdi() -> None:
    assert extract_registry_paths(None) == []
    assert extract_registry_paths("") == []
    assert extract_registry_paths("   ") == []
