"""Gorev 24 -- `derive:` turetimi ve iki yeni sema adi.

Beklenti: docs/beklenti_24_sema_alan_boslugu.md (§9c kabul olcutleri Ö11-Ö15,
kod yazilmadan ONCE baglandi).

BICIM GERCEK (madde 17): tests/fixtures/powercfg_4688_brace.json kullanicinin
2026-09-03 canli kosusundan alinmis bir 4688 kaydidir. `Command` ve
`Parent Process Path` adlari 126 kayitlik G+S+H korpusunun HICBIRINDE
gecmiyordu; bu dosya olmadan bu testler uretimde var olmayan bir bicimi
dogrulardi.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.normalization.formats import load_schema, parse_fields

KOK = Path(__file__).resolve().parents[1]
BS = chr(92)


@pytest.fixture(scope="module")
def gercek_log() -> str:
    veri = json.loads(
        (KOK / "tests" / "fixtures" / "powercfg_4688_brace.json").read_text(encoding="utf-8")
    )
    return veri["log"]


@pytest.fixture(scope="module")
def gercek_alanlar(gercek_log: str) -> dict:
    alanlar, bicim = parse_fields(gercek_log)
    assert bicim == "brace_kv", "fixture bicimi degistiyse testlerin dayanagi kayar"
    return alanlar


# --------------------------------------------------------------- Ö11

def test_command_artik_komut_satiri_alanina_gidiyor(gercek_alanlar):
    """Ö11: `Command` semada; `unknown.Command` KALMAMALI."""
    assert "unknown.Command" not in gercek_alanlar
    assert gercek_alanlar["process.command_line"].text.endswith(" 0")
    assert "powercfg.exe" in gercek_alanlar["process.command_line"].text


def test_parent_process_path_semada(gercek_alanlar):
    """Ö11: yol kendi kanonik alaninda durur, `unknown.*` altinda degil."""
    assert "unknown.Parent Process Path" not in gercek_alanlar
    assert gercek_alanlar["parent.process.path"].text.endswith(
        BS + "v1.0" + BS + "powershell.exe"
    )


# --------------------------------------------------------------- Ö12

def test_ebeveyn_adi_yoldan_turetilir(gercek_alanlar):
    """Ö12: kaynak yalnizca yol yaziyor; ad taban addan gelir.

    Turetim olmadan `parent.process.path` HICBIR kural acmiyordu (0 kosul)."""
    assert gercek_alanlar["parent.process.name"].text == "powershell.exe"
    assert gercek_alanlar["parent.process.name"].informative


# --------------------------------------------------------------- Ö13

def test_acik_deger_turetimi_ezmez():
    """Ö13: kaynak ADI da yaziyorsa kaynagin beyani yetkilidir."""
    log = (
        "{Event ID=4688, Parent Process Name=explorer.exe, "
        "Parent Process Path=C:" + BS + "Windows" + BS + "System32"
        + BS + "WindowsPowerShell" + BS + "v1.0" + BS + "powershell.exe}"
    )
    alanlar, _ = parse_fields(log)
    assert alanlar["parent.process.name"].text == "explorer.exe"
    assert alanlar["parent.process.path"].text.endswith("powershell.exe")


# --------------------------------------------------------------- Ö14

@pytest.mark.parametrize("bos_deger", ["N/A", "-", "NULL SID", ""])
def test_bilgi_tasimayan_yoldan_turetilmez(bos_deger: str):
    """Ö14: 'N/A' bir yol degildir; ondan uretilen ad da bir ad degildir."""
    log = "{Event ID=4688, Parent Process Path=" + bos_deger + "}"
    alanlar, _ = parse_fields(log)
    turetilen = alanlar.get("parent.process.name")
    assert turetilen is None or not turetilen.informative, (
        f"{bos_deger!r} bilgi tasimiyor, taban ad uretilmemeli"
    )


# --------------------------------------------------------- yon tek tarafli

def test_ters_yon_turetimi_tabloda_yok():
    """Taban addan dizin URETILEMEZ; tablo bu yonu tasimamali.

    Gorev 17'nin 'dizinsiz deger dogrulanmis sayilmaz' kurali burada bir
    SESSIZ ihlale acik: birisi simetri adina `parent.process.path`e bir
    `derive` eklerse uydurma bir dizin uretilir."""
    alanlar = load_schema()["fields"]
    for ad, spec in alanlar.items():
        kural = (spec or {}).get("derive") or {}
        if not kural:
            continue
        assert kural.get("rule") == "basename", (
            f"{ad}: yalnizca yol->ad turetimi taniniyor"
        )
        assert ad.endswith(".name") and kural["from"].endswith(".path"), (
            f"{ad}: turetim yonu yol -> ad olmali, tersi degil"
        )


def test_ayrac_karisik_yollarda_taban_ad():
    """QRadar ters bolu, normalize edilmis kaynaklar duz bolu yazabiliyor."""
    for yol, beklenen in (
        ("C:" + BS + "Windows" + BS + "cmd.exe", "cmd.exe"),
        ("/usr/bin/python3", "python3"),
        ("powershell.exe", "powershell.exe"),
    ):
        log = "{Event ID=4688, Parent Process Path=" + yol + "}"
        alanlar, _ = parse_fields(log)
        assert alanlar["parent.process.name"].text == beklenen
