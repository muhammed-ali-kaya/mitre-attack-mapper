"""Varlik kritikligi tablosu ve motoru (Gorev 4).

Beklenti docs/beklenti_4_varlik_kritikligi.md'de, KOD YAZILMADAN ONCE
yazildi ve commit'lendi.
"""
from __future__ import annotations

import pathlib

import pytest
import yaml

from app.normalization.asset_criticality import (
    CONFIG_PATH,
    kapsam_disi_mi,
    siniflandir,
)

TABLO = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))
DESENLER = TABLO["desenler"]


# ------------------------------------------------------------ tablo sozlesmesi

def test_critical_and_high_patterns_reach_the_required_count():
    """Kabul kriteri: >= 40 desen. 'Tablo yazdim' bitirmek degil, sayi
    tutturmak bitirmek."""
    n = sum(1 for d in DESENLER if d["seviye"] in ("critical", "high"))
    assert n >= 40, f"critical+high {n}, en az 40 olmali"


@pytest.mark.parametrize("desen", DESENLER, ids=lambda d: d["desen"])
def test_every_row_declares_a_source(desen):
    """Kaynagi 'fixture'da vardi' olan satir kabul edilmez.

    \\REGISTRY\\MACHINE\\SAM tabloda cunku SAM bir credential deposu --
    T1'de gectigi icin degil. Bu ayrim olmadan tablo Ö1'in aynisi olur:
    test verisine gore yazilmis, held-out sette susan bir tablo."""
    kaynak = desen.get("kaynak") or []
    assert kaynak, f"{desen['desen']}: kaynak beyan edilmemis"
    assert set(kaynak) <= {"attack", "persist", "cred", "defense", "measured"}


def test_unknown_is_not_a_level_you_can_write_in_the_table():
    """`unknown` ESLESMEYENIN varsayilanidir, yazilabilir bir seviye degil.
    Tabloya yazilabilseydi 'bu yolu bilmiyoruz' bir KARAR gibi gorunurdu."""
    assert all(d["seviye"] != "unknown" for d in DESENLER)


# ------------------------------------------------------- beklenti 1: dort probe

def test_the_three_probe_paths_land_where_expected():
    """Beklenti 1 (onceden yazildi): T1 kritik, T2 gurultu, T3 high."""
    assert siniflandir(r"\REGISTRY\MACHINE\SAM").seviye == "critical"
    assert siniflandir(
        r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        r"\Time Zones\Turkey Standard Time").seviye == "noise"
    assert siniflandir(
        r"\REGISTRY\MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender"
    ).seviye == "high"


def test_the_same_key_classifies_the_same_in_every_dialect():
    """Lehce bagimsizligi bedava gelmeli: path_normalizer 2B'de motora
    baglandi, burada YENIDEN YAZILMADI."""
    seviyeler = {
        siniflandir(p).seviye
        for p in (r"HKLM\SAM", r"HKEY_LOCAL_MACHINE\SAM", r"\REGISTRY\MACHINE\SAM")
    }
    assert seviyeler == {"critical"}


# --------------------------------------------- beklenti 3: fixture bicimli mi

@pytest.mark.parametrize("yol", [
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs",
    r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute",
    r"HKCU\Environment\COR_PROFILER",
    r"HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal",
])
def test_paths_absent_from_all_test_data_are_still_classified(yol):
    """BEKLENTI 3 -- en keskin olani.

    Tablo, test verisinde HIC gecmeyen yollari da siniflandirmali. Test
    verisinin TAMAMINDA 3 registry yolu var; tablo yalnizca onlari
    kapsasaydi Ö1'in baska kiliktaki aynisi olurdu."""
    assert siniflandir(yol).seviye in ("critical", "high")


def test_a_more_specific_pattern_wins_over_a_general_one():
    """Services\\... genel olarak high; Services\\EventLog daha spesifik.
    En UZUN eslesen desen kazanir."""
    genel = siniflandir(r"HKLM\SYSTEM\CurrentControlSet\Services\Foo")
    ozel = siniflandir(r"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security")
    assert genel.aile == "service"
    assert ozel.aile == "eventlog-config"


def test_matching_happens_at_a_segment_boundary():
    """'HKLM\\SAMPLE' ile 'HKLM\\SAM' ayni sey degildir. Duz onek
    karsilastirmasi ikisini esitlerdi ve her SAMPLE anahtarini kritik
    yapardi."""
    assert siniflandir(r"HKLM\SAMPLE\Foo").seviye != "critical"
    assert siniflandir(r"HKLM\SAM\Domains\Account").seviye == "critical"


# ------------------------------------------------- hive'siz yollar (A)

def test_a_path_written_without_a_hive_still_classifies():
    """OLCULDU: ATT&CK'teki 283 yolun 38'i hive oneki tasimiyor ve ayni
    anahtar hive'liyken siniflaniyordu. Cozum tabloya hive'siz satir
    eklemek DEGIL -- o tabloyu ikiye katlardi."""
    hiveli = siniflandir(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
    hivesiz = siniflandir(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
    assert hiveli.seviye == hivesiz.seviye == "high"
    assert hivesiz.hive_varsayildi is True
    assert hiveli.hive_varsayildi is False


def test_hive_free_matching_does_not_become_a_suffix_match():
    """GEVSEME KONTROLLU OLMALI -- 2B'deki 'yasak yol baska lehcede
    yazildi diye gecerli olmasin' testinin ayni kalibi.

    Hive eklemek eslesmeyi gevsetir; gevseme SON SEGMENTE kaymamali.
    'AcmeCorp\\Run' bir autorun anahtari DEGILDIR."""
    for yol in (
        r"SOFTWARE\AcmeCorp\Run",
        r"SOFTWARE\AcmeCorp\CurrentVersion\Run",
        r"SOFTWARE\Microsoft\Office\CurrentVersion\Run",
        r"SYSTEM\AcmeControlSet\Services",
    ):
        assert siniflandir(yol).seviye == "unknown", f"{yol} yanlis eslesti"


def test_hive_free_matching_flags_a_level_conflict_and_takes_the_harshest():
    """HKLM ve HKCU AYNI SEY DEGIL: biri makine geneli, digeri kullanici.
    Tabloda ikisi de high olabilir ama bu VARSAYILMIYOR -- hive'lar farkli
    seviye verirse isaretlenir ve en sert olan secilir. Eksik cagirmak,
    fazla cagirmaktan tehlikelidir."""
    k = siniflandir(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
    # Bu anahtar iki hive'da da 'high' -- catisma yok.
    assert k.hive_belirsiz is False
    assert k.seviye == "high"


def test_a_bare_hive_free_fragment_is_not_classified():
    """'SOFTWARE' ya da tek segmentlik bir parca yol degildir."""
    assert siniflandir("SOFTWARE").seviye == "unknown"
    assert siniflandir("CurrentVersion").seviye == "unknown"


# ------------------------------------------------------- unknown != noise

def test_an_unlisted_path_is_unknown_not_noise():
    """Bu maddenin en onemli karari.

    Bilinmeyeni zararsiz saymak, tablonun kapsamadigi HER saldiriyi
    gorunmez yapar. Gorev 5'e baglayici: unknown tek basina
    SUFFICIENT_BENIGN uretemez."""
    k = siniflandir(r"HKLM\SOFTWARE\AcmeCorp\SomeProduct\Settings")
    assert k.seviye == "unknown"
    assert k.bilinmiyor
    assert k.seviye != "noise"


def test_a_non_registry_value_is_unknown_rather_than_guessed():
    assert siniflandir("kullanici SAM dosyasini sordu").seviye == "unknown"
    assert siniflandir(None).seviye == "unknown"
    assert siniflandir("").seviye == "unknown"


def test_out_of_scope_paths_state_a_reason():
    """'Tabloda yok' ile 'tabloya BILEREK alinmadi' farkli seylerdir.
    Ikincisi bir karardir ve kapsama raporunda gerekcesiz sayilmaz."""
    gerekce = kapsam_disi_mi(r"HKLM\Software\NFC\IPA\Foo")
    assert gerekce and "artefakt" in gerekce
    assert kapsam_disi_mi(r"HKLM\SAM") is None
