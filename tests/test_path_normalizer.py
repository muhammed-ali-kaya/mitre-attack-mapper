"""Registry yolu normalizasyonu.

Bayrak vaka: T1003.002 kurali 'HKLM\\SAM' ariyor, log
'\\REGISTRY\\MACHINE\\SAM' yaziyor. Olculdu: ATT&CK metinlerinde
\\REGISTRY\\ gosterimi 697 teknikte TOPLAM 1 kez geciyor, HKLM/HKCU ise
247 kez. Iki taraf farkli dil konusuyor."""

from __future__ import annotations

import pytest

from app.normalization.path_normalizer import (
    looks_like_registry_path,
    normalize_registry_path,
    paths_match,
)


# ---------------------------------------------------------------- bayrak vaka

def test_the_measured_case_kernel_namespace_matches_hklm():
    """known_regression'daki T1003.002: kural HKLM\\SAM, log
    \\REGISTRY\\MACHINE\\SAM. Ayni konum."""
    assert paths_match("\\REGISTRY\\MACHINE\\SAM", "HKLM\\SAM")


def test_defender_policy_path_across_notations():
    assert paths_match(
        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
    )


# ---------------------------------------------------------------- kovan esdegerlikleri

@pytest.mark.parametrize("yazim", [
    "HKLM\\SAM",
    "HKEY_LOCAL_MACHINE\\SAM",
    "\\REGISTRY\\MACHINE\\SAM",
    "REGISTRY\\MACHINE\\SAM",
    "<HKLM>\\SAM",
    "hklm\\sam",
    "HKLM/SAM",
])
def test_every_notation_normalises_to_the_same_form(yazim):
    assert normalize_registry_path(yazim) == "HKLM\\SAM"


def test_current_user_hive():
    assert normalize_registry_path("\\REGISTRY\\USER\\Software") == "HKCU\\SOFTWARE"
    assert paths_match("HKEY_CURRENT_USER\\Software", "\\REGISTRY\\USER\\Software")


def test_escaped_backslashes_are_collapsed():
    """Loglarda kacisli hali sik gorulur."""
    assert normalize_registry_path("\\\\REGISTRY\\\\MACHINE\\\\SAM") == "HKLM\\SAM"


# ---------------------------------------------------------------- onek eslesmesi

def test_a_general_path_matches_a_more_specific_one():
    """ATT&CK metinleri cogu zaman kovan + birkac segment yazar; log tam
    yolu yazar. Genel olanin ozel olani kapsamasi dogru davranistir."""
    assert paths_match("HKLM\\SAM", "\\REGISTRY\\MACHINE\\SAM\\SAM\\Domains\\Account")


def test_prefix_match_respects_segment_boundaries():
    """'HKLM\\SAMPLE' ile 'HKLM\\SAM' AYNI SEY DEGILDIR -- duz startswith
    bunu karistirirdi."""
    assert not paths_match("HKLM\\SAM", "HKLM\\SAMPLE\\Foo")


def test_different_hives_never_match():
    assert not paths_match("HKLM\\Software", "HKCU\\Software")


# ---------------------------------------------------------------- sinir durumlari

@pytest.mark.parametrize("bos", [None, "", "   "])
def test_empty_input_is_none_not_a_match(bos):
    """'bilinmiyor' ile 'bos yol' ayni sey degil; ikisi de eslesme
    uretmemeli."""
    assert normalize_registry_path(bos) is None
    assert not paths_match(bos, "HKLM\\SAM")


def test_non_registry_values_are_recognised():
    assert looks_like_registry_path("\\REGISTRY\\MACHINE\\SAM")
    assert looks_like_registry_path("HKLM\\Software")
    assert looks_like_registry_path("HKEY_USERS\\S-1-5-21")
    assert not looks_like_registry_path("C:\\Windows\\System32\\reg.exe")
    assert not looks_like_registry_path("svchost.exe")
    assert not looks_like_registry_path(None)


def test_file_paths_are_left_alone_by_the_matcher():
    """Yol olmayan degerleri normalize etmeye calismak yanlis eslesme
    uretir -- looks_like_registry_path bu yuzden var."""
    assert not paths_match("C:\\Windows\\System32", "HKLM\\SYSTEM")


# ---------------------------------------------------------------- kapsam siniri

def test_normalisation_cannot_help_when_there_is_no_path():
    """OLCULMUS SINIR: T1685'in ATT&CK metninde HKLM YALIN geciyor,
    ardinda yol yok. Normalizasyon esleme kursa bile eslesecek yol yok --
    bu yuzden T3 vakasi bu tabloyla COZULMEZ ve cozulmesi beklenmiyor."""
    assert not paths_match(
        "HKLM",
        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
    )
