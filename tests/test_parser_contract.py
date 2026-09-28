"""Parser sozlesmesi -- beklenen cikti parser YAZILMADAN ONCE sabitlendi.

Bu dosyadaki beklentiler tests/fixtures/registry_object_access_logs.json
icindeki expected_parsed_fields'tan okunur; oradaki degerler dort logun ham
metninden ELLE yazildi. Sirasi kasitli: once kodu yazip sonra ciktisina
bakarak "evet boyle olmali" demek, dort ornege asiri uyumun en kolay
bicimidir. Beklenti once yazilirsa parser ona uymak zorunda kalir.

TESTLER SU AN xfail: normalize_input hala eski Key=Value regex'ini
kullaniyor (bkz. app/normalization/input_parser.py KEY_VALUE_RE). Gorev 1
bitince XPASS'e donerler ve isaretler kaldirilir.

Kilitlenen dort hata:
  A. anahtar son kelimeye indirgeniyor + dedup -> 'Pipe/Process/Account/
     Object Name' hepsi 'Name' oluyor, ilki (N/A) tutulup gerisi siliniyor
  B. deger ilk boslukta kesiliyor -> 'NT AUTHORITY'->'NT',
     'Query key value|...'->'Query', 'Access Mask'->anahtar 'Mask'
  C. sondaki '}' strip edilmiyor -> 'CustomProp': '0}'
  D. EventID regex'i bosluklu 'Event ID=' bicimini hic gormuyor -> event.id
     dort logda da None; event_id_relevance bileseni ve olay semantigi
     (Gorev 3) tamamen olu
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.normalization.input_parser import normalize_input

FIXTURE = Path(__file__).parent / "fixtures" / "registry_object_access_logs.json"
_FIXTURE_TEXT = FIXTURE.read_text(encoding="utf-8")
_FIXTURE_DATA = json.loads(_FIXTURE_TEXT)
LOGS = {log["id"]: log for log in _FIXTURE_DATA["logs"]}
ALL_IDS = sorted(LOGS)
LIST_FIELDS = set(
    _FIXTURE_DATA["_parser_sozlesmesi"]["tip_sozlesmesi"]["expected_list_fields"]
)

def _fields(log_id: str) -> dict:
    """YETKILI yapi: {canonical_ad: deger}.

    extracted_facts DEGIL -- o, eski tuketiciler icin tutulan duz bir
    izdusum ve eski alan adlarini (EventID, CommandLine) kullaniyor.
    Sozlesme yeni canonical adlar uzerinden yazildi."""
    parsed = normalize_input(LOGS[log_id]["raw"]).get("parsed_fields") or {}
    return {name: field.value for name, field in parsed.items()}




# ---------------------------------------------------------------- tam sozlesme

@pytest.mark.parametrize("log_id", ALL_IDS)
def test_every_field_is_parsed_with_its_full_name_and_value(log_id):
    """Alan alan tam esitlik. Tek bir alanin kaymasi bile burada gorunur."""
    expected = LOGS[log_id]["expected_parsed_fields"]
    actual = _fields(log_id)

    missing = {k: v for k, v in expected.items() if k not in actual}
    wrong = {k: (v, actual[k]) for k, v in expected.items()
             if k in actual and actual[k] != v}

    assert not missing, f"{log_id}: eksik alanlar {sorted(missing)}"
    assert not wrong, f"{log_id}: yanlis degerler {wrong}"


@pytest.mark.parametrize("log_id", ALL_IDS)
def test_field_count_matches_the_hand_written_expectation(log_id):
    assert len(_fields(log_id)) == LOGS[log_id]["expected_field_count"]


@pytest.mark.parametrize("log_id", ALL_IDS)
def test_field_value_types_follow_the_contract(log_id):
    """TIP de sozlesmenin parcasi.

    Tip yazilmazsa parser value.old icin 0 (int) donduren bir sürüme
    kayabilir ve karsilastirma sessizce anlam degistirir. Sayisal gorunen
    degerler STR kalir: ayristirma katmani yorum yapmaz, ham metni tasir.
    '0x2000d' -> int ya da 'New Value=1' -> 1 cevirimi SEMANTIK bir
    karardir ve Gorev 3'un isidir."""
    for name, value in _fields(log_id).items():
        if name in LIST_FIELDS:
            assert isinstance(value, list), f"{name} liste olmali, {type(value).__name__} geldi"
            assert all(isinstance(x, str) for x in value), f"{name} ogeleri str olmali"
        else:
            assert isinstance(value, str), f"{name} str olmali, {type(value).__name__} geldi"


# ---------------------------------------------------------------- bug A: anahtar cakismasi

def test_name_fields_do_not_collapse_into_one_key():
    """BUG A: 'Pipe Name', 'Process Name', 'Account Name', 'Object Name'
    ayri alanlardir; hepsi 'Name' olup dedup ile ilkine (N/A) inemez."""
    f = _fields("T1")
    assert f["pipe.name"] == "N/A"
    assert f["process.name"] == "reg.exe"
    assert f["account.name"] == "svc_backup"
    assert f["object.name"] == "\\REGISTRY\\MACHINE\\SAM"


def test_old_and_new_value_are_separate_keys():
    """BUG A'nin en pahali sonucu: iki deger tek anahtarda cakisinca
    kanit tablosunda 'Value: 0' kaliyordu -- yani 'Defender acik'. Log
    tam tersini soyluyor."""
    f = _fields("T3")
    assert f["value.old"] == "0"
    assert f["value.new"] == "1"


# ---------------------------------------------------------------- bug B: deger kirpilmasi

def test_multi_word_value_is_not_cut_at_the_first_space():
    """BUG B: 'NT AUTHORITY' iki kelimedir. 'NT'ye kirpilinca hesabin
    SISTEM hesabi oldugu bilgisi kayboluyor -- benign baseline'in
    dayandigi sinyal tam olarak bu."""
    assert _fields("T2")["user.domain"] == "NT AUTHORITY"


def test_registry_path_containing_spaces_survives():
    f = _fields("T2")
    assert f["object.name"].endswith("Time Zones\\Turkey Standard Time")
    assert "Windows NT" in f["object.name"]


def test_pipe_separated_value_becomes_a_list():
    """BUG B: 'Query key value|Enumerate sub-keys|Read Control' tek string
    degil UC OGELI listedir; eski parser 'Query' birakiyordu."""
    assert _fields("T1")["access.list"] == [
        "Query key value", "Enumerate sub-keys", "Read Control"
    ]


def test_access_mask_keeps_its_full_field_name():
    """BUG B: 'Access Mask' anahtari 'Mask'a inemez."""
    f = _fields("T1")
    assert f["access.mask"] == "0x2000d"
    assert "Mask" not in f


# ---------------------------------------------------------------- bug C: kapanis parantezi

def test_closing_brace_is_stripped_from_the_last_value():
    """BUG C: son alan '0}' degil '0' olmali."""
    assert _fields("T0")["unknown.CustomProp"] == "0"


# ---------------------------------------------------------------- bug D: Event ID

@pytest.mark.parametrize("log_id,expected", [("T0", "4656"), ("T1", "4656"),
                                             ("T2", "4656"), ("T3", "4657")])
def test_event_id_is_read_from_the_spaced_field_name(log_id, expected):
    """BUG D (brief'te yoktu): EVENT_ID_RE 'EventID' bitisik ariyordu,
    loglarda 'Event ID=' bosluklu geciyor. Dort logda da event_id None
    kaliyordu; event_id_relevance bileseni ve olay semantigi olu kaldi."""
    assert normalize_input(LOGS[log_id]["raw"]).get("event_id") == expected


# ---------------------------------------------------------------- sema disi alanlar

def test_unknown_fields_are_namespaced_and_kept():
    """Sema disi alan silinmez -- kanit tablosunda gorunur."""
    assert _fields("T0")["unknown.CustomProp"] == "0"


def test_unknown_fields_do_not_reach_the_retrieval_query():
    """...ama retrieval sorgusuna girmez: 'CustomProp' ATT&CK korpusunda
    hicbir seye karsilik gelmez, sorguyu yalnizca kirletir."""
    from app.normalization.input_parser import build_enriched_query

    raw = LOGS["T0"]["raw"]
    query = build_enriched_query(raw, normalize_input(raw))
    enrichment = query[len(raw):]
    assert "CustomProp" not in enrichment


# ---------------------------------------------------------------- bilgilendirici alan sayimi

@pytest.mark.parametrize("log_id", ALL_IDS)
def test_informative_field_count(log_id):
    """'N/A' alanlar korunur ama BILGI TASIMAZ. Gorev 12'deki ucuz on
    kapi bu sayiya bakacak; T0'da 15 alanin yalnizca 4'u bilgilendirici."""
    f = _fields(log_id)
    informative = [
        k for k, v in f.items()
        if not k.startswith("unknown.") and str(v).strip().upper() not in ("N/A", "", "-")
    ]
    assert len(informative) == LOGS[log_id]["expected_informative_field_count"]
