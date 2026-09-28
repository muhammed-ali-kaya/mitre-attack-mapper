"""Fixture'in KENDI butunlugu -- parser'a bagli degil, bu yuzden ayri dosya.

test_parser_contract.py modul duzeyinde xfail isaretli (parser henuz
yazilmadi). Bu kontroller oraya konulsaydi onlar da xfail sayilir ve fixture
bozuldugunda kimse duymazdi.

BAGIMSIZLIK KURALI: buradaki hicbir test app.* icinden bir sey import ETMEZ.
Sozlesmedeki sayisal beklentiler, ham metni sayan uc satirlik bagimsiz bir
sayacla dogrulanir (_count_raw_fields). Parser'i kullanmak dairesel olurdu:
parser'in urettigi sayiyi parser'in ciktisiyla dogrulamak hicbir sey
kanitlamaz.

Neden bu kural yazildi: bu oturumda elle yazilmis beklentilerde UC ayri hata
cikti (tutarsiz erisim maskesi, tesadufen gecen XPASS, uc logda birden yanlis
informative sayisi). Sozlesmeyi kod yazmadan once yazmak hatalari koda
donusmeden yakaladi; ama elle yazilan SAYILAR da bagimsiz dogrulanmali."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


def _count_raw_fields(raw: str) -> list[str]:
    """Ham log metnindeki alanlari sayar -- parser'a hic dokunmadan.

    Uc satir, tek is: sus parantezlerini at, ', ' ile bol. Sozlesmedeki her
    sayisal beklenti bunun uzerinden dogrulanir."""
    return raw.strip().lstrip("{").rstrip("}").split(", ")

FIXTURE = Path(__file__).parent / "fixtures" / "registry_object_access_logs.json"
_TEXT = FIXTURE.read_text(encoding="utf-8")
_DATA = json.loads(_TEXT)
LOGS = {log["id"]: log for log in _DATA["logs"]}


def test_fixture_has_no_duplicate_keys():
    """JSON yinelenen anahtarda SESSIZCE sonuncuyu alir.

    Bir alani iki kez yazip birini duzeltmeyi unutmak, testin dogru degeri
    TESADUFEN kullanmasina yol acar; yanlis olan silinene kadar kimse fark
    etmez. json.loads varsayilan haliyle bunu hic bildirmez."""
    duplicates: list[tuple[str, int]] = []

    def detect(pairs):
        seen: dict[str, int] = {}
        for key, _ in pairs:
            seen[key] = seen.get(key, 0) + 1
        duplicates.extend((k, c) for k, c in seen.items() if c > 1)
        return dict(pairs)

    json.loads(_TEXT, object_pairs_hook=detect)
    assert not duplicates, f"fixture'da yinelenen anahtar: {duplicates}"


@pytest.mark.parametrize("log_id", sorted(LOGS))
def test_expected_counts_are_derived_from_the_raw_log(log_id):
    """Beklenen sayilar ham logdan TUREMELI, elle tahmin edilmemeli.

    Ilk yazimda uc logda birden yanlisti: T0'da object.type atlanmisti,
    T1 ve T3'te birer alan eksik sayilmisti. Bu sayilar Gorev 12'deki ucuz
    on kapinin esigini besleyecek, yani tahminle gecmemeli."""
    log = LOGS[log_id]
    segments = _count_raw_fields(log["raw"])

    assert len(segments) == log["expected_field_count"], (
        f"{log_id}: ham logda {len(segments)} alan var, "
        f"fixture {log['expected_field_count']} diyor"
    )

    na_count = sum(1 for s in segments if s.split("=", 1)[1].strip() == "N/A")
    unknown_count = sum(
        1 for k in log["expected_parsed_fields"] if k.startswith("unknown.")
    )
    derived = len(segments) - na_count - unknown_count

    assert derived == log["expected_informative_field_count"], (
        f"{log_id}: ham logdan {derived} bilgilendirici alan cikiyor, "
        f"fixture {log['expected_informative_field_count']} diyor"
    )


@pytest.mark.parametrize("log_id", sorted(LOGS))
def test_expected_field_names_cover_every_raw_field(log_id):
    """expected_parsed_fields ham logdaki her alani karsilamali -- eksik
    birakilan alan, parser onu dusurdugunde testin sessiz kalmasi demek."""
    log = LOGS[log_id]
    segments = _count_raw_fields(log["raw"])

    assert len(log["expected_parsed_fields"]) == len(segments), (
        f"{log_id}: {len(segments)} ham alan var ama "
        f"{len(log['expected_parsed_fields'])} beklenti yazilmis"
    )


def test_type_contract_is_declared():
    contract = _DATA["_parser_sozlesmesi"]["tip_sozlesmesi"]
    assert contract["varsayilan"] == "str"
    assert "access.list" in contract["expected_list_fields"]


def test_list_fields_are_declared_as_lists_in_every_expectation():
    list_fields = set(_DATA["_parser_sozlesmesi"]["tip_sozlesmesi"]["expected_list_fields"])
    for log in _DATA["logs"]:
        for name, value in log["expected_parsed_fields"].items():
            if name in list_fields:
                assert isinstance(value, list), f"{log['id']}.{name} liste olmali"
            else:
                assert isinstance(value, str), f"{log['id']}.{name} str olmali"


def test_no_app_module_is_imported_here():
    """BAGIMSIZLIK: bu dosya app.* icinden hicbir sey import etmemeli.

    Parser'in urettigi sayiyi parser'in ciktisiyla dogrulamak dairesel olur
    ve hicbir sey kanitlamaz. Birisi kolaylik olsun diye normalize_input
    cagirirsa burasi kirmizi yanar."""
    source = Path(__file__).read_text(encoding="utf-8")
    offenders = [
        line.strip() for line in source.splitlines()
        if line.strip().startswith(("import app", "from app"))
    ]
    assert not offenders, f"bagimsizlik ihlali: {offenders}"


def test_known_regressions_declare_a_closing_criterion():
    """Bilinen gerileme SESSIZCE kabul edilmez.

    Kayitli her gerilemenin kok nedeni ve KAPANIS KRITERI yazili olmali;
    aksi halde 'bunu biliyoruz' demek, onu kalici hale getirmenin kibar
    yoludur. Kriter, ilgili gorevin kabul sartlarindan biri olur."""
    for log in _DATA["logs"]:
        reg = log.get("known_regression")
        if not reg:
            continue
        for alan in ("belirti", "kok_neden", "cozum_katmani", "kapanis_kriteri"):
            assert reg.get(alan), f"{log['id']}: known_regression.{alan} bos"


def test_known_regression_list_is_not_growing_silently():
    """Kayitli gerileme sayisi. Artarsa bu test kirmizi yanar ve yeni
    madde bilincli olarak buraya yazilir."""
    kayitli = [l["id"] for l in _DATA["logs"] if l.get("known_regression")]
    assert kayitli == [], (
        f"bilinen gerileme listesi degisti: {kayitli}. "
        "Yeni bir madde eklendiyse kok nedeni ve kapanis kriteriyle birlikte "
        "kaydedilmis olmali; bir madde cozulduyse `kapanmis_gerileme`ye tasinmali."
    )


def test_closed_regressions_keep_their_evidence():
    """KAPANAN gerileme SILINMEZ, kanitiyla durur.

    T1-T1003.002-gate-notation 2B'de kapandi. Kayit tutuluyor cunku bu vaka
    'dogru cevap, yanlis sebep' deseninin en iyi ornegi: kural once hicbir
    4656 logunda eslesemedigi icin T1003.002'yi HER ZAMAN eliyordu ve T0'da
    bu 'dogru sonuc' gibi gorunuyordu.

    Kapanis 'testler gecti' ile degil, ONCEDEN YAZILMIS iki kriterle
    olculdu -- ve kriterler kapanistan aylar once yazilmisti."""
    kapali = [l["kapanmis_gerileme"] for l in _DATA["logs"] if l.get("kapanmis_gerileme")]
    assert kapali, "kapanmis gerileme kaydi kayboldu"
    for k in kapali:
        for alan in ("kriter_1_2A", "kriter_2_2B", "kanit"):
            assert k.get(alan), f"{k.get('id')}: kapanmis_gerileme.{alan} bos"


def test_revoked_technique_ids_are_not_used_as_expected_answers():
    """v19.1 ve v19.2'de T1562* revoked ve T1685'e yonlendiriliyor. Beklenen cevap
    olarak iptal edilmis bir ID yazmak, hatti yanlis hedefe kilitler."""
    for log in _DATA["logs"]:
        for tid in log.get("expected_techniques") or []:
            assert not tid.startswith("T1562"), (
                f"{log['id']}: {tid} v19.1 ve v19.2'de revoked, T1685 kullanilmali"
            )
