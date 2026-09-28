"""Tek bir serbest metin girdisini kanit kapisinin anladigi satira cevirir.

Kanit kapisi ve kontrol ajanlari (app/agents/) yapilandirilmis alanlar
(EventID, Message, CommandLine...) uzerinde calisir; tekli analiz modu ise
duz metin alir. Aradaki koprü app/normalization/input_parser.py'deki
DETERMINISTIK ayiklayicidir -- Key=Value ciftlerini, Message govdesindeki
"Etiket: Deger" alanlarini ve EventID'yi regex ile cikarir. LLM devrede
degildir.

SONUC OLARAK NE DEGISIR: serbest metinde EventID yoksa, EventID sart kosan
bir kanit kosulu saglanamaz. Bu bir eksiklik degil, mimarinin geregi --
"bir PowerShell sureci kod indirdi" cumlesi bir IDDIADIR, kanit degildir.
Kanit kapisi o cumleyi teyit sayamaz; yalnizca metin kosullu kurallar
(field_conditions) serbest metinde de dogrulanabilir."""

from __future__ import annotations

from typing import Any

from app.normalization.input_parser import normalize_input

# Ayiklayicinin urettigi alanlarin kural motorundaki karsiliklari.
_NORMALIZED_FIELD_MAP = {
    "event_id": "EventID",
    "process_name": "NewProcessName",
    "command_line": "CommandLine",
    "user_account": "SubjectUserName",
}


def text_to_row(raw_text: str) -> dict[str, Any]:
    """Serbest metni tek bir 'satir' sozlugune cevirir.

    Message BILEREK ham metnin TAMAMI olur (girdide ayrica Message= alani
    gecse bile). Gerekce: kural kosullari girdinin tamaminda aranmalidir;
    ic Message alani zaten ham metnin bir alt dizesi oldugu icin ona uyan
    her must_match tam metne de uyar."""
    normalized = normalize_input(raw_text)

    row: dict[str, Any] = dict(normalized.get("extracted_facts") or {})
    for source, target in _NORMALIZED_FIELD_MAP.items():
        value = normalized.get(source)
        if value:
            row[target] = value

    # KANONIK ANAHTARLAR -- 2B'nin kural kosullarinin bakacagi yer.
    #
    # YETKILI OLAN BUNLAR. Yukaridaki legacy anahtarlar (CommandLine,
    # NewProcessName...) artik BAGIMSIZ CIKARIM DEGIL, ayni ayristiricinin
    # izdusumu: normalize_input yetki sirasini yetkili ayristirici -> facts
    # -> regex olarak kuruyor (bkz. input_parser, 2026-08-18).
    #
    # IKISI BIRDEN tasiniyor cunku legacy anahtarlarin kural katalogu
    # DISINDA alti tuketicisi var: ioc_extraction, incident, qradar_rule,
    # qradar_adapter, verification (kanit kapisi) ve motorun kendi EventID
    # okumasi. Onlari ayni commit'te tasimak, gerilemenin tasimadan mi
    # yoksa o alti modulden mi geldigini ayirt edilemez yapardi.
    # Legacy anahtarlarin kaldirilmasi AYRI bir gorevdir (Gorev 12 yani).
    #
    # Iki gerceklik riskine karsi: tests/test_extraction_paths.py ayni
    # satirda kanonik ve legacy degerlerin ESIT oldugunu sozlesme yapiyor.
    for ad, alan in (normalized.get("parsed_fields") or {}).items():
        if not ad.startswith("unknown."):
            row[ad] = alan.text

    row["Message"] = raw_text
    return row
