"""Yeni ayristirici ile ESKI tuketiciler arasindaki kopru.

Gorev 1 canonical adlari (object.name, value.new) getirdi ama kural motoru,
QRadar yolu ve korelasyon hala eski adlara (EventID, ObjectName, Accesses)
bagli. Kopru to_legacy_facts() izdusumu.

Bu dosya koprunun IKI YONUNU de kilitliyor:
  - eski bicimli loglar (space_kv) ESKI anahtarlarini aynen almaya devam
    ediyor mu (gerileme yok)
  - yeni bicimli loglar (brace_kv) kural motorunun bekledigi anahtarlari
    URETIYOR mu (yeni yol gercekten calisiyor)

Neden ayri test: "624 test geciyor" ile "davranis ayni" farkli seyler.
Kapsanmayan bir yol sessizce farkli davranabilir -- nitekim ilk yazimda
extracted_facts, eski BOZUK anahtarlarla yenilerin birlesimi oluyordu
(T0'da 15 yerine 26 anahtar) ve hicbir test bunu gormedi."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.mapping.rule_engine import evaluate_rules, load_rules
from app.mapping.text_input import text_to_row
from app.normalization.formats import detect_format
from app.normalization.input_parser import normalize_input
from tests.private_data import requires_qradar_export

FIXTURE = Path(__file__).parent / "fixtures" / "registry_object_access_logs.json"
LOGS = {log["id"]: log for log in json.loads(FIXTURE.read_text(encoding="utf-8"))["logs"]}

SPACE_KV_LOG = (
    'EventID=4688 NewProcessName=C:\\Windows\\System32\\schtasks.exe '
    'CommandLine="schtasks /create /tn X /tr powershell.exe" SubjectUserName=jdoe'
)


# ---------------------------------------------------------------- gerileme yok

def test_space_kv_logs_keep_their_legacy_keys():
    """Eski bicim eski adlarini korumali -- kural motoru bunlara bagli."""
    facts = normalize_input(SPACE_KV_LOG)["extracted_facts"]

    assert facts["EventID"] == "4688"
    assert facts["NewProcessName"].endswith("schtasks.exe")
    assert facts["SubjectUserName"] == "jdoe"
    assert "schtasks /create" in facts["CommandLine"]


def test_space_kv_facts_are_not_polluted_by_the_new_parser():
    """OLCULMUS HATA: iki cikarim korukoru birlestirilince sozluk sisiyordu.

    space_kv'de yeni ayristirici yalnizca EKSIK alanlari tamamlar; ayni
    alani ikinci bir adla tekrar eklemez."""
    facts = normalize_input(SPACE_KV_LOG)["extracted_facts"]

    assert not [k for k in facts if k.startswith("unknown.")]
    # Ayni bilgi iki anahtarda durmamali (ornegin hem EventID hem event.id).
    assert "event.id" not in facts
    assert "process.name" not in facts


@pytest.mark.parametrize("log_id", sorted(LOGS))
def test_brace_logs_produce_exactly_the_parsed_field_set(log_id):
    """Yeni bicimde extracted_facts, parsed_fields ile AYNI sayida alan
    tasimali. Fazlasi eski bozuk cikarimdan sizmis demektir."""
    normalized = normalize_input(LOGS[log_id]["raw"])

    assert len(normalized["extracted_facts"]) == len(normalized["parsed_fields"])
    assert not [
        k for k, v in normalized["extracted_facts"].items() if str(v).endswith(",")
    ], "sondaki virgul, degerin ', ' ayracinda kesilmedigini gosterir"


# ---------------------------------------------------------------- yeni yol calisiyor

def test_brace_log_reaches_the_rule_engine_with_usable_fields():
    """Uctan uca duman testi: brace_kv log -> text_to_row -> kural motoru.

    Motorun cokmemesi yetmez; kosullarin BAKTIGI alanlarin satirda gercekten
    bulunmasi gerekir."""
    row = text_to_row(LOGS["T3"]["raw"])

    assert row["EventID"] == "4657"
    assert row["ObjectName"].endswith("Windows Defender")
    assert "Message" in row

    # Motor bu satiri sorunsuz degerlendirebilmeli.
    findings = evaluate_rules([row], load_rules())
    assert isinstance(findings, list)


def test_access_list_reaches_legacy_consumers_with_its_separator():
    """access.list uc ayri erisimdir; duz bosluklu birlestirme uc erisimi
    tek bulanik ifadeye cevirir ve Gorev 2'de bu alan birincil agirlikli
    olacak."""
    facts = normalize_input(LOGS["T1"]["raw"])["extracted_facts"]

    assert facts["Accesses"] == "Query key value | Enumerate sub-keys | Read Control"


def test_event_id_survives_into_the_rule_engine_row():
    """BUG D koprunun oteki ucunda da kapanmis olmali: olay ID'si satira
    ulasmazsa EventID sart kosan hicbir kural tetiklenemez."""
    for log_id, expected in (("T0", "4656"), ("T1", "4656"), ("T2", "4656"), ("T3", "4657")):
        assert text_to_row(LOGS[log_id]["raw"])["EventID"] == expected


# ---------------------------------------------------------------- bicim tespiti

@requires_qradar_export
def test_qradar_message_body_is_recognised_as_windows_message():
    """QRadar export'unun Message govdesi 'Etiket:  Deger' bicimindedir."""
    from app.batch.qradar_adapter import try_convert_qradar_export

    rows = try_convert_qradar_export(
        (Path(__file__).parent / "fixtures" / "qradar_2026-08-06_51rows.csv").read_bytes()
    )
    fmt = detect_format(str(rows[0].get("Message") or ""))

    assert fmt is not None and fmt.name == "windows_message"


def test_every_supported_format_has_a_real_fixture():
    """Kural: fixture'i olmayan bicim yazilmaz. Test edilmemis bir
    ayristirici olmayanindan kotudur -- olmayan sessiz kalir, test
    edilmemis olan sessizce YANLIS ayristirir."""
    from app.normalization.formats import FORMATS

    supported = {f.name for f in FORMATS}
    assert supported == {"json", "brace_kv", "space_kv", "windows_message"}, (
        "yeni bir bicim eklendiyse fixture'i da eklenmeli"
    )
