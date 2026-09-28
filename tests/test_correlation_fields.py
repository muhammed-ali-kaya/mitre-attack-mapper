from __future__ import annotations

from datetime import datetime

from app.correlation.fields import extract_correlation_fields, extract_event_id, extract_timestamp


def test_extract_correlation_fields_aliases_common_synonyms():
    row = {"Computer": "FS-01", "SrcIP": "10.0.0.5", "TargetFilename": "C:\\evil.dll"}
    fields = extract_correlation_fields(row)
    assert fields["Hostname"] == "FS-01"
    assert fields["SourceIp"] == "10.0.0.5"
    assert fields["FilePath"] == "C:\\evil.dll"


def test_extract_correlation_fields_first_non_empty_wins_on_duplicate_canonical_key():
    # 'Hostname' ve 'Computer' ayni kanonik alana (Hostname) esleniyor -- ilk dolu deger kazanmali
    row = {"Hostname": "FS-01", "Computer": "OTHER-HOST"}
    fields = extract_correlation_fields(row)
    assert fields["Hostname"] == "FS-01"


def test_extract_correlation_fields_missing_field_is_none():
    fields = extract_correlation_fields({"EventID": 4688})
    assert fields["ProcessGuid"] is None
    assert fields["LogonId"] is None


def test_extract_correlation_fields_ignores_nan_and_none():
    fields = extract_correlation_fields({"Hostname": None, "SourceIp": float("nan")})
    assert fields["Hostname"] is None
    assert fields["SourceIp"] is None


def test_extract_timestamp_parses_common_format():
    ts = extract_timestamp({"Timestamp": "2026-08-06 09:21:06"})
    assert ts == datetime(2026, 8, 6, 9, 21, 6)


def test_extract_timestamp_recognizes_alias_columns():
    assert extract_timestamp({"EventTime": "2026-08-06 09:21:06"}) is not None
    assert extract_timestamp({"@timestamp": "2026-08-06 09:21:06"}) is not None


def test_extract_timestamp_returns_none_for_unparseable_value():
    assert extract_timestamp({"Timestamp": "not-a-date"}) is None


def test_extract_timestamp_returns_none_when_no_timestamp_column():
    assert extract_timestamp({"EventID": 4688}) is None


def test_extract_event_id_aliases_and_stringifies():
    assert extract_event_id({"EventID": 4688}) == "4688"
    assert extract_event_id({"event_id": 7045}) == "7045"


def test_extract_event_id_none_when_missing():
    assert extract_event_id({"Hostname": "FS-01"}) is None
