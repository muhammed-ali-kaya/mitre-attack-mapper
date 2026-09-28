from __future__ import annotations

import io
import json

import pytest

from app.batch.serialize import (
    extract_platform_override,
    parse_csv_rows,
    parse_json_rows,
    row_to_kv_string,
    rows_to_batch_items,
)
from app.normalization.input_parser import normalize_input


# -- row_to_kv_string: aliasing ---------------------------------------------

def test_row_to_kv_string_aliases_process_name():
    kv = row_to_kv_string({"ProcessName": "schtasks.exe"})
    assert "NewProcessName=schtasks.exe" in kv


def test_row_to_kv_string_aliases_user():
    kv = row_to_kv_string({"User": "svc_admin"})
    assert "SubjectUserName=svc_admin" in kv


def test_row_to_kv_string_drops_platform_column():
    kv = row_to_kv_string({"EventID": 4688, "Platform": "Windows"})
    assert "Platform" not in kv
    assert "EventID=4688" in kv


# -- whitespace quoting round-tripped through the real normalize_input ------

def test_row_to_kv_string_quoted_commandline_roundtrips_through_normalize_input():
    row = {
        "EventID": 4688,
        "ProcessName": "schtasks.exe",
        "CommandLine": "schtasks /create /tn Updater /tr powershell.exe",
        "User": "svc_admin",
        "SourceIP": "10.10.20.15",
    }
    kv = row_to_kv_string(row)
    normalized = normalize_input(kv)
    assert normalized["extracted_facts"]["CommandLine"] == "schtasks /create /tn Updater /tr powershell.exe"
    assert normalized["extracted_facts"]["EventID"] == "4688"
    assert normalized["process_name"] == "schtasks.exe"
    assert normalized["user_account"] == "svc_admin"


def test_row_to_kv_string_commandline_placed_last_when_other_columns_follow():
    row = {"CommandLine": "cmd.exe /c whoami", "SubjectUserName": "alice"}
    kv = row_to_kv_string(row)
    assert kv.endswith('CommandLine="cmd.exe /c whoami"')


# -- parse_csv_rows -----------------------------------------------------------

def test_parse_csv_rows_blank_cells_become_none():
    csv_text = "EventID,ProcessName\n4688,schtasks.exe\n5140,\n"
    rows = parse_csv_rows(csv_text.encode())
    assert rows[1]["ProcessName"] is None
    assert rows[1]["ProcessName"] != "nan"


def test_parse_csv_rows_reads_expected_row_count():
    csv_text = "EventID,ProcessName\n4688,a.exe\n5140,b.exe\n"
    rows = parse_csv_rows(csv_text.encode())
    assert len(rows) == 2


# -- parse_json_rows -----------------------------------------------------------

def test_parse_json_rows_accepts_array_of_objects():
    data = json.dumps([{"EventID": 4688}, {"EventID": 5140}]).encode()
    rows = parse_json_rows(data)
    assert len(rows) == 2


def test_parse_json_rows_rejects_top_level_object():
    data = json.dumps({"EventID": 4688}).encode()
    with pytest.raises(ValueError, match="nesne listesi"):
        parse_json_rows(data)


# -- extract_platform_override -------------------------------------------------

def test_extract_platform_override_case_insensitive_column_and_value():
    assert extract_platform_override({"platform": "windows"}) == "Windows"
    assert extract_platform_override({"OS": "Linux"}) == "Linux"


def test_extract_platform_override_unrecognized_value_falls_back_to_none():
    assert extract_platform_override({"Platform": "AmigaOS"}) is None


def test_extract_platform_override_no_platform_column():
    assert extract_platform_override({"EventID": 4688}) is None


# -- rows_to_batch_items --------------------------------------------------------

def test_rows_to_batch_items_flags_blank_rows_as_skipped():
    items = rows_to_batch_items([{"EventID": 4688}, {"EventID": None, "ProcessName": None}])
    assert items[0]["skipped"] is False
    assert items[1]["skipped"] is True
    assert items[1]["skip_reason"] is not None
