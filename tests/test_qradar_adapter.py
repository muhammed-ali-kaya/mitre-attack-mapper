from __future__ import annotations

from app.batch.qradar_adapter import (
    normalize_row,
    parse_message_subfields,
    parse_tagged_payload,
    try_convert_qradar_export,
)

SAMPLE_PAYLOAD = (
    "<13>Aug 06 11:48:52 WINHOST-01 AgentDevice=WindowsLog\tAgentLogFile=Security\t"
    "PluginVersion=7.3.1.43\tSource=Microsoft-Windows-Security-Auditing\t"
    "Computer=WINHOST-01\tOriginatingComputer=WINHOST-01\tUser=\tDomain=\t"
    "EventID=5156\tEventIDCode=5156\tEventType=8\tEventCategory=12810\t"
    "RecordNumber=1153228\tTimeGenerated=1786006130\tTimeWritten=1786006130\t"
    "Level=Log Always\tKeywords=Audit Success\tTask=SE_ADT_OBJECTACCESS_FIREWALLCONNECTION\t"
    "Opcode=Info\tMessage=The Windows Filtering Platform has permitted a connection.  "
    "Application Information:  Process ID:  23356  Application Name: "
    "\\device\\harddiskvolume3\\program files\\google\\chrome\\application\\chrome.exe  "
    "Network Information:  Direction:  Outbound  Source Address:  198.51.100.185  "
    "Source Port:  59902  Destination Address: 203.0.113.103  Destination Port:  8888  "
    "Protocol:  6"
)

NORMAL_ROW_PAYLOAD = "EventID=4688 NewProcessName=cmd.exe SubjectUserName=alice"


def test_parse_tagged_payload_extracts_key_value_pairs():
    fields = parse_tagged_payload(SAMPLE_PAYLOAD)
    assert fields["Computer"] == "WINHOST-01"
    assert fields["EventID"] == "5156"
    assert fields["TimeGenerated"] == "1786006130"
    assert fields["Message"].startswith("The Windows Filtering Platform")


def test_parse_message_subfields_extracts_labeled_values():
    fields = parse_tagged_payload(SAMPLE_PAYLOAD)
    subfields = parse_message_subfields(fields["Message"])
    assert subfields["Source Port"] == "59902"
    assert subfields["Destination Port"] == "8888"


def test_normalize_row_produces_canonical_fields():
    row = normalize_row(SAMPLE_PAYLOAD)
    assert row["EventID"] == "5156"
    assert row["Hostname"] == "WINHOST-01"
    assert row["Timestamp"] is not None
    assert row["SourceIp"] == "198.51.100.185"
    assert row["DestinationIp"] == "203.0.113.103"
    assert row["SourcePort"] == "59902"
    assert row["DestinationPort"] == "8888"
    assert "Windows Filtering Platform" in row["Message"]


def test_normalize_row_ignores_placeholder_values():
    payload = SAMPLE_PAYLOAD.replace("Source Address:  198.51.100.185", "Source Address:  -")
    row = normalize_row(payload)
    assert row["SourceIp"] is None


def test_try_convert_qradar_export_detects_tagged_payload_column():
    csv_bytes = (
        f'"col_a","col_b","{SAMPLE_PAYLOAD}"\n'
        f'"col_a2","col_b2","{SAMPLE_PAYLOAD}"\n'
    ).encode("utf-8")
    rows = try_convert_qradar_export(csv_bytes)
    assert rows is not None
    assert len(rows) == 2
    assert rows[0]["EventID"] == "5156"


def test_try_convert_qradar_export_returns_none_for_normal_csv():
    csv_bytes = b"EventID,NewProcessName,SubjectUserName\n4688,cmd.exe,alice\n5140,rundll32.exe,bob\n"
    assert try_convert_qradar_export(csv_bytes) is None


def test_try_convert_qradar_export_returns_none_for_unparseable_bytes():
    assert try_convert_qradar_export(b"\x00\x01\x02not a csv at all\xff") is None
