from __future__ import annotations

from datetime import datetime, timedelta

from app.correlation.engine import build_incident_groups

EMPTY_FIELDS = {
    "Hostname": None, "SubjectUserName": None, "SourceIp": None, "DestinationIp": None,
    "ProcessGuid": None, "ParentProcessGuid": None, "ProcessId": None, "ParentProcessId": None,
    "LogonId": None, "SessionId": None, "ServiceName": None, "FilePath": None,
}


def _item(index: int, skipped: bool = False, timestamp=None, **fields) -> dict:
    return {
        "index": index,
        "skipped": skipped,
        "timestamp": timestamp,
        "correlation_fields": {**EMPTY_FIELDS, **fields},
    }


def test_groups_rows_sharing_hostname():
    t0 = datetime(2026, 8, 6, 9, 0, 0)
    items = [_item(0, timestamp=t0, Hostname="FS-01"), _item(1, timestamp=t0, Hostname="FS-01")]
    assert build_incident_groups(items) == [[0, 1]]


def test_no_group_when_no_shared_field():
    items = [_item(0, Hostname="FS-01"), _item(1, Hostname="OTHER-HOST")]
    assert build_incident_groups(items) == []


def test_singleton_row_produces_no_group():
    items = [_item(0, Hostname="FS-01")]
    assert build_incident_groups(items) == []


def test_process_lineage_cross_match_groups_parent_and_child():
    items = [
        _item(0, ProcessGuid="guid-1"),
        _item(1, ParentProcessGuid="guid-1"),
    ]
    assert build_incident_groups(items) == [[0, 1]]


def test_process_id_fallback_used_only_when_guid_absent():
    items = [_item(0, ProcessId="100"), _item(1, ParentProcessId="100")]
    assert build_incident_groups(items) == [[0, 1]]


def test_time_window_excludes_distant_matches():
    t0 = datetime(2026, 8, 6, 9, 0, 0)
    t_far = t0 + timedelta(hours=48)
    items = [_item(0, timestamp=t0, Hostname="FS-01"), _item(1, timestamp=t_far, Hostname="FS-01")]
    assert build_incident_groups(items) == []


def test_skipped_rows_are_excluded():
    items = [_item(0, Hostname="FS-01"), _item(1, Hostname="FS-01", skipped=True)]
    assert build_incident_groups(items) == []


def test_transitive_grouping_across_three_rows():
    items = [
        _item(0, Hostname="FS-01"),
        _item(1, Hostname="FS-01", SubjectUserName="svc_backup"),
        _item(2, SubjectUserName="svc_backup"),
    ]
    assert build_incident_groups(items) == [[0, 1, 2]]
