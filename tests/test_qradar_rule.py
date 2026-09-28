from __future__ import annotations

from app.reporting.qradar_rule import build_qradar_rule_draft

MAPPING = {
    "attack_id": "T1053",
    "name": "Scheduled Task/Job",
    "confidence_level": "high",
    "detection_recommendation": "Monitor for scheduled task creation via schtasks.exe.",
}


def test_returns_none_when_no_concrete_fields_extracted():
    normalized = {
        "platform": None, "event_id": None, "process_name": None, "command_line": None,
        "user_account": None, "remote_ips": [], "is_remote": False, "detected_tools": [],
    }
    assert build_qradar_rule_draft(MAPPING, normalized) is None


def test_builds_draft_from_process_name_using_basename():
    normalized = {
        "platform": "Windows", "event_id": "4688",
        "process_name": "C:\\Windows\\System32\\schtasks.exe",
        "command_line": "schtasks /create /s 10.10.20.15 /tn UpdateCheck",
        "user_account": "service.admin", "remote_ips": ["10.10.20.15"],
        "is_remote": True, "detected_tools": ["schtasks.exe", "powershell.exe"],
    }

    draft = build_qradar_rule_draft(MAPPING, normalized)

    assert draft is not None
    assert draft["rule_name"] == "[T1053] Scheduled Task/Job - Olasi Gozlem (Taslak)"
    assert 'Apply "[T1053] Scheduled Task/Job - Olasi Gozlem (Taslak)"' in draft["rule_text"]
    assert 'and when the Process Name contains "schtasks.exe"' in draft["rule_text"]
    assert "C:\\Windows\\System32" not in draft["rule_text"]  # only the basename is used


def test_falls_back_to_detected_tools_when_no_process_name():
    normalized = {
        "platform": None, "event_id": None, "process_name": None, "command_line": None,
        "user_account": None, "remote_ips": [], "is_remote": False,
        "detected_tools": ["mimikatz"],
    }

    draft = build_qradar_rule_draft(MAPPING, normalized)

    assert draft is not None
    assert 'and when the Process Name contains one of the following: "mimikatz"' in draft["rule_text"]


def test_includes_command_line_condition_and_truncates_long_snippets():
    normalized = {
        "platform": None, "event_id": None, "process_name": None,
        "command_line": "x" * 200,
        "user_account": None, "remote_ips": [], "is_remote": False, "detected_tools": [],
    }

    draft = build_qradar_rule_draft(MAPPING, normalized)

    assert draft is not None
    assert "Command Line contains" in draft["rule_text"]
    assert "x" * 81 not in draft["rule_text"]  # snippet capped at 80 chars


def test_event_id_becomes_a_note_not_a_rule_test():
    normalized = {
        "platform": None, "event_id": "4688", "process_name": None, "command_line": None,
        "user_account": None, "remote_ips": [], "is_remote": False, "detected_tools": [],
    }

    draft = build_qradar_rule_draft(MAPPING, normalized)

    assert draft is not None
    assert "Event ID" not in draft["rule_text"]  # not a rule test, since DSM mapping is uncertain
    assert any("4688" in n for n in draft["notes"])


def test_is_remote_without_ip_adds_manual_review_test_but_no_concrete_ip():
    normalized = {
        "platform": None, "event_id": None, "process_name": "cmd.exe", "command_line": None,
        "user_account": None, "remote_ips": [], "is_remote": True, "detected_tools": [],
    }

    draft = build_qradar_rule_draft(MAPPING, normalized)

    assert draft is not None
    assert "remote target" in draft["rule_text"]
    assert "Destination IP" not in draft["rule_text"]


def test_remote_ip_present_adds_destination_ip_test():
    normalized = {
        "platform": None, "event_id": None, "process_name": "cmd.exe", "command_line": None,
        "user_account": None, "remote_ips": ["10.10.20.15", "10.10.20.16"], "is_remote": True,
        "detected_tools": [],
    }

    draft = build_qradar_rule_draft(MAPPING, normalized)

    assert draft is not None
    assert "and when the Destination IP is one of the following: 10.10.20.15, 10.10.20.16" in draft["rule_text"]


def test_low_confidence_mapping_adds_extra_warning_note():
    normalized = {
        "platform": None, "event_id": None, "process_name": "cmd.exe", "command_line": None,
        "user_account": None, "remote_ips": [], "is_remote": False, "detected_tools": [],
    }
    low_conf_mapping = dict(MAPPING, confidence_level="low")

    draft = build_qradar_rule_draft(low_conf_mapping, normalized)

    assert draft is not None
    assert any("guven seviyesi" in n for n in draft["notes"])


def test_high_confidence_mapping_does_not_add_confidence_warning():
    normalized = {
        "platform": None, "event_id": None, "process_name": "cmd.exe", "command_line": None,
        "user_account": None, "remote_ips": [], "is_remote": False, "detected_tools": [],
    }

    draft = build_qradar_rule_draft(MAPPING, normalized)

    assert draft is not None
    assert not any("guven seviyesi" in n for n in draft["notes"])


def test_always_includes_official_mitre_detection_text_in_notes():
    normalized = {
        "platform": None, "event_id": None, "process_name": "cmd.exe", "command_line": None,
        "user_account": None, "remote_ips": [], "is_remote": False, "detected_tools": [],
    }

    draft = build_qradar_rule_draft(MAPPING, normalized)

    assert draft is not None
    assert any("Monitor for scheduled task creation via schtasks.exe." in n for n in draft["notes"])
