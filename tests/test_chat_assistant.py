from __future__ import annotations

from app.llm.chat_assistant import build_chat_context, build_chat_system_prompt

RESULT_WITH_MAPPING = {
    "input_summary": {"raw_input": "EventID=4688 NewProcessName=schtasks.exe"},
    "mappings": [
        {
            "attack_id": "T1053",
            "name": "Scheduled Task/Job",
            "object_type": "technique",
            "confidence_level": "high",
            "tactics": ["Execution", "Persistence"],
            "reasoning_summary": "schtasks.exe calistirildigi icin.",
            "evidence": ["NewProcessName=schtasks.exe"],
            "detection_recommendation": "Monitor schtasks.exe usage.",
            "mitigation_recommendations": [{"attack_id": "M1028", "name": "Operating System Configuration"}],
            "validation_notes": ["Isim duzeltildi: 'X' -> 'Scheduled Task/Job'"],
            "qradar_rule_draft": {"rule_name": "[T1053] Scheduled Task/Job - Olasi Gozlem (Taslak)"},
        }
    ],
    "rejected_mappings": [
        {"attack_id": "T9999", "name": "Uydurma Teknik", "validation_issues": ["Bilinmeyen ATT&CK ID"]},
    ],
}

RESULT_WITH_NO_MAPPINGS = {
    "input_summary": {"raw_input": "belirsiz bir metin"},
    "mappings": [],
}


def test_build_chat_context_includes_raw_input():
    context = build_chat_context(RESULT_WITH_MAPPING)
    assert "EventID=4688 NewProcessName=schtasks.exe" in context


def test_build_chat_context_includes_mapping_details():
    context = build_chat_context(RESULT_WITH_MAPPING)
    assert "T1053" in context
    assert "Scheduled Task/Job" in context
    assert "schtasks.exe calistirildigi icin." in context
    assert "NewProcessName=schtasks.exe" in context
    assert "Monitor schtasks.exe usage." in context
    assert "M1028" in context


def test_build_chat_context_includes_qradar_rule_name_when_present():
    context = build_chat_context(RESULT_WITH_MAPPING)
    assert "[T1053] Scheduled Task/Job - Olasi Gozlem (Taslak)" in context


def test_build_chat_context_includes_rejected_mappings():
    context = build_chat_context(RESULT_WITH_MAPPING)
    assert "T9999" in context
    assert "Bilinmeyen ATT&CK ID" in context


def test_build_chat_context_handles_no_mappings_gracefully():
    context = build_chat_context(RESULT_WITH_NO_MAPPINGS)
    assert "belirsiz bir metin" in context
    assert "Kabul edilen eslestirme yok" in context


def test_build_chat_context_does_not_crash_on_missing_optional_fields():
    minimal_result = {"input_summary": {}, "mappings": [{"attack_id": "T1053", "name": "X"}]}
    context = build_chat_context(minimal_result)
    assert "T1053" in context


def test_build_chat_system_prompt_embeds_context_and_scope_rules():
    prompt = build_chat_system_prompt(RESULT_WITH_MAPPING)
    assert "T1053" in prompt
    assert "yeni bir ATT&CK teknigi/ID iddia etme" in prompt
    assert "TASLAK" in prompt
    assert "Turkce yaz" in prompt
