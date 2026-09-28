from __future__ import annotations

import json

from app.validation.validator import (
    REASONING_SUMMARY_MAX_LENGTH,
    AttackKnowledgeBase,
    _looks_quoted_from_input,
    _shorten_reasoning,
    validate_mapping,
    validate_response,
)


def _make_kb(tmp_path, techniques):
    path = tmp_path / "techniques.json"
    path.write_text(json.dumps(techniques), encoding="utf-8")
    return AttackKnowledgeBase(techniques_path=path)


def _valid_mapping(technique):
    return {
        "attack_id": technique["attack_id"],
        "name": technique["name"],
        "object_type": technique["object_type"],
        "tactics": technique["tactics"],
        "source_url": technique["source_url"],
        "confidence_level": "high",
        "evidence": ["schtasks.exe calistirildi"],
    }


# -- _looks_quoted_from_input -------------------------------------------------

def test_looks_quoted_from_input_true_when_words_overlap():
    evidence = "schtasks /create command executed"
    raw_input = "raw log: schtasks /create /s 10.10.20.15"
    assert _looks_quoted_from_input(evidence, raw_input) is True


def test_looks_quoted_from_input_false_when_evidence_is_generic_paraphrase():
    evidence = "Scheduled tasks are commonly used for persistence and execution by adversaries"
    raw_input = "EventID=4688 NewProcessName=schtasks.exe"
    assert _looks_quoted_from_input(evidence, raw_input) is False


def test_looks_quoted_from_input_true_for_empty_evidence():
    assert _looks_quoted_from_input("", "anything") is True


# -- validate_mapping: acceptance / rejection ---------------------------------

def test_validate_mapping_rejects_unknown_attack_id(tmp_path, sample_technique):
    kb = _make_kb(tmp_path, [sample_technique])
    mapping = _valid_mapping(sample_technique)
    mapping["attack_id"] = "T9999"

    is_valid, _, notes = validate_mapping(mapping, kb)

    assert is_valid is False
    assert any("Bilinmeyen ATT&CK ID" in n for n in notes)


def test_validate_mapping_rejects_revoked_technique_when_replacement_unknown(tmp_path, sample_technique):
    """Guncel karsiligi elimizde YOKSA (KB'de bulunmuyorsa) ret devam eder."""
    revoked = dict(sample_technique, revoked=True, revoked_by={"attack_id": "T1059.001", "name": "PowerShell"})
    kb = _make_kb(tmp_path, [revoked])
    mapping = _valid_mapping(revoked)

    is_valid, _, notes = validate_mapping(mapping, kb)

    assert is_valid is False
    assert any("REVOKED" in n and "T1059.001" in n for n in notes)


def test_validate_mapping_redirects_revoked_technique_to_its_replacement(tmp_path, sample_technique):
    """Girdide eski bir ID gectiginde (orn. "T1143 ile iliskili...") model o ID'yi
    tekrarliyor; mapping tumden atilinca sistem hicbir sey dondurmuyordu -- oysa
    guncel karsilik STIX'teki revoked-by iliskisinden zaten biliniyor."""
    replacement = dict(sample_technique, attack_id="T1059.001", name="PowerShell",
                       source_url="https://attack.mitre.org/techniques/T1059/001/")
    revoked = dict(sample_technique, attack_id="T1086", name="PowerShell (revoked)",
                   revoked=True, revoked_by={"attack_id": "T1059.001", "name": "PowerShell"})
    kb = _make_kb(tmp_path, [revoked, replacement])
    mapping = _valid_mapping(revoked)

    is_valid, corrected, notes = validate_mapping(mapping, kb)

    assert is_valid is True
    assert corrected["attack_id"] == "T1059.001"
    assert corrected["name"] == "PowerShell"
    assert any("T1086" in n and "T1059.001" in n for n in notes)


def test_validate_mapping_does_not_loop_on_circular_revocation(tmp_path, sample_technique):
    """Veri bozuk olsa bile (A -> B -> A) sonsuz donguye girilmemeli."""
    a = dict(sample_technique, attack_id="T1000", revoked=True,
             revoked_by={"attack_id": "T2000", "name": "B"})
    b = dict(sample_technique, attack_id="T2000", revoked=True,
             revoked_by={"attack_id": "T1000", "name": "A"})
    kb = _make_kb(tmp_path, [a, b])

    is_valid, _, notes = validate_mapping(_valid_mapping(a), kb)

    assert is_valid is False
    assert any("REVOKED" in n for n in notes)


def test_validate_mapping_accepts_fully_correct_mapping_with_no_notes(tmp_path, sample_technique):
    kb = _make_kb(tmp_path, [sample_technique])
    mapping = _valid_mapping(sample_technique)

    is_valid, corrected, notes = validate_mapping(mapping, kb, raw_input="schtasks.exe calistirildi")

    assert is_valid is True
    assert notes == []
    assert corrected["detection_recommendation"] == sample_technique["detection"]
    assert corrected["mitigation_recommendations"] == sample_technique["mitigations"]


# -- validate_mapping: authoritative corrections ------------------------------

def test_validate_mapping_corrects_wrong_name(tmp_path, sample_technique):
    kb = _make_kb(tmp_path, [sample_technique])
    mapping = _valid_mapping(sample_technique)
    mapping["name"] = "Scheduled Task"  # LLM's slightly wrong guess

    is_valid, corrected, notes = validate_mapping(mapping, kb)

    assert is_valid is True
    assert corrected["name"] == sample_technique["name"]
    assert any("Isim duzeltildi" in n for n in notes)


def test_validate_mapping_corrects_wrong_object_type(tmp_path, sample_subtechnique):
    kb = _make_kb(tmp_path, [sample_subtechnique])
    mapping = _valid_mapping(sample_subtechnique)
    mapping["object_type"] = "technique"  # should be sub-technique

    is_valid, corrected, notes = validate_mapping(mapping, kb)

    assert is_valid is True
    assert corrected["object_type"] == "sub-technique"
    assert any("object_type duzeltildi" in n for n in notes)


def test_validate_mapping_corrects_tactics_not_matching_known_set(tmp_path, sample_technique):
    kb = _make_kb(tmp_path, [sample_technique])
    mapping = _valid_mapping(sample_technique)
    mapping["tactics"] = ["Made Up Tactic"]

    is_valid, corrected, notes = validate_mapping(mapping, kb)

    assert is_valid is True
    assert corrected["tactics"] == sample_technique["tactics"]
    assert any("tactics duzeltildi" in n for n in notes)


def test_validate_mapping_corrects_wrong_source_url(tmp_path, sample_technique):
    kb = _make_kb(tmp_path, [sample_technique])
    mapping = _valid_mapping(sample_technique)
    mapping["source_url"] = "https://example.com/wrong"

    is_valid, corrected, notes = validate_mapping(mapping, kb)

    assert is_valid is True
    assert corrected["source_url"] == sample_technique["source_url"]
    assert any("source_url duzeltildi" in n for n in notes)


def test_validate_mapping_corrects_invalid_confidence_level_to_low(tmp_path, sample_technique):
    kb = _make_kb(tmp_path, [sample_technique])
    mapping = _valid_mapping(sample_technique)
    mapping["confidence_level"] = "extremely-sure"

    is_valid, corrected, notes = validate_mapping(mapping, kb)

    assert is_valid is True
    assert corrected["confidence_level"] == "low"
    assert any("Gecersiz confidence_level" in n for n in notes)


def test_validate_mapping_warns_on_deprecated_technique(tmp_path, sample_technique):
    deprecated = dict(sample_technique, deprecated=True)
    kb = _make_kb(tmp_path, [deprecated])
    mapping = _valid_mapping(deprecated)

    is_valid, _, notes = validate_mapping(mapping, kb)

    assert is_valid is True
    assert any("DEPRECATED" in n for n in notes)


# -- _shorten_reasoning / reasoning_summary length safety net -----------------

def test_shorten_reasoning_leaves_short_text_unchanged():
    text = "Kisa bir gerekce."
    assert _shorten_reasoning(text) == text


def test_shorten_reasoning_truncates_long_text_at_word_boundary_with_ellipsis():
    long_text = "kelime " * 60  # far beyond the limit
    shortened = _shorten_reasoning(long_text)
    assert len(shortened) <= REASONING_SUMMARY_MAX_LENGTH + len("...")
    assert shortened.endswith("...")
    assert not shortened[:-3].endswith(" ")  # no dangling space before the ellipsis


def test_validate_mapping_truncates_overly_long_reasoning_summary(tmp_path, sample_technique):
    kb = _make_kb(tmp_path, [sample_technique])
    mapping = _valid_mapping(sample_technique)
    mapping["reasoning_summary"] = (
        "Scheduled tasks and cron jobs are commonly used for persistence and execution. "
        "Anomalous or unexpected creation, modification, or execution of these tasks may "
        "indicate adversarial activity. Detection should focus on task creation context."
    )

    is_valid, corrected, _ = validate_mapping(mapping, kb)

    assert is_valid is True
    assert len(corrected["reasoning_summary"]) <= REASONING_SUMMARY_MAX_LENGTH + len("...")
    assert corrected["reasoning_summary"].endswith("...")


def test_validate_mapping_leaves_short_reasoning_summary_untouched(tmp_path, sample_technique):
    kb = _make_kb(tmp_path, [sample_technique])
    mapping = _valid_mapping(sample_technique)
    mapping["reasoning_summary"] = "'schtasks /create ... /sc onlogon' zamanlanmis gorev olusturuyor."

    _, corrected, _ = validate_mapping(mapping, kb)

    assert corrected["reasoning_summary"] == mapping["reasoning_summary"]


# -- validate_mapping: evidence quoting and grounding checks ------------------

def test_validate_mapping_flags_evidence_that_is_not_quoted_from_input(tmp_path, sample_technique):
    kb = _make_kb(tmp_path, [sample_technique])
    mapping = _valid_mapping(sample_technique)
    mapping["evidence"] = ["Scheduled tasks are commonly abused by adversaries for persistence"]

    _, _, notes = validate_mapping(mapping, kb, raw_input="EventID=4688 NewProcessName=schtasks.exe")

    assert any("KANIT UYARISI" in n for n in notes)


def test_validate_mapping_does_not_flag_evidence_quoted_from_input(tmp_path, sample_technique):
    kb = _make_kb(tmp_path, [sample_technique])
    mapping = _valid_mapping(sample_technique)
    mapping["evidence"] = ["NewProcessName=schtasks.exe"]

    _, _, notes = validate_mapping(mapping, kb, raw_input="EventID=4688 NewProcessName=schtasks.exe")

    assert not any("KANIT UYARISI" in n for n in notes)


def test_validate_mapping_flags_ungrounded_attack_id_and_lowers_confidence(tmp_path, sample_technique):
    kb = _make_kb(tmp_path, [sample_technique])
    mapping = _valid_mapping(sample_technique)

    _, corrected, notes = validate_mapping(mapping, kb, grounded_attack_ids={"T1059"})

    assert any("GROUNDING UYARISI" in n for n in notes)
    assert corrected["confidence_level"] == "low"


def test_validate_mapping_does_not_flag_grounded_attack_id(tmp_path, sample_technique):
    kb = _make_kb(tmp_path, [sample_technique])
    mapping = _valid_mapping(sample_technique)

    _, corrected, notes = validate_mapping(mapping, kb, grounded_attack_ids={sample_technique["attack_id"]})

    assert not any("GROUNDING UYARISI" in n for n in notes)
    assert corrected["confidence_level"] == "high"


# -- validate_response ---------------------------------------------------------

def test_validate_response_splits_accepted_and_rejected(tmp_path, sample_technique):
    kb = _make_kb(tmp_path, [sample_technique])
    good_mapping = _valid_mapping(sample_technique)
    bad_mapping = _valid_mapping(sample_technique)
    bad_mapping["attack_id"] = "T9999"

    llm_response = {"mappings": [good_mapping, bad_mapping]}
    result = validate_response(llm_response, kb)

    assert len(result["mappings"]) == 1
    assert result["mappings"][0]["attack_id"] == sample_technique["attack_id"]
    assert len(result["rejected_mappings"]) == 1
    assert result["rejected_mappings"][0]["attack_id"] == "T9999"
    assert "validation_issues" in result["rejected_mappings"][0]


def test_validate_response_handles_no_mappings(tmp_path, sample_technique):
    kb = _make_kb(tmp_path, [sample_technique])
    result = validate_response({"mappings": []}, kb)
    assert result["mappings"] == []
    assert result["rejected_mappings"] == []


# -- validate_mapping: required-evidence hard rejection (T1685.005/T1047/T1021.006) --

def _gated_technique(attack_id: str, name: str) -> dict:
    return {
        "attack_version": "19.2",
        "stix_id": f"attack-pattern--{attack_id}",
        "attack_id": attack_id,
        "object_type": "sub-technique" if "." in attack_id else "technique",
        "name": name,
        "description": "desc",
        "is_subtechnique": "." in attack_id,
        "parent_technique_id": attack_id.split(".")[0] if "." in attack_id else None,
        "tactics": ["Defense Evasion"],
        "platforms": ["Windows"],
        "data_sources": [],
        "data_components": [],
        "mitigations": [],
        "procedure_examples": [],
        "groups": [],
        "software": [],
        "permissions_required": None,
        "system_requirements": None,
        "detection": "detection text",
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2020-01-01T00:00:00.000Z",
        "deprecated": False,
        "revoked": False,
        "revoked_by": None,
        "source_url": f"https://attack.mitre.org/techniques/{attack_id}/",
        "chunk_id": None,
    }


def test_validate_mapping_rejects_t1685_005_without_required_evidence(tmp_path):
    technique = _gated_technique("T1685.005", "Clear Windows Event Logs")
    kb = _make_kb(tmp_path, [technique])
    mapping = _valid_mapping(technique)
    raw_input = "EventID=5140 ShareName=\\\\*\\ADMIN$ AccessMask=0x1 AccessList=ReadData"

    is_valid, _, notes = validate_mapping(mapping, kb, raw_input=raw_input)

    assert is_valid is False
    assert any("Technique rejected because required evidence was not found in the supplied log." in n for n in notes)


def test_validate_mapping_accepts_t1685_005_with_eventid_1102(tmp_path):
    technique = _gated_technique("T1685.005", "Clear Windows Event Logs")
    kb = _make_kb(tmp_path, [technique])
    mapping = _valid_mapping(technique)
    mapping["evidence"] = ["EventID=1102"]
    raw_input = 'EventID=1102 SubjectUserName=administrator Message="The audit log was cleared."'

    is_valid, corrected, notes = validate_mapping(mapping, kb, raw_input=raw_input)

    assert is_valid is True
    assert corrected["evidence_check"]["applicable"] is True
    assert corrected["evidence_check"]["satisfied"] is True


def test_validate_mapping_rejects_t1047_without_wmi_evidence(tmp_path):
    technique = _gated_technique("T1047", "Windows Management Instrumentation")
    kb = _make_kb(tmp_path, [technique])
    mapping = _valid_mapping(technique)
    raw_input = "EventID=5140 ShareName=\\\\*\\ADMIN$ AccessMask=0x1 AccessList=ReadData"

    is_valid, _, notes = validate_mapping(mapping, kb, raw_input=raw_input)

    assert is_valid is False
    assert any("Technique rejected because required evidence was not found in the supplied log." in n for n in notes)


def test_validate_mapping_rejects_t1021_006_without_winrm_evidence(tmp_path):
    technique = _gated_technique("T1021.006", "Windows Remote Management")
    kb = _make_kb(tmp_path, [technique])
    mapping = _valid_mapping(technique)
    raw_input = "EventID=5140 ShareName=\\\\*\\ADMIN$ AccessMask=0x1 AccessList=ReadData"

    is_valid, _, notes = validate_mapping(mapping, kb, raw_input=raw_input)

    assert is_valid is False


def test_validate_mapping_leaves_uncatalogued_technique_unaffected_by_evidence_gate(tmp_path, sample_technique):
    kb = _make_kb(tmp_path, [sample_technique])
    mapping = _valid_mapping(sample_technique)

    is_valid, corrected, _ = validate_mapping(mapping, kb, raw_input="totally unrelated text")

    assert is_valid is True
    assert corrected["evidence_check"]["applicable"] is False


def test_validate_mapping_evidence_list_shrinks_when_items_not_quoted(tmp_path, sample_technique):
    kb = _make_kb(tmp_path, [sample_technique])
    mapping = _valid_mapping(sample_technique)
    mapping["evidence"] = ["schtasks.exe calistirildi", "Scheduled tasks are commonly abused by adversaries"]

    _, corrected, notes = validate_mapping(mapping, kb, raw_input="EventID=4688 NewProcessName=schtasks.exe")

    assert corrected["evidence"] == ["schtasks.exe calistirildi"]
    assert any("KANIT UYARISI" in n for n in notes)


# -- validate_response: observed_behaviors filtering ------------------------------

def test_validate_response_filters_ungrounded_observed_behaviors(tmp_path, sample_technique):
    kb = _make_kb(tmp_path, [sample_technique])
    llm_response = {
        "mappings": [],
        "observed_behaviors": [
            "schtasks.exe calistirildi",
            "wevtutil cl security komutu calistirildi ve loglar silindi",
        ],
    }

    result = validate_response(llm_response, kb, raw_input="EventID=4688 NewProcessName=schtasks.exe")

    assert result["observed_behaviors"] == ["schtasks.exe calistirildi"]
    assert result["filtered_observed_behaviors"] == [
        "wevtutil cl security komutu calistirildi ve loglar silindi"
    ]
