from __future__ import annotations

import json

import pytest


@pytest.fixture
def sample_technique() -> dict:
    return {
        "attack_version": "19.2",
        "stix_id": "attack-pattern--0001",
        "attack_id": "T1053",
        "object_type": "technique",
        "name": "Scheduled Task/Job",
        "description": "Adversaries may abuse task scheduling functionality.",
        "is_subtechnique": False,
        "parent_technique_id": None,
        "tactics": ["Execution", "Persistence", "Privilege Escalation"],
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": [],
        "data_components": ["Scheduled Job Creation"],
        "mitigations": [{"attack_id": "M1028", "name": "Operating System Configuration"}],
        "procedure_examples": [
            {"actor": "APT29", "actor_type": "intrusion-set", "description": "Used schtasks for persistence."},
        ],
        "groups": ["APT29"],
        "software": [],
        "permissions_required": None,
        "system_requirements": None,
        "detection": "Monitor for scheduled task creation via schtasks.exe.",
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2020-01-01T00:00:00.000Z",
        "deprecated": False,
        "revoked": False,
        "revoked_by": None,
        "source_url": "https://attack.mitre.org/techniques/T1053/",
        "chunk_id": None,
    }


@pytest.fixture
def sample_subtechnique(sample_technique) -> dict:
    sub = dict(sample_technique)
    sub.update({
        "attack_id": "T1053.005",
        "object_type": "sub-technique",
        "name": "Scheduled Task",
        "is_subtechnique": True,
        "parent_technique_id": "T1053",
        "source_url": "https://attack.mitre.org/techniques/T1053/005/",
    })
    return sub


@pytest.fixture
def sample_mitigation() -> dict:
    return {
        "attack_version": "19.2",
        "stix_id": "course-of-action--0001",
        "attack_id": "M1028",
        "name": "Operating System Configuration",
        "description": "Configure operating systems to prevent abuse.",
        "deprecated": False,
        "revoked": False,
        "mitigated_techniques": ["T1053"],
        "source_url": "https://attack.mitre.org/mitigations/M1028/",
    }


@pytest.fixture
def techniques_json_path(tmp_path, sample_technique, sample_subtechnique):
    revoked = dict(sample_technique)
    revoked.update({
        "attack_id": "T1086",
        "name": "PowerShell (revoked)",
        "revoked": True,
        "revoked_by": {"attack_id": "T1059.001", "name": "PowerShell"},
    })
    techniques = [sample_technique, sample_subtechnique, revoked]
    path = tmp_path / "techniques.json"
    path.write_text(json.dumps(techniques), encoding="utf-8")
    return path


@pytest.fixture
def stix_bundle() -> list[dict]:
    """Kucuk, sentetik bir STIX bundle: 1 teknik + 1 alt teknik + 1 taktik +
    1 mitigation + 1 grup + iliskiler (subtechnique-of, mitigates, uses, detects)."""
    return [
        {
            "type": "x-mitre-tactic",
            "id": "x-mitre-tactic--persistence",
            "x_mitre_shortname": "persistence",
            "name": "Persistence",
            "description": "Persistence tactic.",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "TA0003", "url": "https://attack.mitre.org/tactics/TA0003/"}
            ],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--parent",
            "name": "Scheduled Task/Job",
            "description": "Adversaries may abuse task scheduling functionality.",
            "x_mitre_is_subtechnique": False,
            "x_mitre_platforms": ["Windows"],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "persistence"}],
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1053", "url": "https://attack.mitre.org/techniques/T1053/"}
            ],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--child",
            "name": "Scheduled Task",
            "description": "Adversaries may abuse the Windows Task Scheduler.",
            "x_mitre_is_subtechnique": True,
            "x_mitre_platforms": ["Windows"],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "persistence"}],
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1053.005", "url": "https://attack.mitre.org/techniques/T1053/005/"}
            ],
        },
        {
            "type": "relationship",
            "id": "relationship--1",
            "relationship_type": "subtechnique-of",
            "source_ref": "attack-pattern--child",
            "target_ref": "attack-pattern--parent",
        },
        {
            "type": "course-of-action",
            "id": "course-of-action--1",
            "name": "Operating System Configuration",
            "description": "Configure operating systems to prevent abuse.",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "M1028", "url": "https://attack.mitre.org/mitigations/M1028/"}
            ],
        },
        {
            "type": "relationship",
            "id": "relationship--2",
            "relationship_type": "mitigates",
            "source_ref": "course-of-action--1",
            "target_ref": "attack-pattern--parent",
        },
        {
            "type": "intrusion-set",
            "id": "intrusion-set--1",
            "name": "APT29",
        },
        {
            "type": "relationship",
            "id": "relationship--3",
            "relationship_type": "uses",
            "source_ref": "intrusion-set--1",
            "target_ref": "attack-pattern--parent",
            "description": "APT29 used schtasks for persistence.",
        },
        {
            "type": "x-mitre-data-component",
            "id": "x-mitre-data-component--1",
            "name": "Scheduled Job Creation",
        },
        {
            "type": "x-mitre-analytic",
            "id": "x-mitre-analytic--1",
            "description": "Monitor for scheduled task creation via schtasks.exe.",
            "x_mitre_log_source_references": [
                {"x_mitre_data_component_ref": "x-mitre-data-component--1"}
            ],
        },
        {
            "type": "x-mitre-detection-strategy",
            "id": "x-mitre-detection-strategy--1",
            "x_mitre_analytic_refs": ["x-mitre-analytic--1"],
        },
        {
            "type": "relationship",
            "id": "relationship--4",
            "relationship_type": "detects",
            "source_ref": "x-mitre-detection-strategy--1",
            "target_ref": "attack-pattern--parent",
        },
    ]
