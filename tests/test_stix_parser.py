from __future__ import annotations

import json

from app.parsers.stix_parser import (
    AttackIndex,
    get_attack_id,
    get_source_url,
    load_bundle,
    parse_all_mitigations,
    parse_all_tactics,
    parse_all_techniques,
    parse_technique,
)

ATTACK_VERSION = "19.2"


def _parent(stix_bundle):
    return next(o for o in stix_bundle if o["id"] == "attack-pattern--parent")


def _child(stix_bundle):
    return next(o for o in stix_bundle if o["id"] == "attack-pattern--child")


def test_get_attack_id_reads_mitre_external_reference(stix_bundle):
    assert get_attack_id(_parent(stix_bundle)) == "T1053"


def test_get_attack_id_returns_none_when_no_mitre_reference():
    assert get_attack_id({"external_references": [{"source_name": "other", "external_id": "X1"}]}) is None


def test_get_source_url_reads_mitre_url(stix_bundle):
    assert get_source_url(_parent(stix_bundle)) == "https://attack.mitre.org/techniques/T1053/"


def test_attack_index_tactics_for(stix_bundle):
    index = AttackIndex(stix_bundle)
    assert index.tactics_for(_parent(stix_bundle)) == ["Persistence"]


def test_attack_index_parent_technique_id_for_subtechnique(stix_bundle):
    index = AttackIndex(stix_bundle)
    assert index.parent_technique_id(_child(stix_bundle)) == "T1053"


def test_attack_index_parent_technique_id_for_top_level_technique_is_none(stix_bundle):
    index = AttackIndex(stix_bundle)
    assert index.parent_technique_id(_parent(stix_bundle)) is None


def test_attack_index_mitigations_for(stix_bundle):
    index = AttackIndex(stix_bundle)
    mitigations = index.mitigations_for(_parent(stix_bundle))
    assert mitigations == [{"attack_id": "M1028", "name": "Operating System Configuration"}]


def test_attack_index_procedure_examples_for(stix_bundle):
    index = AttackIndex(stix_bundle)
    procedures, groups, software = index.procedure_examples_for(_parent(stix_bundle))
    assert procedures == [{"actor": "APT29", "actor_type": "intrusion-set", "description": "APT29 used schtasks for persistence."}]
    assert groups == ["APT29"]
    assert software == []


def test_attack_index_detection_for(stix_bundle):
    index = AttackIndex(stix_bundle)
    detection_texts, data_components = index.detection_for(_parent(stix_bundle))
    assert detection_texts == ["Monitor for scheduled task creation via schtasks.exe."]
    assert data_components == ["Scheduled Job Creation"]


def test_attack_index_revoked_by():
    objects = [
        {
            "type": "attack-pattern",
            "id": "attack-pattern--old",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1086", "url": "https://attack.mitre.org/techniques/T1086/"}],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--new",
            "name": "PowerShell",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1059.001", "url": "https://attack.mitre.org/techniques/T1059/001/"}],
        },
        {
            "type": "relationship",
            "id": "relationship--revoke",
            "relationship_type": "revoked-by",
            "source_ref": "attack-pattern--old",
            "target_ref": "attack-pattern--new",
        },
    ]
    index = AttackIndex(objects)
    old = objects[0]
    assert index.revoked_by(old) == {"attack_id": "T1059.001", "name": "PowerShell"}


def test_parse_technique_parent(stix_bundle):
    index = AttackIndex(stix_bundle)
    result = parse_technique(_parent(stix_bundle), index, ATTACK_VERSION)
    assert result["attack_id"] == "T1053"
    assert result["object_type"] == "technique"
    assert result["is_subtechnique"] is False
    assert result["parent_technique_id"] is None
    assert result["tactics"] == ["Persistence"]
    assert result["mitigations"] == [{"attack_id": "M1028", "name": "Operating System Configuration"}]
    assert result["groups"] == ["APT29"]
    assert result["detection"] == "Monitor for scheduled task creation via schtasks.exe."
    assert result["data_components"] == ["Scheduled Job Creation"]
    assert result["deprecated"] is False
    assert result["revoked"] is False


def test_parse_technique_subtechnique(stix_bundle):
    index = AttackIndex(stix_bundle)
    result = parse_technique(_child(stix_bundle), index, ATTACK_VERSION)
    assert result["attack_id"] == "T1053.005"
    assert result["object_type"] == "sub-technique"
    assert result["is_subtechnique"] is True
    assert result["parent_technique_id"] == "T1053"


def test_parse_all_techniques_returns_both(stix_bundle):
    results = parse_all_techniques(stix_bundle, ATTACK_VERSION)
    ids = {r["attack_id"] for r in results}
    assert ids == {"T1053", "T1053.005"}


def test_parse_all_tactics(stix_bundle):
    results = parse_all_tactics(stix_bundle, ATTACK_VERSION)
    assert len(results) == 1
    assert results[0]["shortname"] == "persistence"
    assert results[0]["name"] == "Persistence"


def test_parse_all_mitigations(stix_bundle):
    results = parse_all_mitigations(stix_bundle, ATTACK_VERSION)
    assert len(results) == 1
    assert results[0]["attack_id"] == "M1028"
    assert results[0]["mitigated_techniques"] == ["T1053"]


def test_load_bundle_reads_objects_from_file(tmp_path, stix_bundle):
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps({"type": "bundle", "objects": stix_bundle}), encoding="utf-8")
    loaded = load_bundle(path)
    assert loaded == stix_bundle
