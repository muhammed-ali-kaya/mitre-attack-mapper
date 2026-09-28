"""Enterprise ATT&CK STIX 2.1 bundle'ini yapilandirilmis teknik kayitlarina donusturur.

ATT&CK v19 semasinda `x_mitre_data_sources`, `x_mitre_permissions_required`,
`x_mitre_system_requirements` ve `x_mitre_detection` gibi eski duz alanlar artik
attack-pattern nesnesinde bulunmuyor. Bu bilgiler artik relationship grafigi
uzerinden turetiliyor:

    Teknik --(detects)--> x-mitre-detection-strategy --(x_mitre_analytic_refs)-->
        x-mitre-analytic --(x_mitre_log_source_references)--> x-mitre-data-component

    Teknik --(mitigates, ters yon)--> course-of-action
    Teknik --(uses, ters yon)--> intrusion-set / campaign (grup) veya malware / tool (yazilim)
    Alt teknik --(subtechnique-of)--> ana teknik
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

GROUP_SOURCE_TYPES = {"intrusion-set", "campaign"}
SOFTWARE_SOURCE_TYPES = {"malware", "tool"}


def load_bundle(path: Path) -> list[dict[str, Any]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return data["objects"]


def get_attack_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def get_source_url(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url")
    return None


class AttackIndex:
    """STIX bundle'i bir kere tarayip id/iliski aramalarini O(1) yapan yardimci sinif."""

    def __init__(self, objects: list[dict[str, Any]]):
        self.objects = objects
        self.by_id: dict[str, dict[str, Any]] = {o["id"]: o for o in objects}

        self.tactics_by_shortname: dict[str, dict[str, Any]] = {
            o["x_mitre_shortname"]: o for o in objects if o["type"] == "x-mitre-tactic"
        }

        self.rels_by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.rels_by_target: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for o in objects:
            if o["type"] == "relationship":
                self.rels_by_source[o["source_ref"]].append(o)
                self.rels_by_target[o["target_ref"]].append(o)

        self.analytics_by_id: dict[str, dict[str, Any]] = {
            o["id"]: o for o in objects if o["type"] == "x-mitre-analytic"
        }
        self.data_components_by_id: dict[str, dict[str, Any]] = {
            o["id"]: o for o in objects if o["type"] == "x-mitre-data-component"
        }

    def tactics_for(self, technique: dict[str, Any]) -> list[str]:
        names = []
        for phase in technique.get("kill_chain_phases", []):
            tactic = self.tactics_by_shortname.get(phase["phase_name"])
            if tactic:
                names.append(tactic["name"])
        return names

    def parent_technique_id(self, technique: dict[str, Any]) -> str | None:
        for rel in self.rels_by_source[technique["id"]]:
            if rel["relationship_type"] == "subtechnique-of":
                parent = self.by_id.get(rel["target_ref"])
                if parent:
                    return get_attack_id(parent)
        return None

    def mitigations_for(self, technique: dict[str, Any]) -> list[dict[str, str]]:
        results = []
        for rel in self.rels_by_target[technique["id"]]:
            if rel["relationship_type"] != "mitigates":
                continue
            coa = self.by_id.get(rel["source_ref"])
            if coa is None or coa["type"] != "course-of-action":
                continue
            results.append({"attack_id": get_attack_id(coa), "name": coa["name"]})
        return results

    def procedure_examples_for(
        self, technique: dict[str, Any]
    ) -> tuple[list[dict[str, str]], list[str], list[str]]:
        procedures, groups, software = [], [], []
        for rel in self.rels_by_target[technique["id"]]:
            if rel["relationship_type"] != "uses":
                continue
            source = self.by_id.get(rel["source_ref"])
            if source is None:
                continue
            procedures.append({
                "actor": source["name"],
                "actor_type": source["type"],
                "description": rel.get("description", ""),
            })
            if source["type"] in GROUP_SOURCE_TYPES:
                groups.append(source["name"])
            elif source["type"] in SOFTWARE_SOURCE_TYPES:
                software.append(source["name"])
        return procedures, sorted(set(groups)), sorted(set(software))

    def revoked_by(self, technique: dict[str, Any]) -> dict[str, str] | None:
        for rel in self.rels_by_source[technique["id"]]:
            if rel["relationship_type"] != "revoked-by":
                continue
            replacement = self.by_id.get(rel["target_ref"])
            if replacement:
                return {"attack_id": get_attack_id(replacement), "name": replacement["name"]}
        return None

    def detection_for(
        self, technique: dict[str, Any]
    ) -> tuple[list[str], list[str]]:
        """Teknige bagli detection strategy -> analytic -> data component zincirini cozer.

        Dondurulen: (detection_texts, data_component_names)
        """
        detection_texts = []
        data_components = set()
        for rel in self.rels_by_target[technique["id"]]:
            if rel["relationship_type"] != "detects":
                continue
            strategy = self.by_id.get(rel["source_ref"])
            if strategy is None or strategy["type"] != "x-mitre-detection-strategy":
                continue
            for analytic_ref in strategy.get("x_mitre_analytic_refs", []):
                analytic = self.analytics_by_id.get(analytic_ref)
                if analytic is None:
                    continue
                if analytic.get("description"):
                    detection_texts.append(analytic["description"])
                for log_ref in analytic.get("x_mitre_log_source_references", []):
                    dc_id = log_ref.get("x_mitre_data_component_ref")
                    dc = self.data_components_by_id.get(dc_id)
                    if dc:
                        data_components.add(dc["name"])
                    elif log_ref.get("name"):
                        data_components.add(log_ref["name"])
        return detection_texts, sorted(data_components)


def parse_technique(technique: dict[str, Any], index: AttackIndex, attack_version: str) -> dict[str, Any]:
    procedures, groups, software = index.procedure_examples_for(technique)
    detection_texts, data_components = index.detection_for(technique)

    return {
        "attack_version": attack_version,
        "stix_id": technique["id"],
        "attack_id": get_attack_id(technique),
        "object_type": "sub-technique" if technique.get("x_mitre_is_subtechnique") else "technique",
        "name": technique["name"],
        "description": technique.get("description", ""),
        "is_subtechnique": bool(technique.get("x_mitre_is_subtechnique")),
        "parent_technique_id": index.parent_technique_id(technique) if technique.get("x_mitre_is_subtechnique") else None,
        "tactics": index.tactics_for(technique),
        "platforms": technique.get("x_mitre_platforms", []),
        "data_sources": [],
        "data_components": data_components,
        "mitigations": index.mitigations_for(technique),
        "procedure_examples": procedures,
        "groups": groups,
        "software": software,
        "permissions_required": None,
        "system_requirements": None,
        "detection": "\n".join(detection_texts) if detection_texts else None,
        "created": technique.get("created"),
        "modified": technique.get("modified"),
        "deprecated": bool(technique.get("x_mitre_deprecated")),
        "revoked": bool(technique.get("revoked")),
        "revoked_by": index.revoked_by(technique) if technique.get("revoked") else None,
        "source_url": get_source_url(technique),
        "chunk_id": None,
    }


def parse_all_techniques(objects: list[dict[str, Any]], attack_version: str) -> list[dict[str, Any]]:
    index = AttackIndex(objects)
    techniques = [o for o in objects if o["type"] == "attack-pattern"]
    return [parse_technique(t, index, attack_version) for t in techniques]


def parse_all_tactics(objects: list[dict[str, Any]], attack_version: str) -> list[dict[str, Any]]:
    """Taktikleri ayristirir -- attack_id (TA numarasi) DAHIL.

    attack_id eskiden hic saklanmiyordu: tactics.json'daki her kaydin
    external_id'si dusuyordu, dolayisiyla cikti yalnizca taktik ADINI
    tasiyabiliyordu. Isim tek basina kimlik degil -- v19'da taktikler
    yeniden adlandirildi (Defense Evasion -> Stealth) ve ayrildi
    (Defense Impairment / TA0112 yeni bir taktik). Numarayi saklamak,
    surumler arasi tek sabit referansi elde tutmak demek."""
    return [
        {
            "attack_version": attack_version,
            "attack_id": get_attack_id(o),
            "stix_id": o["id"],
            "shortname": o["x_mitre_shortname"],
            "name": o["name"],
            "description": o.get("description", ""),
            "source_url": get_source_url(o),
        }
        for o in objects
        if o["type"] == "x-mitre-tactic"
    ]


def parse_all_mitigations(objects: list[dict[str, Any]], attack_version: str) -> list[dict[str, Any]]:
    index = AttackIndex(objects)
    mitigations = [o for o in objects if o["type"] == "course-of-action"]
    results = []
    for m in mitigations:
        mitigated_techniques = [
            get_attack_id(index.by_id[rel["target_ref"]])
            for rel in index.rels_by_source[m["id"]]
            if rel["relationship_type"] == "mitigates" and rel["target_ref"] in index.by_id
        ]
        results.append({
            "attack_version": attack_version,
            "stix_id": m["id"],
            "attack_id": get_attack_id(m),
            "name": m["name"],
            "description": m.get("description", ""),
            "deprecated": bool(m.get("x_mitre_deprecated")),
            "revoked": bool(m.get("revoked")),
            "mitigated_techniques": mitigated_techniques,
            "source_url": get_source_url(m),
        })
    return results
