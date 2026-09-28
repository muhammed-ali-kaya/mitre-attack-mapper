from __future__ import annotations

from datetime import datetime

from app.correlation.dedup import dedupe_techniques, split_by_confidence


def _mapping(attack_id="T1059.001", confidence_score=0.5, evidence=None, **kw) -> dict:
    return {
        "attack_id": attack_id, "name": "PowerShell", "object_type": "sub-technique",
        "tactics": ["Execution"], "confidence_score": confidence_score,
        "evidence": evidence or [], **kw,
    }


def _technique(attack_id="T1059.001", level="high", score=0.8) -> dict:
    return {"attack_id": attack_id, "confidence_level": level, "max_confidence_score": score}


def test_split_by_confidence_keeps_high_and_medium_as_strong():
    strong, weak = split_by_confidence([
        _technique("T1003.001", "high", 0.8),
        _technique("T1059.001", "medium", 0.6),
        _technique("T1220", "low", 0.25),
        _technique("T1137.002", "insufficient", 0.1),
    ])
    assert [t["attack_id"] for t in strong] == ["T1003.001", "T1059.001"]
    assert [t["attack_id"] for t in weak] == ["T1220", "T1137.002"]


def test_split_by_confidence_loses_nothing():
    techniques = [_technique(f"T10{i}", "low" if i % 2 else "high") for i in range(6)]
    strong, weak = split_by_confidence(techniques)
    assert len(strong) + len(weak) == len(techniques)


def test_split_by_confidence_falls_back_to_score_when_level_missing():
    """Eski kayitli sonuc dosyalarinda confidence_level alani yok."""
    strong, weak = split_by_confidence([
        {"attack_id": "T1003.001", "max_confidence_score": 0.8},
        {"attack_id": "T1220", "max_confidence_score": 0.25},
    ])
    assert [t["attack_id"] for t in strong] == ["T1003.001"]
    assert [t["attack_id"] for t in weak] == ["T1220"]


def test_dedupe_carries_confidence_level_from_representative():
    entries = [
        {"row_index": 0, "timestamp": None,
         "mapping": _mapping(confidence_score=0.3, confidence_level="low")},
        {"row_index": 1, "timestamp": None,
         "mapping": _mapping(confidence_score=0.8, confidence_level="high")},
    ]
    deduped = dedupe_techniques(entries)
    # Ayni teknik bir satirda zayif, digerinde guclu goruldu -- guclu kazanir.
    assert deduped[0]["confidence_level"] == "high"


def test_counts_occurrences_across_rows():
    entries = [
        {"row_index": 0, "timestamp": None, "mapping": _mapping()},
        {"row_index": 1, "timestamp": None, "mapping": _mapping()},
        {"row_index": 2, "timestamp": None, "mapping": _mapping()},
    ]
    deduped = dedupe_techniques(entries)
    assert len(deduped) == 1
    assert deduped[0]["occurrence_count"] == 3
    assert deduped[0]["source_row_indices"] == [0, 1, 2]


def test_separates_distinct_attack_ids():
    entries = [
        {"row_index": 0, "timestamp": None, "mapping": _mapping(attack_id="T1059.001")},
        {"row_index": 1, "timestamp": None, "mapping": _mapping(attack_id="T1547.001")},
    ]
    deduped = dedupe_techniques(entries)
    ids = {d["attack_id"] for d in deduped}
    assert ids == {"T1059.001", "T1547.001"}


def test_evidence_deduplicated_and_capped_at_five():
    entries = [
        {"row_index": i, "timestamp": None, "mapping": _mapping(evidence=[f"ev-{i}"])}
        for i in range(7)
    ]
    deduped = dedupe_techniques(entries)
    assert len(deduped[0]["evidence"]) == 5


def test_representative_mapping_has_highest_confidence():
    low = _mapping(confidence_score=0.2)
    high = _mapping(confidence_score=0.9)
    entries = [
        {"row_index": 0, "timestamp": None, "mapping": low},
        {"row_index": 1, "timestamp": None, "mapping": high},
    ]
    deduped = dedupe_techniques(entries)
    assert deduped[0]["max_confidence_score"] == 0.9
    assert deduped[0]["representative_mapping"] is high


def test_first_seen_timestamp_is_earliest_across_occurrences():
    t_early = datetime(2026, 8, 6, 9, 0, 0)
    t_late = datetime(2026, 8, 6, 10, 0, 0)
    entries = [
        {"row_index": 0, "timestamp": t_late, "mapping": _mapping()},
        {"row_index": 1, "timestamp": t_early, "mapping": _mapping()},
    ]
    deduped = dedupe_techniques(entries)
    assert deduped[0]["first_seen_timestamp"] == t_early
