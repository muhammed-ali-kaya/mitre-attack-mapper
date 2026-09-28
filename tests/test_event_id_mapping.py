from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.validation.event_id_mapping import (
    EVENT_ID_DATA_COMPONENTS,
    data_components_for_event_id,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TECHNIQUES_FILE = PROJECT_ROOT / "data" / "processed" / "techniques.json"


def _known_data_components() -> set[str]:
    techniques = json.loads(TECHNIQUES_FILE.read_text(encoding="utf-8"))
    return {dc for t in techniques for dc in (t.get("data_components") or [])}


@pytest.mark.skipif(not TECHNIQUES_FILE.exists(), reason="ATT&CK verisi kurulmamis")
def test_every_mapped_component_name_exists_in_the_knowledge_base():
    """Yazim hatasi bu tabloda sessizce 'hicbir zaman eslesmez'e donusur --
    bilesen hep None doner ve bunu fark etmek zordur. Tablo gercek veriye
    karsi dogrulanmali."""
    known = _known_data_components()
    used = {c for components in EVENT_ID_DATA_COMPONENTS.values() for c in components}

    unknown = used - known
    assert not unknown, f"KB'de olmayan veri bileseni adlari: {sorted(unknown)}"


def test_process_creation_event_ids_map_to_process_creation():
    for event_id in ("4688", "1"):
        assert "Process Creation" in data_components_for_event_id(event_id)


def test_overlapping_channel_ids_merge_both_sources():
    """1, 3, 10 gibi numaralar hem Sysmon hem Security'de var; girdide kanal
    genelde yazmadigi icin ikisinin birlesimi kullaniliyor."""
    assert data_components_for_event_id("1") >= {"Process Creation", "Command Execution"}


def test_service_install_event_ids_agree():
    assert data_components_for_event_id("7045") == data_components_for_event_id("4697")


def test_unknown_event_id_returns_empty_set_not_none():
    assert data_components_for_event_id("99999") == set()


def test_missing_event_id_is_handled():
    assert data_components_for_event_id(None) == set()
    assert data_components_for_event_id("") == set()


def test_whitespace_and_numeric_input_are_normalised():
    assert data_components_for_event_id(" 4688 ") == data_components_for_event_id("4688")
    assert data_components_for_event_id(4688) == data_components_for_event_id("4688")


# -- confidence entegrasyonu --------------------------------------------------

def _confidence(event_id, data_components, detection=""):
    from app.validation.confidence import compute_confidence

    mapping = {"evidence": [], "retrieval_support_score": 0.0}
    technique = {"detection": detection, "data_components": data_components, "platforms": []}
    normalized = {"event_id": event_id, "extracted_facts": {}, "platform": None}
    return compute_confidence(mapping, technique, normalized, "girdi")["components"]["event_id_relevance"]


def test_relevance_is_one_when_event_type_matches_technique_telemetry():
    assert _confidence("4688", ["Process Creation", "Command Execution"]) == 1.0


def test_relevance_is_zero_when_event_type_does_not_match():
    """4688 surec olusturma log'u; ag trafigiyle tespit edilen bir teknige
    eslesmesi sorgulanmali."""
    assert _confidence("4688", ["Network Traffic Content"]) == 0.0


def test_relevance_is_none_without_event_id():
    assert _confidence(None, ["Process Creation"]) is None


def test_relevance_is_none_when_technique_has_no_data_components():
    """Sinyal yok demek, uyusmuyor demek degil -- None ortalamadan cikarilir."""
    assert _confidence("4688", []) is None


def test_relevance_is_none_for_unknown_event_id():
    assert _confidence("99999", ["Process Creation"]) is None


def test_detection_text_event_id_takes_precedence():
    """Detection metninde EventID acikca geciyorsa en dogrudan kanit odur."""
    assert _confidence("4625", ["Network Traffic Content"],
                       detection="Monitor for Event ID 4625 failures") == 1.0
