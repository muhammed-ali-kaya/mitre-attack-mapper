from __future__ import annotations

from app.ingestion.chunking import (
    chunk_detection_guidance,
    chunk_mitigation,
    chunk_procedure_examples,
    chunk_technique_content_type,
    chunk_technique_description,
    chunk_technique_naive,
    estimate_tokens,
)


def test_estimate_tokens_scales_with_word_count():
    assert estimate_tokens("one two three") == 4  # round(3 * 1.3) = 4


def test_estimate_tokens_never_returns_zero_for_empty_text():
    assert estimate_tokens("") == 1


def test_chunk_technique_description_uses_technique_content_type(sample_technique):
    chunk = chunk_technique_description(sample_technique)
    assert chunk["content_type"] == "technique_description"
    assert chunk["chunk_id"] == "T1053::technique_description::0"
    assert "[T1053] Scheduled Task/Job" in chunk["text"]
    assert sample_technique["description"] in chunk["text"]
    assert chunk["metadata"]["name"] == "Scheduled Task/Job"


def test_chunk_technique_description_uses_subtechnique_content_type(sample_subtechnique):
    chunk = chunk_technique_description(sample_subtechnique)
    assert chunk["content_type"] == "subtechnique_description"
    assert chunk["metadata"]["is_subtechnique"] is True
    assert chunk["metadata"]["parent_technique_id"] == "T1053"


def test_chunk_procedure_examples_empty_list_returns_empty(sample_technique):
    technique = dict(sample_technique, procedure_examples=[])
    assert chunk_procedure_examples(technique) == []


def test_chunk_procedure_examples_splits_into_multiple_buckets_when_over_budget(sample_technique):
    long_description = " ".join(["word"] * 150)  # -> ~199 tokens per formatted line
    examples = [
        {"actor": f"Actor{i}", "actor_type": "intrusion-set", "description": long_description}
        for i in range(3)
    ]
    technique = dict(sample_technique, tactics=[], platforms=[], attack_id="T0001", name="X", procedure_examples=examples)

    chunks = chunk_procedure_examples(technique)

    assert len(chunks) == 2
    assert "Actor0" in chunks[0]["text"] and "Actor1" in chunks[0]["text"]
    assert "Actor2" not in chunks[0]["text"]
    assert "Actor2" in chunks[1]["text"]
    assert chunks[0]["chunk_id"] == "T0001::procedure_example::0"
    assert chunks[1]["chunk_id"] == "T0001::procedure_example::1"


def test_chunk_detection_guidance_returns_none_without_detection(sample_technique):
    technique = dict(sample_technique, detection=None)
    assert chunk_detection_guidance(technique) is None


def test_chunk_detection_guidance_includes_detection_text_and_data_components(sample_technique):
    chunk = chunk_detection_guidance(sample_technique)
    assert chunk is not None
    assert chunk["content_type"] == "detection_guidance"
    assert sample_technique["detection"] in chunk["text"]
    assert "Scheduled Job Creation" in chunk["text"]


def test_chunk_technique_content_type_combines_description_examples_and_detection(sample_technique):
    chunks = chunk_technique_content_type(sample_technique)
    content_types = [c["content_type"] for c in chunks]
    assert content_types == ["technique_description", "procedure_example", "detection_guidance"]


def test_chunk_technique_content_type_omits_detection_when_absent(sample_technique):
    technique = dict(sample_technique, detection=None)
    chunks = chunk_technique_content_type(technique)
    assert "detection_guidance" not in [c["content_type"] for c in chunks]


def test_chunk_mitigation_includes_related_techniques(sample_mitigation):
    chunk = chunk_mitigation(sample_mitigation)
    assert chunk["chunk_id"] == "M1028::mitigation::0"
    assert chunk["content_type"] == "mitigation"
    assert "(mitigation)" in chunk["text"]
    assert "T1053" in chunk["text"]


def test_chunk_mitigation_shows_dash_when_no_related_techniques(sample_mitigation):
    mitigation = dict(sample_mitigation, mitigated_techniques=[])
    chunk = chunk_mitigation(mitigation)
    assert "Ilgili Teknikler: -" in chunk["text"]


def test_chunk_technique_naive_includes_all_optional_sections_when_present(sample_technique):
    chunk = chunk_technique_naive(sample_technique)
    assert chunk["content_type"] == "naive_full"
    assert chunk["chunk_id"] == "T1053::naive::0"
    assert "Mitigations:" in chunk["text"]
    assert "Prosedur Ornekleri:" in chunk["text"]
    assert "Tespit:" in chunk["text"]


def test_chunk_technique_naive_omits_optional_sections_when_empty(sample_technique):
    technique = dict(sample_technique, mitigations=[], procedure_examples=[], detection=None)
    chunk = chunk_technique_naive(technique)
    assert "Mitigations:" not in chunk["text"]
    assert "Prosedur Ornekleri:" not in chunk["text"]
    assert "Tespit:" not in chunk["text"]


def test_chunk_technique_naive_limits_procedure_examples_to_three(sample_technique):
    examples = [
        {"actor": f"Actor{i}", "actor_type": "intrusion-set", "description": "did something"}
        for i in range(5)
    ]
    technique = dict(sample_technique, procedure_examples=examples)
    chunk = chunk_technique_naive(technique)
    assert "Actor2" in chunk["text"]
    assert "Actor3" not in chunk["text"]
    assert "Actor4" not in chunk["text"]
