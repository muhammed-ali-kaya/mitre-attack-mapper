from __future__ import annotations

from app.validation.confidence import compute_confidence


def _technique(**overrides):
    base = {
        "attack_id": "T1053",
        "platforms": ["Windows", "Linux"],
        "detection": "Monitor for scheduled task creation via schtasks.exe.",
    }
    base.update(overrides)
    return base


def _mapping(**overrides):
    base = {
        "attack_id": "T1053",
        "evidence": ["schtasks.exe calistirildi"],
        # Guven hesabina giren skor SORGU ICI normalize edilmis olandir
        # (bkz. improved_pipeline.normalize_support). retrieval_support_score
        # ham deger olarak tasinir ama hesaba girmez.
        "retrieval_support_score": 0.12,
        "retrieval_rank_score": 1.0,
        "evidence_check": {"applicable": False},
    }
    base.update(overrides)
    return base


# -- component exclusion (None handling) ----------------------------------------

def test_field_match_is_none_when_no_extracted_facts():
    normalized = {"extracted_facts": {}, "platform": None, "event_id": None}
    result = compute_confidence(_mapping(), _technique(), normalized, "schtasks.exe calistirildi")
    assert result["components"]["field_match"] is None


def test_event_id_relevance_is_none_when_technique_detection_has_no_event_id():
    normalized = {"extracted_facts": {}, "platform": None, "event_id": "4688"}
    result = compute_confidence(_mapping(), _technique(), normalized, "EventID=4688")
    assert result["components"]["event_id_relevance"] is None


def test_platform_match_is_none_when_no_platform_detected():
    normalized = {"extracted_facts": {}, "platform": None, "event_id": None}
    result = compute_confidence(_mapping(), _technique(), normalized, "schtasks.exe calistirildi")
    assert result["components"]["platform_match"] is None


def test_platform_match_true_when_platform_in_technique_platforms():
    normalized = {"extracted_facts": {}, "platform": "Windows", "event_id": None}
    result = compute_confidence(_mapping(), _technique(), normalized, "schtasks.exe calistirildi")
    assert result["components"]["platform_match"] == 1.0


def test_platform_match_false_when_platform_not_in_technique_platforms():
    normalized = {"extracted_facts": {}, "platform": "macOS", "event_id": None}
    result = compute_confidence(_mapping(), _technique(), normalized, "schtasks.exe calistirildi")
    assert result["components"]["platform_match"] == 0.0


def test_event_id_relevance_matches_technique_detection_text():
    technique = _technique(detection="Series of failures (Event ID 4625) targeting accounts.")
    normalized = {"extracted_facts": {}, "platform": None, "event_id": "4625"}
    result = compute_confidence(_mapping(), technique, normalized, "EventID=4625")
    assert result["components"]["event_id_relevance"] == 1.0


def test_event_id_relevance_mismatch_scores_zero():
    technique = _technique(detection="Series of failures (Event ID 4625) targeting accounts.")
    normalized = {"extracted_facts": {}, "platform": None, "event_id": "4688"}
    result = compute_confidence(_mapping(), technique, normalized, "EventID=4688")
    assert result["components"]["event_id_relevance"] == 0.0


# -- ungrounded mapping -----------------------------------------------------------

def test_retrieval_similarity_is_zero_when_ungrounded():
    mapping = _mapping(retrieval_support_score=None, retrieval_rank_score=None)
    normalized = {"extracted_facts": {}, "platform": None, "event_id": None}
    result = compute_confidence(mapping, _technique(), normalized, "schtasks.exe calistirildi")
    assert result["components"]["retrieval_similarity"] == 0.0


def test_raw_reranker_score_does_not_reach_the_confidence_score():
    """REGRESYON: ham skor guven hesabina GIRMEZ.

    Ham cross-encoder ciktisi sorgular arasi karsilastirilamaz. Once ona
    sigmoid uygulaniyordu; cross-encoder zaten sigmoid'lidir, ikinci sigmoid
    (0, 0.24] araligini 0.500-0.559'a eziyor ve bilesen sabitleniyordu."""
    low_raw = compute_confidence(
        _mapping(retrieval_support_score=0.001, retrieval_rank_score=1.0),
        _technique(), {"extracted_facts": {}, "platform": None, "event_id": None},
        "schtasks.exe calistirildi",
    )
    high_raw = compute_confidence(
        _mapping(retrieval_support_score=0.240, retrieval_rank_score=1.0),
        _technique(), {"extracted_facts": {}, "platform": None, "event_id": None},
        "schtasks.exe calistirildi",
    )
    assert low_raw["components"]["retrieval_similarity"] == 1.0
    assert high_raw["components"]["retrieval_similarity"] == 1.0
    assert low_raw["score"] == high_raw["score"]


def test_retrieval_component_actually_varies_between_candidates():
    """Bilesenin siralamaya bilgi katmasi icin adaylar arasinda DEGISMESI
    gerekir. Eski halinde 0.500 ile 0.559 arasinda kaliyordu."""
    best = compute_confidence(
        _mapping(retrieval_rank_score=1.0), _technique(),
        {"extracted_facts": {}, "platform": None, "event_id": None}, "schtasks.exe calistirildi",
    )
    worst = compute_confidence(
        _mapping(retrieval_rank_score=0.0), _technique(),
        {"extracted_facts": {}, "platform": None, "event_id": None}, "schtasks.exe calistirildi",
    )
    assert best["components"]["retrieval_similarity"] - worst["components"]["retrieval_similarity"] == 1.0
    assert best["score"] > worst["score"]


# -- evidence coverage blends required-artifact match ------------------------------

def test_evidence_coverage_blends_required_ratio_when_applicable():
    mapping = _mapping(evidence_check={"applicable": True, "found": ["wmic.exe"], "missing": ["WMI"]})
    normalized = {"extracted_facts": {}, "platform": None, "event_id": None}
    result = compute_confidence(mapping, _technique(), normalized, "schtasks.exe calistirildi")
    # quoted_ratio=1.0 (single evidence item quoted from raw_input), required_ratio=0.5 -> blend 0.75
    assert result["components"]["evidence_coverage"] == 0.75


# -- bucket boundaries --------------------------------------------------------------

def test_confidence_level_high_at_or_above_0_75():
    mapping = _mapping(retrieval_rank_score=1.0)  # sorgunun en iyi adayi
    normalized = {"extracted_facts": {}, "platform": None, "event_id": None}
    result = compute_confidence(mapping, _technique(), normalized, "schtasks.exe calistirildi")
    assert result["score"] >= 0.75
    assert result["level"] == "high"


def test_confidence_level_insufficient_when_all_signals_absent():
    mapping = _mapping(retrieval_support_score=None, retrieval_rank_score=None, evidence=[])
    normalized = {"extracted_facts": {}, "platform": None, "event_id": None}
    result = compute_confidence(mapping, _technique(), normalized, "unrelated text")
    assert result["score"] < 0.25
    assert result["level"] == "insufficient"
