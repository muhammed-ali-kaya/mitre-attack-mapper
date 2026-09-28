from __future__ import annotations

import pytest

from app.evaluation.metrics import (
    hallucination_rate,
    hierarchical_score,
    is_correct_abstention,
    retrieval_recall_at_k,
)

KB_BY_ID = {
    "T1053": {"parent_technique_id": None, "tactics": ["Persistence"]},
    "T1053.005": {"parent_technique_id": "T1053", "tactics": ["Persistence"]},
    "T1053.002": {"parent_technique_id": "T1053", "tactics": ["Persistence"]},
    "T1059": {"parent_technique_id": None, "tactics": ["Persistence"]},
    "T1027": {"parent_technique_id": None, "tactics": ["Defense Evasion"]},
}


@pytest.fixture
def scenario():
    return {
        "expected_attack_ids": ["T1053.005"],
        "acceptable_alternatives": ["T1053.002"],
        "expected_tactics": ["Persistence"],
    }


def test_hierarchical_score_exact_match_is_1(scenario):
    assert hierarchical_score(["T1053.005"], scenario, KB_BY_ID) == 1.0


def test_hierarchical_score_acceptable_alternative_is_0_7(scenario):
    assert hierarchical_score(["T1053.002"], scenario, KB_BY_ID) == 0.7


def test_hierarchical_score_correct_parent_without_subtechnique_is_0_5(scenario):
    assert hierarchical_score(["T1053"], scenario, KB_BY_ID) == 0.5


def test_hierarchical_score_same_tactic_wrong_technique_is_0_1(scenario):
    assert hierarchical_score(["T1059"], scenario, KB_BY_ID) == 0.1


def test_hierarchical_score_irrelevant_prediction_is_0(scenario):
    assert hierarchical_score(["T1027"], scenario, KB_BY_ID) == 0.0


def test_hierarchical_score_takes_best_among_predictions(scenario):
    assert hierarchical_score(["T1027", "T1053.005"], scenario, KB_BY_ID) == 1.0


def test_hierarchical_score_negative_example_with_no_prediction_is_1():
    scenario = {"expected_attack_ids": [], "acceptable_alternatives": []}
    assert hierarchical_score([], scenario, KB_BY_ID) == 1.0


def test_hierarchical_score_negative_example_with_a_prediction_is_0():
    scenario = {"expected_attack_ids": [], "acceptable_alternatives": []}
    assert hierarchical_score(["T1053.005"], scenario, KB_BY_ID) == 0.0


def test_is_correct_abstention_negative_case_with_no_confident_mapping_is_true():
    scenario = {"negative_case": True}
    mappings = [{"attack_id": "T1053.005", "confidence_level": "low"}]
    assert is_correct_abstention(mappings, scenario) is True


def test_is_correct_abstention_negative_case_with_confident_mapping_is_false():
    scenario = {"negative_case": True}
    mappings = [{"attack_id": "T1053.005", "confidence_level": "high"}]
    assert is_correct_abstention(mappings, scenario) is False


def test_is_correct_abstention_not_applicable_returns_none(scenario):
    scenario = dict(scenario, expected_level="high")
    assert is_correct_abstention([], scenario) is None


def test_is_correct_abstention_insufficient_high_confidence_within_allowed_is_true(scenario):
    scenario = dict(scenario, expected_level="insufficient")
    mappings = [{"attack_id": "T1053.005", "confidence_level": "high"}]
    assert is_correct_abstention(mappings, scenario) is True


def test_is_correct_abstention_insufficient_high_confidence_outside_allowed_is_false(scenario):
    scenario = dict(scenario, expected_level="insufficient")
    mappings = [{"attack_id": "T1027", "confidence_level": "high"}]
    assert is_correct_abstention(mappings, scenario) is False


def test_retrieval_recall_at_k_hit_within_k(scenario):
    retrieved = ["T1027", "T1053.005", "T1059"]
    assert retrieval_recall_at_k(retrieved, scenario, k=2) == 1.0


def test_retrieval_recall_at_k_miss_outside_k(scenario):
    retrieved = ["T1027", "T1059", "T1053.005"]
    assert retrieval_recall_at_k(retrieved, scenario, k=2) == 0.0


def test_retrieval_recall_at_k_no_expected_returns_none():
    scenario = {"expected_attack_ids": [], "acceptable_alternatives": []}
    assert retrieval_recall_at_k(["T1053.005"], scenario, k=5) is None


def test_retrieval_recall_at_k_deduplicates_so_repeats_dont_fill_the_window(scenario):
    # Repeated "T1027" entries don't count as separate slots, so the scan keeps
    # going until it collects k *unique* ids -- T1053.005 is the 2nd unique id here.
    retrieved = ["T1027", "T1027", "T1027", "T1053.005"]
    assert retrieval_recall_at_k(retrieved, scenario, k=1) == 0.0
    assert retrieval_recall_at_k(retrieved, scenario, k=2) == 1.0


def test_hallucination_rate_empty_mappings_is_0():
    assert hallucination_rate([], KB_BY_ID) == 0.0


def test_hallucination_rate_all_valid_is_0():
    mappings = [{"attack_id": "T1053"}, {"attack_id": "T1053.005"}]
    assert hallucination_rate(mappings, KB_BY_ID) == 0.0


def test_hallucination_rate_computes_ratio_of_unknown_ids():
    mappings = [{"attack_id": "T1053"}, {"attack_id": "T9999"}, {"attack_id": "T8888"}]
    assert hallucination_rate(mappings, KB_BY_ID) == pytest.approx(2 / 3)


# -- informational_only isareti alarm sayilmaz --------------------------------

def test_informational_mappings_do_not_count_as_false_positive():
    """karar katmani 'bilgi amacli' diye ayirdiysa alarm uretilmemis
    demektir; olcut alarm sonucunu olcmeli."""
    scenario = {"negative_case": True, "expected_level": "insufficient",
                "expected_attack_ids": [], "acceptable_alternatives": []}
    mappings = [{"attack_id": "T1053.005", "confidence_level": "high", "informational_only": True}]

    assert is_correct_abstention(mappings, scenario) is True


def test_alerting_mapping_on_benign_input_is_still_a_failure():
    scenario = {"negative_case": True, "expected_level": "insufficient",
                "expected_attack_ids": [], "acceptable_alternatives": []}
    mappings = [{"attack_id": "T1053.005", "confidence_level": "high"}]

    assert is_correct_abstention(mappings, scenario) is False


def test_informational_flag_also_applies_to_insufficient_level_scenarios():
    scenario = {"negative_case": False, "expected_level": "insufficient",
                "expected_attack_ids": ["T1110"], "acceptable_alternatives": []}
    mappings = [{"attack_id": "T1620", "confidence_level": "high", "informational_only": True}]

    assert is_correct_abstention(mappings, scenario) is True
