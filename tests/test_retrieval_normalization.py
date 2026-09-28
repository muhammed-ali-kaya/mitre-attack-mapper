"""Reranker skorlarinin sorgu ici normalizasyonu (Gorev 6A).

Neden ayri bir dosya: bu, guven skorunun EN AGIR bileseninin (0.30)
davranisini belirliyor ve bir kez sessizce bozuldu -- ham skor ikinci kez
sigmoid'den geciriliyordu ve bilesen pratikte sabitti."""

from __future__ import annotations

from app.retrieval.improved_pipeline import normalize_support


def test_relative_score_spans_the_full_range_within_a_query():
    out = normalize_support({"T1003.002": 0.047, "T1112": 0.020, "T1552.002": 0.062})

    assert out["T1552.002"]["relative"] == 1.0   # en iyi aday
    assert out["T1112"]["relative"] == 0.0       # en kotu aday
    assert 0.0 < out["T1003.002"]["relative"] < 1.0


def test_absolute_score_is_preserved_untouched():
    """Mutlak deger karar katmani icin saklanir; siralamada kullanilmaz."""
    out = normalize_support({"T1003.002": 0.047, "T1112": 0.020})
    assert out["T1003.002"]["absolute"] == 0.047
    assert out["T1112"]["absolute"] == 0.020


def test_scores_from_different_queries_are_not_comparable_in_absolute_terms():
    """Olculmus gerekce: T3'un en iyi adayi 0.236, T1'inki 0.047 idi. Ikisi de
    kendi sorgusunun EN IYISI -- mutlak buyukluk 'daha guvenilir' demek degil.
    Normalizasyon ikisini de 1.0 yapar, cunku ifade ettikleri sey ayni."""
    t1 = normalize_support({"T1003.002": 0.047, "T1112": 0.020})
    t3 = normalize_support({"T1059.001": 0.236, "T1546.013": 0.206})

    assert t1["T1003.002"]["relative"] == t3["T1059.001"]["relative"] == 1.0
    assert t1["T1003.002"]["absolute"] != t3["T1059.001"]["absolute"]


def test_single_candidate_is_the_best_of_its_query():
    out = normalize_support({"T1053.005": 0.004})
    assert out["T1053.005"]["relative"] == 1.0
    assert out["T1053.005"]["absolute"] == 0.004


def test_identical_scores_do_not_produce_a_division_by_zero():
    out = normalize_support({"T1": 0.1, "T2": 0.1})
    assert out["T1"]["relative"] == out["T2"]["relative"] == 1.0


def test_empty_input_is_handled():
    assert normalize_support({}) == {}
