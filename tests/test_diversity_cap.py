"""Aday havuzu cesitlilik siniri (2C).

Kilitlenen sey: tek bir teknigin chunk'lari havuzu doldurup reranker'in
top-10'unu ele gecirmesin. Olculen patoloji -- T3'te LLM'e giden 10 chunk'in
7'si T1059.001'in prosedur ornekleriydi ve baglamda dogru cevabi tarif eden
hicbir metin yoktu."""

from __future__ import annotations

import pytest

from app.retrieval.improved_pipeline import (
    MAX_CHUNKS_PER_TECHNIQUE,
    cap_per_technique,
)


def _chunk(attack_id: str, i: int = 0) -> dict:
    return {"attack_id": attack_id, "chunk_id": f"{attack_id}::c::{i}"}


def _pool(*spec: tuple[str, int]) -> list[dict]:
    """('T1059.001', 7) -> o teknikten 7 chunk, verilen sirada."""
    out = []
    for attack_id, count in spec:
        out.extend(_chunk(attack_id, i) for i in range(count))
    return out


def test_cap_limits_chunks_per_technique():
    capped = cap_per_technique(_pool(("T1059.001", 7), ("T1685", 1)), 2)
    ids = [c["attack_id"] for c in capped]

    assert ids.count("T1059.001") == 2
    assert ids.count("T1685") == 1


def test_cap_preserves_order():
    """Sinir SIRALAMAYI degistirmez -- yalnizca fazlalik chunk'lari atar.
    Siralamayi da degistirseydi RRF'in isini bozardi."""
    pool = [_chunk("A", 0), _chunk("B", 0), _chunk("A", 1), _chunk("C", 0), _chunk("A", 2)]
    capped = cap_per_technique(pool, 2)

    assert [c["chunk_id"] for c in capped] == ["A::c::0", "B::c::0", "A::c::1", "C::c::0"]


def test_cap_keeps_the_highest_ranked_chunks_of_a_technique():
    """Atilanlar SONDAKILER olmali: RRF sirasi alaka sirasidir."""
    capped = cap_per_technique(_pool(("A", 5)), 2)
    assert [c["chunk_id"] for c in capped] == ["A::c::0", "A::c::1"]


def test_no_cap_returns_the_pool_untouched():
    pool = _pool(("A", 5), ("B", 3))
    assert cap_per_technique(pool, None) is pool
    assert cap_per_technique(pool, 0) is pool


def test_cap_does_not_add_techniques():
    """Sinir yeni teknik EKLEYEMEZ -- yalnizca mevcut havuzu yeniden dagitir.

    Olculmus sonucu: T3'te havuzdaki benzersiz teknik sayisi uc kolda da 12
    kaldi; degisen sey reranker top-10'unun 4'ten 8'e cikmasiydi. Bu yuzden
    hicbir sinir, retrieval'in HIC getirmedigi bir teknigi (T1685, semantic
    117. sira) yukari cekemez -- o is artefakt cikarimina ait."""
    pool = _pool(("A", 5), ("B", 3))
    capped = cap_per_technique(pool, 2)

    assert {c["attack_id"] for c in capped} <= {c["attack_id"] for c in pool}


def test_cap_shortens_the_pool_and_does_not_backfill():
    """BILINEN SINIR: liste kisalir, yerine yeni aday cekilmez.

    Olculdu: T3'te havuz 20 -> 14. Reranker yine 10 aliyor (14 >= 10), o
    yuzden bu asamada kayip yok; ama gercek telafi SEMANTIC_CANDIDATES'i
    buyutup sonra sinirlamak olurdu. Bu test o davranisi BELGELER, dogru
    kabul etmez -- degistirilirse bilincli degistirilsin."""
    pool = _pool(("A", 8), ("B", 2))
    assert len(pool) == 10
    assert len(cap_per_technique(pool, 2)) == 4


def test_default_is_a_cap_not_unlimited():
    """None birakmak, olculen tek patolojik davranisi varsayilan tutmak
    olurdu: sinirsiz kol T3'te cokuyor (4 benzersiz), sinirli kollar
    cokmuyor (8/7), diger uc logda uc kol birebir ayni."""
    assert MAX_CHUNKS_PER_TECHNIQUE == 2


@pytest.mark.parametrize("limit", [1, 2, 3])
def test_cap_never_exceeds_its_limit(limit):
    capped = cap_per_technique(_pool(("A", 9), ("B", 9), ("C", 2)), limit)
    counts: dict[str, int] = {}
    for chunk in capped:
        counts[chunk["attack_id"]] = counts.get(chunk["attack_id"], 0) + 1

    assert all(n <= limit for n in counts.values())
