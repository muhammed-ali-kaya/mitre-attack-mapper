from __future__ import annotations

from app.llm.prompts import (
    CHUNK_CHAR_LIMIT,
    CONTEXT_CHAR_BUDGET,
    build_context,
)


def make_chunk(attack_id: str, text: str, content_type: str = "technique_description") -> dict:
    return {
        "chunk_id": f"{attack_id}::{content_type}::0",
        "attack_id": attack_id,
        "content_type": content_type,
        "text": text,
        "metadata": {
            "attack_id": attack_id,
            "name": f"Teknik {attack_id}",
            "object_type": "technique",
            "source_url": f"https://attack.mitre.org/techniques/{attack_id}/",
        },
    }


def test_long_chunk_text_is_truncated():
    context = build_context([make_chunk("T1001", "A" * (CHUNK_CHAR_LIMIT + 500))])
    assert "[...]" in context
    assert "A" * (CHUNK_CHAR_LIMIT + 1) not in context


def test_short_chunk_text_is_left_alone():
    context = build_context([make_chunk("T1001", "kisa aciklama")])
    assert "kisa aciklama" in context
    assert "[...]" not in context


def test_context_stays_within_budget_and_drops_tail_candidates():
    # Her biri butcenin ucte biri kadar: 10 adayin hepsi sigmamali.
    chunks = [make_chunk(f"T10{i:02d}", "B" * (CONTEXT_CHAR_BUDGET // 3)) for i in range(10)]
    context = build_context(chunks)

    assert len(context) <= CONTEXT_CHAR_BUDGET + CHUNK_CHAR_LIMIT
    # Adaylar alaka sirasinda geldigi icin bastakiler korunmali, kuyruk dusmeli.
    assert "T1000" in context
    assert "T1009" not in context


def test_first_candidate_survives_even_when_it_alone_exceeds_budget():
    """Baglamsiz prompt gondermektense kirpilmis baglam gondermek yeglenir.

    Tek chunk butceyi asamaz (CHUNK_CHAR_LIMIT kirpiyor); asabilmesi icin ayni
    attack_id'ye ait cok sayida chunk'in tek adayda gruplanmasi gerekir."""
    n = (CONTEXT_CHAR_BUDGET // CHUNK_CHAR_LIMIT) + 2
    chunks = [make_chunk("T1001", "C" * CHUNK_CHAR_LIMIT, f"content_type_{i}") for i in range(n)]
    chunks.append(make_chunk("T1002", "D" * 100))

    context = build_context(chunks)
    assert "T1001" in context
    assert len(context) > CONTEXT_CHAR_BUDGET  # ilk aday butceye ragmen korundu
    assert "T1002" not in context


def test_budget_can_be_disabled():
    chunks = [make_chunk(f"T10{i:02d}", "E" * (CONTEXT_CHAR_BUDGET // 3)) for i in range(10)]
    context = build_context(chunks, char_budget=None)
    assert "T1009" in context


def test_chunks_sharing_an_attack_id_are_grouped_into_one_candidate():
    chunks = [
        make_chunk("T1001", "aciklama metni", "technique_description"),
        make_chunk("T1001", "tespit metni", "detection_guidance"),
        make_chunk("T1002", "baska teknik", "technique_description"),
    ]
    context = build_context(chunks)
    assert context.count("[ADAY ") == 2
    assert "aciklama metni" in context
    assert "tespit metni" in context
