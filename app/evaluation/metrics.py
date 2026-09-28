"""Degerlendirme metrikleri (dokuman bolum 32)."""

from __future__ import annotations

from typing import Any


def hierarchical_score(predicted_ids: list[str], scenario: dict[str, Any], kb_by_id: dict[str, Any]) -> float:
    """Bolum 32.3: tam dogru alt teknik=1.0, dogru ana teknik (alt teknik eksik)=0.5,
    ayni taktik ama yanlis teknik=0.1, ilgisiz=0.0. Kabul edilebilir alternatif=0.7."""
    expected = set(scenario["expected_attack_ids"])
    alternatives = set(scenario["acceptable_alternatives"])
    if not expected:
        return 1.0 if not predicted_ids else 0.0

    expected_parents = {kb_by_id[e]["parent_technique_id"] for e in expected if e in kb_by_id and kb_by_id[e].get("parent_technique_id")}
    expected_tactics = set(scenario.get("expected_tactics", []))

    best = 0.0
    for pid in predicted_ids:
        if pid in expected:
            best = max(best, 1.0)
        elif pid in alternatives:
            best = max(best, 0.7)
        elif pid in expected_parents:
            best = max(best, 0.5)
        elif pid in kb_by_id and expected_tactics & set(kb_by_id[pid].get("tactics", [])):
            best = max(best, 0.1)
    return best


def is_correct_abstention(predicted_mappings: list[dict[str, Any]], scenario: dict[str, Any]) -> bool | None:
    """Belirsiz/negatif senaryolarda sistem asiri ozguvenli davranmamis mi?
    Uygulanamayan (normal) senaryolarda None doner.

    negative_case=True (mesru/benign aktivite): amac, ID dogrulugu degil -- sistemin
    meshru bir aktiviteye YUKSEK/ORTA guvenle saldiri etiketi yapistirmamasi. Bu yuzden
    acceptable_alternatives'e bakilmaksizin herhangi bir high/medium confidence mapping
    basarisizlik sayilir (yuzeysel olarak teknige uysa bile).

    expected_level='insufficient' (belirsiz ama negatif degil): sistem 'high' guvenle
    kesinlik iddia etmemeli, ama beklenen/alternatif bir ID'ye dusuk/orta guvenle
    isaret etmesi makul kabul edilir.
    """
    # "informational_only" isaretli eslestirmeler alarm URETMEZ: activity
    # karar katmani (bkz. app/validation/decision.py) bunlari
    # "bu is mesru gorunuyor, alarm uretme" diye ayirmis demektir ve arayuz de
    # onlari o sekilde gosterir.
    #
    # Metrik degistirildi -- gerekcesi: bu olcut "sistem mesru bir aktiviteye
    # saldiri etiketi yapistirdi mi" sorusunu soruyor. Acikca "bilgi amacli,
    # alarm uretilmemeli" diye isaretlenmis bir kayit saldiri etiketi degildir.
    # Katman eklenmeden once boyle bir ayrim yoktu, dolayisiyla eski tanim
    # eksikti; bu haliyle olcut davranisi degil, davranisin alarm sonucunu
    # olcuyor -- SOC acisindan anlamli olan da bu.
    alerting = [m for m in predicted_mappings if not m.get("informational_only")]

    if scenario.get("negative_case"):
        high_conf = [m for m in alerting if m.get("confidence_level") in {"high", "medium"}]
        return len(high_conf) == 0

    if scenario["expected_level"] != "insufficient":
        return None

    allowed = set(scenario["expected_attack_ids"]) | set(scenario["acceptable_alternatives"])
    bad = [
        m for m in alerting
        if m.get("confidence_level") == "high" and m.get("attack_id") not in allowed
    ]
    return len(bad) == 0


def retrieval_recall_at_k(retrieved_attack_ids: list[str], scenario: dict[str, Any], k: int) -> float | None:
    expected = set(scenario["expected_attack_ids"]) | set(scenario["acceptable_alternatives"])
    if not expected:
        return None
    top_k_unique: list[str] = []
    for aid in retrieved_attack_ids:
        if aid not in top_k_unique:
            top_k_unique.append(aid)
        if len(top_k_unique) >= k:
            break
    return 1.0 if expected & set(top_k_unique) else 0.0


def hallucination_rate(mappings: list[dict[str, Any]], kb_by_id: dict[str, Any]) -> float:
    if not mappings:
        return 0.0
    bad = sum(1 for m in mappings if m.get("attack_id") not in kb_by_id)
    return bad / len(mappings)
