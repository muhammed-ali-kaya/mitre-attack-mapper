"""Kompozit guven skoru (kullanici talebi: 'Retrieval score tek basina confidence
olmasin'). LLM'in kendi bildirdigi confidence_level yerine gecen, birden fazla
gerekce-tabanli bilesenden hesaplanan bir skor uretir:

- retrieval_similarity : reranker'in (cross-encoder) skoru, sigmoid ile [0,1]'e
- evidence_coverage     : 'evidence' maddelerinin girdiden gercekten alinti
                          olma orani + (varsa) zorunlu-kanit eslesme orani
- field_match           : cikarilan Key=Value fact'lerinden kaci LLM'in
                          evidence metninde gecmis
- event_id_relevance    : girdideki EventID'nin urettigi telemetri turu,
                          teknigin veri bilesenleriyle (data_components)
                          uyusuyor mu. Detection metninde EventID acikca
                          geciyorsa once o kullanilir; ama bu tekniklerin
                          yalnizca %1'inde oluyor (bkz. event_id_mapping.py).
- platform_match        : tespit edilen platform, teknigin platforms listesinde mi

Her bilesen bagimsizdir; uygulanamayan bilesenler (orn. teknigin detection
metninde hic EventID gecmiyor) None doner ve agirlikli ortalamadan cikarilir --
cezalandirilmaz. Boylece cogu teknik icin eksik sinyal, skoru yapay olarak
dusurmez."""

from __future__ import annotations

import math
import re
from typing import Any

from app.validation.event_id_mapping import data_components_for_event_id
from app.validation.validator import _looks_quoted_from_input

_EVENT_ID_IN_DETECTION_RE = re.compile(r"event\s*id\s*[:#]?\s*(\d{3,4})", re.IGNORECASE)

WEIGHTS = {
    "retrieval_similarity": 0.30,
    "evidence_coverage": 0.30,
    "field_match": 0.15,
    "event_id_relevance": 0.15,
    "platform_match": 0.10,
}


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


def compute_confidence(
    mapping: dict[str, Any],
    technique: dict[str, Any],
    normalized: dict[str, Any],
    raw_input: str,
) -> dict[str, Any]:
    # SORGU ICI normalize edilmis skor (bkz. improved_pipeline.normalize_support).
    #
    # Eskiden burada ham skora sigmoid uygulaniyordu. Reranker (cross-encoder)
    # ciktisini ZATEN sigmoid'den geciriyor -- gozlenen aralik (0, 0.24], hepsi
    # pozitif. Ikinci sigmoid o araligi 0.500-0.559'a eziyordu: bilesenin
    # agirligi en yuksek olan (0.30) pratikte SABITTI ve siralamaya hicbir sey
    # katmiyordu. Dort logluk olcumde kompozit skor bu yuzden yalnizca
    # evidence_coverage'in iki durumuna (0.29 / 0.65) indirgenmisti.
    #
    # Ham skor mapping["retrieval_support_score"] altinda duruyor ama guven
    # hesabina GIRMIYOR: sorgular arasi karsilastirilamaz oldugu icin bir
    # sorgudaki 0.24 ile digerindeki 0.05 ayni seyi ifade etmez.
    rank_score = mapping.get("retrieval_rank_score")
    retrieval_similarity = rank_score if rank_score is not None else 0.0

    evidence_list = mapping.get("evidence") or []
    quoted_ratio = (
        sum(1 for e in evidence_list if _looks_quoted_from_input(e, raw_input)) / len(evidence_list)
        if evidence_list else 0.0
    )
    evidence_check = mapping.get("evidence_check") or {}
    if evidence_check.get("applicable"):
        total = len(evidence_check.get("found", [])) + len(evidence_check.get("missing", []))
        required_ratio = len(evidence_check.get("found", [])) / total if total else 1.0
        evidence_coverage = (quoted_ratio + required_ratio) / 2
    else:
        evidence_coverage = quoted_ratio

    extracted_facts = normalized.get("extracted_facts") or {}
    evidence_text = " ".join(evidence_list).lower()
    field_match = (
        sum(1 for v in extracted_facts.values() if v and v.lower() in evidence_text) / len(extracted_facts)
        if extracted_facts else None
    )

    # Once teknigin detection metninde EventID acikca geciyorsa onu kullan --
    # en dogrudan kanit. Ama bu 697 teknigin yalnizca 6'sinda oluyor, o yuzden
    # asil yol EventID'yi teknigin veri bilesenleriyle karsilastirmak
    # (bkz. app/validation/event_id_mapping.py).
    observed_event_id = normalized.get("event_id")
    detection_text = (technique or {}).get("detection") or ""
    technique_event_ids = set(_EVENT_ID_IN_DETECTION_RE.findall(detection_text))

    if not observed_event_id:
        event_id_relevance = None
    elif technique_event_ids:
        event_id_relevance = 1.0 if observed_event_id in technique_event_ids else 0.0
    else:
        observed_components = data_components_for_event_id(observed_event_id)
        technique_components = set((technique or {}).get("data_components") or [])
        if not observed_components or not technique_components:
            # Tanimadigimiz bir EventID ya da veri bileseni olmayan bir teknik:
            # sinyal yok demek, uyusmuyor demek degil -- None ortalamadan
            # cikariliyor, 0.0 ise cezalandirirdi.
            event_id_relevance = None
        else:
            event_id_relevance = 1.0 if observed_components & technique_components else 0.0

    detected_platform = normalized.get("platform")
    technique_platforms = (technique or {}).get("platforms") or []
    if not detected_platform:
        platform_match = None
    else:
        platform_match = 1.0 if detected_platform in technique_platforms else 0.0

    components = {
        "retrieval_similarity": retrieval_similarity,
        "evidence_coverage": evidence_coverage,
        "field_match": field_match,
        "event_id_relevance": event_id_relevance,
        "platform_match": platform_match,
    }
    available = {k: v for k, v in components.items() if v is not None}
    weight_sum = sum(WEIGHTS[k] for k in available) or 1.0
    score = sum(WEIGHTS[k] * v for k, v in available.items()) / weight_sum

    if score >= 0.75:
        level = "high"
    elif score >= 0.50:
        level = "medium"
    elif score >= 0.25:
        level = "low"
    else:
        level = "insufficient"

    return {"level": level, "score": score, "components": components}
