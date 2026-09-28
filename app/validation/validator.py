"""LLM ciktisini resmi ATT&CK verisine karsi dogrular (dokuman bolum 27).

Felsefe: LLM'in attack_id secimine ve evidence/reasoning metnine guveniyoruz
(bunlar gercekten girdiye dayanan yorumlar). Ama isim, object_type, tactics,
source_url gibi alanlar zaten bizim elimizde kesin olarak bilinen bilgiler --
LLM bunlari yanlis yazarsa (orn. "sub-technique" yerine "technique" demek gibi
kucuk bir etiketleme hatasi) dogru eslestirmeyi tumden reddetmek yerine kendi
otoriter verimizle DUZELTIYORUZ. Yalnizca kimligin kendisi supheliyse (attack_id
bizim veride yok, ya da REVOKED) mapping tumden reddediliyor.

Gecersiz/uydurma mapping'ler sessizce silinmez -- ayri bir 'rejected_mappings'
listesine, sebebiyle birlikte tasinir.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from app.ingestion.attack_version import attack_version
from app.validation.evidence_requirements import EvidenceCheckResult, check_required_evidence

PROCESSED_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "processed"

_VALID_CONFIDENCE_LEVELS = {"high", "medium", "low", "insufficient"}

REASONING_SUMMARY_MAX_LENGTH = 200


def _shorten_reasoning(text: str, max_length: int = REASONING_SUMMARY_MAX_LENGTH) -> str:
    """LLM'in kisa tutma talimatina (prompt/schema) uymayabilecegi bilinen bir
    sinirlama oldugundan (bkz. app/llm/prompts.py), kod tarafinda garanti altina
    alinan bir kesme uygulanir -- prompt sadece 'yardimci', bu 'garanti' katmanidir."""
    if len(text) <= max_length:
        return text
    truncated = text[:max_length].rsplit(" ", 1)[0].rstrip(".,;: ")
    return f"{truncated}..."


class AttackKnowledgeBase:
    """techniques.json'i bir kere yukleyip attack_id -> kayit sozlugu olarak tutar."""

    def __init__(self, techniques_path: Path = PROCESSED_DIR / "techniques.json"):
        techniques = json.loads(techniques_path.read_text(encoding="utf-8"))
        self.by_id: dict[str, dict[str, Any]] = {t["attack_id"]: t for t in techniques}


def _looks_quoted_from_input(evidence: str, raw_input: str) -> bool:
    """Kanitin girdiden gercekten alinti olup olmadigini kaba bir sekilde kontrol eder
    (tam substring degil -- kelimelerin en az yarisinin girdide gecip gecmedigine bakar,
    kucuk bicimlendirme farklarina tolerandi olmasi icin)."""
    ev_words = [w for w in evidence.lower().split() if len(w) > 3]
    if not ev_words:
        return True
    input_lower = raw_input.lower()
    matches = sum(1 for w in ev_words if w in input_lower)
    return matches / len(ev_words) >= 0.5


def validate_mapping(
    mapping: dict[str, Any],
    kb: AttackKnowledgeBase,
    grounded_attack_ids: set[str] | None = None,
    raw_input: str | None = None,
    _redirected_from: frozenset[str] = frozenset(),
) -> tuple[bool, dict[str, Any], list[str]]:
    """Donus: (kabul_edildi_mi, duzeltilmis_mapping, notlar)"""
    notes: list[str] = []
    attack_id = mapping.get("attack_id")

    technique = kb.by_id.get(attack_id)
    if technique is None:
        return False, mapping, [
            f"Bilinmeyen ATT&CK ID: '{attack_id}' (guncel v{attack_version()} verisinde yok, uydurma olabilir)"
        ]

    if technique["revoked"]:
        # Revoked teknigin guncel karsiligi elimizdeyken mapping'i tumden atmak,
        # bildigimiz dogru cevabi cope atmak demekti: girdide eski bir ID gectigi
        # icin (orn. "T1143 ile iliskili...") model o ID'yi tekrarlayinca sistem
        # hicbir sey dondurmuyordu. STIX'teki revoked-by iliskisi tam olarak bu
        # yonlendirme icin var; KB'de 149 revoked teknigin karsiligi biliniyor.
        # Karsiligi bilinmiyorsa (ya da KB'de yoksa) eski davranis korunur.
        replacement = technique.get("revoked_by")
        replacement_id = replacement["attack_id"] if replacement else None
        if replacement_id in kb.by_id and replacement_id not in _redirected_from:
            is_valid, corrected, inner_notes = validate_mapping(
                {**mapping, "attack_id": replacement_id},
                kb,
                grounded_attack_ids,
                raw_input,
                _redirected_from | {attack_id},
            )
            redirect_note = (
                f"REVOKED teknik {attack_id} ({technique['name']}) guncel karsiligi "
                f"{replacement_id} ({replacement['name']}) ile degistirildi"
            )
            return is_valid, corrected, [redirect_note, *inner_notes]

        hint = f", yerine gecen teknik: {replacement_id} ({replacement['name']})" if replacement else ""
        return False, mapping, [f"Teknik REVOKED (kullanimdan kaldirilmis){hint}"]

    # Zorunlu kanit kontrolu: bazi teknikler icin (bkz. evidence_requirements.py)
    # belirli artefact'lardan en az biri girdide gecmiyorsa teknik tumden
    # reddedilir -- LLM'in kendi guven seviyesi veya retrieval skoru bunu
    # gecersiz kilamaz.
    evidence_check = (
        check_required_evidence(attack_id, raw_input)
        if raw_input is not None
        else EvidenceCheckResult(applicable=False, satisfied=True)
    )
    if evidence_check.applicable and not evidence_check.satisfied:
        return False, {**mapping, "evidence_check": asdict(evidence_check)}, [
            "Technique rejected because required evidence was not found in the supplied log.",
            f"Aranan kanit terimleri (en az biri gecmeliydi): {', '.join(evidence_check.missing)}",
        ]

    corrected = dict(mapping)

    reasoning_summary = mapping.get("reasoning_summary")
    if isinstance(reasoning_summary, str) and len(reasoning_summary) > REASONING_SUMMARY_MAX_LENGTH:
        corrected["reasoning_summary"] = _shorten_reasoning(reasoning_summary)

    if mapping.get("name") != technique["name"]:
        notes.append(f"Isim duzeltildi: '{mapping.get('name')}' -> '{technique['name']}'")
        corrected["name"] = technique["name"]

    expected_object_type = "sub-technique" if technique["is_subtechnique"] else "technique"
    if mapping.get("object_type") != expected_object_type:
        notes.append(f"object_type duzeltildi: '{mapping.get('object_type')}' -> '{expected_object_type}'")
        corrected["object_type"] = expected_object_type

    claimed_tactics = set(mapping.get("tactics") or [])
    real_tactics = set(technique["tactics"])
    if claimed_tactics - real_tactics:
        notes.append(f"tactics duzeltildi: {sorted(claimed_tactics)} -> {technique['tactics']}")
        corrected["tactics"] = technique["tactics"]

    claimed_url = (mapping.get("source_url") or "").rstrip("/")
    real_url = (technique["source_url"] or "").rstrip("/")
    if claimed_url != real_url:
        notes.append(f"source_url duzeltildi: '{mapping.get('source_url')}' -> '{technique['source_url']}'")
        corrected["source_url"] = technique["source_url"]

    if mapping.get("confidence_level") not in _VALID_CONFIDENCE_LEVELS:
        notes.append(f"Gecersiz confidence_level ('{mapping.get('confidence_level')}') -> 'low' yapildi")
        corrected["confidence_level"] = "low"

    if technique["deprecated"]:
        notes.append("UYARI: Teknik DEPRECATED")

    # Tespit/onleme onerileri LLM'e uydurtulmuyor -- dogrudan kendi parse ettigimiz
    # resmi MITRE verisinden (techniques.json) ekleniyor, boylece halusinasyon riski yok.
    corrected["detection_recommendation"] = technique.get("detection")
    corrected["mitigation_recommendations"] = technique.get("mitigations", [])
    corrected["data_components"] = technique.get("data_components", [])

    if raw_input is not None:
        evidence_list = mapping.get("evidence") or []
        quoted = [e for e in evidence_list if _looks_quoted_from_input(e, raw_input)]
        dropped = len(evidence_list) - len(quoted)
        if dropped:
            notes.append(
                f"KANIT UYARISI: {dropped} 'evidence' maddesi girdiden birebir alinti gibi "
                "gorunmedigi icin dogrulanmis ciktidan cikarildi (teknigin genel aciklamasina benziyordu)"
            )
        corrected["evidence"] = quoted

    # KARAR: RETRIEVAL BIR ONERIDIR, KISIT DEGIL.
    #
    # Ajanlar bulgu kumesine teknik EKLEYEMEZ (sozlesme, app/agents/base.py).
    # LLM icin ayni sinir YOK: aday havuzunda olmayan bir teknigi secebilir.
    # Bu kod bunu engellemiyor, CEZALANDIRIYOR -- guveni 'low'a indirip
    # gerekce dusuyor. Karar bilincli ama gerekcesi bugune kadar hicbir yerde
    # yaziliydi degildi; asagisi o eksigi kapatiyor.
    #
    # NEDEN ENGELLEMIYORUZ: retrieval'in bulamamasi, teknigin yanlis oldugu
    # anlamina gelmiyor.
    #
    # DUZELTME (2026-08-16): burada once "olculdu: T1'de dogru cevap havuz
    # DISINDAN geldi ve dogruydu" yaziyordu. O olcum GECERSIZ -- probe,
    # dongunun ikinci tur havuzunu okuyordu ve birinci turda BULUNMUS bir
    # teknigi "havuz disi" gosteriyordu. Duzeltilmis olcum: T1003.002 aday
    # havuzunda VARDI (reranker 7. sirasi), onu duren sey ajan katmaniydi.
    #
    # Dort probe logunda havuz disi secim sayilari (duzeltilmis olcum):
    #     T0: 0 (parser oncesi 2 idi, ikisi de YANLIS teknikti)
    #     T1: 0    T2: 0    T3: 0
    # Yani su an elimizde "havuz disi secim dogru cevabi kurtardi" diyen
    # TEK BIR OLCUM YOK. Karari yine de degistirmiyoruz, ama gerekcesi artik
    # olcum degil ILKE: retrieval bir ONERIDIR, kisit degil; aday havuzunun
    # eksik olabilecegini varsaymak, LLM'i havuzun kalitesine mahkum
    # etmekten guvenlidir. Bu ilkeyi destekleyen ya da curuten bir olcum
    # cikarsa karar yeniden degerlendirilmeli.
    #
    # NEDEN CEZALANDIRIYORUZ: bagimsiz bir teyit yok. Retrieval'dan gelen bir
    # teknigin arkasinda en azindan korpustan bir belge var; parametrik
    # hafizadan gelenin arkasinda yalnizca modelin kendisi var.
    #
    # OLCULMEMIS SORU (Gorev 2A'nin kabul kriteri): bu uyariyi alan
    # tekniklerin kaci DOGRU cikiyor? Genelde dogruysa ceza yanlis yondedir --
    # retrieval'in zayifligini LLM telafi ediyor ve biz telafiyi
    # cezalandiriyoruz demektir. 2A retrieval'i guclendirdikce havuz disi
    # secim ORANI DUSMELI; dusmuyorsa 2A ise yaramamis demektir.
    if grounded_attack_ids is not None and attack_id not in grounded_attack_ids:
        notes.append(
            "GROUNDING UYARISI: bu ATT&CK ID, LLM'e gonderilen retrieval sonuclari arasinda yoktu "
            "(modelin kendi bilgisinden gelmis olabilir) -> confidence 'low' yapildi"
        )
        corrected["confidence_level"] = "low"

    corrected["evidence_check"] = asdict(evidence_check)

    return True, corrected, notes


def validate_response(
    llm_response: dict[str, Any],
    kb: AttackKnowledgeBase,
    grounded_attack_ids: set[str] | None = None,
    raw_input: str | None = None,
) -> dict[str, Any]:
    accepted = []
    rejected = []

    for mapping in llm_response.get("mappings", []):
        is_valid, corrected, notes = validate_mapping(mapping, kb, grounded_attack_ids, raw_input)
        if is_valid:
            if notes:
                corrected["validation_notes"] = notes
            accepted.append(corrected)
        else:
            rejected.append({**corrected, "validation_issues": notes})

    result = dict(llm_response)
    result["mappings"] = accepted
    result["rejected_mappings"] = rejected

    if raw_input is not None:
        behaviors = llm_response.get("observed_behaviors") or []
        kept = [b for b in behaviors if _looks_quoted_from_input(b, raw_input)]
        result["observed_behaviors"] = kept
        result["filtered_observed_behaviors"] = [b for b in behaviors if b not in kept]

    return result
