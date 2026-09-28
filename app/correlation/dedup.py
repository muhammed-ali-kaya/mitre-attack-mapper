"""Bir incident icindeki satirlardan gelen ATT&CK mapping'lerini attack_id
bazinda tekillestirir (kullanici talebi: '10 farkli PowerShell logu varsa
yalnizca T1059.001 (10 occurrences) seklinde gosterilsin')."""

from __future__ import annotations

from datetime import datetime
from typing import Any

EVIDENCE_CAP = 5

# Incident anlatisina (attack chain, ozet, risk skoru) yalnizca bu guven
# seviyeleri girer. Gerekce: 51 satirlik gercek bir kosuda uretilen 44
# teknigin 13'u 0.25-0.40 skorluydu (Verclsid, XSL Script Processing, Office
# Test gibi tek kanita dayanan eslesmeler). Bunlar zinciri okunamaz hale
# getiriyor ve risk skorunu sisiriyordu. Elenmiyorlar -- ayri bir "zayif
# sinyal" listesine dusuyorlar (bkz. split_by_confidence), yani bulgu
# kaybolmuyor, yalnizca ana anlatidan ayriliyor.
STRONG_CONFIDENCE_LEVELS = frozenset({"high", "medium"})

#: confidence_level tasimayan eski kayitlar icin geri dusus esigi.
FALLBACK_STRONG_SCORE = 0.5

#: Guclu duzeylerin gosterim sirasi -- en gucluden zayifa.
_LEVEL_ORDER = ("high", "medium", "low")


def dedupe_techniques(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """entries: her biri {'row_index': int, 'timestamp': datetime | None,
    'mapping': dict} seklinde -- incident'teki tum satirlarin kabul edilmis
    (result['mappings']) eslesmeleri, satir bilgisiyle birlikte."""
    groups: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        attack_id = entry["mapping"].get("attack_id")
        if not attack_id:
            continue
        groups.setdefault(attack_id, []).append(entry)

    deduped: list[dict[str, Any]] = []
    for attack_id, group in groups.items():
        mappings = [g["mapping"] for g in group]
        representative = max(mappings, key=lambda m: m.get("confidence_score") or 0.0)

        evidence: list[str] = []
        for m in mappings:
            for ev in m.get("evidence") or []:
                if len(evidence) >= EVIDENCE_CAP:
                    break
                if ev not in evidence:
                    evidence.append(ev)

        timestamps: list[datetime] = [g["timestamp"] for g in group if g["timestamp"] is not None]

        deduped.append({
            "attack_id": attack_id,
            "name": representative.get("name"),
            "object_type": representative.get("object_type"),
            "tactics": representative.get("tactics", []),
            "occurrence_count": len(group),
            "source_row_indices": sorted({g["row_index"] for g in group}),
            "first_seen_timestamp": min(timestamps) if timestamps else None,
            "evidence": evidence,
            "max_confidence_score": max((m.get("confidence_score") or 0.0) for m in mappings),
            # Temsilci eslesmenin seviyesi = grubun EN YUKSEK skorlu eslesmesinin
            # seviyesi (representative zaten skora gore secildi). Ayni teknik bir
            # satirda zayif, digerinde guclu kanitla gorulduyse guclu olan kazanir.
            "confidence_level": representative.get("confidence_level"),
            "representative_mapping": representative,
        })

    return sorted(deduped, key=lambda d: d["attack_id"])


def split_by_confidence(
    deduped: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(guclu, zayif) olarak ikiye ayirir.

    Zayif olanlar SILINMEZ: cagiran taraf onlari ayri bir bolumde gosterir
    (bkz. app/ui/bulk_view.py, app/reporting/incident_report.py). Boylece
    "neden bu teknigi atladin?" sorusunun cevabi ekranda duruyor.

    confidence_level yoksa skora duseriz: eski kosularda kaydedilmis sonuc
    dosyalarinda bu alan yok (bkz. data/bulk_results/) ve onlar da bu
    ekranda yuklenebiliyor -- alan eksik diye her teknigi zayif saymak, o
    dosyalari acilamaz hale getirirdi."""
    strong: list[dict[str, Any]] = []
    weak: list[dict[str, Any]] = []
    for technique in deduped:
        level = technique.get("confidence_level")
        if level is None:
            is_strong = (technique.get("max_confidence_score") or 0.0) >= FALLBACK_STRONG_SCORE
        else:
            is_strong = level in STRONG_CONFIDENCE_LEVELS
        (strong if is_strong else weak).append(technique)
    return strong, weak


# --- GOSTERIM (Gorev 25) --------------------------------------------------
# Sikayet: ekranda 3 teknik "yeterli", 22'si "zayif" yaziyor ama AYIRAN
# ESIK hicbir yerde yazmiyor. Analist esigi bilmeden listeye guvenemez.
#
# Cumle ESIGIN KENDISINDEN uretiliyor, elle yazilmiyor: yukaridaki
# STRONG_CONFIDENCE_LEVELS veya geri dusus esigi degisirse ekrandaki
# metin de kendiliginden degisir.

_LEVEL_TR = {"high": "yüksek", "medium": "orta", "low": "düşük"}


def confidence_threshold_sentence() -> str:
    """'Kanit duzeyi yeterli' ne demek -- tek cumle."""
    levels = ", ".join(
        _LEVEL_TR.get(level, level)
        for level in _LEVEL_ORDER
        if level in STRONG_CONFIDENCE_LEVELS
    )
    return (
        f"Bir teknik ancak güven düzeyi **{levels}** ise kanıt düzeyi yeterli "
        "sayılır ve saldırı zincirine, analist özetine ve risk skoruna girer; "
        f"düzeyi olmayan eski kayıtlarda eşik güven skoru ≥ {FALLBACK_STRONG_SCORE}. "
        "Bunun altındakiler elenmez, 'Doğrulama Gerektiren Zayıf Sinyaller' "
        "bölümünde listelenir."
    )
