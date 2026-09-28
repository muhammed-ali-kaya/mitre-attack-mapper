"""Toplu analizin en ust katmani: satir bazli bagimsiz analiz sonuclarindan
(app/batch/orchestrator.py) incident'leri kurar. Sirasiyla: gruplama (engine),
teknik tekillestirme (dedup), attack chain (attack_chain), kronolojik kanit
(timeline), IOC/artefact ozeti (ioc_extraction) ve risk skoru (risk_score) --
hicbiri LLM cagirmiyor, hepsi bir onceki asamanin ciktisina deterministik
fonksiyonlar uygular."""

from __future__ import annotations

from collections import Counter
from typing import Any

from app.correlation.attack_chain import build_attack_chain
from app.correlation.dedup import dedupe_techniques, split_by_confidence
from app.correlation.engine import build_incident_groups
from app.correlation.ioc_extraction import extract_incident_iocs
from app.correlation.risk_score import compute_risk_score
from app.correlation.summary_builder import build_attack_summary
from app.correlation.timeline import build_evidence_timeline


def _most_common(values: list[str | None]) -> str | None:
    present = [v for v in values if v]
    if not present:
        return None
    return Counter(present).most_common(1)[0][0]


def _dedup_entries(items_by_index: dict[int, dict[str, Any]], row_indices: list[int]) -> list[dict[str, Any]]:
    entries = []
    for row_index in row_indices:
        item = items_by_index[row_index]
        analysis = item.get("analysis")
        for mapping in (analysis.get("mappings") if analysis else None) or []:
            entries.append({"row_index": row_index, "timestamp": item.get("timestamp"), "mapping": mapping})
    return entries


def rebuild_incident_presentation(
    incident: dict[str, Any], items: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    """Kaydedilmis bir incident'in sunum katmanini yeniden uretir.

    Neden gerekli: incident'ler diske yazildiginda attack_chain, risk,
    timeline ve attack_summary de birlikte yaziliyor (bkz. app/batch/
    result_store.py). Bu alanlarin uretim mantigi degistiginde -- zayif
    sinyallerin ayrilmasi, zincirin birincil taktige indirgenmesi, ozetin
    Turkcelestirilmesi, kanit metninin ham logdan arindirilmasi -- eski
    dosyalar hala ESKI ciktiyi tasiyor. Tek bir toplu kosu saatler surdugu
    icin "yeniden calistir" gercekci bir cozum degil; bunun yerine dosyadaki
    DEGISMEYEN veriden sunum alanlarini yeniden turetiyoruz. LLM'e gidilmez,
    satir analizleri aynen korunur.

    items verilirse timeline da bastan kuruluyor: kayitli timeline'daki
    'evidence' metni, o tarihteki secim mantigiyla donmus durumda (gercek
    bir dosyada 51 girisin 17'si kanit yerine ham log satiri tasiyordu,
    bkz. app/correlation/timeline.py::_evidence_text)."""
    deduped = incident.get("deduped_techniques") or []
    timeline = (
        build_evidence_timeline(items, incident["row_indices"])
        if items is not None and incident.get("row_indices")
        else incident.get("timeline") or []
    )

    strong, weak = split_by_confidence(deduped)
    attack_chain = build_attack_chain(strong)

    upgraded = dict(incident)
    upgraded["timeline"] = timeline
    upgraded["techniques"] = strong
    upgraded["weak_techniques"] = weak
    upgraded["attack_chain"] = attack_chain
    upgraded["risk"] = compute_risk_score(strong, attack_chain, excluded_low_confidence=len(weak))
    upgraded["attack_summary"] = build_attack_summary(
        timeline,
        strong,
        hostname=incident.get("hostname"),
        primary_user=incident.get("primary_user"),
        weak_technique_count=len(weak),
    )
    return upgraded


def build_incidents(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items_by_index = {it["index"]: it for it in items}
    groups = build_incident_groups(items)

    incidents = []
    for n, row_indices in enumerate(groups, start=1):
        deduped = dedupe_techniques(_dedup_entries(items_by_index, row_indices))
        # Zayif sinyaller anlatinin (zincir/ozet/risk) disinda tutulur ama
        # incident sozlugunde tasinir -- arayuz ve rapor onlari ayri bir
        # bolumde gosteriyor. Bkz. app/correlation/dedup.py::split_by_confidence.
        strong, weak = split_by_confidence(deduped)
        attack_chain = build_attack_chain(strong)
        timeline = build_evidence_timeline(items, row_indices)
        ioc_summary = extract_incident_iocs(items, row_indices)
        risk = compute_risk_score(strong, attack_chain, excluded_low_confidence=len(weak))

        hostnames = [items_by_index[i]["correlation_fields"].get("Hostname") for i in row_indices]
        users = [items_by_index[i]["correlation_fields"].get("SubjectUserName") for i in row_indices]
        hostname = _most_common(hostnames)
        primary_user = _most_common(users)

        attack_summary = build_attack_summary(
            timeline,
            strong,
            hostname=hostname,
            primary_user=primary_user,
            weak_technique_count=len(weak),
        )

        incidents.append({
            "id": f"INC-{n}",
            "hostname": hostname,
            "primary_user": primary_user,
            "row_indices": row_indices,
            "timeline": timeline,
            # 'deduped_techniques' TUM teknikleri tasimaya devam ediyor (geriye
            # donuk uyumluluk: kaydedilmis eski sonuc dosyalari ve raporlar bu
            # anahtari bekliyor). Anlatida kullanilan ayrilmis liste asagida.
            "deduped_techniques": deduped,
            "techniques": strong,
            "weak_techniques": weak,
            "attack_chain": attack_chain,
            "risk": risk,
            "ioc_summary": ioc_summary,
            "attack_summary": attack_summary,
        })

    return incidents
