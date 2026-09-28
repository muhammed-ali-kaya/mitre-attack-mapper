"""Toplu (CSV/JSON) analiz akisinin ust duzey giris noktasi -- gercek SIEM
mantigi: her satir ONCE mevcut tekli-log pipeline'iyla (app/retrieval/
*_pipeline.py) BAGIMSIZ analiz edilir (birlestirilmis tek metin DEGIL, her
satir kendi LLM cagrisini alir), SONRA deterministik korelasyon motoru
(app/correlation/) satirlar arasi iliskiyi bulup incident'leri kurar.

Tek satirlik analiz akisinda bir LLM cagrisinin ara sira gecersiz/kesik JSON
uretmesi (app/llm/ollama_client.py'nin de belirttigi gibi bilinen, kalici
olmayan bir durum) tek istekte kabul edilebilir bir risktir -- ama toplu
analizde N satir = N cagri demek, bu yuzden tek bir satirin basarisiz olmasi
TUM toplu analizi cokertmemeli.

Yeniden deneme stratejisi (kullanici talebi): basarisiz olan satir HEMEN
tekrar denenmez (ayni gecici sorun -- orn. VRAM'den model atilmasi -- art
arda iki denemede de surebilir); once TUM satirlar bir kez islenir, en sonda
o ana kadar basarisiz kalanlar TEK TUR halinde tekrar denenir. Ikinci
denemede de basarisiz olursa satir 'analysis=None, analysis_error=...' ile
isaretlenip ATLANIR -- app/correlation/* zaten analysis=None olan satirlari
(mapping katkisi olmadan) sessizce atlayacak sekilde yazildi."""

from __future__ import annotations

from typing import Any, Callable

from app.batch.serialize import rows_to_batch_items
from app.correlation.fields import extract_correlation_fields, extract_timestamp
from app.correlation.incident import build_incidents
from app.retrieval.baseline_pipeline import run_baseline_query
from app.retrieval.improved_pipeline import run_improved_query

# on_progress(current, total, phase) -- phase: "analiz" (ilk gecis) veya "yeniden_deneme" (ikinci gecis)
OnProgress = Callable[[int, int, str], None]


def _analyze_row_once(item: dict[str, Any], system_choice: str) -> tuple[dict[str, Any] | None, str | None]:
    try:
        if system_choice.startswith("Gelistirilmis"):
            return run_improved_query(item["raw_log"], platform=item["platform"]), None
        return run_baseline_query(item["raw_log"]), None
    except Exception as e:  # LLM'in gecersiz/kesik JSON uretmesi dahil -- satir bazinda izole edilir
        return None, str(e)


def run_bulk_analysis(
    rows: list[dict[str, Any]],
    system_choice: str,
    on_progress: OnProgress | None = None,
) -> dict[str, Any]:
    items = rows_to_batch_items(rows)
    usable = [it for it in items if not it["skipped"]]
    n = len(usable)

    failed: list[dict[str, Any]] = []
    for i, item in enumerate(usable, start=1):
        item["correlation_fields"] = extract_correlation_fields(item["source_row"])
        item["timestamp"] = extract_timestamp(item["source_row"])
        item["analysis"], item["analysis_error"] = _analyze_row_once(item, system_choice)
        if item["analysis_error"]:
            failed.append(item)
        if on_progress:
            on_progress(i, n, "analiz")

    for i, item in enumerate(failed, start=1):
        if on_progress:
            on_progress(i, len(failed), "yeniden_deneme")
        item["analysis"], item["analysis_error"] = _analyze_row_once(item, system_choice)

    for item in items:
        if item["skipped"]:
            item["analysis"] = None
            item["analysis_error"] = None
            item["correlation_fields"] = {}
            item["timestamp"] = None

    return {"items": items, "incidents": build_incidents(items)}
