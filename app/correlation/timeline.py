"""Incident icin kronolojik 'Evidence Timeline' (kullanici ornegi: saat +
EventID + kanit ifadesi). Zaman damgasi olmayan satirlar sona, orijinal
sirayla eklenir -- kaybolmazlar, sadece siralama iddiasi yapilmaz."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from app.correlation.fields import extract_event_id

_FAR_FUTURE = datetime.max

# Kanit alaninin "ham log geri yapistirilmis" halini yakalayan desen:
# Timestamp="..." EventID=4673 Hostname=... gibi ard arda ANAHTAR=DEGER
# ciftleri. Sema kanittan BIREBIR ALINTI istiyor (bkz. app/llm/schemas.py),
# model bazen bunu "satirin tamamini kopyala" diye anliyor. Boyle bir metin
# timeline'da bilgi vermiyor -- zaten yanindaki sutunlarda ayni veri var.
_RAW_LOG_PATTERN = re.compile(r'\w+="?[^"\s]+"?\s+\w+=')

# Bu uzunlugun ustundeki kanit tek satirlik bir timeline girisine sigmaz;
# reasoning_summary (sema geregi <=220 karakter, Turkce) daha iyi bir ozet.
_EVIDENCE_LENGTH_LIMIT = 240


def _top_mapping(analysis: dict[str, Any] | None) -> dict[str, Any] | None:
    if not analysis:
        return None
    mappings = analysis.get("mappings") or []
    if not mappings:
        return None
    return max(mappings, key=lambda m: m.get("confidence_score") or 0.0)


def _looks_like_raw_log(text: str) -> bool:
    """Kanit yerine ham log satirinin kopyalanip kopyalanmadigini kestirir."""
    return bool(_RAW_LOG_PATTERN.search(text)) or len(text) > _EVIDENCE_LENGTH_LIMIT


def _evidence_text(mapping: dict[str, Any] | None) -> str:
    """Timeline'da gosterilecek TEK satirlik kanit ifadesi.

    Oncelik sirasi kasitli: once ham log gibi gorunmeyen ilk alinti, sonra
    modelin Turkce kisa gerekcesi, en son teknik adi. Ham log gibi gorunen
    alintilar ATILMIYOR -- yalnizca timeline ozetinde geri plana aliniyor;
    tam kanit listesi Bireysel Log Analizi'nde ve 'tam kanıt metinleri'
    expander'inda oldugu gibi duruyor (bkz. app/ui/bulk_view.py)."""
    if mapping is None:
        return "-"

    evidence_list = [e.strip() for e in (mapping.get("evidence") or []) if e and e.strip()]
    for evidence in evidence_list:
        if not _looks_like_raw_log(evidence):
            return evidence

    reasoning = (mapping.get("reasoning_summary") or "").strip()
    if reasoning:
        return reasoning
    if evidence_list:
        return evidence_list[0]
    return f"{mapping.get('attack_id')} ({mapping.get('name')})"


def build_evidence_timeline(items: list[dict[str, Any]], indices: list[int]) -> list[dict[str, Any]]:
    """items: app/batch/orchestrator.py'nin urettigi tam satir listesi (index'e
    gore erisilebilir). indices: bu incident'e ait satir index'leri.

    Her giriste 'attack_id'/'technique_name' de tutulur (o satirin en yuksek
    guvenli eslesmesi) -- app/correlation/summary_builder.py bunlari, Attack
    Summary'yi kronolojik sirada, ilk-goruldugu teknige gore uretmek icin kullanir."""
    by_index = {it["index"]: it for it in items}

    entries = []
    for row_index in indices:
        item = by_index[row_index]
        mapping = _top_mapping(item.get("analysis"))
        entries.append({
            "row_index": row_index,
            "timestamp": item.get("timestamp"),
            "event_id": extract_event_id(item["source_row"]),
            "evidence": _evidence_text(mapping),
            "attack_id": mapping.get("attack_id") if mapping else None,
            "technique_name": mapping.get("name") if mapping else None,
        })

    entries.sort(key=lambda e: (e["timestamp"] is None, e["timestamp"] or _FAR_FUTURE, e["row_index"]))
    return entries
