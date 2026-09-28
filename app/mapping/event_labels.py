"""Olay ID'lerinin GOSTERIM adi ve hangi log kaynagindan geldigi (Gorev 25).

Iki sikayet:
  4. "Persistence: 11, 12, 13, 4657, 4663, 4697, 4720..." -- analist bu
     ID'leri ezbere bilmez.
  5. Tablo boslugu gosteriyor ama AKSIYONU soylemiyor.

AD ICIN YENI TABLO ACILMADI (madde 7). `config/event_semantics.yaml`
zaten olay basina `anlam` tutuyor; ad oradan okunur. Katalogda olmayan
ID CIPLAK kalir -- ikinci bir ad tablosu acmak, ayni gercegin iki kaynagi
demek olurdu (Gorev 24'un dersi).

OLCULMUS SINIR: kural katalogunun bekledigi 48 olay ID'sinin 27'si
event_semantics.yaml'de YOK, yani cogu ID adsiz kalacak
(scripts/measure_task25_readability.py). Bu bir eksiklik degil, bilinen
ve GORUNUR bir sinirdir -- katalogu buyutmek analiz katmanini degistirir
ve bu gorevin kapsami disidir.

Log kaynagi eslemesi `config/log_sources.yaml`de VERI olarak duruyor.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from app.normalization.event_semantics import event_semantics

CONFIG_DIR = Path(__file__).resolve().parents[2] / "config"
LOG_SOURCES_FILE = CONFIG_DIR / "log_sources.yaml"

_SOURCES: dict[str, Any] | None = None


def _load_sources() -> dict[str, Any]:
    global _SOURCES
    if _SOURCES is None:
        _SOURCES = yaml.safe_load(LOG_SOURCES_FILE.read_text(encoding="utf-8"))
    return _SOURCES


def event_name(event_id: str | None) -> str | None:
    """Olayin tek cumlelik adi; katalogda yoksa None."""
    semantics = event_semantics(event_id)
    if semantics is None:
        return None
    anlam = (semantics.get("anlam") or "").strip()
    return anlam or None


def event_label(event_id: str | None) -> str:
    """Ekrana basilacak biçim: `4657 (registry degeri degistirildi)`.

    Adi bilinmeyen ID CIPLAK doner -- uydurma ad basmak, analistin
    dogrulayamayacagi bir bilgi vermek olurdu."""
    text = str(event_id).strip() if event_id is not None else ""
    name = event_name(text)
    return f"{text} ({name})" if name else text


def event_labels(event_ids) -> list[str]:
    return [event_label(e) for e in event_ids]


def log_source(event_id: str | None) -> str:
    """Bu olayi toplayan log kaynagi. Istisnalar araliklardan ONCE bakilir."""
    data = _load_sources()
    text = str(event_id).strip() if event_id is not None else ""

    exception = (data.get("istisnalar") or {}).get(text)
    if exception:
        return exception

    if text.isdigit():
        number = int(text)
        for band in data.get("araliklar") or []:
            if band["min"] <= number <= band["max"]:
                return band["kaynak"]

    return data.get("bilinmiyor") or "kaynağı bilinmiyor"


def required_log_sources(event_ids) -> dict[str, list[str]]:
    """kaynak -> o kaynaktan gelen olay ID'leri (sirali, tekrarsiz)."""
    grouped: dict[str, list[str]] = {}
    for event_id in event_ids:
        text = str(event_id).strip()
        bucket = grouped.setdefault(log_source(text), [])
        if text not in bucket:
            bucket.append(text)
    return grouped


def required_sources_sentence(event_ids) -> str:
    """'Bu taktigi gorebilmek icin gereken log kaynagi: ...' -- tek satir.

    Bos liste gelirse BOS DIZE doner; cagiran taraf satiri hic basmaz.
    Icerigi olmayan bir madde isareti basmak Gorev 24'te duzeltilen
    kusurun ta kendisiydi."""
    grouped = required_log_sources(event_ids)
    if not grouped:
        return ""
    parts = [f"{source} ({', '.join(ids)})" for source, ids in grouped.items()]
    return "Gerekli log kaynağı: " + " · ".join(parts)
