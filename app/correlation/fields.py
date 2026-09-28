"""Toplu analizde satirlar arasi korelasyon icin kullanilan alanlarin
CSV/JSON kaynak satirindan (source_row) cikarilmasi.

app/batch/serialize.py'deki CANONICAL_FIELD_ALIASES tablosunu tekrar kullanir
(Sysmon/Windows Event Log es anlamlilarini zaten kanonik isimlere ceviriyor)
-- boylece CSV kolon adlandirmasi (Hostname/Computer/ComputerName gibi)
farkli olsa da korelasyon motoru hep ayni alan adlarini gorur."""

from __future__ import annotations

from datetime import datetime
from typing import Any

import pandas as pd

from app.batch.serialize import CANONICAL_FIELD_ALIASES, _sanitize_key

CORRELATION_FIELDS: list[str] = [
    "Hostname", "SubjectUserName", "SourceIp", "DestinationIp",
    "ProcessGuid", "ParentProcessGuid", "ProcessId", "ParentProcessId",
    "LogonId", "SessionId", "ServiceName", "FilePath",
]

TIMESTAMP_FIELD = "Timestamp"
EVENT_ID_FIELD = "EventID"


def _canonical_key(key: Any) -> str | None:
    if key is None:
        return None
    alias = CANONICAL_FIELD_ALIASES.get(str(key).strip().casefold())
    return alias if alias else _sanitize_key(key)


def extract_correlation_fields(source_row: dict[str, Any]) -> dict[str, str | None]:
    """Satirdaki her kolonu kanonik korelasyon alan adina cevirir; ayni alan
    icin birden fazla kolon varsa (orn. hem 'Hostname' hem 'Computer') ilk
    dolu deger kazanir -- input_parser.py'nin _extract_facts'iyle ayni
    setdefault semantigi."""
    fields: dict[str, str | None] = {name: None for name in CORRELATION_FIELDS}
    for key, value in source_row.items():
        canonical = _canonical_key(key)
        if canonical not in CORRELATION_FIELDS:
            continue
        if fields[canonical] is not None:
            continue
        if value is None:
            continue
        text = str(value).strip()
        if not text or text.lower() == "nan":
            continue
        fields[canonical] = text
    return fields


def extract_timestamp(source_row: dict[str, Any]) -> datetime | None:
    """Timestamp'e denk gelen ilk dolu kolonu pandas ile parse eder.
    Parse edilemezse (veya boyle bir kolon yoksa) None doner -- satir yine de
    analiz edilir, yalnizca kronolojik siralamada en sona konur ve zaman
    penceresi kontrolunden muaf tutulur (bkz. app/correlation/engine.py)."""
    for key, value in source_row.items():
        if _canonical_key(key) != TIMESTAMP_FIELD or value is None:
            continue
        parsed = pd.to_datetime(value, errors="coerce")
        if pd.isna(parsed):
            continue
        return parsed.to_pydatetime()
    return None


def extract_event_id(source_row: dict[str, Any]) -> str | None:
    """app/correlation/timeline.py ve ioc_extraction.py'nin EventID'ye gore
    kategorilendirme yapabilmesi icin kaynak satirdan EventID'yi cikarir."""
    for key, value in source_row.items():
        if _canonical_key(key) == EVENT_ID_FIELD and value is not None:
            text = str(value).strip()
            if text and text.lower() != "nan":
                return text
    return None
