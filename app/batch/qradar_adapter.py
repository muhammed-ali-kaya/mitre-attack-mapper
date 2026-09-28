"""QRadar'in headersiz 'Log Activity' CSV export'unu -- gercek header satiri
OLMAYAN, bir kolonunda gomulu tab-ayracli 'AgentDevice=...Message=...'
payload'i bulunan format -- otomatik algilayip bizim sistemin bekledigi
basliklara sahip normalize satirlara cevirir.

Neden: bu formatta gercek sinyal, QRadar'in pozisyonel meta-kolonlarinda
DEGIL (bunlarin anlami export'tan export'a degisebilir, header olmadan
guvenilir sekilde tahmin edilemez) -- kendini tanimlayan tek kolonda (Computer=,
User=, EventID=, TimeGenerated=, Message=...). Bu yuzden diger 80+ kolonu
pozisyonel olarak eslemeye CALISMIYORUZ; yalnizca bu kolonu icerigine gore
bulup (index sabit degil, export'tan export'a kayabilir) parse ediyoruz.

Message icindeki 'Label:  Value' alt-alanlari (Account Name, Logon ID,
Process ID, Source/Destination Address...) best-effort regex ile cikarilir --
kusursuz degil (bazi 'section header' etiketleri kendi degeri olmadigi icin
bir sonraki gercek etikete karisabilir), ama Message'in TAMAMI yine de her
satirda ayri bir kolon olarak tutulur ve app/batch/serialize.py uzerinden
LLM analizine gider -- bu yuzden alan cikarimindaki kusurlar LLM analizinin
kalitesini degil, yalnizca korelasyon motorunun yakalayabildigi yapisal alan
sayisini (SourceIp, LogonId, vb.) etkiler."""

from __future__ import annotations

import io
import re
from datetime import datetime
from typing import Any

import pandas as pd

TAGGED_PAYLOAD_RE = re.compile(r"AgentDevice=\S+.*?EventID=\d+.*?Message=", re.DOTALL)
KV_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=")
LABEL_VALUE_RE = re.compile(
    r"([A-Z][A-Za-z0-9 /]{1,40}?):\s{1,4}(.*?)(?=(?:\s{2,}[A-Z][A-Za-z0-9 /]{1,40}?:)|$)", re.DOTALL
)

# Hedef alan -> Message icindeki etiketin SONU bu string(ler)den biriyle
# eslesiyorsa (suffix match -- section-header kirliligini tolere etmek icin,
# bkz. modul docstring'i) o degeri al. Ilk eslesen kazanir.
FIELD_LABEL_SUFFIXES: dict[str, list[str]] = {
    "SubjectUserName": ["Account Name"],
    "LogonId": ["Logon ID"],
    "ProcessId": ["Process ID", "New Process ID"],
    "NewProcessName": ["New Process Name", "Process Name", "Application Name"],
    "ServiceName": ["Service Name"],
    "SourceIp": ["Source Address"],
    "DestinationIp": ["Destination Address"],
    "SourcePort": ["Source Port"],
    "DestinationPort": ["Destination Port"],
    "FilePath": ["Object Name"],
}

IGNORED_VALUES = {"-", "N/A", "NULL SID"}

# Payload kolonunu icerigine gore bulmak icin: ornek satirlarin en az bu
# orandaki kismi TAGGED_PAYLOAD_RE ile eslesmeli.
MIN_MATCH_RATIO = 0.6
SAMPLE_SIZE = 20


def _find_payload_column(df: pd.DataFrame) -> int | None:
    sample = df.head(SAMPLE_SIZE)
    best_col, best_ratio = None, 0.0
    for col in df.columns:
        values = sample[col].astype(str)
        ratio = values.str.contains(TAGGED_PAYLOAD_RE, regex=True, na=False).mean()
        if ratio > best_ratio:
            best_col, best_ratio = col, ratio
    return best_col if best_ratio >= MIN_MATCH_RATIO else None


def parse_tagged_payload(payload: str) -> dict[str, str]:
    """'<13>Aug 06 ... AgentDevice=WindowsLog\\tComputer=X\\t...\\tMessage=...' seklindeki
    satiri tab-ayracli Key=Value ciftlerine ayirir (son alan Message, satirin
    geri kalanini -- icinde yanlislikla tab gecse bile -- kapsar)."""
    parts = payload.split("\t")
    fields: dict[str, str] = {}
    for i, part in enumerate(parts):
        m = KV_RE.match(part)
        if not m:
            continue
        key = m.group(1)
        value = part[m.end():]
        if key == "Message":
            value = "\t".join([value] + parts[i + 1:])
        fields[key] = value
    return fields


def parse_message_subfields(message: str) -> dict[str, str]:
    return {m.group(1).strip(): m.group(2).strip() for m in LABEL_VALUE_RE.finditer(message)}


def _pick_by_suffix(subfields: dict[str, str], suffixes: list[str]) -> str | None:
    for label, value in subfields.items():
        if value in IGNORED_VALUES or not value:
            continue
        for suffix in suffixes:
            if label.endswith(suffix):
                return value
    return None


def normalize_row(payload: str) -> dict[str, Any]:
    tagged = parse_tagged_payload(payload)
    message = tagged.get("Message", "")
    subfields = parse_message_subfields(message)

    row: dict[str, Any] = {
        "Timestamp": (
            datetime.fromtimestamp(int(tagged["TimeGenerated"])).strftime("%Y-%m-%d %H:%M:%S")
            if tagged.get("TimeGenerated", "").isdigit() else None
        ),
        "EventID": tagged.get("EventID"),
        "Hostname": tagged.get("Computer"),
        "Message": message or None,
    }
    for field, suffixes in FIELD_LABEL_SUFFIXES.items():
        row[field] = _pick_by_suffix(subfields, suffixes)
    return row


def try_convert_qradar_export(file_bytes: bytes) -> list[dict[str, Any]] | None:
    """Dosya QRadar'in headersiz export formatina benziyorsa normalize edilmis
    satirlarin listesini (app/batch/serialize.py'nin rows_to_batch_items'ina
    dogrudan verilebilir), benzemiyorsa None doner -- caller normal
    app.batch.serialize.parse_csv_rows'a dusmeli."""
    try:
        df = pd.read_csv(io.BytesIO(file_bytes), header=None)
    except Exception:
        return None

    payload_col = _find_payload_column(df)
    if payload_col is None:
        return None

    return [normalize_row(str(v)) for v in df[payload_col].astype(str)]
