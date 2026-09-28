"""CSV/JSON toplu yukleme: yapilandirilmis satirlari (EventID, ProcessName,
CommandLine, ... gibi ayri sutunlar) mevcut pipeline'in zaten anladigi
Key=Value raw-log metnine cevirir.

Felsefe: app/normalization/input_parser.py hic degistirilmiyor. Onun genel
KEY_VALUE_RE regex'i zaten herhangi bir "Key=Value" ciftini extracted_facts'e
yakaliyor -- bu yuzden burada satir sutunlarini Key=Value formatinda birlestirmek
yeterli, ayri bir sutun-esleme/parse katmani gerekmiyor. Iki kucuk uyumluluk
notu:

1. PROCESS_NAME_RE/USER_RE (input_parser.py) yalnizca "NewProcessName"/
   "SubjectUserName" anahtarlarini taniyor -- bu yuzden yaygin es anlamlilari
   (ProcessName, User, ...) burada CANONICAL_FIELD_ALIASES ile bu anahtarlara
   cevriliyor. Bu yalnizca kozmetik "Girdi Normalizasyonu" panelini ve QRadar
   taslagini etkiler; extracted_facts (genel KEY_VALUE_RE ile dolduruluyor) ve
   LLM'e giden ham metin etkilenmiyor.
2. COMMAND_LINE_RE (input_parser.py) `CommandLine=...` degerini satir sonuna
   kadar (bir sonraki Key=Value ciftini de yutarak) yakaliyor -- bilinen, test
   edilmemis bir onceden var olan kisitlama. Bunu duzeltmek yerine (kapsam
   disi), CommandLine ciftini serilestirilen metnin HER ZAMAN EN SONUNA
   koyuyoruz, boylece yutacak bir sey kalmiyor.
"""

from __future__ import annotations

import io
import json
import math
import re
from typing import Any

import pandas as pd

CANONICAL_FIELD_ALIASES: dict[str, str] = {
    "processname": "NewProcessName", "process": "NewProcessName",
    "newprocessname": "NewProcessName", "image": "NewProcessName",
    "user": "SubjectUserName", "username": "SubjectUserName",
    "subjectusername": "SubjectUserName", "useraccount": "SubjectUserName",
    "eventid": "EventID", "event_id": "EventID",
    "commandline": "CommandLine", "command_line": "CommandLine", "command": "CommandLine",
    # Correlation engine (app/correlation/) alan adlari -- Sysmon/Windows Event
    # Log'da ayni bilgi icin yaygin kullanilan es anlamlilari kanonik isimlere
    # cevirir, boylece CSV kolon adlandirmasi ne olursa olsun correlation
    # motoru ayni alan adlarini gorur.
    "hostname": "Hostname", "computer": "Hostname", "computername": "Hostname",
    "sourceip": "SourceIp", "srcip": "SourceIp", "sourceaddress": "SourceIp", "src": "SourceIp",
    "destinationip": "DestinationIp", "dstip": "DestinationIp",
    "destip": "DestinationIp", "destinationaddress": "DestinationIp", "dst": "DestinationIp",
    "processguid": "ProcessGuid",
    "parentprocessguid": "ParentProcessGuid",
    "processid": "ProcessId", "newprocessid": "ProcessId", "pid": "ProcessId",
    "parentprocessid": "ParentProcessId", "ppid": "ParentProcessId",
    "logonid": "LogonId", "targetlogonid": "LogonId",
    "sessionid": "SessionId",
    "servicename": "ServiceName",
    "filepath": "FilePath", "targetfilename": "FilePath",
    "timestamp": "Timestamp", "eventtime": "Timestamp", "utctime": "Timestamp", "@timestamp": "Timestamp",
}

PLATFORM_COLUMN_NAMES = {"platform", "os", "operatingsystem"}
PLATFORM_VALUE_MAP = {"windows": "Windows", "linux": "Linux", "macos": "macOS", "osx": "macOS"}

_INVALID_KEY_CHARS_RE = re.compile(r"[^A-Za-z0-9_]")


def _sanitize_key(key: str) -> str:
    alias = CANONICAL_FIELD_ALIASES.get(str(key).strip().casefold())
    if alias:
        return alias
    cleaned = _INVALID_KEY_CHARS_RE.sub("", str(key).strip())
    if not cleaned or not re.match(r"[A-Za-z_]", cleaned[0]):
        cleaned = f"_{cleaned}"
    return cleaned


def _format_kv_value(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, float):
        if math.isnan(value):
            return None
        if value.is_integer():
            value = int(value)
    if isinstance(value, (list, dict)):
        text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    else:
        text = str(value)
    text = text.strip()
    if not text:
        return None
    if re.search(r"\s", text):
        escaped = text.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return text


def extract_platform_override(row: dict[str, Any]) -> str | None:
    for key, value in row.items():
        if key is None or str(key).strip().casefold() not in PLATFORM_COLUMN_NAMES:
            continue
        if value is None:
            continue
        mapped = PLATFORM_VALUE_MAP.get(str(value).strip().casefold())
        if mapped:
            return mapped
    return None


def row_to_kv_string(row: dict[str, Any]) -> str:
    platform_keys = {k for k in row if k is not None and str(k).strip().casefold() in PLATFORM_COLUMN_NAMES}

    pairs: list[tuple[str, str]] = []
    commandline_pair: tuple[str, str] | None = None
    for key, value in row.items():
        if key in platform_keys:
            continue
        formatted = _format_kv_value(value)
        if formatted is None:
            continue
        sanitized_key = _sanitize_key(key)
        if sanitized_key == "CommandLine":
            commandline_pair = (sanitized_key, formatted)
        else:
            pairs.append((sanitized_key, formatted))

    if commandline_pair:
        pairs.append(commandline_pair)

    return " ".join(f"{k}={v}" for k, v in pairs)


def canonicalize_row(row: dict[str, Any]) -> dict[str, Any]:
    """Ham CSV/JSON satirinin kolon adlarini kanonik isimlere cevirir.

    Neden ayri bir fonksiyon: row_to_kv_string ayni cevrimi yapiyor ama
    ciktisi bir METIN. Kapsam analizi (app/mapping/coverage.py) satirin
    "EventID" alanina SOZLUK olarak bakmak zorunda -- kullanicinin CSV'sinde
    kolon adi 'event_id' de olsa 'EventID' de olsa ayni sonucu vermeli.
    Ayni takma-ad tablosunu iki yerde tutmamak icin tek kaynak burasi."""
    canonical: dict[str, Any] = {}
    for key, value in row.items():
        if key is None:
            continue
        canonical[_sanitize_key(key)] = value
    return canonical


def parse_csv_rows(file_bytes: bytes) -> list[dict[str, Any]]:
    df = pd.read_csv(io.BytesIO(file_bytes))
    df = df.astype(object).where(pd.notnull(df), None)
    return df.to_dict("records")


def parse_json_rows(file_bytes: bytes) -> list[dict[str, Any]]:
    data = json.loads(file_bytes.decode("utf-8"))
    if not isinstance(data, list) or not all(isinstance(item, dict) for item in data):
        raise ValueError("JSON dosyasi bir nesne listesi (array) olmalidir")
    return data


def rows_to_batch_items(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items = []
    for i, row in enumerate(rows):
        raw_log = row_to_kv_string(row)
        skipped = not raw_log.strip()
        items.append({
            "index": i,
            "raw_log": raw_log,
            "platform": extract_platform_override(row),
            "source_row": row,
            "skipped": skipped,
            "skip_reason": "satir bos (tum alanlar bos/None)" if skipped else None,
        })
    return items
