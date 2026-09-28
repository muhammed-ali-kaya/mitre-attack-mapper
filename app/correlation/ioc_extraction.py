"""Incident icin IOC/artefact ozeti: suspicious processes, network
connections, downloaded files, created services/users, registry changes,
credential access. Tamamen deterministik -- bilinen Sysmon/Windows Security
EventID'leri ve anahtar kelime tablolariyla calisir, LLM kullanilmaz.

NOT (Ö1, 2026-08-17): burada atif yapilan QUERY_ENRICHMENT tablosu
KALDIRILDI -- teknik ADINI sorguya enjekte ediyordu, yani retrieval
yerine kopya cekiyordu. Buradaki tablolar AYNI RISKI TASIMIYOR: ciktilari
IOC/artefakt etiketleri (dosya, servis, baglanti), teknik adi degil ve
retrieval sorgusuna girmiyorlar. Yine de Gorev 12'de veriye tasinmalari
gerekiyor -- kod icinde tablo olmalari ayri bir sorun."""

from __future__ import annotations

from typing import Any

from app.correlation.fields import extract_event_id
from app.normalization.input_parser import normalize_input

PROCESS_CREATE_EVENT_IDS = {"1", "4688"}
NETWORK_CONNECT_EVENT_IDS = {"3"}
SERVICE_INSTALL_EVENT_IDS = {"7045", "4697"}
USER_CREATE_EVENT_IDS = {"4720"}
REGISTRY_EVENT_IDS = {"12", "13", "14"}
CREDENTIAL_ACCESS_EVENT_IDS = {"10"}

DOWNLOAD_INDICATORS = [
    "downloadfile", "downloadstring", "invoke-webrequest", "iwr ",
    "certutil -urlcache", "certutil.exe -urlcache", "bitsadmin", "wget ", "curl ",
]
CREDENTIAL_KEYWORDS = ["lsass", "mimikatz", "sekurlsa"]
HASH_FIELD_NAMES = {"hash", "sha256", "sha1", "md5"}


def _row_facts(item: dict[str, Any]) -> dict[str, Any]:
    normalized = normalize_input(item["raw_log"])
    return normalized["extracted_facts"]


def extract_incident_iocs(items: list[dict[str, Any]], indices: list[int]) -> dict[str, list[dict[str, Any]]]:
    by_index = {it["index"]: it for it in items}

    suspicious_processes: list[dict[str, Any]] = []
    suspicious_network_connections: list[dict[str, Any]] = []
    downloaded_files: list[dict[str, Any]] = []
    created_services: list[dict[str, Any]] = []
    created_users: list[dict[str, Any]] = []
    registry_changes: list[dict[str, Any]] = []
    credential_access: list[dict[str, Any]] = []
    ioc_list: list[dict[str, str]] = []
    seen_iocs: set[tuple[str, str]] = set()

    def _add_ioc(ioc_type: str, value: str | None) -> None:
        if not value:
            return
        key = (ioc_type, value.casefold())
        if key in seen_iocs:
            return
        seen_iocs.add(key)
        ioc_list.append({"type": ioc_type, "value": value})

    for row_index in indices:
        item = by_index[row_index]
        source_row = item["source_row"]
        fields = item["correlation_fields"]
        facts = _row_facts(item)
        event_id = extract_event_id(source_row)
        command_line = (facts.get("CommandLine") or "").lower()
        process_name = facts.get("NewProcessName")
        target_image = (facts.get("TargetImage") or "").lower()

        base = {"row_index": row_index, "hostname": fields.get("Hostname"), "user": fields.get("SubjectUserName")}

        if event_id in PROCESS_CREATE_EVENT_IDS or process_name:
            suspicious_processes.append({
                **base, "process_name": process_name,
                "command_line": facts.get("CommandLine"), "process_id": fields.get("ProcessId"),
            })
            _add_ioc("process", process_name)

        if event_id in NETWORK_CONNECT_EVENT_IDS or fields.get("SourceIp") or fields.get("DestinationIp"):
            suspicious_network_connections.append({
                **base, "source_ip": fields.get("SourceIp"), "destination_ip": fields.get("DestinationIp"),
            })
            _add_ioc("ip", fields.get("SourceIp"))
            _add_ioc("ip", fields.get("DestinationIp"))

        if any(indicator in command_line for indicator in DOWNLOAD_INDICATORS):
            downloaded_files.append({**base, "command_line": facts.get("CommandLine"), "file_path": fields.get("FilePath")})
            _add_ioc("file_path", fields.get("FilePath"))

        if event_id in SERVICE_INSTALL_EVENT_IDS or fields.get("ServiceName"):
            created_services.append({**base, "service_name": fields.get("ServiceName")})
            _add_ioc("service", fields.get("ServiceName"))

        if event_id in USER_CREATE_EVENT_IDS:
            created_users.append({**base, "target_user": facts.get("TargetUserName") or facts.get("SubjectUserName")})

        if event_id in REGISTRY_EVENT_IDS or facts.get("TargetObject"):
            registry_changes.append({**base, "target_object": facts.get("TargetObject")})

        is_credential_access = (
            event_id in CREDENTIAL_ACCESS_EVENT_IDS
            or "lsass" in target_image
            or "lsass" in (process_name or "").lower()
            or any(k in command_line for k in CREDENTIAL_KEYWORDS)
            or any(k in (process_name or "").lower() for k in CREDENTIAL_KEYWORDS)
        )
        if is_credential_access:
            credential_access.append({**base, "process_name": process_name, "target_image": facts.get("TargetImage")})

        if fields.get("FilePath"):
            _add_ioc("file_path", fields.get("FilePath"))
        for key, value in facts.items():
            if key.casefold() in HASH_FIELD_NAMES and value:
                _add_ioc("hash", value)

    return {
        "suspicious_processes": suspicious_processes,
        "suspicious_network_connections": suspicious_network_connections,
        "downloaded_files": downloaded_files,
        "created_services": created_services,
        "created_users": created_users,
        "registry_changes": registry_changes,
        "credential_access": credential_access,
        "ioc_list": ioc_list,
    }
