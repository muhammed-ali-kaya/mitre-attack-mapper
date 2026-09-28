"""Teknik bazinda zorunlu kanit kataloglari (kullanici talebi: 'bir MITRE
teknigi belirli artefact'lar gerektiriyorsa bunlarin logda gercekten bulunup
bulunmadigi kontrol edilsin; hicbiri yoksa teknik elensin').

Kasitli olarak kucuk tutuldu: yalnizca kullanicinin belirttigi 3 teknik icin
kanit listesi var. Kapsam disindaki teknikler icin applicable=False doner --
onlar icin app/validation/validator.py'deki mevcut yumusak kontroller
(evidence-alinti kontrolu, grounding kontrolu) gecerliligini korur. Yeni bir
teknik eklemek EVIDENCE_REQUIREMENTS'a tek satir eklemek kadar kolay olmali.

Eslesme: her terim, listedeki DIGERLERINDEN BAGIMSIZ bir alternatif (OR) --
listede gecen terimlerden en az biri girdide bulunursa teknik kaniti
"saglanmis" sayilir. Noktalama farklarina (EventID=1102 vs "EventID 1102",
WMIC.exe vs wmic.exe) tolerandi olmak icin hem girdi hem terimler
karsilastirmadan once normallestirilir (kucuk harf + alfanumerik-disi
karakterler tek bosluga indirgenir)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

_NORMALIZE_RE = re.compile(r"[^a-z0-9]+")


def _normalize(text: str) -> str:
    return _NORMALIZE_RE.sub(" ", text.lower()).strip()


EVIDENCE_REQUIREMENTS: dict[str, list[str]] = {
    "T1685.005": ["wevtutil", "Remove-EventLog", "EventID 1102", "winevt", "*.evtx deletion"],
    "T1047": ["wmic.exe", "WMI", "Win32_Process", "COM WMI", "powershell Get-WmiObject"],
    "T1021.006": ["WinRM", "winrs", "WSMAN", "port 5985", "port 5986"],
}


@dataclass
class EvidenceCheckResult:
    applicable: bool
    satisfied: bool
    found: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)


def check_required_evidence(attack_id: str, raw_input: str) -> EvidenceCheckResult:
    required_terms = EVIDENCE_REQUIREMENTS.get(attack_id)
    if not required_terms:
        return EvidenceCheckResult(applicable=False, satisfied=True)

    normalized_input = _normalize(raw_input)
    found = [t for t in required_terms if _normalize(t) in normalized_input]
    missing = [t for t in required_terms if t not in found]
    return EvidenceCheckResult(applicable=True, satisfied=bool(found), found=found, missing=missing)


# Ham log alan adlarinin Turkce karsiliklari. Bolum eskiden "NewProcessName=
# C:\\...\\schtasks.exe" gibi ciftleri oldugu gibi basiyordu; log alan adlarini
# bilmeyen birine bu hicbir sey anlatmiyor. Ceviri KOD tarafinda, sabit bir
# sozlukle yapiliyor -- bu bolumun tamami LLM'siz uretildigi icin (bkz.
# build_evidence_summary) buraya bir model cagrisi sokmak bolumun tek garantisini
# bozardi. Sozlukte olmayan alan adi oldugu gibi birakilir: uydurma bir Turkce
# karsilik, anlasilmaz ama dogru olan orijinalden kotudur.
FACT_LABELS_TR: dict[str, str] = {
    "EventID": "Olay kimligi",
    "EventCode": "Olay kimligi",
    "NewProcessName": "Calistirilan surec",
    "ProcessName": "Surec",
    "ParentProcessName": "Ust surec",
    "CommandLine": "Komut satiri",
    "SubjectUserName": "Islemi yapan hesap",
    "TargetUserName": "Hedef hesap",
    "TargetDomainName": "Hedef alan adi",
    "WorkstationName": "Is istasyonu",
    "LogonType": "Oturum acma turu",
    "SourceIp": "Kaynak adres",
    "DestinationIp": "Hedef adres",
    "ServiceName": "Servis adi",
    "ImagePath": "Calistirilabilir dosya yolu",
    "ObjectName": "Erisilen nesne",
    "ShareName": "Paylasim adi",
    "AccessMask": "Erisim maskesi",
    "AccessList": "Erisim listesi",
}


def _humanize_fact(key: str, value: str) -> str:
    return f"{FACT_LABELS_TR.get(key, key)}: {value}"


def build_evidence_summary(
    extracted_facts: dict[str, str],
    mappings: list[dict[str, Any]],
    rejected_mappings: list[dict[str, Any]],
) -> dict[str, list[str]]:
    """Rapor sonu 'Loglardan cikarilan kanit' bolumu -- sadece kod tarafinda
    uretilir, LLM ciktisi hic kullanilmaz, bu yuzden 'assumed' hep bos doner."""
    detected = [_humanize_fact(k, v) for k, v in extracted_facts.items()]
    not_detected: list[str] = []

    for m in list(mappings) + list(rejected_mappings):
        check = m.get("evidence_check") or {}
        if not check.get("applicable"):
            continue
        for term in check.get("found", []):
            item = f"{m.get('attack_id')} icin beklenen kanit: {term}"
            if item not in detected:
                detected.append(item)
        for term in check.get("missing", []):
            item = f"{m.get('attack_id')} icin beklenen kanit: {term}"
            if item not in not_detected:
                not_detected.append(item)

    return {"detected": detected, "not_detected": not_detected, "assumed": []}
