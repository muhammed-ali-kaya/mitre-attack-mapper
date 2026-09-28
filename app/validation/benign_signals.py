"""Girdide MESRU/ONAYLI aktiviteye isaret eden sinyalleri arar.

Neden var: sistem hicbir zaman "bu normal is" demiyordu. 60 senaryoluk test
setinde 9 negatif/belirsiz ornegin 9'unda da yanlis pozitif uretti -- onayli
degisiklik talebiyle kurulan zamanlanmis gorev T1053.005, Windows Update
(wuauclt.exe /detectnow) T1569.002, sirket ici Nexus deposundan curl ile paket
cekme T1567.001 (veri sizdirma) olarak isaretlendi. Bir SOC ekibi icin bu
kabul edilemez: alarm yorgunlugu operasyonel olarak en pahali sorun.

Tasarim kararlari:

1. TAMAMEN DETERMINISTIK. LLM cagirmaz. Sebep: yanlis pozitifi azaltmak icin
   ikinci bir olasiliksal katman eklemek, hatanin kaynagini belirsizlestirirdi.
   Burada bulunan her sinyalin girdide birebir karsiligi var ve gosterilebilir.

2. BASTIRMAZ, ISARETLER. Sinyaller eslestirmeleri silmez; "bu aktivite mesru
   olabilir" uyarisi uretir ve guven skorunu dusurur. Sebep: sinyaller
   taklit edilebilir -- saldirgan komut satirina "ticket #4521" yazabilir.
   Kanit gosterip karari analiste birakmak, sessizce gizlemekten guvenli.

3. Sinyaller GEREKCESIYLE doner. "Supheli degil" demek yetmez; analist neden
   oyle dendigini gormeli, aksi halde katman bir kara kutu olur.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Degisiklik/talep kaydi referanslari. Bir islemin onaylanmis bir is kaydina
# bagli olmasi, SOC'un "yetkili mi" sorusunun standart cevabi.
_TICKET_PATTERNS = [
    re.compile(r"\b(?:ticket|talep|kayit|case|inc|req)\s*#?\s*\d{3,}\b", re.IGNORECASE),
    re.compile(r"\b(?:CHG|INC|REQ|RITM|TASK)\d{5,}\b", re.IGNORECASE),
    re.compile(r"\bdegisiklik\s+talebi\b", re.IGNORECASE),
    re.compile(r"\bchange\s+request\b", re.IGNORECASE),
]

# Onay/yetki dili. Tek basina zayif; diger sinyallerle birlikte anlamli.
_AUTHORIZATION_PATTERNS = [
    re.compile(r"\bonayl[ıi]\b", re.IGNORECASE),
    re.compile(r"\byetkilendiril(?:mis|di)\b", re.IGNORECASE),
    re.compile(r"\bimzal[ıi]\b", re.IGNORECASE),
    re.compile(r"\bapproved\b", re.IGNORECASE),
    re.compile(r"\bauthoriz(?:ed|ation)\b", re.IGNORECASE),
    re.compile(r"\bsigned\b", re.IGNORECASE),
    re.compile(r"\bplanl[ıi]\s+bak[ıi]m\b", re.IGNORECASE),
    re.compile(r"\bscheduled\s+maintenance\b", re.IGNORECASE),
]

# Kendi isini yaparken surekli log ureten Windows sistem surecleri. Bunlari
# saldiri olarak isaretlemek klasik bir yanlis pozitif kaynagi.
_ROUTINE_SYSTEM_PROCESSES = {
    "wuauclt.exe": "Windows Update istemcisi",
    "tiworker.exe": "Windows Modules Installer",
    "trustedinstaller.exe": "Windows Modules Installer",
    "msmpeng.exe": "Microsoft Defender tarama motoru",
    "mpcmdrun.exe": "Microsoft Defender komut satiri araci",
    "sppsvc.exe": "Windows yazilim koruma servisi",
    "usoclient.exe": "Windows Update orkestratoru",
    "compattelrunner.exe": "Windows uyumluluk telemetrisi",
    "searchindexer.exe": "Windows arama dizinleyici",
}

# Kurum ici altyapi adlari: bunlara giden trafik "disari veri cikisi" degil.
_INTERNAL_INFRA_PATTERNS = [
    re.compile(r"\bnexus\b", re.IGNORECASE),
    re.compile(r"\bartifactory\b", re.IGNORECASE),
    re.compile(r"\b(?:sirket|kurum)\s*(?:-|\s)?\s*(?:ici|internal)\b", re.IGNORECASE),
    re.compile(r"\binternal\s+(?:repo|registry|mirror|server)\b", re.IGNORECASE),
    re.compile(r"\bdahili\b", re.IGNORECASE),
    re.compile(r"\.(?:local|internal|corp|lan)\b", re.IGNORECASE),
]

# Rutin IT rollerinin adi gecen girdiler. Zayif sinyal -- yalnizca destekleyici.
_IT_ROLE_PATTERNS = [
    re.compile(r"\b(?:bt|it)\s+depart(?:man[ıi]|ment)\b", re.IGNORECASE),
    re.compile(r"\bsistem\s+y[oö]neticisi\b", re.IGNORECASE),
    re.compile(r"\byard[ıi]m\s+masas[ıi]\b", re.IGNORECASE),
    re.compile(r"\bhelp\s*desk\b", re.IGNORECASE),
    re.compile(r"\bgelistirici\b", re.IGNORECASE),
]


@dataclass
class BenignSignals:
    """Bulunan mesruiyet sinyalleri. signals listesi analiste gosterilir."""

    signals: list[str] = field(default_factory=list)
    strong: bool = False

    @property
    def found(self) -> bool:
        return bool(self.signals)


def _matches(patterns: list[re.Pattern[str]], text: str) -> str | None:
    for pattern in patterns:
        match = pattern.search(text)
        if match:
            return match.group(0).strip()
    return None


def detect_benign_signals(raw_input: str) -> BenignSignals:
    """Girdideki mesruiyet sinyallerini toplar.

    'strong', tek basina bir aktiviteyi mesru saymaya yetecek kadar belirgin
    bir sinyal bulundugunu soyler: onayli bir is kaydi referansi, ya da rutin
    bir Windows sistem sureci. Digerleri (onay dili, IT rolu, ic altyapi) tek
    baslarina zayif -- ikisi bir araya gelirse guclu sayilir."""
    result = BenignSignals()
    if not raw_input:
        return result

    text = raw_input
    lowered = text.lower()
    weak_count = 0

    ticket = _matches(_TICKET_PATTERNS, text)
    if ticket:
        result.signals.append(f"Onayli is kaydi referansi: \"{ticket}\"")
        result.strong = True

    for process, description in _ROUTINE_SYSTEM_PROCESSES.items():
        if process in lowered:
            result.signals.append(f"Rutin Windows sistem sureci: {process} ({description})")
            result.strong = True
            break

    authorization = _matches(_AUTHORIZATION_PATTERNS, text)
    if authorization:
        result.signals.append(f"Yetki/onay ifadesi: \"{authorization}\"")
        weak_count += 1

    internal = _matches(_INTERNAL_INFRA_PATTERNS, text)
    if internal:
        result.signals.append(f"Kurum ici altyapi referansi: \"{internal}\"")
        weak_count += 1

    role = _matches(_IT_ROLE_PATTERNS, text)
    if role:
        result.signals.append(f"Rutin BT rolu: \"{role}\"")
        weak_count += 1

    # Iki zayif sinyalin ust uste binmesi (orn. "sistem yoneticisi" + "imzali")
    # tek basina bir ticket referansi kadar aciklayici.
    if weak_count >= 2:
        result.strong = True

    return result
