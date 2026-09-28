"""Kutupsallik (polarity): bir log satiri guvenlik kontrolunun CALISTIGINI mi
yoksa BOZULDUGUNU mu gosteriyor?

Bu ayrim projedeki en pahali hatanin kok nedeniydi. Gercek bir kosuda
"The Windows Filtering Platform has permitted a connection" (EventID 5156)
satiri T1686.003 'Windows Host Firewall' teknigine, 14 kez, eslestirilmisti.
Oysa o satir guvenlik duvarinin CALISTIGININ kanitidir -- bir baglantiyi
denetleyip izin vermistir. Guvenlik duvarinin devre disi birakildigi kaydi
degildir. Ayni veri setinde guvenlik duvari degisikligi olaylari (4946-4954,
5025) hic yoktu; yani teknik tumuyle uydurulmustu.

Uc durum yerine dort: ENFORCING / BREAKING / AMBIGUOUS / NEUTRAL.
AMBIGUOUS ayri tutuluyor cunku "izin verildi" ve "devre disi" ifadelerinin
ikisini birden tasiyan bir satir, Impair Defenses ailesi icin kanit
SAYILMAMALI -- karar veremiyorsak tetiklemeyiz."""

from __future__ import annotations

import re
from enum import Enum


class Polarity(str, Enum):
    ENFORCING = "enforcing"      # kontrol calisti (izin verdi / engelledi / denetledi)
    BREAKING = "breaking"        # kontrol bozuldu (kapatildi / silindi / atlatildi)
    AMBIGUOUS = "ambiguous"      # ikisine de isaret eden ifadeler var
    NEUTRAL = "neutral"          # ikisi de yok


# Kontrolun CALISTIGINI gosteren ifadeler. Dikkat: "blocked"/"denied" de bu
# gruba girer -- bir baglantinin engellenmesi guvenlik duvarinin calistigi
# anlamina gelir, bozuldugu degil. Bu, sezgiye aykiri gorunup en cok yanlis
# yapilan yerdir.
_ENFORCING_PATTERNS = [
    r"\bhas permitted\b",
    r"\bpermitted\b",
    r"\ballowed\b",
    r"\bwas allowed\b",
    r"\bblocked\b",
    r"\bdenied\b",
    r"\bprevented\b",
    r"\bquarantined\b",
    r"\baudit success\b",
    r"\bsuccess audit\b",
]

# Kontrolun BOZULDUGUNU gosteren ifadeler.
_BREAKING_PATTERNS = [
    r"\bdisabled\b",
    r"\bturned off\b",
    r"\bstopped\b",
    r"\bshut down\b",
    r"\bbypass(ed)?\b",
    r"\bdeleted\b",
    r"\bremoved\b",
    r"\bcleared\b",
    r"\bwas changed\b",
    r"\bhas been made to\b",
    r"\brule (added|deleted|modified|changed)\b",
    r"\bexception list\b",
    r"\baudit polic(y|ies) (was |were )?changed\b",
    r"\bsetting.{0,30}changed\b",
    r"\bunloaded\b",
    r"\btampered\b",
]

_ENFORCING_RE = [re.compile(p, re.IGNORECASE) for p in _ENFORCING_PATTERNS]
_BREAKING_RE = [re.compile(p, re.IGNORECASE) for p in _BREAKING_PATTERNS]


def classify(text: str | None) -> Polarity:
    """Serbest metinden (genellikle Windows olay Message alani) kutupsallik."""
    if not text:
        return Polarity.NEUTRAL

    enforcing = any(r.search(text) for r in _ENFORCING_RE)
    breaking = any(r.search(text) for r in _BREAKING_RE)

    if enforcing and breaking:
        return Polarity.AMBIGUOUS
    if enforcing:
        return Polarity.ENFORCING
    if breaking:
        return Polarity.BREAKING
    return Polarity.NEUTRAL


# Impair Defenses ailesi: bu on ekleri tasiyan teknikler YALNIZCA BREAKING
# kanittan uretilebilir. Aile uyeligi teknik ID'sinden turetiliyor ki YAML'a
# yeni bir alt teknik eklendiginde koruma kendiliginden gecerli olsun.
_IMPAIR_DEFENSES_PREFIXES = ("T1562", "T1685", "T1686")


def is_impair_defenses(technique_id: str) -> bool:
    return technique_id.startswith(_IMPAIR_DEFENSES_PREFIXES)


def evidence_allowed(technique_id: str, polarity: Polarity) -> bool:
    """Bu kutupsalliktaki bir satir, bu teknige kanit olabilir mi?

    Impair Defenses disindaki teknikler icin kutupsallik bir engel degil
    (orn. T1059.001 PowerShell calistirma, 'success audit' satirindan
    uretilebilir). Aile icindeyse yalnizca BREAKING kabul edilir."""
    if not is_impair_defenses(technique_id):
        return True
    return polarity is Polarity.BREAKING
