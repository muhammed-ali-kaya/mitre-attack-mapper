"""Incident seviyesinde MITRE ATT&CK 'kill chain' gorunumu: tekillestirilmis
teknikleri kanonik taktik sirasina gore fazlara (phase) ayirir.

Siralama data/processed/tactics.json'daki shortname'lere (TA-numaralarina
karsilik gelen klasik Enterprise matrisi sirasi) gore sabitlenmistir --
JSON dosyasindaki kayit sirasi rastgele oldugu icin (bkz. app/parsers/
stix_parser.py) buradan bir siralama cikarilamaz. Bu projenin ATT&CK v19.1
(ve v19.2) verisi 'Defense Evasion' taktigini 'Stealth' olarak yeniden adlandirmis ve
ayrica 'Defense Impairment' adinda yeni bir taktik eklemis (techniques.json'da
dogrulandi) -- ikisi de Privilege Escalation ile Credential Access arasina
yerlestirildi."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

TACTICS_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "processed" / "tactics.json"

_SHORTNAME_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "stealth", "defense-impairment",
    "credential-access", "discovery", "lateral-movement", "collection",
    "command-and-control", "exfiltration", "impact",
]


def _load_tactic_order() -> list[str]:
    try:
        tactics = json.loads(TACTICS_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return [sn.replace("-", " ").title() for sn in _SHORTNAME_ORDER]
    names_by_shortname = {t["shortname"]: t["name"] for t in tactics}
    ordered = [names_by_shortname[sn] for sn in _SHORTNAME_ORDER if sn in names_by_shortname]
    # tactics.json'da olup siralama listesinde olmayan (ileride eklenebilecek) bir
    # taktik varsa sessizce yok sayilmasin -- sona eklenir.
    ordered += [name for name in names_by_shortname.values() if name not in ordered]
    return ordered


TACTIC_ORDER: list[str] = _load_tactic_order()


def primary_tactic(technique: dict[str, Any]) -> str | None:
    """Teknigin kill chain'de cizilecegi tek faz: ait oldugu taktikler icinden
    kanonik sirada EN ERKEN olani.

    Neden en erken: kill chain bir zaman/ilerleme anlatisi. T1053.005 hem
    Execution hem Persistence'a ait; saldirgan once calistirir, sonra kalici
    olur -- teknigi Execution'da gostermek akisi dogru kurar. Teknigin diger
    taktikleri kaybolmuyor, MITRE Matrix tablosunda tam liste duruyor."""
    tactics = technique.get("tactics") or []
    if not tactics:
        return None
    ordered = [t for t in TACTIC_ORDER if t in tactics]
    return ordered[0] if ordered else tactics[0]


def build_attack_chain(
    deduped_techniques: list[dict[str, Any]], *, primary_tactic_only: bool = True
) -> list[dict[str, Any]]:
    """Tekillestirilmis teknikleri taktik fazlarina dagitir; yalnizca en az bir
    teknigi olan fazlar kanonik TACTIC_ORDER sirasiyla doner.

    primary_tactic_only=True (varsayilan): her teknik YALNIZCA birincil
    taktiginde cizilir. Gerekce: bir teknik ait oldugu her faza konuldugunda
    gercek bir kosuda 31 teknik ~60 dugume cikiyor ve diyagram okunamiyordu
    (T1543.003 hem Persistence hem Privilege Escalation, T1547.* dorder kez...).
    Teknigin tum taktikleri MITRE Matrix tablosunda gorunmeye devam ediyor.

    primary_tactic_only=False: eski davranis -- teknik ait oldugu HER fazda
    tekrarlanir (MITRE'ye birebir sadik gorunum)."""
    by_tactic: dict[str, list[dict[str, Any]]] = {}
    for technique in deduped_techniques:
        if primary_tactic_only:
            tactics = [primary_tactic(technique)] if primary_tactic(technique) else []
        else:
            tactics = technique.get("tactics") or []
        for tactic in tactics:
            by_tactic.setdefault(tactic, []).append(technique)

    chain = []
    for tactic in TACTIC_ORDER:
        if tactic in by_tactic:
            chain.append({"tactic": tactic, "techniques": by_tactic[tactic]})
    # TACTIC_ORDER'da olmayan (beklenmedik) bir taktik adi gelirse yine de
    # gosterilsin -- sessizce kaybolmasin.
    for tactic, techniques in by_tactic.items():
        if tactic not in TACTIC_ORDER:
            chain.append({"tactic": tactic, "techniques": techniques})
    return chain
