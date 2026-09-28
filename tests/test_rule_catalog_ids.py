"""Kural katalogu ATT&CK bilgi tabanina karsi: her kural CANLI bir teknige ve
DOGRU adla yazilmali.

NEDEN VAR (K1a, docs/beklenti_K1_kural_kalitesi.md §2): katalog 19.x
yeniden yapilanmasindan once yazilmisti ve kimse ID'leri bilgi tabanina karsi
sinamiyordu. Olculen sonuc:
  - uc kural EMEKLI ID altinda duruyordu (T1070.001, T1562.001, T1562.002);
    model canli ID urettigi icin bu kurallar HIC calismiyordu;
  - T1685.005'in ID'si altinda bir guvenlik duvari kurali vardi. 19.2'de
    T1685.005 = Clear Windows Event Logs. Model dogru teknigi secince kapi onu
    guvenlik duvari kosuluyla sinayip ELIYORDU (dondurulmus 19.2 kosusunda
    rawlog-009, skor 0.1).
Ad karsilastirmasi o ikinci kusuru yakalayan tek sinamadir: kuralin kendi
`name` alani ne yaptigini soyluyordu, ID'si baska bir sey soyluyordu.

Uretilen veriye baglidir (taze klonda atlanir, bkz. tests/generated_data.py).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from tests.generated_data import TEKNIKLER, requires_attack_data

KOK = Path(__file__).resolve().parent.parent
KURALLAR = yaml.safe_load((KOK / "rules" / "attack_mappings.yaml").read_text(encoding="utf-8"))["techniques"]


def _bilgi_tabani() -> dict[str, dict]:
    kayitlar = json.loads(TEKNIKLER.read_text(encoding="utf-8"))
    return {k["attack_id"]: k for k in kayitlar}


@requires_attack_data
def test_every_rule_names_a_live_technique():
    """Emekli ya da kaldirilmis bir ID altindaki kural hicbir secimle
    eslesemez -- sessizce olu bir kuraldir."""
    kb = _bilgi_tabani()
    olu = []
    for r in KURALLAR:
        tid = r["technique_id"]
        kayit = kb.get(tid)
        if kayit is None:
            olu.append(f"{tid}: bilgi tabaninda yok")
        elif kayit.get("revoked") or kayit.get("deprecated"):
            yerine = (kayit.get("revoked_by") or {}).get("attack_id")
            olu.append(f"{tid}: {'revoked -> ' + str(yerine) if kayit.get('revoked') else 'deprecated'}")
    assert not olu, "canli olmayan teknik ID'li kurallar:\n  " + "\n  ".join(olu)


@requires_attack_data
def test_every_rule_name_matches_the_technique_name():
    """Kuralin adi ile ID'sinin bilgi tabanindaki adi ayni olmali. Farkliysa
    kural ya yanlis ID'ye yazilmistir ya da adi bayattir."""
    kb = _bilgi_tabani()
    uyumsuz = [
        f"{r['technique_id']}: kural={r.get('name')!r} / ATT&CK={kb[r['technique_id']]['name']!r}"
        for r in KURALLAR
        if r["technique_id"] in kb and r.get("name") != kb[r["technique_id"]]["name"]
    ]
    assert not uyumsuz, "adi tutmayan kurallar:\n  " + "\n  ".join(uyumsuz)
