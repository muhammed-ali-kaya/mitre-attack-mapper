"""Alti fixture'in KARAR SINIFI ve GEREKCE ZINCIRI (Gorev 5).

Sinif dogru cikip gerekce yanlis olabilir -- bu oturumda ayni desen bes kez
yakalandi. Bu betik zinciri yazdirir ki sinif kadar SEBEP de gozle
denetlenebilsin.

LLM CAGIRMAZ. Karar fonksiyonu deterministik; girdiler fixture loglarindan
ayristiriliyor. Teknik seti ve dogrulanmis kanit disaridan veriliyor
(fixture'larda yaziyor), cunku bu betigin olctugu sey retrieval degil KARAR.
"""
from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.agents.base import AgentDecision, Verdict
from app.agents.verification import VerificationReport
from app.normalization.input_parser import normalize_input
from app.validation.decision import decide

FIXTURES = ROOT / "tests" / "fixtures"
#: Yalnizca T1'in dogrulanmis teknigi var; digerlerinde teknik seti bos.
#: T3/T5'te bu KASITLI -- retrieval T1685'i bulamiyor (2A'nin isi) ve
#: kararin teknik setinden BAGIMSIZ oldugunu tam da bu gosteriyor.
TEKNIKLER = {"T1": ["T1003.002"]}


def _loglar() -> list[dict]:
    kayit = []
    for ad in ("registry_object_access_logs.json", "baseline_suppression_logs.json"):
        kayit += json.loads((FIXTURES / ad).read_text(encoding="utf-8"))["logs"]
    return sorted(kayit, key=lambda l: l["id"])


def main() -> int:
    hatali = 0
    for log in _loglar():
        teknikler = TEKNIKLER.get(log["id"], [])
        mappings = [{"attack_id": t} for t in teknikler]
        rapor = VerificationReport(
            accepted=mappings,
            rejected=[],
            decisions=[
                AgentDecision(agent_id="gate", technique_id=t,
                              verdict=Verdict.CONFIRM, reason="fixture")
                for t in teknikler
            ],
        )
        karar = decide(normalize_input(log["raw"]), mappings, rapor)
        beklenen = log["expected_decision"]
        tutar = karar.decision == beklenen
        hatali += 0 if tutar else 1

        g = karar.inputs
        print("=" * 78)
        print(f"{log['id']}  {log['baslik']}")
        print(f"   KARAR    : {karar.decision}   "
              f"{'OK' if tutar else '!! beklenen ' + beklenen}")
        print(f"   ozet     : {karar.reason}")
        print(f"   girdiler : kritiklik={g['kritiklik']}/{g['kritiklik_ailesi']}  "
              f"erisim={g['erisim_sinifi']}  kanit={g['dogrulanmis_kanit']}  "
              f"teknik={g['teknik_sayisi']}")
        print(f"              aktor={g['aktor']['process']}/{g['aktor']['account']}")
        print(f"   yollar   : A={karar.paths['A']}  B={karar.paths['B']}")
        print("   GEREKCE ZINCIRI:")
        for adim in karar.reason_chain:
            print(f"     - {adim}")

    print("=" * 78)
    print(f"{'TUM FIXTURE`LAR BEKLENTIYE UYUYOR' if not hatali else str(hatali) + ' UYUMSUZ'}")
    return 1 if hatali else 0


if __name__ == "__main__":
    raise SystemExit(main())
