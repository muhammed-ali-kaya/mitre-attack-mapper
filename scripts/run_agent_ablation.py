"""Ajan katmani ablasyonu: 60 senaryoda "katman acik" vs "katman kapali".

NEDEN TEK KOSU: ajan katmani yalnizca eleyebilir ya da guven dusurebilir --
teknik EKLEYEMEZ (bkz. app/agents/base.py). Bu yuzden "katman kapali" hali,
katmanin ONUNDEKI listeden ibarettir; senaryolari iki kez kosturmak gerekmez.
improved_pipeline o listeyi `mappings_before_agents` altinda sakliyor.
Sonuc yaklasik degil BIREBIR: ayni LLM ciktisi uzerinden iki metrik takimi.

Ikinci fayda: LLM cagrisi tek, yani ~25 dakika yerine ~50 dakika harcamiyoruz
ve iki kolun farki modelin orneklem gurultusunden etkilenmiyor.
"""

from __future__ import annotations

import json
import sys
import traceback
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.evaluation.metrics import (
    hallucination_rate,
    hierarchical_score,
    is_correct_abstention,
)
from app.evaluation.run_hygiene import prepare_run, shuffled
from app.retrieval.improved_pipeline import run_improved_query

SCENARIOS_FILE = PROJECT_ROOT / "evaluation" / "test_scenarios.json"
TECHNIQUES_FILE = PROJECT_ROOT / "data" / "processed" / "techniques.json"
RESULTS_DIR = PROJECT_ROOT / "evaluation" / "results"
OUT_FILE = RESULTS_DIR / "agent_ablation.jsonl"
SUMMARY_FILE = RESULTS_DIR / "agent_ablation_summary.json"

# Kosu basinda doldurulur; ozete yazilir ki sonuc hangi kosullarda
# uretildigi bilinmeden yorumlanmasin.
_HYGIENE: dict = {}


def score_arm(mappings: list[dict], scenario: dict, kb_by_id: dict) -> dict:
    predicted_ids = [m["attack_id"] for m in mappings]
    return {
        "predicted_ids": predicted_ids,
        "n_techniques": len(predicted_ids),
        "hierarchical_score": hierarchical_score(predicted_ids, scenario, kb_by_id),
        "correct_abstention": is_correct_abstention(mappings, scenario),
        "hallucination_rate": hallucination_rate(mappings, kb_by_id),
        "n_high_confidence": sum(
            1 for m in mappings if (m.get("confidence_level") or "").lower() == "high"
        ),
    }


def main() -> None:
    scenarios = json.loads(SCENARIOS_FILE.read_text(encoding="utf-8"))
    techniques = json.loads(TECHNIQUES_FILE.read_text(encoding="utf-8"))
    kb_by_id = {t["attack_id"]: t for t in techniques}

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_FILE.open("w", encoding="utf-8")
    rows: list[dict] = []

    # Olcum hijyeni: isinma cagrisi + sabit seed'li karistirma.
    # Gerekce olculdu -- ilk sorgu soguk modele gider ve soguk model ayni
    # girdiye farkli cevap verir (bkz. app/evaluation/run_hygiene.py).
    # Sabit sirada bu, hep AYNI senaryonun bozuk olculmesi demektir.
    global _HYGIENE
    _HYGIENE = prepare_run()
    print(f"hijyen: {_HYGIENE}", flush=True)
    scenarios = shuffled(scenarios)

    for i, scenario in enumerate(scenarios, start=1):
        print(f"[{i}/{len(scenarios)}] {scenario['test_id']} ({scenario['category']})", flush=True)
        try:
            result = run_improved_query(scenario["input"], platform=scenario.get("platform"))
        except Exception as e:
            print(f"  HATA: {e}", flush=True)
            traceback.print_exc()
            row = {"test_id": scenario["test_id"], "category": scenario["category"], "error": str(e)}
            rows.append(row)
            out.write(json.dumps(row, ensure_ascii=False) + "\n")
            out.flush()
            continue

        with_agents = score_arm(result.get("mappings") or [], scenario, kb_by_id)
        without_agents = score_arm(
            result.get("mappings_before_agents") or [], scenario, kb_by_id
        )

        rejected = result.get("agent_rejected_mappings") or []
        decisions = result.get("agent_decisions") or []
        row = {
            "test_id": scenario["test_id"],
            "category": scenario["category"],
            "expected": scenario.get("expected_attack_ids"),
            "negative_case": scenario.get("negative_case"),
            "with_agents": with_agents,
            "without_agents": without_agents,
            "n_agent_rejected": len(rejected),
            "rejected_ids": [m.get("attack_id") for m in rejected],
            "rejected_reasons": [
                f"{m.get('agent_id')}: {m.get('agent_reason')}" for m in rejected
            ],
            "n_decisions": len(decisions),
            "agent_seconds": (result.get("timings") or {}).get("agent_verification_seconds"),
            "total_seconds": (result.get("timings") or {}).get("total_seconds"),
        }
        rows.append(row)
        out.write(json.dumps(row, ensure_ascii=False) + "\n")
        out.flush()

        delta = with_agents["hierarchical_score"] - without_agents["hierarchical_score"]
        mark = "=" if abs(delta) < 1e-9 else ("+" if delta > 0 else "-")
        print(
            f"  kapali={without_agents['hierarchical_score']:.3f} "
            f"acik={with_agents['hierarchical_score']:.3f} [{mark}] "
            f"elenen={len(rejected)}",
            flush=True,
        )

    out.close()
    summarize(rows)


def _mean(values: list[float]) -> float:
    usable = [v for v in values if v is not None]
    return round(sum(usable) / len(usable), 4) if usable else 0.0


def summarize(rows: list[dict]) -> None:
    ok = [r for r in rows if "error" not in r]
    if not ok:
        print("Ozetlenecek basarili senaryo yok.")
        return

    def arm(key: str, metric: str) -> list[float]:
        return [r[key][metric] for r in ok]

    changed = [r for r in ok if r["n_agent_rejected"] > 0]
    helped = [
        r for r in changed
        if r["with_agents"]["hierarchical_score"] > r["without_agents"]["hierarchical_score"]
    ]
    hurt = [
        r for r in changed
        if r["with_agents"]["hierarchical_score"] < r["without_agents"]["hierarchical_score"]
    ]

    summary = {
        # Hangi korumalarin uygulandigi sonuctan ayrilamaz olmali: isinma
        # yapilmadan uretilmis bir tablo, yapilmisla karsilastirilamaz.
        "hygiene": _HYGIENE,
        "n_scenarios": len(ok),
        "n_errors": len(rows) - len(ok),
        "without_agents": {
            "hierarchical_score": _mean(arm("without_agents", "hierarchical_score")),
            # correct_abstention yalnizca negatif/belirsiz senaryolarda tanimli;
            # digerlerinde None doner ve ortalamaya girmemeli.
            "correct_abstention": _mean(
                [float(x) for x in arm("without_agents", "correct_abstention") if x is not None]
            ),
            "hallucination_rate": _mean(arm("without_agents", "hallucination_rate")),
            "avg_techniques": _mean(arm("without_agents", "n_techniques")),
            "avg_high_confidence": _mean(arm("without_agents", "n_high_confidence")),
        },
        "with_agents": {
            "hierarchical_score": _mean(arm("with_agents", "hierarchical_score")),
            "correct_abstention": _mean(
                [float(x) for x in arm("with_agents", "correct_abstention") if x is not None]
            ),
            "hallucination_rate": _mean(arm("with_agents", "hallucination_rate")),
            "avg_techniques": _mean(arm("with_agents", "n_techniques")),
            "avg_high_confidence": _mean(arm("with_agents", "n_high_confidence")),
        },
        "n_scenarios_touched": len(changed),
        "n_scenarios_improved": len(helped),
        "n_scenarios_worsened": len(hurt),
        "worsened_details": [
            {"test_id": r["test_id"], "rejected": r["rejected_ids"], "reasons": r["rejected_reasons"]}
            for r in hurt
        ],
        "improved_details": [
            {"test_id": r["test_id"], "rejected": r["rejected_ids"]} for r in helped
        ],
        "avg_agent_seconds": _mean([r.get("agent_seconds") for r in ok]),
    }

    SUMMARY_FILE.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    print("\n" + "=" * 70)
    print(f"SENARYO: {summary['n_scenarios']} basarili, {summary['n_errors']} hata")
    print(f"{'METRIK':28s} {'KAPALI':>10s} {'ACIK':>10s}")
    for metric in ["hierarchical_score", "correct_abstention", "hallucination_rate",
                   "avg_techniques", "avg_high_confidence"]:
        print(f"{metric:28s} {summary['without_agents'][metric]:>10.4f} "
              f"{summary['with_agents'][metric]:>10.4f}")
    print(f"\nKatmanin dokundugu senaryo : {summary['n_scenarios_touched']}")
    print(f"  iyilestirdigi            : {summary['n_scenarios_improved']}")
    print(f"  kotulestirdigi           : {summary['n_scenarios_worsened']}")
    print(f"Ajan katmani suresi (ort.) : {summary['avg_agent_seconds']:.3f} sn")
    print(f"\nOzet -> {SUMMARY_FILE}")


if __name__ == "__main__":
    main()
