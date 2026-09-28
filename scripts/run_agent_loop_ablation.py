"""Uc kollu ablasyon: ajansiz / ajanli / ajanli+dongulu.

NEDEN UC KOL
    Iki kollu olcum (scripts/run_agent_ablation.py) "ajan katmani ise
    yariyor mu?" sorusunu cevapliyor. Ama katmana bir de yeniden retrieval
    dongusu eklendi (app/agents/graph.py) ve iki kollu olcumde dongunun
    katkisi ajan katmaninin katkisiyla KARISIK geliyor. Ucuncu kol o ikisini
    ayiriyor:

        A) ajansiz          -> LLM'in ham secimi (dogrulama katmani oncesi)
        B) ajanli, dongusuz -> birinci turun ajanlardan gecmis hali
        C) ajanli + dongulu -> nihai cikti (birikimli, en fazla 1 ek tur)

    B - A  = ajan katmaninin katkisi
    C - B  = dongunun katkisi

NEDEN TEK KOSU
    Uc kol da AYNI kosudan cikiyor: pipeline ucunu de ayri anahtarlarda
    tasiyor. Senaryolari uc kez kosturmak hem uc kat surerdi hem de kollar
    arasindaki farka modelin orneklem gurultusu karisirdi. Burada fark
    yaklasik degil BIREBIR.

    Tek istisna: C kolu ikinci bir LLM cagrisi yapiyor, yani PAHALI. Bu bir
    olcum kusuru degil, olculen seyin kendisi -- ozette sure de raporlaniyor.

CIKTI DOSYASI ayri tutuldu (agent_loop_ablation.*): iki kollu betigin
sonuclarinin uzerine yazmasin, ikisi yan yana durabilsin.
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
from app.retrieval.improved_pipeline import run_improved_query

SCENARIOS_FILE = PROJECT_ROOT / "evaluation" / "test_scenarios.json"
TECHNIQUES_FILE = PROJECT_ROOT / "data" / "processed" / "techniques.json"
RESULTS_DIR = PROJECT_ROOT / "evaluation" / "results"
OUT_FILE = RESULTS_DIR / "agent_loop_ablation.jsonl"
SUMMARY_FILE = RESULTS_DIR / "agent_loop_ablation_summary.json"

# Kol adi -> pipeline ciktisindaki anahtar
ARMS = {
    "no_agents": "mappings_before_agents",
    "agents": "mappings_after_first_pass",
    "agents_loop": "mappings",
}

METRICS = [
    "hierarchical_score",
    "correct_abstention",
    "hallucination_rate",
    "avg_techniques",
    "avg_high_confidence",
]


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

        arms = {
            name: score_arm(result.get(key) or [], scenario, kb_by_id)
            for name, key in ARMS.items()
        }

        loop_trace = result.get("loop_trace") or []
        row = {
            "test_id": scenario["test_id"],
            "category": scenario["category"],
            "expected": scenario.get("expected_attack_ids"),
            "negative_case": scenario.get("negative_case"),
            **arms,
            "loop_passes": result.get("loop_passes", 0),
            "loop_reasons": [t.get("reason") for t in loop_trace],
            "loop_excluded_ids": [
                aid for t in loop_trace for aid in (t.get("excluded_attack_ids") or [])
            ],
            "n_agent_rejected": len(result.get("agent_rejected_mappings") or []),
            "rejected_ids": [
                m.get("attack_id") for m in (result.get("agent_rejected_mappings") or [])
            ],
            "agent_seconds": (result.get("timings") or {}).get("agent_verification_seconds"),
            "llm_seconds": (result.get("timings") or {}).get("llm_seconds"),
            "total_seconds": (result.get("timings") or {}).get("total_seconds"),
        }
        rows.append(row)
        out.write(json.dumps(row, ensure_ascii=False) + "\n")
        out.flush()

        print(
            "  ajansiz={:.2f}  ajanli={:.2f}  +dongu={:.2f}   tur={}  elenen={}".format(
                arms["no_agents"]["hierarchical_score"],
                arms["agents"]["hierarchical_score"],
                arms["agents_loop"]["hierarchical_score"],
                row["loop_passes"],
                row["n_agent_rejected"],
            ),
            flush=True,
        )

    out.close()
    summarize(rows)


def _mean(values: list) -> float:
    usable = [v for v in values if v is not None]
    return round(sum(usable) / len(usable), 4) if usable else 0.0


def _arm_summary(ok: list[dict], arm: str) -> dict:
    return {
        "hierarchical_score": _mean([r[arm]["hierarchical_score"] for r in ok]),
        # correct_abstention yalnizca negatif/belirsiz senaryolarda tanimli;
        # digerlerinde None doner ve ortalamaya girmemeli.
        "correct_abstention": _mean(
            [float(r[arm]["correct_abstention"]) for r in ok
             if r[arm]["correct_abstention"] is not None]
        ),
        "hallucination_rate": _mean([r[arm]["hallucination_rate"] for r in ok]),
        "avg_techniques": _mean([r[arm]["n_techniques"] for r in ok]),
        "avg_high_confidence": _mean([r[arm]["n_high_confidence"] for r in ok]),
    }


def _compare(ok: list[dict], base: str, arm: str) -> dict:
    """Iki kolu senaryo senaryo karsilastirir.

    n_changed'i predicted_ids uzerinden hesapliyoruz, bir sayaca guvenerek
    degil: iki kolun ciktisi farkliysa senaryo DEGISMISTIR. Iki kollu
    betikte 'dokundugu senaryo' sayaci n_agent_rejected'a bakiyordu ve
    guven dusurmeyle biten degisiklikleri kaciriyordu."""
    changed = [r for r in ok if r[base]["predicted_ids"] != r[arm]["predicted_ids"]]
    improved = [
        r for r in changed
        if r[arm]["hierarchical_score"] > r[base]["hierarchical_score"]
    ]
    worsened = [
        r for r in changed
        if r[arm]["hierarchical_score"] < r[base]["hierarchical_score"]
    ]
    return {
        "delta_hierarchical_score": round(
            _mean([r[arm]["hierarchical_score"] for r in ok])
            - _mean([r[base]["hierarchical_score"] for r in ok]),
            4,
        ),
        "n_changed": len(changed),
        "n_improved": len(improved),
        "n_worsened": len(worsened),
        "worsened_details": [
            {
                "test_id": r["test_id"],
                "expected": r["expected"],
                base: r[base]["predicted_ids"],
                arm: r[arm]["predicted_ids"],
                "rejected_ids": r["rejected_ids"],
            }
            for r in worsened
        ],
        "improved_details": [
            {
                "test_id": r["test_id"],
                "expected": r["expected"],
                base: r[base]["predicted_ids"],
                arm: r[arm]["predicted_ids"],
            }
            for r in improved
        ],
    }


def summarize(rows: list[dict]) -> None:
    ok = [r for r in rows if "error" not in r]
    if not ok:
        print("Ozetlenecek basarili senaryo yok.")
        return

    looped = [r for r in ok if r["loop_passes"] > 0]

    summary = {
        "n_scenarios": len(ok),
        "n_errors": len(rows) - len(ok),
        "arms": {arm: _arm_summary(ok, arm) for arm in ARMS},
        # Ajan katmaninin katkisi
        "agents_vs_none": _compare(ok, "no_agents", "agents"),
        # Dongunun katkisi
        "loop_vs_agents": _compare(ok, "agents", "agents_loop"),
        "loop": {
            "n_scenarios_looped": len(looped),
            "pct_looped": round(100 * len(looped) / len(ok), 1),
            "avg_total_seconds_all": _mean([r["total_seconds"] for r in ok]),
            "avg_total_seconds_looped": _mean([r["total_seconds"] for r in looped]),
            "avg_total_seconds_not_looped": _mean(
                [r["total_seconds"] for r in ok if r["loop_passes"] == 0]
            ),
            "reasons": _count(
                [reason for r in looped for reason in r["loop_reasons"] if reason]
            ),
        },
        "avg_agent_seconds": _mean([r["agent_seconds"] for r in ok]),
    }

    SUMMARY_FILE.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    print("\n" + "=" * 78)
    print(f"SENARYO: {summary['n_scenarios']} basarili, {summary['n_errors']} hata")
    print()
    print(f"{'METRIK':26s} {'AJANSIZ':>12s} {'AJANLI':>12s} {'+DONGU':>12s}")
    for metric in METRICS:
        print(
            f"{metric:26s} "
            + "".join(f"{summary['arms'][arm][metric]:>12.4f}" for arm in ARMS)
        )

    print()
    for label, key in [
        ("AJAN KATMANININ KATKISI (ajanli - ajansiz)", "agents_vs_none"),
        ("DONGUNUN KATKISI        (+dongu - ajanli)", "loop_vs_agents"),
    ]:
        cmp = summary[key]
        print(f"{label}")
        print(f"   skor farki   : {cmp['delta_hierarchical_score']:+.4f}")
        print(f"   degisen      : {cmp['n_changed']} senaryo")
        print(f"   iyilesen     : {cmp['n_improved']}")
        print(f"   kotulesen    : {cmp['n_worsened']}")
        print()

    loop = summary["loop"]
    print(f"DONGU: {loop['n_scenarios_looped']} senaryoda tetiklendi (%{loop['pct_looped']})")
    print(f"   dongulu senaryo suresi   : {loop['avg_total_seconds_looped']:.1f} sn")
    print(f"   dongusuz senaryo suresi  : {loop['avg_total_seconds_not_looped']:.1f} sn")
    for reason, count in loop["reasons"].items():
        print(f"   [{count}] {reason}")

    print(f"\nOzet -> {SUMMARY_FILE}")


def _count(values: list[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


if __name__ == "__main__":
    main()
