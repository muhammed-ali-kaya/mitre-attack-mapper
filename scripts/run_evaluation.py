"""60 test senaryosunu hem baseline hem gelistirilmis sistemde calistirip
dokuman bolum 32 metriklerini hesaplar. Cok uzun surdugu icin her senaryo
sonrasi sonuclari diske yazar (crash-safe) ve ilerlemeyi ekrana basar."""

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
    retrieval_recall_at_k,
)
from app.retrieval.baseline_pipeline import run_baseline_query
from app.retrieval.improved_pipeline import run_improved_query

SCENARIOS_FILE = PROJECT_ROOT / "evaluation" / "test_scenarios.json"
TECHNIQUES_FILE = PROJECT_ROOT / "data" / "processed" / "techniques.json"
RESULTS_DIR = PROJECT_ROOT / "evaluation" / "results"


def evaluate_one(system_name: str, result: dict, scenario: dict, kb_by_id: dict) -> dict:
    predicted_ids = [m["attack_id"] for m in result.get("mappings", [])]
    retrieved_ids = []
    for cid in result.get("retrieved_chunk_ids", []):
        aid = cid.split("::")[0]
        retrieved_ids.append(aid)

    return {
        "test_id": scenario["test_id"],
        "category": scenario["category"],
        "system": system_name,
        "predicted_ids": predicted_ids,
        "hierarchical_score": hierarchical_score(predicted_ids, scenario, kb_by_id),
        "recall_at_5": retrieval_recall_at_k(retrieved_ids, scenario, 5),
        "recall_at_10": retrieval_recall_at_k(retrieved_ids, scenario, 10),
        "correct_abstention": is_correct_abstention(result.get("mappings", []), scenario),
        "hallucination_rate": hallucination_rate(result.get("mappings", []), kb_by_id),
        "n_rejected": len(result.get("rejected_mappings", [])),
        "total_seconds": result.get("timings", {}).get("total_seconds"),
    }


def main() -> None:
    scenarios = json.loads(SCENARIOS_FILE.read_text(encoding="utf-8"))
    techniques = json.loads(TECHNIQUES_FILE.read_text(encoding="utf-8"))
    kb_by_id = {t["attack_id"]: t for t in techniques}

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    baseline_out = (RESULTS_DIR / "eval_baseline.jsonl").open("w", encoding="utf-8")
    improved_out = (RESULTS_DIR / "eval_improved.jsonl").open("w", encoding="utf-8")
    raw_out = (RESULTS_DIR / "eval_raw_outputs.jsonl").open("w", encoding="utf-8")

    for i, scenario in enumerate(scenarios, start=1):
        print(f"[{i}/{len(scenarios)}] {scenario['test_id']} ({scenario['category']})", flush=True)

        try:
            baseline_result = run_baseline_query(scenario["input"])
            baseline_metrics = evaluate_one("baseline", baseline_result, scenario, kb_by_id)
        except Exception as e:
            print(f"  BASELINE HATA: {e}", flush=True)
            traceback.print_exc()
            baseline_result = {"error": str(e)}
            baseline_metrics = {"test_id": scenario["test_id"], "category": scenario["category"], "system": "baseline", "error": str(e)}

        try:
            improved_result = run_improved_query(scenario["input"], platform=scenario.get("platform"))
            improved_metrics = evaluate_one("improved", improved_result, scenario, kb_by_id)
        except Exception as e:
            print(f"  IMPROVED HATA: {e}", flush=True)
            traceback.print_exc()
            improved_result = {"error": str(e)}
            improved_metrics = {"test_id": scenario["test_id"], "category": scenario["category"], "system": "improved", "error": str(e)}

        baseline_out.write(json.dumps(baseline_metrics, ensure_ascii=False) + "\n")
        baseline_out.flush()
        improved_out.write(json.dumps(improved_metrics, ensure_ascii=False) + "\n")
        improved_out.flush()
        raw_out.write(json.dumps({
            "test_id": scenario["test_id"], "baseline_raw": baseline_result, "improved_raw": improved_result,
        }, ensure_ascii=False) + "\n")
        raw_out.flush()

        b_score = baseline_metrics.get("hierarchical_score")
        i_score = improved_metrics.get("hierarchical_score")
        print(f"  baseline_score={b_score}  improved_score={i_score}", flush=True)

    baseline_out.close()
    improved_out.close()
    raw_out.close()
    print("Tum senaryolar tamamlandi.\n", flush=True)

    # Ozeti burada uretiyoruz ki jsonl'lerden ayrisamasin: comparison_summary.json
    # bir sure elle uretilip geride kalmis, rapora ve sunuma giden rakamlar
    # yanindaki veriyle uyusmaz hale gelmisti (bkz. summarize_evaluation.py ->
    # source_fingerprint).
    from scripts.summarize_evaluation import main as summarize

    summarize()


if __name__ == "__main__":
    main()
