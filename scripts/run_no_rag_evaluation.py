"""60 test senaryosunu RAG'siz (dogrudan LLM) pipeline'da calistirir."""

from __future__ import annotations

import json
import sys
import traceback
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.evaluation.metrics import hallucination_rate, hierarchical_score, is_correct_abstention
from app.retrieval.no_rag_pipeline import run_no_rag_query

SCENARIOS_FILE = PROJECT_ROOT / "evaluation" / "test_scenarios.json"
TECHNIQUES_FILE = PROJECT_ROOT / "data" / "processed" / "techniques.json"
OUT_FILE = PROJECT_ROOT / "evaluation" / "results" / "eval_no_rag.jsonl"


def main() -> None:
    scenarios = json.loads(SCENARIOS_FILE.read_text(encoding="utf-8"))
    techniques = json.loads(TECHNIQUES_FILE.read_text(encoding="utf-8"))
    kb_by_id = {t["attack_id"]: t for t in techniques}

    with OUT_FILE.open("w", encoding="utf-8") as out:
        for i, scenario in enumerate(scenarios, start=1):
            print(f"[{i}/{len(scenarios)}] {scenario['test_id']}", flush=True)
            try:
                result = run_no_rag_query(scenario["input"])
                predicted_ids = [m["attack_id"] for m in result.get("mappings", [])]
                metrics = {
                    "test_id": scenario["test_id"],
                    "category": scenario["category"],
                    "system": "no_rag",
                    "predicted_ids": predicted_ids,
                    "hierarchical_score": hierarchical_score(predicted_ids, scenario, kb_by_id),
                    "correct_abstention": is_correct_abstention(result.get("mappings", []), scenario),
                    "hallucination_rate": hallucination_rate(result.get("mappings", []), kb_by_id),
                    "n_rejected": len(result.get("rejected_mappings", [])),
                    "total_seconds": result.get("timings", {}).get("total_seconds"),
                }
            except Exception as e:
                print(f"  HATA: {e}", flush=True)
                traceback.print_exc()
                metrics = {"test_id": scenario["test_id"], "category": scenario["category"], "system": "no_rag", "error": str(e)}

            out.write(json.dumps(metrics, ensure_ascii=False) + "\n")
            out.flush()
            print(f"  skor={metrics.get('hierarchical_score')}", flush=True)

    print("Tum senaryolar tamamlandi.", flush=True)


if __name__ == "__main__":
    main()
