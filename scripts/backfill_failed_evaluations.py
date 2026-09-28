"""eval_baseline.jsonl / eval_improved.jsonl icindeki 'error' iceren satirlari
(timeout yiyen senaryolari) yeni retry mekanizmali ollama_client ile tekrar
calistirip yerine yazar."""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.run_evaluation import evaluate_one
from app.retrieval.baseline_pipeline import run_baseline_query
from app.retrieval.improved_pipeline import run_improved_query

RESULTS_DIR = PROJECT_ROOT / "evaluation" / "results"


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.open(encoding="utf-8")]


def save_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def main() -> None:
    scenarios = json.loads((PROJECT_ROOT / "evaluation" / "test_scenarios.json").read_text(encoding="utf-8"))
    scenarios_by_id = {s["test_id"]: s for s in scenarios}
    techniques = json.loads((PROJECT_ROOT / "data" / "processed" / "techniques.json").read_text(encoding="utf-8"))
    kb_by_id = {t["attack_id"]: t for t in techniques}

    for system_name, path, run_fn in [
        ("baseline", RESULTS_DIR / "eval_baseline.jsonl", None),
        ("improved", RESULTS_DIR / "eval_improved.jsonl", None),
    ]:
        rows = load_jsonl(path)
        failed = [(i, r) for i, r in enumerate(rows) if "error" in r]
        print(f"{system_name}: {len(failed)} basarisiz senaryo bulundu")

        for idx, row in failed:
            test_id = row["test_id"]
            scenario = scenarios_by_id[test_id]
            print(f"  yeniden deneniyor: {test_id}")
            try:
                if system_name == "baseline":
                    result = run_baseline_query(scenario["input"])
                else:
                    result = run_improved_query(scenario["input"], platform=scenario.get("platform"))
                new_metrics = evaluate_one(system_name, result, scenario, kb_by_id)
                rows[idx] = new_metrics
                print(f"    basarili, yeni skor={new_metrics['hierarchical_score']}")
            except Exception as e:
                print(f"    yine basarisiz: {e}")
                rows[idx] = {**row, "retry_error": str(e)}

            save_jsonl(path, rows)  # her senaryo sonrasi kaydet (crash-safe)

        print(f"{system_name} guncellendi: {path}")


if __name__ == "__main__":
    main()
