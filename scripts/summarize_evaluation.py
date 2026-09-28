"""eval_baseline.jsonl ve eval_improved.jsonl dosyalarindan dokuman bolum 32/33
icin ozet metrikler ve baseline-vs-improved karsilastirma tablosu uretir."""

from __future__ import annotations

import hashlib
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = PROJECT_ROOT / "evaluation" / "results"


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.open(encoding="utf-8")]


def source_fingerprint(path: Path) -> dict:
    """Ozetin hangi jsonl'den uretildigini kaydeder.

    Gerekcesi: comparison_summary.json bir sure yanindaki jsonl dosyalariyla
    alakasiz sayilar tasidi (baseline 0.315 yaziyordu, jsonl'den yeniden
    hesaplaninca 0.392 cikiyordu) ve bu rakamlar rapora ve sunuma gecmisti.
    Ozet turetilmis bir dosya oldugu icin kaynagiyla birlikte damgalanmadikca
    boyle bir sapma gozle fark edilmiyor -- artik check_summary_is_current()
    ile dogrulanabiliyor."""
    data = path.read_bytes()
    return {
        "file": path.name,
        "sha256": hashlib.sha256(data).hexdigest()[:16],
        "n_rows": data.count(b"\n"),
    }


def check_summary_is_current(summary_path: Path, sources: list[Path]) -> tuple[bool, str]:
    """Ozetin kaynak jsonl'lerle hala uyusup uyusmadigini soyler."""
    if not summary_path.exists():
        return False, "comparison_summary.json yok"
    meta = json.loads(summary_path.read_text(encoding="utf-8")).get("meta")
    if not meta:
        return False, "ozet damgasiz uretilmis (eski surum), guncelligi dogrulanamiyor"

    current = {f["file"]: f["sha256"] for f in (source_fingerprint(p) for p in sources)}
    stamped = {f["file"]: f["sha256"] for f in meta.get("sources", [])}
    stale = [name for name, h in current.items() if stamped.get(name) != h]
    if stale:
        return False, f"ozet bayat -- su dosyalar degismis: {', '.join(stale)}"
    return True, f"ozet guncel (uretim: {meta.get('generated_at')})"


def mean(xs: list[float]) -> float | None:
    xs = [x for x in xs if x is not None]
    return sum(xs) / len(xs) if xs else None


def summarize_system(rows: list[dict], scenarios_by_id: dict[str, dict]) -> dict:
    ok_rows = [r for r in rows if "error" not in r]
    error_rows = [r for r in rows if "error" in r]

    top1_correct = sum(1 for r in ok_rows if r.get("hierarchical_score") == 1.0)
    partial_or_better = sum(1 for r in ok_rows if (r.get("hierarchical_score") or 0) >= 0.5)

    by_category: dict[str, list[float]] = defaultdict(list)
    for r in ok_rows:
        by_category[r["category"]].append(r.get("hierarchical_score") or 0.0)

    abstention_scores = [r["correct_abstention"] for r in ok_rows if r.get("correct_abstention") is not None]

    return {
        "n_total": len(rows),
        "n_errors": len(error_rows),
        "mean_hierarchical_score": mean([r.get("hierarchical_score") for r in ok_rows]),
        "top1_exact_accuracy": top1_correct / len(ok_rows) if ok_rows else None,
        "partial_or_better_rate": partial_or_better / len(ok_rows) if ok_rows else None,
        "mean_recall_at_5": mean([r.get("recall_at_5") for r in ok_rows]),
        "mean_recall_at_10": mean([r.get("recall_at_10") for r in ok_rows]),
        "mean_hallucination_rate": mean([r.get("hallucination_rate") for r in ok_rows]),
        "abstention_accuracy": mean(abstention_scores) if abstention_scores else None,
        "n_abstention_applicable": len(abstention_scores),
        "mean_total_seconds": mean([r.get("total_seconds") for r in ok_rows]),
        "score_by_category": {cat: mean(scores) for cat, scores in by_category.items()},
    }


def main() -> None:
    scenarios = json.loads((PROJECT_ROOT / "evaluation" / "test_scenarios.json").read_text(encoding="utf-8"))
    scenarios_by_id = {s["test_id"]: s for s in scenarios}

    baseline_file = RESULTS_DIR / "eval_baseline.jsonl"
    improved_file = RESULTS_DIR / "eval_improved.jsonl"
    baseline_rows = load_jsonl(baseline_file)
    improved_rows = load_jsonl(improved_file)

    baseline_summary = summarize_system(baseline_rows, scenarios_by_id)
    improved_summary = summarize_system(improved_rows, scenarios_by_id)

    missing = [tid for tid in scenarios_by_id if tid not in {r["test_id"] for r in baseline_rows}]

    report = {
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "sources": [source_fingerprint(baseline_file), source_fingerprint(improved_file)],
            "n_scenarios_expected": len(scenarios_by_id),
            "missing_test_ids": missing,
        },
        "baseline": baseline_summary,
        "improved": improved_summary,
    }
    out_file = RESULTS_DIR / "comparison_summary.json"
    out_file.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    # Yarim kalan kosu sessizce "tamamlanmis" gibi ozetlenmesin: 11 Agustos
    # kosusu 58/60'ta kesilmisti ve eksik 2 senaryo hicbir yerde gorunmuyordu.
    if missing:
        print(f"UYARI: {len(missing)} senaryo sonuclarda yok: {', '.join(missing)}\n")

    print("=== BASELINE vs GELISTIRILMIS SISTEM KARSILASTIRMASI ===\n")
    print(f"{'Metrik':<32} {'Baseline':>12} {'Gelistirilmis':>15}")
    rows_to_print = [
        ("Toplam senaryo", "n_total", "{:.0f}"),
        ("Hata sayisi", "n_errors", "{:.0f}"),
        ("Ort. hiyerarsik skor", "mean_hierarchical_score", "{:.3f}"),
        ("Top-1 tam dogruluk", "top1_exact_accuracy", "{:.1%}"),
        (">=0.5 skor orani", "partial_or_better_rate", "{:.1%}"),
        ("Ort. Recall@5", "mean_recall_at_5", "{:.3f}"),
        ("Ort. Recall@10", "mean_recall_at_10", "{:.3f}"),
        ("Ort. halusinasyon orani", "mean_hallucination_rate", "{:.3f}"),
        ("Abstention dogrulugu", "abstention_accuracy", "{:.1%}"),
        ("Ort. yanit suresi (s)", "mean_total_seconds", "{:.1f}"),
    ]
    for label, key, fmt in rows_to_print:
        b_val = baseline_summary.get(key)
        i_val = improved_summary.get(key)
        b_str = fmt.format(b_val) if b_val is not None else "N/A"
        i_str = fmt.format(i_val) if i_val is not None else "N/A"
        print(f"{label:<32} {b_str:>12} {i_str:>15}")

    print("\n=== Kategoriye gore ortalama skor ===")
    all_cats = sorted(set(baseline_summary["score_by_category"]) | set(improved_summary["score_by_category"]))
    print(f"{'Kategori':<28} {'Baseline':>12} {'Gelistirilmis':>15}")
    for cat in all_cats:
        b = baseline_summary["score_by_category"].get(cat)
        i = improved_summary["score_by_category"].get(cat)
        b_str = f"{b:.3f}" if b is not None else "N/A"
        i_str = f"{i:.3f}" if i is not None else "N/A"
        print(f"{cat:<28} {b_str:>12} {i_str:>15}")

    print(f"\nDetayli rapor: {out_file}")


if __name__ == "__main__":
    main()
