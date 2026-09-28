"""Gorev 25 — Ö0: gosterim degisikligi ANALIZ CIKTISINI degistirmedi.

Gorev 24'un `measure_task24_side_effect.py`'siyle ayni desen: taban cizgi
git'ten okunur, gerilemede exit 1.

NEDEN GEREKLI: bu gorevde "sayilar ayni kalsin, sadece okunabilir olsun"
denildi. Bir gosterim yamasi analiz katmanina sizarsa bunun sessizce
olmasi en kotu sonuc olurdu -- risk skoru veya guclu/zayif ayrimi
degisirse ekran daha okunakli ama YANLIS olur.

OLCULEN: gercek kosu dosyasi uzerinde
  - risk.score / risk.severity / risk.breakdown (her anahtar)
  - guclu ve zayif teknik attack_id kumeleri (split_by_confidence)
  - kapsam raporunun assessable / unassessable bolunmesi
Bunlarin hicbiri bu gorevde eklenen modullerden gecmez; betik onlarin
gecmedigini KANITLAR, varsaymaz.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.batch.serialize import canonicalize_row
from app.correlation.dedup import split_by_confidence
from app.mapping.coverage import build_coverage_report

RESULT = Path("data/bulk_results/bulk_20260904_030101.json")
BASELINE = Path("evaluation/results/task25_display_only.json")


def snapshot() -> dict:
    """Analiz katmaninin SU ANKI ciktisi -- gosterim modulleri cagrilmadan."""
    result = json.loads(RESULT.read_text(encoding="utf-8"))

    incidents = []
    for inc in result["incidents"]:
        deduped = inc.get("techniques") or inc["deduped_techniques"]
        strong, weak = split_by_confidence(deduped + (inc.get("weak_techniques") or []))
        incidents.append({
            "id": inc["id"],
            "risk_score": inc["risk"]["score"],
            "risk_severity": inc["risk"]["severity"],
            "risk_breakdown": inc["risk"]["breakdown"],
            "strong": sorted(t["attack_id"] for t in strong),
            "weak": sorted(t["attack_id"] for t in weak),
        })

    rows = [canonicalize_row(it["source_row"]) for it in result["items"]]
    report = build_coverage_report(rows)

    return {
        "incidents": incidents,
        "dataset_event_ids": list(report.dataset_event_ids),
        "assessable": sorted(t.tactic for t in report.assessable),
        "unassessable": sorted(t.tactic for t in report.unassessable),
        "missing_by_tactic": {
            t.tactic: list(t.missing_event_ids) for t in report.tactics
        },
    }


def main() -> int:
    current = snapshot()

    if not BASELINE.exists():
        BASELINE.parent.mkdir(parents=True, exist_ok=True)
        BASELINE.write_text(
            json.dumps(current, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(f"Taban cizgi yazildi: {BASELINE}")
        print("Bu ILK kosu. Degisiklikten ONCE calistirilmis olmasi gerekir --")
        print("degisiklikten sonra yazilan bir taban cizgi hicbir sey kanitlamaz.")
        return 0

    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    if baseline == current:
        print("Ö0 GECTI — analiz ciktisi taban cizgiyle BIREBIR ayni.")
        for inc in current["incidents"]:
            print(f"  {inc['id']}: risk {inc['risk_score']}/100 {inc['risk_severity']} · "
                  f"{len(inc['strong'])} guclu / {len(inc['weak'])} zayif teknik")
        print(f"  kapsam: {len(current['assessable'])} degerlendirilebilir / "
              f"{len(current['unassessable'])} degerlendirilemez taktik")
        return 0

    print("Ö0 BASARISIZ — analiz ciktisi DEGISTI. Gosterim yamasi sizmis:")
    for key in sorted(set(baseline) | set(current)):
        if baseline.get(key) != current.get(key):
            print(f"  FARK -> {key}")
            print(f"    taban : {json.dumps(baseline.get(key), ensure_ascii=False)[:300]}")
            print(f"    simdi : {json.dumps(current.get(key), ensure_ascii=False)[:300]}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
