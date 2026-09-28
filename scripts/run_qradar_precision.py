"""QRadar hassasiyet olcumu -- ajan katmani GURULTUYU kesiyor mu?

NEDEN AYRI BIR OLCUM
    60 senaryoluk set kurasyonlu ve temiz: girdi nettir, LLM zaten cogunda
    dogru teknigi bulur. Boyle bir sette bir dogrulama katmaninin
    yapabilecegi en iyi sey HICBIR SEYI BOZMAMAKTIR -- kesecek yanlis
    pozitif yoktur. Katmanin degeri orada olculemez.

    Bu olcum tam tersi bir veriyle calisir: gercek bir QRadar export'u,
    51 satir, neredeyse tamami rutin gurultu.

VERININ DOGRULANMIS OZELLIKLERI (betik bunlari kendi kontrol eder)
    EventID dagilimi : 5156 x23, 4673 x11, 5158 x9, 4656 x5, 4658/4690/403
    Surec olusturma  : YOK (4688/4104 hic yok)
    Firewall DEGISIKLIGI: YOK (4946-4954, 5025 hic yok)

    Bu iki yokluk olcutu belirliyor:
      - Firewall degisikligi olmadigi icin T1562*/T1686* ailesinden cikan
        HER teknik tanimi geregi yanlis pozitiftir. Eski sistem tam da
        burada 14 kez T1686.003 uretmisti (kaynak: 5156 "permitted" satirlari).
      - Surec olusturma kaydi olmadigi icin T1059*/T1053*/T1204* gibi
        "sunu calistirdi" iddialari veriyle DESTEKLENMEZ. Bunlari ayri
        sayiyoruz: kesin yanlis degil ama kanitsiz.

GERCEK SINYALLER (bastirilmamasi gerekenler)
    satir 46 -> PowerShell izi
    satir 49 -> tdrfagent

    Basarili bir katman gurultuyu keserken bu iki satiri AYAKTA BIRAKMALI.
    Her seyi elemek de bir basari degildir -- sessiz bir sistem, yanlis
    alarm veren sistem kadar kullanissizdir.

CALISTIRMA
    python scripts/run_qradar_precision.py            # 51 satir, ~85 dk
    python scripts/run_qradar_precision.py --limit 10 # hizli deneme
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import traceback
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.batch.qradar_adapter import try_convert_qradar_export
from app.batch.serialize import rows_to_batch_items
from app.retrieval.improved_pipeline import run_improved_query

FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "qradar_2026-08-06_51rows.csv"
RESULTS_DIR = PROJECT_ROOT / "evaluation" / "results"
OUT_FILE = RESULTS_DIR / "qradar_precision.jsonl"
SUMMARY_FILE = RESULTS_DIR / "qradar_precision_summary.json"

# Firewall DEGISIKLIGI olaylari -- veride yoklugu dogrulanacak.
FIREWALL_CHANGE_EVENT_IDS = {
    "4946", "4947", "4948", "4949", "4950", "4951", "4952", "4953", "4954", "5025"
}
PROCESS_CREATION_EVENT_IDS = {"4688", "4104", "1"}

# Veri firewall degisikligi icermedigi icin bu aile yanlis pozitiftir.
IMPOSSIBLE_TECHNIQUE_RE = re.compile(r"^T1562|^T1686")
# Surec olusturma kaydi olmadigi icin bunlar kanitsiz iddialardir.
UNSUPPORTED_EXECUTION_RE = re.compile(r"^T1059|^T1053|^T1204|^T1106|^T1569")

# 1-indeksli satir numaralari (bkz. modul basligi).
SIGNAL_ROWS = {46: "PowerShell izi", 49: "tdrfagent"}


def verify_dataset_premises(rows: list[dict]) -> dict:
    """Olcutun dayandigi iki yoklugu betik kendi dogrular.

    Fixture degisirse olcut sessizce yanlis hale gelmesin -- bu proje o
    tuzagi daha once yasadi (bkz. summarize_evaluation.py source_fingerprint)."""
    event_ids = [str(r.get("EventID") or "").strip() for r in rows]
    fw_change = [i + 1 for i, e in enumerate(event_ids) if e in FIREWALL_CHANGE_EVENT_IDS]
    proc_create = [i + 1 for i, e in enumerate(event_ids) if e in PROCESS_CREATION_EVENT_IDS]

    premises = {
        "n_rows": len(rows),
        "firewall_change_rows": fw_change,
        "process_creation_rows": proc_create,
        "premises_hold": not fw_change and not proc_create,
    }
    if not premises["premises_hold"]:
        print("UYARI: veri kumesi beklenen ozellikleri tasimiyor -- olcut gecersiz olabilir.")
        print(f"  firewall degisikligi satirlari: {fw_change}")
        print(f"  surec olusturma satirlari: {proc_create}")
    return premises


def classify(mappings: list[dict]) -> dict:
    ids = [m.get("attack_id") or "" for m in mappings]
    return {
        "ids": ids,
        "n": len(ids),
        "n_high": sum(
            1 for m in mappings if (m.get("confidence_level") or "").lower() == "high"
        ),
        "impossible": [i for i in ids if IMPOSSIBLE_TECHNIQUE_RE.match(i)],
        "unsupported_execution": [i for i in ids if UNSUPPORTED_EXECUTION_RE.match(i)],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=None, help="ilk N satir (hizli deneme)")
    args = parser.parse_args()

    rows = try_convert_qradar_export(FIXTURE.read_bytes())
    premises = verify_dataset_premises(rows)

    items = rows_to_batch_items(rows)
    if args.limit:
        items = items[: args.limit]

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_FILE.open("w", encoding="utf-8")
    records: list[dict] = []

    for item in items:
        row_no = item["index"] + 1
        if item.get("skipped"):
            continue

        print(f"[satir {row_no}/{len(items)}]", flush=True)
        t0 = time.time()
        try:
            result = run_improved_query(item["raw_log"], platform=item.get("platform"))
        except Exception as e:
            print(f"  HATA: {e}", flush=True)
            traceback.print_exc()
            record = {"row": row_no, "error": str(e)}
            records.append(record)
            out.write(json.dumps(record, ensure_ascii=False) + "\n")
            out.flush()
            continue

        after = classify(result.get("mappings") or [])
        before = classify(result.get("mappings_before_agents") or [])
        rejected = result.get("agent_rejected_mappings") or []

        record = {
            "row": row_no,
            "event_id": str(rows[item["index"]].get("EventID") or ""),
            "is_signal_row": row_no in SIGNAL_ROWS,
            "signal_label": SIGNAL_ROWS.get(row_no),
            "before": before,
            "after": after,
            "n_rejected": len(rejected),
            "rejected_ids": [m.get("attack_id") for m in rejected],
            "rejected_reasons": [
                f"{m.get('agent_id')}: {m.get('agent_reason')}" for m in rejected
            ],
            "loop_passes": result.get("loop_passes"),
            "loop_trace": result.get("loop_trace"),
            "seconds": round(time.time() - t0, 1),
        }
        records.append(record)
        out.write(json.dumps(record, ensure_ascii=False) + "\n")
        out.flush()

        print(
            f"  kapali={before['n']} teknik ({before['n_high']} yuksek) -> "
            f"acik={after['n']} teknik ({after['n_high']} yuksek) "
            f"| imkansiz {len(before['impossible'])}->{len(after['impossible'])} "
            f"| {record['seconds']}sn",
            flush=True,
        )

    out.close()
    summarize(records, premises)


def summarize(records: list[dict], premises: dict) -> None:
    ok = [r for r in records if "error" not in r]
    if not ok:
        print("Ozetlenecek basarili satir yok.")
        return

    def total(key: str, field: str) -> int:
        return sum(r[key][field] for r in ok)

    def total_len(key: str, field: str) -> int:
        return sum(len(r[key][field]) for r in ok)

    before_unique = {i for r in ok for i in r["before"]["ids"]}
    after_unique = {i for r in ok for i in r["after"]["ids"]}

    signal_rows = [r for r in ok if r["is_signal_row"]]
    signals_kept = [r for r in signal_rows if r["after"]["n"] > 0]

    # Analist yuku: kac satir en az bir YUKSEK guvenli teknik uretti?
    noisy_before = sum(1 for r in ok if r["before"]["n_high"] > 0)
    noisy_after = sum(1 for r in ok if r["after"]["n_high"] > 0)

    summary = {
        "premises": premises,
        "n_rows_analyzed": len(ok),
        "n_errors": len(records) - len(ok),
        "techniques_total": {"before": total("before", "n"), "after": total("after", "n")},
        "techniques_unique": {
            "before": sorted(before_unique), "after": sorted(after_unique),
            "n_before": len(before_unique), "n_after": len(after_unique),
        },
        "high_confidence_total": {
            "before": total("before", "n_high"), "after": total("after", "n_high"),
        },
        "impossible_family": {
            "before": total_len("before", "impossible"),
            "after": total_len("after", "impossible"),
        },
        "unsupported_execution_claims": {
            "before": total_len("before", "unsupported_execution"),
            "after": total_len("after", "unsupported_execution"),
        },
        "rows_with_high_confidence": {"before": noisy_before, "after": noisy_after},
        "signal_rows": {
            "expected": SIGNAL_ROWS,
            "kept": [r["row"] for r in signals_kept],
            "lost": [r["row"] for r in signal_rows if r["after"]["n"] == 0],
        },
        "n_agent_rejections": sum(r["n_rejected"] for r in ok),
        "loop_triggered_rows": [r["row"] for r in ok if (r.get("loop_passes") or 0) > 0],
        "avg_seconds": round(sum(r["seconds"] for r in ok) / len(ok), 1),
    }

    SUMMARY_FILE.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    print("\n" + "=" * 72)
    print(f"QRADAR HASSASIYET OLCUMU -- {summary['n_rows_analyzed']} satir")
    print(f"veri onkosullari saglandi: {premises['premises_hold']}")
    print()
    print(f"{'OLCUT':38s} {'KAPALI':>9s} {'ACIK':>9s}")
    print(f"{'toplam teknik':38s} {summary['techniques_total']['before']:>9d} "
          f"{summary['techniques_total']['after']:>9d}")
    print(f"{'benzersiz teknik':38s} {summary['techniques_unique']['n_before']:>9d} "
          f"{summary['techniques_unique']['n_after']:>9d}")
    print(f"{'yuksek guvenli teknik':38s} {summary['high_confidence_total']['before']:>9d} "
          f"{summary['high_confidence_total']['after']:>9d}")
    print(f"{'IMKANSIZ aile (T1562/T1686)':38s} {summary['impossible_family']['before']:>9d} "
          f"{summary['impossible_family']['after']:>9d}")
    print(f"{'kanitsiz calistirma iddiasi':38s} "
          f"{summary['unsupported_execution_claims']['before']:>9d} "
          f"{summary['unsupported_execution_claims']['after']:>9d}")
    print(f"{'yuksek guvenli teknik iceren satir':38s} "
          f"{summary['rows_with_high_confidence']['before']:>9d} "
          f"{summary['rows_with_high_confidence']['after']:>9d}")
    print()
    print(f"Gercek sinyaller korundu : {summary['signal_rows']['kept']} "
          f"(kaybedilen: {summary['signal_rows']['lost'] or 'yok'})")
    print(f"Ajan elemesi             : {summary['n_agent_rejections']}")
    print(f"Dongu tetiklenen satir   : {len(summary['loop_triggered_rows'])}")
    print(f"Satir basina sure (ort.) : {summary['avg_seconds']} sn")
    print(f"\nOzet -> {SUMMARY_FILE}")


if __name__ == "__main__":
    main()
