"""Gorev 25 olcumu — Ö1/Ö5/Ö6: gosterim katmaninin KAPSAMASI.

Uc soruyu gercek veriye sorar (fixture degil):
  Ö1 kac teknige "ne oldu" cumlesi kurulabiliyor (olay katalogda var mi,
     anlamli alanlar satirda DOLU mu),
  Ö5 kural katalogunun bekledigi olay ID'lerinin kaci adsiz kaliyor,
  Ö6 kullanicinin onerdigi log-kaynagi eslemesi hangi ID'leri YANLIS
     siniflar.

LLM/indeks gerekmez."""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.correlation.dedup import split_by_confidence
from app.mapping.rule_engine import load_rules
from app.mapping.text_input import text_to_row
from app.normalization.event_semantics import event_semantics

RESULT = Path("data/bulk_results/bulk_20260904_030101.json")


def _rows_by_index(items):
    out = {}
    for it in items:
        if it.get("skipped") or not it.get("raw_log"):
            continue
        out[it["index"]] = text_to_row(it["raw_log"])
    return out


def main() -> int:
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    rows = _rows_by_index(result["items"])

    print(f"== girdi: {RESULT} — {len(result['items'])} satir, "
          f"{len(result['incidents'])} incident\n")

    # ---- Ö1
    print("== Ö1 — teknik basina cumle kurulabilirligi")
    total = with_event = with_fields = 0
    eksik_olaylar: Counter = Counter()
    for inc in result["incidents"]:
        deduped = inc.get("techniques") or inc["deduped_techniques"]
        strong, weak = split_by_confidence(deduped + (inc.get("weak_techniques") or []))
        for tech in strong + weak:
            total += 1
            idx = (tech.get("source_row_indices") or [None])[0]
            row = rows.get(idx) or {}
            event_id = row.get("event.id") or row.get("EventID")
            sem = event_semantics(str(event_id) if event_id else None)
            if sem is None:
                eksik_olaylar[str(event_id)] += 1
                continue
            with_event += 1
            dolu = [f for f in (sem.get("anlamli_alanlar") or []) if row.get(f)]
            if dolu:
                with_fields += 1
    print(f"   teknik sayisi              : {total}")
    print(f"   olayi katalogda olan       : {with_event}")
    print(f"   + anlamli alani DOLU olan  : {with_fields}")
    print(f"   katalogda OLMAYAN olaylar  : {dict(eksik_olaylar)}\n")

    # ---- Ö5
    print("== Ö5 — kural katalogunun bekledigi olay ID'leri adsiz mi")
    beklenen = set()
    for rule in load_rules():
        beklenen.update(str(e) for e in (rule.required_event_ids or []))
    adsiz = sorted(e for e in beklenen if event_semantics(e) is None)
    print(f"   kurallarin bekledigi ID    : {len(beklenen)}")
    print(f"   adi katalogda OLMAYAN      : {len(adsiz)} -> {adsiz}\n")

    # ---- Ö6
    print("== Ö6 — kullanicinin onerdigi basit esleme neyi yanlis siniflar")
    print("   kural: 1-30 Sysmon | 4xxx/5xxx Windows Security | 7045 System")
    supheli = []
    for e in sorted(beklenen | {str(k) for k in rows_event_ids(rows)}, key=_key):
        sem = event_semantics(e)
        if sem is None:
            continue
        basit = _basit_kaynak(e)
        # Katalogda kanal ipucu tasiyan olaylar: PowerShell ve Sysmon
        anlam = (sem.get("anlam") or "").casefold()
        if "powershell" in anlam and basit == "Windows Güvenlik denetimi":
            supheli.append((e, basit, sem.get("anlam")))
        if "sysmon" in anlam and basit != "Sysmon":
            supheli.append((e, basit, sem.get("anlam")))
    for e, basit, anlam in supheli:
        print(f"   YANLIS: {e} -> '{basit}' ama katalog diyor ki: {anlam}")
    if not supheli:
        print("   (yanlis siniflanan ID bulunamadi)")
    return 0


def rows_event_ids(rows):
    out = set()
    for row in rows.values():
        e = row.get("event.id") or row.get("EventID")
        if e:
            out.add(str(e))
    return out


def _key(e: str):
    return (0, int(e)) if e.isdigit() else (1, 0)


def _basit_kaynak(event_id: str) -> str:
    if not event_id.isdigit():
        return "bilinmiyor"
    n = int(event_id)
    if 1 <= n <= 30:
        return "Sysmon"
    if event_id == "7045":
        return "System log"
    if 4000 <= n < 6000:
        return "Windows Güvenlik denetimi"
    return "bilinmiyor"


if __name__ == "__main__":
    raise SystemExit(main())
