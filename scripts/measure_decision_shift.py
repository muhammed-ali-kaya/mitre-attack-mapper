"""Gorev 5 yan etkisi: detect_benign_signals karardan cikinca ne degisti?

SORU. Eski katman iki kaynagi birlestiriyordu: LLM'in activity_verdict
beyani + kod tarafindaki mesruiyet sinyalleri. Sinyallerden biri 'strong'
ise karar KOSULSUZ 'likely_benign' oluyordu -- LLM ne derse desin. O kural
artik yok (sinyal taklit edilebilir oldugu icin karardan cikarildi).

NE OLCULEBILIR, NE OLCULEMEZ -- ayrimi bastan yaz.
    OLCULEBILIR: 'strong' sinyalin hangi senaryolarda atesledigi. Bu KOD
    tarafinda ve deterministik; LLM cagirmadan sayilir. Eski sistemin bu
    senaryolarda 'likely_benign' verecegi kesindi.

    OLCULEMEZ: eski sistemin GERI KALAN senaryolarda ne dedigi. O karar
    LLM'in activity_verdict alanina bagliydi ve alan artik yok. Yeniden
    uretmek icin eski kodu geri almak gerekirdi; yapilmadi. Rapor bu sinirla
    okunur -- "60 senaryonun tamami icin once/sonra" DENEMEZ.

ADIM 2 (--pipeline): etkilenen senaryolar gercek hattan gecirilir ve
yeni karar sinifi + informational_only bayragi olculur. Yalnizca etkilenen
altkume kosulur: 60'in tamami ~1-2 saat surer ve sorunun cevabini
degistirmez.
"""
from __future__ import annotations

import argparse
import collections
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.normalization.asset_criticality import siniflandir
from app.normalization.command_line_paths import extract_registry_paths
from app.normalization.event_semantics import describe
from app.normalization.input_parser import normalize_input
from app.validation.benign_signals import detect_benign_signals

SENARYOLAR = ROOT / "evaluation" / "test_scenarios.json"


def _val(field):
    v = getattr(field, "value", field)
    if v is None:
        return None
    if isinstance(v, list):
        return v or None
    s = str(v).strip()
    return None if not s or s.upper() == "N/A" else s


def _girdiler(raw: str) -> dict:
    """Karar fonksiyonunun LLM'siz okuyabildigi girdiler."""
    n = normalize_input(raw)
    pf = n.get("parsed_fields") or {}
    g = lambda *ks: next((_val(pf.get(k)) for k in ks if _val(pf.get(k))), None)

    yol = g("object.name", "registry.path", "file.path")
    if not yol:
        for aday in extract_registry_paths(g("process.command_line", "command_line")):
            yol = aday
            break
    k = siniflandir(yol) if yol else None
    d = describe(g("event.id") or n.get("event_id"), g("access.mask"),
                 g("object.type"), g("access.list"))
    return {
        "kritiklik": "YOK" if not yol else ("unknown" if k.bilinmiyor else k.seviye),
        "aile": (k.aile if k else None),
        "erisim": d.get("access_class"),
        "hesap": g("account.name", "user.name", "subject.user"),
        "surec": g("process.name"),
    }


def adim_1_etkilenen_populasyon(senaryolar: list[dict]) -> list[dict]:
    print("1) ETKILENEN POPULASYON -- 'strong' sinyal kac senaryoda atesliyor?")
    etkilenen = []
    kategori = collections.Counter()
    for s in senaryolar:
        raw = s.get("input") or ""
        sinyal = detect_benign_signals(raw)
        if not sinyal.strong:
            continue
        girdi = _girdiler(raw)
        etkilenen.append({**s, "_sinyal": sinyal.signals, "_girdiler": girdi})
        kategori[s.get("category")] += 1

    print(f"   strong sinyal        : {len(etkilenen)}/{len(senaryolar)}")
    for kat, n in sorted(kategori.items()):
        print(f"        {kat:26s} {n}")
    print()
    print("   Bu senaryolarda ESKI sistem KOSULSUZ 'likely_benign' verirdi.")
    print("   Yeni sistemde karar bu sinyale BAKMIYOR; asagida ne kaldigi:")
    print(f"   {'test_id':22s} {'kritiklik':10s} {'erisim':7s} {'yolB?':6s} sinyal")
    for e in etkilenen:
        g = e["_girdiler"]
        yolb = g["kritiklik"] in ("critical", "high") and g["erisim"] == "write"
        print(f"   {str(e.get('test_id'))[:22]:22s} {g['kritiklik']:10s} "
              f"{str(g['erisim'] or '-'):7s} {str(yolb):6s} {e['_sinyal'][0][:38]}")
    return etkilenen


def adim_1b_yol_b_taramasi(senaryolar: list[dict]) -> None:
    """Yol B 60 senaryonun kacinda tetiklenebilir? (LLM'siz, kesin)"""
    say = collections.Counter()
    for s in senaryolar:
        g = _girdiler(s.get("input") or "")
        say[g["kritiklik"]] += 1
        if g["kritiklik"] in ("critical", "high") and g["erisim"] == "write":
            say["YOL_B"] += 1
    print("\n1b) YOL B TARAMASI (LLM gerekmez)")
    for k in ("YOK", "unknown", "noise", "medium", "high", "critical"):
        if say[k]:
            print(f"   kritiklik {k:9s} {say[k]:3d}")
    print(f"   YOL B tetiklenir  {say['YOL_B']:3d}/{len(senaryolar)}")
    print("   => Yol B duzyazi senaryolarda kurulamaz. Bu senaryolarda karar")
    print("      TAMAMEN Yol A'ya, yani DOGRULANMIS KANIT sayisina bagli.")


def adim_2_pipeline(etkilenen: list[dict], limit: int) -> None:
    """Etkilenen senaryolari GERCEK hattan gecir."""
    from app.retrieval.improved_pipeline import run_improved_query

    print(f"\n2) GERCEK HAT -- {min(limit, len(etkilenen))} senaryo")
    print(f"   {'test_id':22s} {'KARAR':22s} {'kanit':6s} {'alarm':6s} info_only")
    dagilim = collections.Counter()
    tutarsiz = 0
    for e in etkilenen[:limit]:
        sonuc = run_improved_query(e["input"], platform=None)
        karar = sonuc.get("decision") or {}
        sinif = karar.get("decision")
        mappings = sonuc.get("mappings") or []
        alarm = sinif == "SUFFICIENT_SUSPICIOUS"
        info = [m.get("informational_only") for m in mappings]
        # SOZLESME: alarm uretmeyen her kararda TUM eslestirmeler
        # informational_only olmali; metrics.py bu bayragi okuyor.
        beklenen_info = not alarm
        uyumlu = all(bool(x) is beklenen_info for x in info) if mappings else True
        tutarsiz += 0 if uyumlu else 1
        dagilim[sinif] += 1
        print(f"   {str(e.get('test_id'))[:22]:22s} {str(sinif):22s} "
              f"{karar.get('inputs', {}).get('dogrulanmis_kanit', '?'):<6} "
              f"{str(alarm):6s} {info if mappings else '(eslestirme yok)'}"
              f"{'' if uyumlu else '   <-- TUTARSIZ'}")

    print(f"\n   dagilim: {dict(dagilim)}")
    print(f"   informational_only tutarsizligi: {tutarsiz}"
          f"{'  <-- alarm davranisi KORUNMADI' if tutarsiz else '  (bayrak dogru)'}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pipeline", action="store_true",
                    help="etkilenen senaryolari gercek hattan gecir (LLM gerekir)")
    ap.add_argument("--limit", type=int, default=99)
    ap.add_argument("--negatives", action="store_true",
                    help="etkilenen 4 yerine negatif_ornek kategorisinin 5'ini kosar "
                         "-- negative-005'te 'strong' sinyal YOK, kontrol vakasidir")
    args = ap.parse_args()

    senaryolar = json.loads(SENARYOLAR.read_text(encoding="utf-8"))
    etkilenen = adim_1_etkilenen_populasyon(senaryolar)
    adim_1b_yol_b_taramasi(senaryolar)
    if args.pipeline:
        hedef = etkilenen
        if args.negatives:
            # KONTROL VAKASI ICIN: negative-005'te guclu sinyal yok, yani eski
            # sistemde de bu senaryonun karari LLM'den geliyordu. Onu da
            # kosmak, degisimin sinyal kaldirmasindan mi yoksa baska bir
            # seyden mi geldigini ayirt ediyor.
            etkilenen_id = {e.get("test_id") for e in etkilenen}
            hedef = [
                {**s, "_sinyal": ["(kontrol -- guclu sinyal yok)"]}
                if s.get("test_id") not in etkilenen_id
                else next(e for e in etkilenen if e.get("test_id") == s.get("test_id"))
                for s in senaryolar if s.get("category") == "negatif_ornek"
            ]
        adim_2_pipeline(hedef, args.limit)
    else:
        print("\n(--pipeline verilmedi: adim 2 atlandi)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
