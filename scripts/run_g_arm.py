"""G kolunu (51 gercek QRadar satiri) hat uzerinde kosar -- DEVAM EDEBILIR.

NEDEN DEVAM EDEBILIR: olculdu (2026-08-30) ki olay basina sicak sure 80-120
sn, yani 51 satir ~85 dakika. Tek bir on plan cagrisi bu kadar surmez ve
bu olcum ARKA PLANDA KOSTURULMAZ (sicak kol daha once iki kez arka planda
sebebi bulunamadan oldu). Cozum: her cagri bir SURE BUTCESI kadar calisir,
her satirdan SONRA diske yazar, butce dolunca temiz cikar. Tekrar cagrilinca
kaldigi yerden devam eder.

    .venv/Scripts/python.exe scripts/run_g_arm.py                # 480 sn butce
    .venv/Scripts/python.exe scripts/run_g_arm.py --budget 300
    .venv/Scripts/python.exe scripts/run_g_arm.py --durum         # yalniz ilerleme

BU BETIK PUAN VERMEZ. Yalnizca hattin ham ciktisini kaydeder. Puanlama ayri
bir betikte -- kosarken puan gormek, kosu ortasinda esik ayarlama cazibesi
uretir.

KAYDEDILEN ALANLAR ucun eksene birebir karsilik gelir (beklenti belgesi §4):
    Eksen 1 karar : decision, paths, inputs, suppression
    Eksen 2 teknik: mappings (sirali)
    Eksen 3 kayip : retrieval_candidates -> mappings_before_agents ->
                    rejected_mappings -> agent_rejected_mappings -> mappings
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time

KOK = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KOK))

from app.retrieval.improved_pipeline import run_improved_query  # noqa: E402

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ETIKETLER = KOK / "evaluation" / "g_arm_qradar_labels.json"
SONUC = KOK / "evaluation" / "results" / "g_arm_run.json"

# NEDEN --out VAR (Gorev 15): duzeltmeden sonraki kosu, oncekinin uzerine
# YAZMAMALI. Onceki kosu "Yol B kapaliyken alinmis olcum" olarak duruyor ve
# farkin okunabilmesi icin ikisi YAN YANA gerekli. Varsayilan yol degismedi,
# yani eski cagri bicimi aynen calisir.


def _yaz(m: str = "") -> None:
    print(m, flush=True)


def _ozet(sonuc: dict) -> dict:
    """Hattin ciktisindan SADECE puanlamaya gereken alanlari alir.

    Tam cikti satir basina ~40 KB; 51 satirda dosya okunamaz hale gelir.
    Burada birakilan her alan bir metrige baglidir (bkz. modul basligi)."""
    karar = sonuc.get("decision") or {}
    return {
        "decision": karar.get("decision"),
        "paths": karar.get("paths"),
        "inputs": karar.get("inputs"),
        "suppression": karar.get("suppression"),
        "reason": karar.get("reason"),
        "mappings": [
            {"attack_id": m.get("attack_id"), "confidence_level": m.get("confidence_level")}
            for m in sonuc.get("mappings") or []
        ],
        "mappings_before_agents": [
            m.get("attack_id") for m in sonuc.get("mappings_before_agents") or []
        ],
        "rejected_mappings": [
            m.get("attack_id") for m in sonuc.get("rejected_mappings") or []
        ],
        "agent_rejected_mappings": [
            m.get("attack_id") for m in sonuc.get("agent_rejected_mappings") or []
        ],
        "retrieval_candidates": [
            c.get("attack_id") for c in sonuc.get("retrieval_candidates") or []
        ],
        "retrieved_chunk_sayisi": len(sonuc.get("retrieved_chunk_ids") or []),
        "loop_passes": sonuc.get("loop_passes"),
        "split_event_count": (sonuc.get("split") or {}).get("event_count"),
        "split_warning": (sonuc.get("split") or {}).get("warning"),
        "toplam_sn": (sonuc.get("timings") or {}).get("total_seconds"),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--budget", type=float, default=480.0, help="saniye (varsayilan 480)")
    ap.add_argument("--durum", action="store_true", help="kosmadan ilerlemeyi yaz")
    ap.add_argument("--out", type=pathlib.Path, default=None,
                    help="sonuc dosyasi (varsayilan evaluation/results/g_arm_run.json)")
    # NEDEN --set (Gorev 13, S kolu): S'i kosmak icin IKINCI bir kosucu
    # yazmak, bu oturumda uc kez isiran "ayni isi yapan iki kod yolu"
    # deseninin ta kendisi olurdu. Kol dosyalarinin semasi ayni (`kayitlar`
    # icinde id/input); degisen yalnizca hangi dosyanin okundugu.
    ap.add_argument("--set", dest="kol", type=pathlib.Path, default=None,
                    help="kol dosyasi (varsayilan evaluation/g_arm_qradar_labels.json)")
    args = ap.parse_args()

    kaynak = (args.kol.resolve() if args.kol else ETIKETLER)
    etiketler = json.loads(kaynak.read_text(encoding="utf-8"))["kayitlar"]
    # resolve(): goreli --out yolu relative_to(KOK)'u patlatiyordu.
    hedef = (args.out.resolve() if args.out else SONUC)
    hedef.parent.mkdir(parents=True, exist_ok=True)
    birikim: dict = (
        json.loads(hedef.read_text(encoding="utf-8")) if hedef.exists() else {}
    )

    kalan = [e for e in etiketler if e["id"] not in birikim]
    _yaz(f"{kaynak.stem}: {len(etiketler)} kayit | biten {len(birikim)} | kalan {len(kalan)}")

    if args.durum:
        return 0
    if not kalan:
        _yaz("Hepsi bitti. Puanlama: scripts/score_g_arm.py")
        return 0

    t0 = time.time()
    sureler = [
        v.get("kosu_sn") for v in birikim.values() if isinstance(v.get("kosu_sn"), (int, float))
    ]
    for sira, etiket in enumerate(kalan, 1):
        gecen = time.time() - t0
        if gecen >= args.budget:
            _yaz(f"\nSure butcesi doldu ({gecen:.0f}s >= {args.budget:.0f}s). Temiz cikiliyor.")
            break

        t1 = time.time()
        _yaz(f"[{etiket['id']}] ({sira}/{len(kalan)}) EventID={etiket['event_id']} kosuyor...")
        try:
            ham = run_improved_query(etiket["input"])
        except Exception as exc:  # olcum yarida kalmasin; hata da bir sonuctur
            birikim[etiket["id"]] = {"hata": f"{type(exc).__name__}: {exc}"}
            hedef.write_text(
                json.dumps(birikim, ensure_ascii=False, indent=1), encoding="utf-8"
            )
            _yaz(f"[{etiket['id']}] HATA: {type(exc).__name__}: {exc}")
            continue

        sn = time.time() - t1
        sureler.append(sn)
        kayit = _ozet(ham)
        kayit["kosu_sn"] = round(sn, 1)
        birikim[etiket["id"]] = kayit

        # HER SATIRDAN SONRA yazilir: 85 dakikalik bir kosuyu sonunda tek
        # seferde yazmak, yarida kesilmede her seyi goturur (beklenti §5.5).
        hedef.write_text(json.dumps(birikim, ensure_ascii=False, indent=1), encoding="utf-8")

        ort = sum(sureler) / len(sureler)
        kalan_sayi = len(etiketler) - len(birikim)
        _yaz(
            f"[{etiket['id']}] {sn:.0f}s -> {kayit['decision']} | "
            f"{len(kayit['mappings'])} teknik "
            f"{[m['attack_id'] for m in kayit['mappings']]}"
        )
        _yaz(
            f"      biten {len(birikim)}/{len(etiketler)} | ort {ort:.0f}s | "
            f"kalan ~{kalan_sayi * ort / 60:.0f} dk"
        )

    kalan_sayi = len(etiketler) - len(birikim)
    _yaz(f"\nYazildi: {hedef.relative_to(KOK)}  ({len(birikim)}/{len(etiketler)})")
    if kalan_sayi:
        _yaz(f"KALAN {kalan_sayi} satir. Ayni komutu tekrar calistir.")
    else:
        _yaz("G kolu TAMAMLANDI. Puanlama: scripts/score_g_arm.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
