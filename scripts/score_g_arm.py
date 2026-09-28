"""G kolunun puanlamasi -- UC EKSEN AYRI, tek 'dogruluk' sayisi YOK.

Eksenlerin tanimi docs/beklenti_13_heldout_set.md §4'te, kosu yapilmadan
once yazildi. Bu betik o tanimi uyguluyor, yenisini icat etmiyor.

    Eksen 1  KARAR SINIFI   isabet, yanlis alarm orani, yol dagilimi
    Eksen 2  TEKNIK         yanlis pozitif teknik; G-045 AYRI satir
    Eksen 3  KAYIP KATMANI  beklenen teknik nerede kayboldu

RECALL YAZILMAZ. Gerekcesi beklenti belgesinde (§2.2): 51 satirin yalnizca
1'i teknik bekliyor, tek satira dayanan bir recall sayisi anlamsizdir ve
okuyanı yanıltır. G'nin olctugu sey yanlis alarm oranidir.

    .venv/Scripts/python.exe scripts/score_g_arm.py
"""
from __future__ import annotations

import argparse
import collections
import json
import pathlib
import sys

KOK = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KOK))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ETIKETLER = KOK / "evaluation" / "g_arm_qradar_labels.json"
KOSU = KOK / "evaluation" / "results" / "g_arm_run.json"
RAPOR = KOK / "evaluation" / "results" / "g_arm_score.json"

SUSPICIOUS = "SUFFICIENT_SUSPICIOUS"


def _yaz(m: str = "") -> None:
    print(m, flush=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kosu", type=pathlib.Path, default=None,
                    help="puanlanacak kosu dosyasi")
    ap.add_argument("--rapor", type=pathlib.Path, default=None,
                    help="puan raporunun yazilacagi dosya")
    args = ap.parse_args()
    kosu_yolu = args.kosu or KOSU
    rapor_yolu = args.rapor or RAPOR

    etiketler = {
        e["id"]: e for e in json.loads(ETIKETLER.read_text(encoding="utf-8"))["kayitlar"]
    }
    kosu = json.loads(kosu_yolu.read_text(encoding="utf-8"))
    ortak = [i for i in etiketler if i in kosu and "hata" not in kosu[i]]
    hatali = [i for i in kosu if "hata" in kosu[i]]

    _yaz("=" * 74)
    _yaz("G KOLU PUANLAMASI -- 51 gercek QRadar satiri")
    _yaz("=" * 74)
    _yaz(f"puanlanan {len(ortak)}/{len(etiketler)} | hatali kosu {len(hatali)}")

    # ---------- EKSEN 1: KARAR SINIFI ------------------------------------
    _yaz("\n" + "-" * 74)
    _yaz("EKSEN 1 -- KARAR SINIFI")
    _yaz("-" * 74)

    isabet = [i for i in ortak if kosu[i]["decision"] == etiketler[i]["expected_decision"]]
    kacan = [i for i in ortak if etiketler[i]["expected_decision"] == SUSPICIOUS
             and kosu[i]["decision"] != SUSPICIOUS]
    yanlis_alarm = [i for i in ortak if etiketler[i]["negative_case"]
                    and kosu[i]["decision"] == SUSPICIOUS]
    negatifler = [i for i in ortak if etiketler[i]["negative_case"]]

    dagilim = collections.Counter(kosu[i]["decision"] for i in ortak)
    _yaz(f"  sinif isabeti        : {len(isabet)}/{len(ortak)}")
    _yaz(f"  cikan sinif dagilimi : {dict(dagilim)}")
    _yaz(f"  YANLIS ALARM ORANI   : {len(yanlis_alarm)}/{len(negatifler)} negatif ornekte"
         f"  {'-> ' + str(yanlis_alarm) if yanlis_alarm else ''}")
    _yaz(f"  kacirilan pozitif    : {len(kacan)} {kacan if kacan else ''}")

    # --- ONEMSIZ TABAN CIZGISI -- sinif isabetinin tuzagi -------------
    # "50/51 dogru" tek basina okunursa sistem iyi gorunur. Ama cikan
    # dagilim tek sinifsa, HICBIR SEY YAPMAYAN sabit bir siniflandirici da
    # ayni puani alir. O sayiyi yanina yazmadan isabet raporlanmaz.
    en_sik_sinif, en_sik_n = dagilim.most_common(1)[0]
    sabit = sum(
        1 for i in ortak if etiketler[i]["expected_decision"] == en_sik_sinif
    )
    _yaz(f"  ONEMSIZ TABAN        : sabit '{en_sik_sinif}' diyen siniflandirici "
         f"{sabit}/{len(ortak)} alir")
    if sabit >= len(isabet):
        _yaz("  >> UYARI: sinif isabeti onemsiz tabani GECMIYOR. Bu sayi "
             "sistemin ayirt ettigini GOSTERMEZ.")

    yollar = collections.Counter()
    for i in ortak:
        p = kosu[i].get("paths") or {}
        yollar[f"A={p.get('A')} B={p.get('B')}"] += 1
    _yaz(f"  yol dagilimi         : {dict(yollar)}")
    bastirilan = [i for i in ortak if kosu[i].get("suppression")]
    _yaz(f"  bastirma atesleyen   : {len(bastirilan)} {bastirilan if bastirilan else ''}")

    # ---------- EKSEN 2: TEKNIK ------------------------------------------
    _yaz("\n" + "-" * 74)
    _yaz("EKSEN 2 -- TEKNIK  (recall YAZILMIYOR, bkz. modul basligi)")
    _yaz("-" * 74)

    yanlis_pozitif = collections.Counter()
    teknikli_satir = 0
    toplam_teknik = 0
    for i in ortak:
        beklenen = set(etiketler[i]["expected_attack_ids"])
        cikan = [m["attack_id"] for m in kosu[i]["mappings"]]
        toplam_teknik += len(cikan)
        if cikan:
            teknikli_satir += 1
        for t in cikan:
            if t not in beklenen:
                yanlis_pozitif[t] += 1

    bos_bekleyen = [i for i in ortak if not etiketler[i]["expected_attack_ids"]]
    bos_bekleyip_uretmeyen = [i for i in bos_bekleyen if not kosu[i]["mappings"]]
    _yaz(f"  teknik BEKLENMEYEN satir      : {len(bos_bekleyen)}")
    _yaz(f"  bunlarin kaci gercekten bos   : {len(bos_bekleyip_uretmeyen)}/{len(bos_bekleyen)}")
    _yaz(f"  toplam uretilen teknik        : {toplam_teknik}")
    _yaz(f"  satir basina ortalama         : {toplam_teknik / max(len(ortak), 1):.1f}")
    _yaz(f"  essiz yanlis pozitif teknik   : {len(yanlis_pozitif)}")
    _yaz("  en sik yanlis pozitifler      :")
    for t, n in yanlis_pozitif.most_common(10):
        _yaz(f"      {t:14} {n:3d} satirda")

    # ---------- TEK POZITIF: AYRI SATIR ----------------------------------
    _yaz("\n  --- G-045 (tek pozitif satir) AYRI raporlanir ---")
    e, k = etiketler.get("G-045"), kosu.get("G-045")
    if e and k:
        cikan = [m["attack_id"] for m in k["mappings"]]
        beklenen = e["expected_attack_ids"]
        bulunan = [t for t in beklenen if t in cikan]
        _yaz(f"      beklenen : {beklenen}")
        _yaz(f"      cikan    : {cikan}")
        _yaz(f"      top-1    : {'EVET' if cikan[:1] and cikan[0] in beklenen else 'HAYIR'}")
        _yaz(f"      top-3    : {'EVET' if set(cikan[:3]) & set(beklenen) else 'HAYIR'}")
        _yaz(f"      bulunan  : {bulunan or 'HICBIRI'}")
        _yaz(f"      karar    : {k['decision']} (beklenen {e['expected_decision']})")

    # ---------- EKSEN 3: KAYIP KATMANI -----------------------------------
    _yaz("\n" + "-" * 74)
    _yaz("EKSEN 3 -- DOGRU TEKNIK HANGI KATMANDA KAYBOLDU")
    _yaz("-" * 74)

    katman = collections.Counter()
    ayrinti = []
    for i in ortak:
        cikan = {m["attack_id"] for m in kosu[i]["mappings"]}
        for t in etiketler[i]["expected_attack_ids"]:
            if t in cikan:
                katman["cikti (kayip yok)"] += 1
                continue
            k2 = kosu[i]
            if t in (k2.get("agent_rejected_mappings") or []):
                yer = "ajan katmani eledi"
            elif t in (k2.get("rejected_mappings") or []):
                yer = "kanit kapisi eledi"
            elif t in (k2.get("mappings_before_agents") or []):
                yer = "ajan sonrasi kayboldu"
            elif t in (k2.get("retrieval_candidates") or []):
                yer = "LLM secmedi (aday havuzunda VARDI)"
            else:
                yer = "retrieval aday havuzuna HIC girmedi"
            katman[yer] += 1
            ayrinti.append((i, t, yer))

    if not katman:
        _yaz("  (teknik bekleyen satir yok)")
    for yer, n in katman.most_common():
        _yaz(f"  {yer:38} {n}")
    for i, t, yer in ayrinti:
        _yaz(f"      {i} {t:12} -> {yer}")

    # ---------- INCELEME BAYRAGI -----------------------------------------
    _yaz("\n" + "-" * 74)
    _yaz("INCELEME BAYRAGI TASIYAN SATIRLAR")
    _yaz("-" * 74)
    for i in ortak:
        if etiketler[i]["review_flag"]:
            _yaz(f"  {i}: karar={kosu[i]['decision']} "
                 f"teknik={[m['attack_id'] for m in kosu[i]['mappings']]}")

    sureler = [kosu[i].get("kosu_sn") for i in ortak if kosu[i].get("kosu_sn")]
    _yaz("\n" + "-" * 74)
    _yaz(f"SURE: toplam {sum(sureler) / 60:.0f} dk | satir basina ort "
         f"{sum(sureler) / len(sureler):.0f} sn | en uzun {max(sureler):.0f} sn")

    rapor_yolu.write_text(
        json.dumps(
            {
                "puanlanan": len(ortak),
                "eksen1_karar": {
                    "sinif_isabeti": f"{len(isabet)}/{len(ortak)}",
                    "cikan_dagilim": dict(dagilim),
                    "yanlis_alarm": f"{len(yanlis_alarm)}/{len(negatifler)}",
                    "kacirilan_pozitif": kacan,
                    "onemsiz_taban": f"{sabit}/{len(ortak)}",
                    "yol_dagilimi": dict(yollar),
                    "bastirma_atesleyen": bastirilan,
                },
                "eksen2_teknik": {
                    "toplam_uretilen": toplam_teknik,
                    "satir_basina": round(toplam_teknik / max(len(ortak), 1), 2),
                    "essiz_yanlis_pozitif": len(yanlis_pozitif),
                    "en_sik": yanlis_pozitif.most_common(10),
                    "teknik_beklenmeyip_bos_kalan": (
                        f"{len(bos_bekleyip_uretmeyen)}/{len(bos_bekleyen)}"
                    ),
                },
                "eksen3_kayip_katmani": dict(katman),
                "eksen3_ayrinti": ayrinti,
                "_not": "recall bilerek yazilmadi -- tek pozitif satir",
            },
            ensure_ascii=False,
            indent=1,
        ),
        encoding="utf-8",
    )
    _yaz(f"\nRapor: {rapor_yolu.relative_to(KOK)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
