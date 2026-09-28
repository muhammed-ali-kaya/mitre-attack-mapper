"""G kolunun IKI kosusunu yan yana koyar -- KARAR ve TEKNIK AYRI eksenlerde.

    .venv/Scripts/python.exe scripts/compare_g_arm_runs.py \
        --once evaluation/results/g_arm_run.json \
        --sonra evaluation/results/g_arm_run_v2.json

NEDEN TEK BIR "IYILESTI" SAYISI YOK
    Gorev 15'in duzeltmesi IKI SEYI BIRDEN degistiriyor (beklenti SS5):

      1. KARAR YOLU  -- access.mask kurtarildi, erisim_sinifi artik 'write',
                        yani Yol B ATESLENEBILIR. Amaclanan etki.
      2. TEKNIK LISTESI -- kurtarilan process.id / source.ip / handle.id /
                        object.name alanlari discriminating_fields uzerinden
                        SORGU 1. KATMANINA giriyor, yani retrieval farkli
                        aday getirebilir. Yan etki.

    Tek bir dogruluk sayisi bu ikisini toplayip hangi katmanin degistigini
    KAYBETTIRIR -- HANDOFF'un "karar sinifi dogrulugu != teknik listesi
    dogrulugu" maddesi ve docs/sonuc_13_g_kolu.md SS1'in kendi dersi.

KOSMADAN ONCE YAZILAN TAHMIN (beklenti SS5) BURADA SINANIR
    Bes 4656 satiri (G-007, G-015, G-029, G-030, G-040) 0x2001F maskesiyle
    handle istiyor; maske 'Set key value' iceriyor. Tahmin: Yol B bu bes
    satirda ateslenir ve yanlis alarm 0/49 -> 5/49 cikar. Bu bir GERILEME
    DEGIL, olcumun ilk kez mumkun olmasidir: 0/49 kazanilmamisti.
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
SUSPICIOUS = "SUFFICIENT_SUSPICIOUS"

# Beklenti SS5'te KOSMADAN ONCE yazilan tahmin. Kod burada, ciktiyi gorup
# degistirilmemesi icin sabit.
TAHMIN_YOL_B = ["G-007", "G-015", "G-029", "G-030", "G-040"]


def _yaz(m: str = "") -> None:
    print(m, flush=True)


def _yukle(yol: pathlib.Path) -> dict:
    return json.loads(yol.read_text(encoding="utf-8"))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", type=pathlib.Path,
                    default=KOK / "evaluation" / "results" / "g_arm_run.json")
    ap.add_argument("--sonra", type=pathlib.Path,
                    default=KOK / "evaluation" / "results" / "g_arm_run_v2.json")
    ap.add_argument("--rapor", type=pathlib.Path,
                    default=KOK / "evaluation" / "results" / "g_arm_karsilastirma.json")
    args = ap.parse_args()

    etiketler = {
        e["id"]: e for e in _yukle(ETIKETLER)["kayitlar"]
    }
    a = {k: v for k, v in _yukle(args.once).items() if not k.startswith("_")}
    b = {k: v for k, v in _yukle(args.sonra).items() if not k.startswith("_")}

    ortak = [i for i in etiketler
             if i in a and i in b and "hata" not in a[i] and "hata" not in b[i]]

    _yaz("=" * 74)
    _yaz("G KOLU -- IKI KOSU YAN YANA")
    _yaz("=" * 74)
    _yaz(f"  once : {args.once.name}  ({len(a)} satir)")
    _yaz(f"  sonra: {args.sonra.name}  ({len(b)} satir)")
    _yaz(f"  karsilastirilan: {len(ortak)}/{len(etiketler)}")
    if len(ortak) < len(etiketler):
        _yaz("  >> UYARI: kosu eksik. Asagidaki sayilar TAM KOSU degildir.")

    # ================= EKSEN 1 -- KARAR ==================================
    _yaz("\n" + "-" * 74)
    _yaz("EKSEN 1 -- KARAR YOLU (amaclanan etki)")
    _yaz("-" * 74)

    def _sayilar(kosu: dict) -> dict:
        negatifler = [i for i in ortak if etiketler[i]["negative_case"]]
        return {
            "isabet": sum(1 for i in ortak
                          if kosu[i]["decision"] == etiketler[i]["expected_decision"]),
            "dagilim": dict(collections.Counter(kosu[i]["decision"] for i in ortak)),
            "yanlis_alarm": [i for i in negatifler if kosu[i]["decision"] == SUSPICIOUS],
            "negatif": len(negatifler),
            "yol_B": [i for i in ortak if (kosu[i].get("paths") or {}).get("B")],
            "yol_A": [i for i in ortak if (kosu[i].get("paths") or {}).get("A")],
            "bastirma": [i for i in ortak if kosu[i].get("suppression")],
        }

    sa, sb = _sayilar(a), _sayilar(b)
    _yaz(f"  {'':22s} {'ONCE':>22s}   {'SONRA':>22s}")
    _yaz(f"  {'sinif isabeti':22s} {str(sa['isabet']) + '/' + str(len(ortak)):>22s}   "
         f"{str(sb['isabet']) + '/' + str(len(ortak)):>22s}")
    _yaz(f"  {'yanlis alarm':22s} "
         f"{str(len(sa['yanlis_alarm'])) + '/' + str(sa['negatif']):>22s}   "
         f"{str(len(sb['yanlis_alarm'])) + '/' + str(sb['negatif']):>22s}")
    _yaz(f"  {'Yol A atesleyen':22s} {len(sa['yol_A']):>22d}   {len(sb['yol_A']):>22d}")
    _yaz(f"  {'Yol B atesleyen':22s} {len(sa['yol_B']):>22d}   {len(sb['yol_B']):>22d}")
    _yaz(f"  {'bastirma atesleyen':22s} {len(sa['bastirma']):>22d}   {len(sb['bastirma']):>22d}")
    _yaz(f"  once  dagilim: {sa['dagilim']}")
    _yaz(f"  sonra dagilim: {sb['dagilim']}")

    karar_degisen = [i for i in ortak if a[i]["decision"] != b[i]["decision"]]
    _yaz(f"\n  KARARI DEGISEN SATIR: {len(karar_degisen)}")
    for i in karar_degisen:
        e = etiketler[i]
        pa = (a[i].get("paths") or {})
        pb = (b[i].get("paths") or {})
        dogru = "DOGRU" if b[i]["decision"] == e["expected_decision"] else "YANLIS"
        _yaz(f"    {i}  {a[i]['decision']} -> {b[i]['decision']}  [{dogru}]"
             f"  (beklenen {e['expected_decision']}, negatif={e['negative_case']})")
        _yaz(f"         yol once A={pa.get('A')} B={pa.get('B')}"
             f"  | sonra A={pb.get('A')} B={pb.get('B')}")

    # --- TAHMININ SINANMASI ---
    _yaz("\n  --- kosmadan once yazilan tahmin (beklenti SS5) ---")
    _yaz(f"      tahmin: Yol B su bes satirda ateslenir: {TAHMIN_YOL_B}")
    _yaz(f"      gercek: Yol B {sorted(sb['yol_B'])}")
    tuttu = sorted(sb["yol_B"]) == sorted(TAHMIN_YOL_B)
    _yaz(f"      TAHMIN {'TUTTU' if tuttu else 'TUTMADI'}")
    if not tuttu:
        _yaz(f"        tahmin edilip ateslenmeyen: {sorted(set(TAHMIN_YOL_B) - set(sb['yol_B']))}")
        _yaz(f"        tahmin edilmeyip atesleyen: {sorted(set(sb['yol_B']) - set(TAHMIN_YOL_B))}")

    # ================= EKSEN 2 -- TEKNIK =================================
    _yaz("\n" + "-" * 74)
    _yaz("EKSEN 2 -- TEKNIK LISTESI (yan etki: sorgu degisti)")
    _yaz("-" * 74)

    def _teknikler(kosu: dict, i: str) -> list[str]:
        return [m["attack_id"] for m in kosu[i]["mappings"]]

    teknik_degisen = [i for i in ortak if _teknikler(a, i) != _teknikler(b, i)]
    toplam_a = sum(len(_teknikler(a, i)) for i in ortak)
    toplam_b = sum(len(_teknikler(b, i)) for i in ortak)

    yp_a, yp_b = collections.Counter(), collections.Counter()
    for i in ortak:
        beklenen = set(etiketler[i]["expected_attack_ids"])
        for t in _teknikler(a, i):
            if t not in beklenen:
                yp_a[t] += 1
        for t in _teknikler(b, i):
            if t not in beklenen:
                yp_b[t] += 1

    _yaz(f"  {'toplam uretilen teknik':30s} {toplam_a:>8d} -> {toplam_b:<8d}")
    _yaz(f"  {'satir basina ortalama':30s} "
         f"{toplam_a / max(len(ortak), 1):>8.1f} -> {toplam_b / max(len(ortak), 1):<8.1f}")
    _yaz(f"  {'essiz yanlis pozitif teknik':30s} {len(yp_a):>8d} -> {len(yp_b):<8d}")
    _yaz(f"  {'teknik listesi degisen satir':30s} {len(teknik_degisen):>8d}")

    # KAZANC ile KAYIP AYRI. "Teknik sayisi azaldi" tek basina iyilesme
    # DEGILDIR: dogru teknigi de atmis olabilir (HANDOFF dersi 11).
    _yaz("\n  yalniz ONCE ureten / yalniz SONRA ureten teknikler:")
    sadece_a, sadece_b = collections.Counter(), collections.Counter()
    for i in ortak:
        ta, tb = set(_teknikler(a, i)), set(_teknikler(b, i))
        for t in ta - tb:
            sadece_a[t] += 1
        for t in tb - ta:
            sadece_b[t] += 1
    _yaz(f"    ONCE'de olup SONRA'da olmayan : {dict(sadece_a.most_common(10))}")
    _yaz(f"    SONRA'da olup ONCE'de olmayan : {dict(sadece_b.most_common(10))}")

    # --- G-045 tek pozitif: AYRI ---
    _yaz("\n  --- G-045 (tek pozitif satir) ---")
    if "G-045" in ortak:
        beklenen = etiketler["G-045"]["expected_attack_ids"]
        _yaz(f"      beklenen : {beklenen}")
        _yaz(f"      once     : {_teknikler(a, 'G-045')}")
        _yaz(f"      sonra    : {_teknikler(b, 'G-045')}")
    else:
        _yaz("      kosuda yok")

    rapor = {
        "_aciklama": "G kolu iki kosu karsilastirmasi -- karar ve teknik AYRI eksen",
        "once": str(args.once.name),
        "sonra": str(args.sonra.name),
        "karsilastirilan": len(ortak),
        "eksen1_karar": {
            "once": {k: (v if not isinstance(v, list) else sorted(v)) for k, v in sa.items()},
            "sonra": {k: (v if not isinstance(v, list) else sorted(v)) for k, v in sb.items()},
            "karari_degisen": karar_degisen,
            "tahmin_yol_b": TAHMIN_YOL_B,
            "tahmin_tuttu": tuttu,
        },
        "eksen2_teknik": {
            "toplam_once": toplam_a,
            "toplam_sonra": toplam_b,
            "essiz_yanlis_pozitif_once": len(yp_a),
            "essiz_yanlis_pozitif_sonra": len(yp_b),
            "listesi_degisen_satir": teknik_degisen,
            "sadece_once": dict(sadece_a),
            "sadece_sonra": dict(sadece_b),
        },
    }
    args.rapor.parent.mkdir(parents=True, exist_ok=True)
    args.rapor.write_text(json.dumps(rapor, ensure_ascii=False, indent=2), encoding="utf-8")
    _yaz(f"\nyazildi: {args.rapor.relative_to(KOK)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
