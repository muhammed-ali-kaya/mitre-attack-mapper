"""K1 -- kural katalogu degisikliginin kanit kapisi uzerindeki yan etkisi.
Tahmin disi degisiklikte exit 1.

TABAN CIZGISI GIT'TEN OKUNUR (`git show d1439f6:rules/attack_mappings.yaml`),
elle kopyalanmis bir "onceki katalog" tutulmaz: kopya bayatlar.

NE OLCULUR: kayitli kosularin `mappings_before_agents` secimleri, ham girdiden
`text_to_row` ile kurulan satirlar uzerinde kanit kapisindan
(`evidence_gate_decisions`) TABAN ve GUNCEL katalogla ayri ayri gecirilir;
karar farki (confirm / reject / abstain / susma) beklenti belgesinin
(docs/beklenti_K1_kural_kalitesi.md §4) adim tablosuyla karsilastirilir.
Tahminler TABANA gore BIRIKIMLIDIR.

KORPUS (186 kayit): G 51 (g_arm_run_v2.json + gercek QRadar CSV), S 60, H 15,
dondurulmus 19.2'nin 60 senaryosu (controlled_attack_19_2/eval_raw_outputs.jsonl).
Dondurulmus dosyalar yalnizca OKUNUR.

LLM ve indeks GEREKMEZ. Cikti yalnizca kimlik + teknik + karar tasir, ham log
metni yazmaz (yayin kapisi B'nin konusu).

Kullanim:
    python scripts/measure_k1_side_effect.py --step K1a
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

KOK = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KOK))

from app.agents.verification import evidence_gate_decisions  # noqa: E402
from app.mapping.rule_engine import load_rules  # noqa: E402
from app.mapping.text_input import text_to_row  # noqa: E402

TABAN = "d1439f6"
R = KOK / "evaluation" / "results"
G_CSV = KOK / "tests" / "fixtures" / "qradar_2026-08-06_51rows.csv"
CIKTI_DIZIN = KOK / "docs" / "olcum_k1"

# --- beklenti belgesi §4, TABANA gore birikimli -----------------------------
K1A = {
    ("B60", "rawlog-009", "T1685.005"): ("reject", "confirm"),
    ("S", "S-A-10", "T1685.005"): ("reject", "confirm"),
    ("S", "S-ID-07", "T1685.001"): ("susma", "confirm"),
    ("S", "S-A-11", "T1685.001"): ("susma", "reject"),
    ("S", "S-ID-09", "T1685"): ("susma", "reject"),
    ("G", "G-026", "T1685.001"): ("susma", "reject"),
    ("S", "S-EK2-02", "T1685.001"): ("susma", "reject"),
    ("B60", "platform-002", "T1543.001"): ("abstain", "susma"),
    # beklenen gerilemeler (D4 c) -- K1a' geri cevirmeli
    ("S", "S-ID-09", "T1686"): ("susma", "reject"),
    ("S", "S-ID-10", "T1686"): ("susma", "reject"),
    ("S", "S-ID-13", "T1685.001"): ("susma", "reject"),
}
K1A2 = {**K1A,
        ("S", "S-ID-09", "T1686"): ("susma", "confirm"),
        ("S", "S-ID-10", "T1686"): ("susma", "confirm"),
        ("S", "S-ID-13", "T1685.001"): ("susma", "confirm")}
K1D = {**K1A2,
       ("S", "S-A-12", "T1059.001"): ("reject", "confirm"),
       ("S", "S-A-13", "T1547.001"): ("reject", "confirm")}
BEKLENEN = {"baseline": {}, "K1a": K1A, "K1a2": K1A2, "K1b": K1A2, "K1c": K1A2, "K1d": K1D}


def _ids(mappings) -> list[str]:
    return [m if isinstance(m, str) else m.get("attack_id") for m in (mappings or [])]


def _set_girdileri(yol: Path) -> dict[str, str]:
    ham = json.loads(yol.read_text(encoding="utf-8"))
    kayitlar = ham["kayitlar"] if isinstance(ham, dict) else ham
    return {k["id"]: k["input"] for k in kayitlar if isinstance(k, dict) and k.get("input")}


def korpus() -> list[tuple[str, str, str, list[str]]]:
    """(kol, kimlik, ham_metin, secimler)."""
    kayitlar: list[tuple[str, str, str, list[str]]] = []
    if G_CSV.exists():
        from app.batch.qradar_adapter import try_convert_qradar_export
        from app.batch.serialize import row_to_kv_string

        g = try_convert_qradar_export(G_CSV.read_bytes())
        kosu = json.loads((R / "g_arm_run_v2.json").read_text(encoding="utf-8"))
        for i, satir in enumerate(g):
            k = f"G-{i:03d}"
            kayitlar.append(("G", k, row_to_kv_string(satir), _ids(kosu.get(k, {}).get("mappings_before_agents"))))
    else:
        print(f"  NOT: {G_CSV.name} yok (yayin kopyasi) -- G kolu olculmedi")
    for kol, setf, kosuf in (("S", "s_arm_set.json", "s_arm_run.json"), ("H", "heldout_set.json", "h_arm_run.json")):
        girdiler = _set_girdileri(KOK / "evaluation" / setf)
        kosu = json.loads((R / kosuf).read_text(encoding="utf-8"))
        for k, v in kosu.items():
            kayitlar.append((kol, k, girdiler.get(k, ""), _ids(v.get("mappings_before_agents"))))
    sen = json.loads((KOK / "evaluation" / "test_scenarios.json").read_text(encoding="utf-8"))
    sen = sen if isinstance(sen, list) else sen["scenarios"]
    girdi = {s["test_id"]: s["input"] for s in sen}
    for satir in (R / "controlled_attack_19_2" / "eval_raw_outputs.jsonl").read_text(encoding="utf-8").splitlines():
        r = json.loads(satir)
        kayitlar.append(("B60", r["test_id"], girdi[r["test_id"]], _ids((r.get("improved_raw") or {}).get("mappings_before_agents"))))
    return kayitlar


def kararlar(kayitlar, kurallar) -> dict[tuple[str, str, str], str]:
    sonuc: dict[tuple[str, str, str], str] = {}
    for kol, k, metin, secimler in kayitlar:
        if not metin or not secimler:
            continue
        satir = text_to_row(metin)
        d = {x.technique_id: x.verdict.value for x in evidence_gate_decisions([{"attack_id": s} for s in secimler], [satir], kurallar)}
        for s in secimler:
            sonuc[(kol, k, s)] = d.get(s, "susma")
    return sonuc


def taban_kurallar():
    ham = subprocess.run(["git", "show", f"{TABAN}:rules/attack_mappings.yaml"], cwd=KOK,
                         capture_output=True, check=True).stdout
    with tempfile.NamedTemporaryFile("wb", suffix=".yaml", delete=False) as f:
        f.write(ham)
        yol = Path(f.name)
    try:
        return load_rules(yol)
    finally:
        yol.unlink(missing_ok=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--step", required=True, choices=list(BEKLENEN))
    a = ap.parse_args()

    kayitlar = korpus()
    print(f"korpus: {len(kayitlar)} kayit "
          + str({kol: sum(1 for x in kayitlar if x[0] == kol) for kol in ('G', 'S', 'H', 'B60')}))
    once = kararlar(kayitlar, taban_kurallar())
    sonra = kararlar(kayitlar, load_rules())

    degisen = {k: (once[k], sonra[k]) for k in once if once[k] != sonra[k]}
    beklenen = BEKLENEN[a.step]
    tahmin_disi = {k: v for k, v in degisen.items() if beklenen.get(k) != v}
    gerceklesmeyen = {k: v for k, v in beklenen.items() if degisen.get(k) != v}

    print(f"\nadim {a.step}: tabana gore degisen karar {len(degisen)} / beklenen {len(beklenen)}")
    for k, (o, s) in sorted(degisen.items()):
        isaret = "  " if beklenen.get(k) == (o, s) else "!!"
        print(f"  {isaret} {k[0]:3} {k[1]:14} {k[2]:10} {o:>8} -> {s}")
    for k, v in sorted(gerceklesmeyen.items()):
        print(f"  !! BEKLENIP GERCEKLESMEYEN: {k} {v[0]} -> {v[1]} (olculen: {degisen.get(k, 'degismedi')})")

    CIKTI_DIZIN.mkdir(parents=True, exist_ok=True)
    (CIKTI_DIZIN / f"yan_etki_{a.step}.json").write_text(json.dumps({
        "adim": a.step,
        "taban": TABAN,
        "korpus_kayit": len(kayitlar),
        "karar_sayisi": len(once),
        "degisen": [{"kol": k[0], "kayit": k[1], "teknik": k[2], "once": o, "sonra": s}
                    for k, (o, s) in sorted(degisen.items())],
        "tahmin_disi": [list(k) for k in sorted(tahmin_disi)],
        "gerceklesmeyen": [list(k) for k in sorted(gerceklesmeyen)],
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    if tahmin_disi or gerceklesmeyen:
        print(f"\nSONUC: TAHMIN DISI ({len(tahmin_disi)} beklenmeyen, {len(gerceklesmeyen)} gerceklesmeyen)")
        return 1
    print("\nSONUC: tahminle birebir")
    return 0


if __name__ == "__main__":
    sys.exit(main())
