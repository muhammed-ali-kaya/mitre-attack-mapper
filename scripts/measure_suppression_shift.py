"""Bastirma duzeltmesinin YAN ETKISI: kac kayit sinif degistirdi?

Karar katmani deterministiktir; LLM'in payi kayitli kosuda DONMUS durumda
(hangi teknikler secildi, kac tanesi dogrulandi). Yani S ve G kollarinin
kararlari, hattı yeniden kosmadan CEVRIMDISI yeniden uretilebilir:

    decide(normalize_input(ham), kayitli_mappings, sahte_dogrulama)

`sahte_dogrulama`, kayitli `inputs.dogrulanmis_kanit` sayisini birebir
yeniden uretir. Bu bir tahmin degil, kaydin kendi sayisidir.

SADIKLIK ONCE OLCULUR. Betik once bugunku kodla yeniden oynatir ve kayitli
kararla karsilastirir. Sadiklik %100 degilse fark okunmaz ve betik 2 ile
cikar -- cunku o durumda "duzeltme nesi degistirdi" sorusu, oynatmanin
kendi kusuruyla karisir. (Bu, oturumun yedi kez isirdigi deseni onlemek
icin: olcum araci once kendi sagligini gostermeli.)

    python scripts/measure_suppression_shift.py            # sadiklik + dagilim
    python scripts/measure_suppression_shift.py --kaydet X  # dagilimi X'e yaz
    python scripts/measure_suppression_shift.py --karsilastir X   # X ile fark

Tipik kullanim: duzeltmeden ONCE --kaydet, duzeltmeden SONRA --karsilastir.

Cikis kodu: 2 sadiklik bozuksa, 0 diger her durumda (fark bir HATA degil
olcumdur; kac kaydin degistigi burada YARGILANMAZ, raporlanir).
"""
from __future__ import annotations

import argparse
import collections
import json
import pathlib
import sys

KOK = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KOK))

from app.agents.base import AgentDecision, Verdict  # noqa: E402
from app.agents.verification import VerificationReport  # noqa: E402
from app.normalization.input_parser import normalize_input  # noqa: E402
from app.validation.decision import decide  # noqa: E402

KOLLAR = {
    "S": (KOK / "evaluation" / "s_arm_set.json",
          KOK / "evaluation" / "results" / "s_arm_run.json"),
    "G": (KOK / "evaluation" / "g_arm_qradar_labels.json",
          KOK / "evaluation" / "results" / "g_arm_run_v2.json"),
}


def _yaz(m: str = "") -> None:
    print(m, flush=True)


def _dogrulama(mappings: list[dict], kanit_sayisi: int) -> VerificationReport:
    """Kayitli `dogrulanmis_kanit` sayisini birebir yeniden uretir.

    dogrulanmis_kanit_sayisi() 'kabul edilen VE confirm alan' teknikleri
    sayiyor; ilk N teknige CONFIRM vermek tam olarak N uretir."""
    onaylanan = [m["attack_id"] for m in mappings[:kanit_sayisi]]
    kararlar = [
        AgentDecision(agent_id="replay", technique_id=t, verdict=Verdict.CONFIRM,
                      reason="kayitli kosudan yeniden uretildi")
        for t in onaylanan
    ]
    return VerificationReport(accepted=list(mappings), rejected=[], decisions=kararlar)


def oynat(kol: str) -> dict[str, dict]:
    set_yolu, kosu_yolu = KOLLAR[kol]
    kayitlar = {r["id"]: r for r in
                json.loads(set_yolu.read_text(encoding="utf-8"))["kayitlar"]}
    kosu = json.loads(kosu_yolu.read_text(encoding="utf-8"))

    cikti: dict[str, dict] = {}
    for rid, saklanan in kosu.items():
        ham = kayitlar[rid]["input"]
        mappings = saklanan.get("mappings") or []
        kanit = (saklanan.get("inputs") or {}).get("dogrulanmis_kanit") or 0
        karar = decide(normalize_input(ham), mappings, _dogrulama(mappings, kanit))
        cikti[rid] = {
            "kayitli": saklanan.get("decision"),
            "oynatilan": karar.decision,
            "bastirma": karar.suppression is not None,
            "kayitli_bastirma": saklanan.get("suppression") is not None,
            "paths": karar.paths,
            "process": (karar.inputs.get("aktor") or {}).get("process"),
        }
    return cikti


def olc(sadiklik_zorunlu: bool = True) -> tuple[dict[str, dict], bool]:
    hepsi: dict[str, dict] = {}
    sadik = True
    for kol in KOLLAR:
        sonuc = oynat(kol)
        hepsi[kol] = sonuc
        uyan = sum(1 for v in sonuc.values() if v["kayitli"] == v["oynatilan"])
        bast = sum(1 for v in sonuc.values() if v["bastirma"])
        _yaz(f"  {kol} kolu: {len(sonuc)} kayit | oynatma kayitliyla uyuyor "
             f"{uyan}/{len(sonuc)} | bastirma atesleyen {bast}")
        for rid, v in sonuc.items():
            if v["kayitli"] != v["oynatilan"]:
                _yaz(f"      FARK {rid}: kayitli={v['kayitli']} "
                     f"oynatilan={v['oynatilan']}")
        if uyan != len(sonuc):
            sadik = False
    return hepsi, sadik


def _dagilim(hepsi: dict[str, dict]) -> dict:
    return {
        kol: {rid: {"karar": v["oynatilan"], "bastirma": v["bastirma"]}
              for rid, v in sonuc.items()}
        for kol, sonuc in hepsi.items()
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kaydet", type=pathlib.Path, default=None)
    ap.add_argument("--karsilastir", type=pathlib.Path, default=None)
    ap.add_argument("--sadiklik-atla", action="store_true",
                    help="duzeltmeden SONRA: oynatma artik kayitli kosudan "
                         "farkli olacaktir, sadiklik sarti aranmaz")
    args = ap.parse_args()

    _yaz("SADIKLIK — bugunku kod kayitli kosuyu yeniden uretiyor mu?")
    hepsi, sadik = olc()
    _yaz()

    if not sadik and not args.sadiklik_atla:
        _yaz("SADIKLIK BOZUK: oynatma kayitli kosuyu yeniden uretemiyor.")
        _yaz("Fark okunmaz. Once oynatmanin kendisi duzeltilmeli.")
        return 2

    for kol, sonuc in hepsi.items():
        sayac = collections.Counter(v["oynatilan"] for v in sonuc.values())
        _yaz(f"  {kol} dagilim: {dict(sayac)}")
    _yaz()

    if args.kaydet:
        args.kaydet.parent.mkdir(parents=True, exist_ok=True)
        args.kaydet.write_text(
            json.dumps(_dagilim(hepsi), ensure_ascii=False, indent=2), encoding="utf-8")
        _yaz(f"kaydedildi: {args.kaydet}")

    if args.karsilastir:
        onceki = json.loads(args.karsilastir.read_text(encoding="utf-8"))
        _yaz("FARK — kayit kayit")
        toplam = 0
        for kol, sonuc in hepsi.items():
            eski = onceki.get(kol, {})
            for rid, v in sonuc.items():
                e = eski.get(rid)
                if not e:
                    continue
                if e["karar"] != v["oynatilan"] or e["bastirma"] != v["bastirma"]:
                    toplam += 1
                    _yaz(f"  {kol} {rid}: {e['karar']} -> {v['oynatilan']}"
                         f"   bastirma {e['bastirma']} -> {v['bastirma']}"
                         f"   (process={v['process']!r})")
        _yaz(f"  toplam degisen kayit: {toplam}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
