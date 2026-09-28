"""Gorev 18 -- 4656 maske duzeltmesinin B1 cifti uzerindeki etkisi.

NEDEN AYRI ARAC: measure_suppression_shift.py sadiklik kapisi yuzunden
Gorev 17'den sonra cikis 2 veriyor (docs/sonuc_17 §6.2 -- kasitli bir karar
katmani degisikliginden sonra "sadiklik kaybi" ile "amaclanan kayma" ayni
olcumdur ve o arac ikisini ayirmiyor). Bu arac tabani KAYITLI KOSUYA degil,
BIR ONCEKI KODUN OYNATMASINA gore aliyor -- yani karsilastirilan iki sayi da
ayni yoldan uretiliyor.

LLM ve indeks GEREKMEZ. Kararlar cevrimdisi yeniden uretiliyor:
teknik listesi ve dogrulanmis kanit sayisi kayitli kosudan BIREBIR aliniyor,
degisen tek sey karar katmaninin kendisi.

    python scripts/measure_b1_mask.py                  # B1 + dagilim
    python scripts/measure_b1_mask.py --kaydet X       # dagilimi X'e yaz
    python scripts/measure_b1_mask.py --karsilastir X  # X ile fark

Cikis kodu 1: B1 kabul olcutu saglanmiyorsa (sonuc_13_s_kolu.md §3).
Olcut 1. ciftte ULASILAMAZ ve bu koda baglandi -- bkz. ULASILAMAZ sabiti ve
docs/beklenti_18_maske_talep.md §3.1. Beklentiyi hafizadan degil dosyadan
okumak icin degil, okunabilir kalmasi icin burada da yazili.
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
from app.normalization.event_semantics import describe  # noqa: E402
from app.normalization.input_parser import normalize_input  # noqa: E402
from app.validation.decision import decide  # noqa: E402

KOLLAR = {
    "S": (KOK / "evaluation" / "s_arm_set.json",
          KOK / "evaluation" / "results" / "s_arm_run.json"),
    "G": (KOK / "evaluation" / "g_arm_qradar_labels.json",
          KOK / "evaluation" / "results" / "g_arm_run_v2.json"),
}

B1 = ["S-B1-1A", "S-B1-1B", "S-B1-2A", "S-B1-2B", "S-B1-3A", "S-B1-3B"]

#: Yol A atesli oldugu icin maske duzeltmesinin ulasamayacagi kayitlar.
#: KOSMADAN ONCE yazildi (beklenti_18 §3.1): Yol A bastirilamaz, dolayisiyla
#: bu kaydin karari maskeden bagimsiz SUSPICIOUS kalir. Olcut burada
#: gevsetilmiyor -- ULASILAMAZ ilan ediliyor, ki 3/3 iddia edilmesin.
ULASILAMAZ = {"S-B1-1A"}

INSUFFICIENT = "INSUFFICIENT_DATA"
SUSPICIOUS = "SUFFICIENT_SUSPICIOUS"


def _yaz(m: str = "") -> None:
    print(m, flush=True)


def _dogrulama(mappings: list[dict], kanit_sayisi: int) -> VerificationReport:
    """Kayitli `dogrulanmis_kanit` sayisini birebir yeniden uretir."""
    onaylanan = [m["attack_id"] for m in mappings[:kanit_sayisi]]
    kararlar = [
        AgentDecision(agent_id="replay", technique_id=t, verdict=Verdict.CONFIRM,
                      reason="kayitli kosudan yeniden uretildi")
        for t in onaylanan
    ]
    return VerificationReport(accepted=list(mappings), rejected=[], decisions=kararlar)


def _kayitlar(kol: str) -> tuple[dict, dict]:
    set_yolu, kosu_yolu = KOLLAR[kol]
    kayitlar = {r["id"]: r for r in
                json.loads(set_yolu.read_text(encoding="utf-8"))["kayitlar"]}
    return kayitlar, json.loads(kosu_yolu.read_text(encoding="utf-8"))


def oynat(kol: str) -> dict[str, dict]:
    kayitlar, kosu = _kayitlar(kol)
    cikti: dict[str, dict] = {}
    for rid, saklanan in kosu.items():
        ham = kayitlar[rid]["input"]
        mappings = saklanan.get("mappings") or []
        kanit = (saklanan.get("inputs") or {}).get("dogrulanmis_kanit") or 0
        norm = normalize_input(ham)
        karar = decide(norm, mappings, _dogrulama(mappings, kanit))
        cikti[rid] = {
            "karar": karar.decision,
            "erisim": (karar.inputs.get("erisim_sinifi")),
            "yollar": karar.paths,
            "kanit": kanit,
        }
    return cikti


# ------------------------------------------------------------------ B1

def olc_b1() -> bool:
    kayitlar, kosu = _kayitlar("S")
    oynatilan = oynat("S")

    _yaz("1. B1 CIFTI -- ayirt edici cift (3 anahtar x 2)")
    _yaz("   olcut (sonuc_13 §3): A yarilari INSUFFICIENT_DATA'ya duser,")
    _yaz("   B yarilari SUSPICIOUS kalir. Ikisi birden susarsa duzeltme")
    _yaz("   ayirt etmiyor, her seyi bastiriyordur.")
    _yaz()

    saglandi = True
    for rid in B1:
        kayit, o = kayitlar[rid], oynatilan[rid]
        parsed = norm_parsed(kayit["input"])
        beklenen = kayit.get("expected_decision")
        yarim = "A" if rid.endswith("A") else "B"
        hedef = INSUFFICIENT if yarim == "A" else SUSPICIOUS

        if rid in ULASILAMAZ:
            durum = "ULASILAMAZ (Yol A atesli -- beklenti_18 §3.1)"
        elif o["karar"] == hedef:
            durum = "OLCUT SAGLANDI"
        else:
            durum = "OLCUT SAGLANMADI"
            saglandi = False

        _yaz(f"  {rid}  olay={parsed['event_id']}  maske={parsed['mask']}")
        _yaz(f"     erisim_sinifi = {o['erisim']}   (talep edilen: {parsed['requested']})")
        _yaz(f"     yollar A={o['yollar'].get('A')} B={o['yollar'].get('B')}  kanit={o['kanit']}")
        _yaz(f"     kayitli={kosu[rid].get('decision')}  ->  simdi={o['karar']}")
        _yaz(f"     beklenen={beklenen}   {durum}")
        _yaz()
    return saglandi


def norm_parsed(ham: str) -> dict:
    norm = normalize_input(ham)
    p = norm.get("parsed_fields") or {}

    def al(ad: str):
        f = p.get(ad)
        return getattr(f, "value", None)

    eid = al("event.id") or norm.get("event_id")
    d = describe(eid, al("access.mask"), al("object.type"), al("access.list"))
    return {
        "event_id": eid,
        "mask": al("access.mask"),
        "requested": d.get("requested_class"),
    }


# ------------------------------------------------------- dagilim / fark

def dagilim() -> dict[str, dict[str, str]]:
    return {kol: {k: v["karar"] for k, v in oynat(kol).items()} for kol in KOLLAR}


def yaz_dagilim(d: dict) -> None:
    _yaz("2. DAGILIM (cevrimdisi oynatma, LLM tarafi donmus)")
    for kol, kararlar in d.items():
        sayim = collections.Counter(kararlar.values())
        _yaz(f"  {kol} kolu: {len(kararlar)} kayit | {dict(sayim)}")
    _yaz()


def yaz_fark(onceki: dict, simdiki: dict) -> None:
    _yaz("3. FARK -- duzeltmeden ONCEKI OYNATMAYA gore")
    toplam = 0
    for kol in KOLLAR:
        a, b = onceki.get(kol, {}), simdiki.get(kol, {})
        farklar = [(k, a[k], b[k]) for k in sorted(b) if k in a and a[k] != b[k]]
        toplam += len(farklar)
        _yaz(f"  {kol} kolu: {len(farklar)}/{len(b)} kayit sinif degistirdi")
        for k, eski, yeni in farklar:
            _yaz(f"     {k}: {eski} -> {yeni}")
    _yaz()
    _yaz(f"  TOPLAM {toplam} kayit degisti.")
    _yaz()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kaydet")
    ap.add_argument("--karsilastir")
    a = ap.parse_args()

    _yaz("=" * 72)
    _yaz("GOREV 18 -- 4656 MASKE DUZELTMESI")
    _yaz("=" * 72)
    _yaz()

    saglandi = olc_b1()
    d = dagilim()
    yaz_dagilim(d)

    if a.kaydet:
        pathlib.Path(a.kaydet).write_text(
            json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")
        _yaz(f"  kaydedildi: {a.kaydet}")
        _yaz()
    if a.karsilastir:
        onceki = json.loads(pathlib.Path(a.karsilastir).read_text(encoding="utf-8"))
        yaz_fark(onceki, d)

    _yaz("-" * 72)
    _yaz(f"  B1 OLCUTU: {'SAGLANDI' if saglandi else 'SAGLANMADI'}"
         f"   (ULASILAMAZ sayilan: {', '.join(sorted(ULASILAMAZ))})")
    return 0 if saglandi else 1


if __name__ == "__main__":
    raise SystemExit(main())
