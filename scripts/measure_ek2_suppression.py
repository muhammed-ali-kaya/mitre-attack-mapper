"""EK-2 bastirmasi neden atesle(me)di -- IKI ADAYI AYIRAN olcum.

S kolunda dort EK-2 kaydinin dordu de SUFFICIENT_SUSPICIOUS cikti ve
dordunde de `suppression=None` idi. Iki aday aciklama vardi ve S kosusu
ikisini AYIRMIYORDU:

    (a) bastirma adimina hic ulasilmiyor  (Yol B kurulmuyor, ya da Yol A
        onu geciyor -- iki durumda da `baseline_bastirir_mi` CAGRILMAZ)
    (b) alan doldurulmuyor               (process.name / account.name bos)

Ayiran olcum: bastirma fonksiyonuna giden GIRDIYI yaz. Cagriliyor mu,
cagriliyorsa hangi degerlerle? Cagrilmiyorsa (a), cagrilip eslesmiyorsa (b)
-- ya da ikisi de degilse UCUNCU bir sebep vardir ve o zaman gorunur.

Betik uc bolum olcer:

  1. ULASILIYOR MU     -- fixture T4/T5 (Gorev 5) ve S-EK2-01..04 icin
                          Yol A/B, aktor alanlari, `baseline_bastirir_mi`
                          cagrisinin dogrudan sonucu ve gerekce zinciri.
  2. TEK DEGISKENLI PROB -- S-EK2-01/02'de YALNIZCA process.name'in BICIMI
                          degistirilir (tam yol -> taban ad). Baska hicbir
                          sey degismez. Sinif degisiyorsa ayrimi yapan sey
                          degerin BICIMIDIR, mekanizma degil.
  3. BICIM SAYIMI      -- process.name gercek korpuslarda tam yol mu taban
                          ad mi tasiyor? Fixture'in bicimi gercek veride
                          ne siklikta goruluyor?

LLM ve indeks GEREKMEZ: uc bolum de deterministik katmanlarda.

    python scripts/measure_ek2_suppression.py

Cikis kodu: dort EK-2 kaydinin karar sinifi beklentisiyle uyusmuyorsa 1.
Yani bu betik ayni zamanda duzeltmenin KABUL OLCUTUDUR -- duzeltmeden once
1, dogru duzeltmeden sonra 0 dondurmelidir. Ama sadece 0'a bakmak yetmez:
bolum 1'in "EK-2-03/04 bastirilmadi" satirlari da ayakta kalmalidir, yoksa
sayilar duzelirken kor nokta acilmis olur.
"""
from __future__ import annotations

import json
import pathlib
import sys
from pathlib import PureWindowsPath

KOK = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KOK))

from app.normalization.input_parser import normalize_input  # noqa: E402
from app.validation.decision import (  # noqa: E402
    aktor,
    baseline_bastirir_mi,
    decide,
    erisim_sinifi,
    varlik_kritikligi,
)

FIXTURE = KOK / "tests" / "fixtures" / "baseline_suppression_logs.json"
S_SET = KOK / "evaluation" / "s_arm_set.json"
SENARYOLAR = KOK / "evaluation" / "test_scenarios.json"
G_KOSU = KOK / "evaluation" / "results" / "g_arm_run_v2.json"

AYRAC = (chr(92), "/")


def _yaz(m: str = "") -> None:
    print(m, flush=True)


def _s_kayitlari() -> dict[str, dict]:
    return {r["id"]: r for r in json.loads(S_SET.read_text(encoding="utf-8"))["kayitlar"]}


def _fixture_loglari() -> dict[str, dict]:
    return {g["id"]: g for g in json.loads(FIXTURE.read_text(encoding="utf-8"))["logs"]}


def _alan_degeri(normalized: dict, ad: str) -> str | None:
    f = (normalized.get("parsed_fields") or {}).get(ad)
    return getattr(f, "value", None)


def _yol_mu(deger: str | None) -> bool:
    return bool(deger) and any(a in deger for a in AYRAC)


# --------------------------------------------------- 1. ULASILIYOR MU

def _tek_olcum(etiket: str, raw: str, beklenen: str | None) -> dict:
    n = normalize_input(raw)
    seviye, aile, _yol = varlik_kritikligi(n)
    ak = aktor(n)
    karar = decide(n, [], None)

    # Bastirma CAGRILIR MI? decide() yalnizca (Yol B ve Yol A degil)
    # durumunda cagirir. Burada iki seyi ayri ayri yaziyoruz: cagrilma
    # kosulu saglandi mi, ve cagri kendisi ne donuyor.
    cagrildi = karar.paths["B"] and not karar.paths["A"]
    dondu = baseline_bastirir_mi(aile, ak)

    _yaz(f"  {etiket}")
    _yaz(f"     aile={aile}  kritiklik={seviye}  erisim={erisim_sinifi(n)}")
    _yaz(f"     aktor.process = {ak['process']!r}   ({'TAM YOL' if _yol_mu(ak['process']) else 'taban ad'})")
    _yaz(f"     aktor.account = {ak['account']!r}")
    _yaz(f"     yollar A={karar.paths['A']} B={karar.paths['B']}  ->  bastirma cagrildi mi: "
         f"{'EVET' if cagrildi else 'HAYIR'}")
    _yaz(f"     baseline_bastirir_mi(...) -> {'ESLESTI' if dondu else 'ESLESMEDI'}")
    _yaz(f"     karar = {karar.decision}" + (f"   (beklenen {beklenen})" if beklenen else ""))
    for satir in karar.reason_chain:
        _yaz(f"        . {satir}")
    _yaz()
    return {
        "etiket": etiket,
        "aile": aile,
        "process": ak["process"],
        "account": ak["account"],
        "cagrildi": cagrildi,
        "eslesti": bool(dondu),
        "karar": karar.decision,
        "beklenen": beklenen,
    }


def olc_ulasilabilirlik() -> list[dict]:
    _yaz("1. BASTIRMA ADIMINA ULASILIYOR MU, ULASILIYORSA HANGI DEGERLERLE")
    _yaz("   (fixture ile S kayitlari YAN YANA -- fark buradaysa mekanizma saglamdir)")
    _yaz()
    sonuc = []
    for log in _fixture_loglari().values():
        sonuc.append(_tek_olcum(f"FIXTURE {log['id']}", log["raw"], log["expected_decision"]))
    kay = _s_kayitlari()
    for kid in ("S-EK2-01", "S-EK2-02", "S-EK2-03", "S-EK2-04"):
        r = kay[kid]
        sonuc.append(_tek_olcum(kid, r["input"], r["expected_decision"]))
    return sonuc


# ------------------------------------------------ 2. TEK DEGISKENLI PROB

def olc_bicim_probu() -> list[dict]:
    """process.name'in yalnizca BICIMINI degistirip sinifi tekrar olcer.

    Degistirilen tek sey: ham metindeki tam yol, kendi taban adiyla yer
    degistirir. Olay ID, nesne yolu, hesap, maske -- hepsi ayni kalir.
    """
    _yaz("2. TEK DEGISKENLI PROB -- yalnizca process.name'in BICIMI degisiyor")
    _yaz()
    sonuc = []
    for kid, r in _s_kayitlari().items():
        if not kid.startswith("S-EK2"):
            continue
        raw = r["input"]
        tam = _alan_degeri(normalize_input(raw), "process.name")
        if not _yol_mu(tam):
            continue
        taban = PureWindowsPath(tam).name
        degisik = raw.replace(tam, taban)
        onceki = decide(normalize_input(raw), [], None)
        sonraki = decide(normalize_input(degisik), [], None)
        _yaz(f"  {kid}: {tam!r} -> {taban!r}")
        _yaz(f"     {onceki.decision}  ->  {sonraki.decision}"
             f"   (beklenen {r['expected_decision']})")
        _yaz(f"     bastirma: {'YOK' if onceki.suppression is None else 'VAR'}"
             f"  ->  {'YOK' if sonraki.suppression is None else 'VAR'}")
        _yaz()
        sonuc.append({
            "id": kid, "tam_yol": tam, "taban": taban,
            "once": onceki.decision, "sonra": sonraki.decision,
            "beklenen": r["expected_decision"],
        })
    return sonuc


# --------------------------------------------------------- 3. BICIM SAYIMI

def _korpus_ham() -> dict[str, list[str]]:
    korpus: dict[str, list[str]] = {}
    korpus["S kolu (60 log)"] = [r["input"] for r in
                                 json.loads(S_SET.read_text(encoding="utf-8"))["kayitlar"]]
    ham = json.loads(SENARYOLAR.read_text(encoding="utf-8"))
    kayitlar = ham if isinstance(ham, list) else (ham.get("scenarios") or ham.get("kayitlar") or [])
    korpus["60 senaryo"] = [(r.get("input") or r.get("text") or r.get("raw") or "") for r in kayitlar]
    korpus["fixture T4/T5"] = [g["raw"] for g in _fixture_loglari().values()]
    return korpus


def olc_bicim_sayimi() -> dict:
    _yaz("3. process.name HANGI BICIMDE GELIYOR (bastirma tam esitlikle karsilastiriyor)")
    _yaz()
    tablo = {}
    for ad, hamlar in _korpus_ham().items():
        yol = taban = 0
        for h in hamlar:
            v = _alan_degeri(normalize_input(h), "process.name")
            if not v:
                continue
            if _yol_mu(v):
                yol += 1
            else:
                taban += 1
        tablo[ad] = {"tam_yol": yol, "taban_ad": taban}
        _yaz(f"  {ad:<18} tam yol={yol:<3} taban ad={taban}")

    if G_KOSU.exists():
        g = json.loads(G_KOSU.read_text(encoding="utf-8"))
        yol = taban = bos = 0
        for r in g.values():
            p = ((r.get("inputs") or {}).get("aktor") or {}).get("process")
            if not p:
                bos += 1
            elif _yol_mu(p):
                yol += 1
            else:
                taban += 1
        tablo["G kolu (51 QRadar)"] = {"tam_yol": yol, "taban_ad": taban, "bos": bos}
        _yaz(f"  {'G kolu (51 QRadar)':<18} tam yol={yol:<3} taban ad={taban}  bos={bos}")
    _yaz()
    return tablo


# ------------------------------------------------------------------ main

def main() -> int:
    _yaz("=" * 72)
    _yaz("EK-2 BASTIRMA TESHISI")
    _yaz("=" * 72)
    _yaz()
    ulasim = olc_ulasilabilirlik()
    prob = olc_bicim_probu()
    olc_bicim_sayimi()

    ek2 = [u for u in ulasim if u["etiket"].startswith("S-EK2")]
    tutan = [u for u in ek2 if u["karar"] == u["beklenen"]]

    _yaz("-" * 72)
    _yaz("TESHIS")
    _yaz("-" * 72)
    cagrilan = [u for u in ek2 if u["cagrildi"]]
    alani_dolu = [u for u in ek2 if u["process"] and u["account"]]
    _yaz(f"  (a) bastirma adimina ulasilmiyor  : {len(ek2) - len(cagrilan)}/{len(ek2)} kayit")
    _yaz(f"  (b) aktor alani bos               : {len(ek2) - len(alani_dolu)}/{len(ek2)} kayit")
    _yaz(f"  ucuncu sebep (bicim uyusmazligi)  : "
         f"{sum(1 for p in prob if p['once'] != p['sonra'])}/{len(prob)} kayit "
         f"yalnizca BICIM degisince sinif degistirdi")
    _yaz()
    _yaz(f"  EK-2 karar sinifi: {len(tutan)}/{len(ek2)}")
    for u in ek2:
        im = "TUTTU" if u["karar"] == u["beklenen"] else "TUTMADI"
        _yaz(f"     {im:<8} {u['etiket']}  {u['karar']}  (beklenen {u['beklenen']})")
    _yaz()
    return 0 if len(tutan) == len(ek2) else 1


if __name__ == "__main__":
    raise SystemExit(main())
