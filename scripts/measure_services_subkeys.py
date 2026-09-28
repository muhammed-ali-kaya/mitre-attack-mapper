"""Gorev 16 -- `Services\\<ad>\\<altanahtar>` kritikligi alt anahtara bagli mi?

    .venv/Scripts/python.exe scripts/measure_services_subkeys.py

NEDEN
    G kolunun yeniden kosusunda Yol B'nin urettigi BES yanlis alarmin hepsi
    ayni desen: svchost.exe, `Services\\<ad>\\Performance` anahtarina 0x2001F
    handle. Kritiklik `high`, aile `service`.

    Hipotez: kusur Yol B'de degil, tablonun `Services` altini TEK SATIRLA
    high saymasinda. `Performance` bir servisin sayac YAPILANDIRMASIDIR --
    kalicilik noktasi degil. `ImagePath` / `ServiceDll` ise kalicilik.
    Yani kritiklik ALT ANAHTARA bagli olabilir; bu K2'nin (alan secimi olaya
    bagli) kardesi.

PAYDA NEDEN ATT&CK
    measure_criticality_coverage.py'nin gerekcesi aynen gecerli: elde 5
    gercek Performance satiri var ve ONLARA BAKARAK tablo duzenlemek
    yasak -- "esikleri fixture ciktisina bakarak ayarlamak" kuralinin ta
    kendisi olurdu. ATT&CK bagimsiz bir kaynak.

OLCUM DUZELTMESI (ilk yazimda hata vardi, kayda geciyor)
    Ilk surum ham metinde regex aradi ve `<code>` HTML etiketleri ile
    markdown backtick'leri yolun icinde kaldigi icin alt anahtarlari
    `enum<`, `parameters<` gibi BOZUK adlarla cikardi; ImagePath hic
    gorunmedi. Metin once temizleniyor. Bozuk adlarin kendisi uyariydi:
    bir cikarim aracinin urettigi ad SEMANTIK olarak imkansizsa
    ('parameters<' bir registry anahtari degildir), arac kirilmistir.
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import re
import sys

KOK = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KOK))

from app.normalization.asset_criticality import siniflandir  # noqa: E402

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

CIKTI = KOK / "evaluation" / "results" / "services_subkeys.json"

HTML_RE = re.compile(r"</?[a-z][^>]*>", re.I)
# Yolun BITTIGI yer: bosluk, backtick, tirnak, parantez, nokta+bosluk.
SERVICES_RE = re.compile(r"Services\\(?P<kuyruk>[^\s`'\"()<>]+)", re.I)

# Servis ADI yerine gecen yer tutucular -- alt anahtar analizinde servis adi
# onemli degil, ondan SONRAKI segment onemli.
YER_TUTUCU = re.compile(r"^[\[<{].*[\]>}]$|^\*+$")

# Bu projede AYRI olarak aranan deger/alt anahtar adlari. Hipotezin iki
# tarafi: kalicilik tasiyanlar ve yapilandirma olanlar.
ARANAN = ["ImagePath", "ServiceDll", "Performance", "Start", "FailureCommand",
          "Parameters", "Enum", "Data", "TimeProviders", "Type"]


def _canli_teknikler() -> list[dict]:
    return [
        t for t in json.loads(
            (KOK / "data/processed/techniques.json").read_text(encoding="utf-8"))
        if not t.get("revoked") and not t.get("deprecated")
    ]


def _metin(t: dict) -> str:
    parca = [str(t.get(k) or "") for k in ("description", "detection")]
    parca += [str(p) for p in (t.get("procedure_examples") or [])]
    metin = " ".join(parca)
    while "\\\\" in metin:
        metin = metin.replace("\\\\", "\\")
    return HTML_RE.sub(" ", metin)


def olc() -> dict:
    teknikler = _canli_teknikler()

    gecisler = []           # her `Services\...` gecisi
    alt_anahtar = collections.defaultdict(set)   # ilk alt anahtar -> {teknik}
    aranan_sayim = {a: set() for a in ARANAN}

    for t in teknikler:
        tid = t.get("attack_id") or t.get("id") or "?"
        metin = _metin(t)

        for a in ARANAN:
            # REGISTRY BAGLAMI SART. Ilk olcumde bu sart YOKTU ve sonuc
            # yaniltiyordu: 'Start' 62, 'Data' 339, 'Type' 75 teknik
            # cikiyordu -- cunku bunlar duz Ingilizce kelimeler. Bir ad
            # arandiginda arandigi BAGLAM sart kosulmazsa sayim DILI olcer,
            # registry'yi degil. Bu sayilar bir iddiaya dayanak yapilsaydi
            # "Performance 8 teknikte geciyor" denip yanlis sonuca varilirdi.
            for m in re.finditer(rf"\b{re.escape(a)}\b", metin, re.I):
                yakin = metin[max(0, m.start() - 60): m.end() + 40]
                if ("\\" in metin[max(0, m.start() - 40): m.end() + 10]
                        or re.search(r"registry|HKLM|HKEY", yakin, re.I)):
                    aranan_sayim[a].add(tid)
                    break

        for m in SERVICES_RE.finditer(metin):
            kuyruk = m.group("kuyruk").rstrip(".,;:")
            seg = [s for s in kuyruk.split("\\") if s]
            if not seg:
                continue
            servis = seg[0]
            # Servis adindan SONRAKI ilk segment alt anahtardir.
            alt = seg[1] if len(seg) > 1 else None
            gecisler.append({
                "teknik": tid, "servis": servis, "alt": alt,
                "tam": "Services\\" + kuyruk,
                "yer_tutucu_servis": bool(YER_TUTUCU.match(servis)),
            })
            if alt:
                alt_anahtar[alt.casefold()].add(tid)

    return {
        "teknik_sayisi": len(teknikler),
        "gecisler": gecisler,
        "alt_anahtar": {k: sorted(v) for k, v in alt_anahtar.items()},
        "aranan": {a: sorted(v) for a, v in aranan_sayim.items()},
    }


def _olay_sinifi_olcumu() -> dict:
    """Bes yanlis alarmin olay turu + korpusun bu ayrimi olcup olcemedigi."""
    from app.batch.qradar_adapter import try_convert_qradar_export
    from app.normalization.event_semantics import event_semantics

    csv = KOK / "tests" / "fixtures" / "qradar_2026-08-06_51rows.csv"
    satirlar = try_convert_qradar_export(csv.read_bytes()) or []
    dagilim = collections.Counter(
        str(r.get("EventID") or "").strip() for r in satirlar)
    alarm = {f"G-{i:03d}": str(satirlar[i].get("EventID") or "").strip()
             for i in (7, 15, 29, 30, 40)}
    return {
        "dagilim": dict(dagilim.most_common()),
        "alarm_olaylari": alarm,
        "n_4663": dagilim.get("4663", 0),
        "n_4657": dagilim.get("4657", 0),
        "not_4656": (event_semantics("4656") or {}).get("not"),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--liste", action="store_true")
    args = ap.parse_args()

    s = olc()
    g = s["gecisler"]

    print("=" * 74)
    print("Services\\ ALT ANAHTARLARI -- ATT&CK canli teknik metinleri")
    print("=" * 74)
    print(f"  taranan canli teknik : {s['teknik_sayisi']}")
    print(f"  Services\\ gecisi     : {len(g)}  ({len({x['teknik'] for x in g})} teknikte)")
    print()
    print("  TAM YOLLAR")
    for x in sorted(g, key=lambda x: (x["teknik"], x["tam"])):
        yt = " [yer tutucu servis]" if x["yer_tutucu_servis"] else ""
        print(f"    {x['teknik']:12s} {x['tam']}{yt}")

    print()
    print("  ILK ALT ANAHTAR DAGILIMI")
    for ad, tids in sorted(s["alt_anahtar"].items(), key=lambda kv: (-len(kv[1]), kv[0])):
        print(f"    {ad[:24]:24s} {len(tids):3d} teknik  {', '.join(tids)}")

    # --- ADI GECEN / GECMEYEN alt anahtarlar ---------------------------
    print()
    print("-" * 74)
    print("ARANAN ADLARIN ATT&CK'TEKI VARLIGI (REGISTRY BAGLAMI SART)")
    print("-" * 74)
    for a in ARANAN:
        tids = s["aranan"][a]
        isaret = "" if tids else "   <-- ATT&CK'te HIC GECMIYOR"
        print(f"    {a:16s} {len(tids):3d} teknik  {', '.join(tids[:8])}"
              + (" ..." if len(tids) > 8 else "") + isaret)

    # --- mevcut tablo ayirt edebiliyor mu? -----------------------------
    print()
    print("-" * 74)
    print("MEVCUT TABLO NE DIYOR")
    print("-" * 74)
    denenen = sorted(set(list(s["alt_anahtar"]) + [a.casefold() for a in ARANAN]))
    tablo = {}
    for ad in denenen:
        yol = f"HKLM\\SYSTEM\\CurrentControlSet\\Services\\ornekservis\\{ad}"
        k = siniflandir(yol)
        tablo[ad] = {"seviye": k.seviye, "aile": k.aile, "desen": k.eslesen_desen}
        print(f"    {ad[:22]:22s} {k.seviye:9s} {str(k.aile)[:16]:16s} {k.eslesen_desen}")

    desenler = {v["desen"] for v in tablo.values()}
    print()
    print(f"  {len(denenen)} farkli alt anahtar -> {len(desenler)} farkli desen")
    if len(desenler) == 1:
        print("  >> TABLO ALT ANAHTARI AYIRT EDEMIYOR: hepsi TEK satira dusuyor.")
        print("     AMA bu bir kusur DEGIL (asagi bak): olculen alt anahtarlarin")
        print("     hepsi ATT&CK'te kalicilik/hijack tasiyor, `Performance` dahil.")

    # ---------------------------------------------------------------
    # HIPOTEZ CURUDU -> asil ayrim nerede? Talep edilen vs GERCEKLESEN
    # erisim. Bu bolum bes yanlis alarmin gercek sebebini olcer.
    # ---------------------------------------------------------------
    olay = _olay_sinifi_olcumu()
    print()
    print("-" * 74)
    print("ASIL AYRIM -- TALEP EDILEN mi, GERCEKLESEN mi?")
    print("-" * 74)
    print(f"  QRadar korpusu olay ID dagilimi: {olay['dagilim']}")
    print(f"  bes alarm satirinin olay ID'si  : {olay['alarm_olaylari']}")
    print(f"  4663 (gerceklesen erisim) satir : {olay['n_4663']}")
    print(f"  4657 (deger degisti) satir      : {olay['n_4657']}")
    print()
    print("  event_semantics.yaml 4656 notu:")
    print(f"    {olay['not_4656']}")
    print()
    print("  describe() ne yapiyor: access_class = mask_class or event_class")
    print("  yani MASKE KOSULSUZ KAZANIYOR. 4656'da maske TALEP EDILEN eristir,")
    print("  gerceklesen degil -- tablonun kendi notu bunu soyluyor ama kural")
    print("  onu gecersiz kiliyor.")
    if olay["n_4663"] == 0 and olay["n_4657"] == 0:
        print()
        print("  >> G KORPUSU BU AYRIMI OLCEMEZ: 0 tane 4663, 0 tane 4657 var.")
        print("     S kolu bu cifti ICERMEK ZORUNDA (ayni anahtar, biri 4656")
        print("     biri 4663), yoksa duzeltmenin dogru calistigi gosterilemez.")

    CIKTI.parent.mkdir(parents=True, exist_ok=True)
    CIKTI.write_text(json.dumps({
        "_aciklama": "Services alt anahtarlarinin ATT&CK'teki dagilimi + tablonun cevabi",
        "_hipotez": "Services\<ad>\Performance high olmamali (yapilandirma)",
        "_sonuc": "HIPOTEZ CURUDU. T1574.011 Performance anahtarini bir hijack "
                  "noktasi olarak anlatiyor ve ATT&CK'in kendi tespit rehberi onu "
                  "ImagePath/ServiceDll/FailureCommand ile AYNI cumlede sayiyor. "
                  "Tablo dogru; kusur talep/gerceklesme ayriminin yapilmamasinda.",
        "olay_sinifi": olay,
        "taranan_teknik": s["teknik_sayisi"],
        "gecisler": g,
        "alt_anahtar": s["alt_anahtar"],
        "aranan_adlar": s["aranan"],
        "tablo_cevabi": tablo,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nyazildi: {CIKTI.relative_to(KOK)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
