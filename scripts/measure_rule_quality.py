"""K1 -- kural katalogu kalite OLCUMU. Duzeltme YOK.

Uc kusur sinifi sayilir. Tanimlar islemseldir ve raporda yazili.

SINIF 1  kapsadigini beyan ettigi olay icin HIC eslesemez
   1a (statik)   kosulun baktigi ALAN, beyan edilen olayin anlamli
                 alanlari arasinda YOK. Message/event.message haric --
                 onlar ham metnin tamami, her olayda var.
SINIF 2  baska bir teknigin gostergesini kendine mal ediyor
   2a  tek must_match icinde 2+ bayrak/alt komut alternatifi (ADAY)
   2b  ayni ayirt edici jeton iki FARKLI teknigin kuralinda
SINIF 3  ayirt edici kosul tasimiyor
   3a  hic field_conditions yok -- yalnizca olay ID'siyle atesliyor
   3b  yalnizca AD tabanli kosul; komut satiri/nesne/argüman yok
   3c  yalnizca must_not_match -- pozitif kanit hic yok

Bir kural birden fazla sinifa girebilir.
"""
import collections
import json
import pathlib
import re
import sys

KOK = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KOK))

import yaml  # noqa: E402

KURALLAR = yaml.safe_load((KOK / "rules" / "attack_mappings.yaml").read_text(encoding="utf-8"))["techniques"]
OLAYLAR = yaml.safe_load((KOK / "config" / "event_semantics.yaml").read_text(encoding="utf-8"))["events"]

HAM_METIN_ALANLARI = {"Message", "event.message"}
AD_ALANLARI = {"process.name", "parent.process.name", "file.name", "target.image"}


def kosullari_duzle(fc):
    for c in fc or []:
        if "any_of" in c:
            for alt in c["any_of"]:
                yield alt.get("field"), alt.get("must_match"), alt.get("must_not_match")
        else:
            yield c.get("field"), c.get("must_match"), c.get("must_not_match")


def kural_adi(r, i):
    return f"{r['technique_id']}#{i}"


def sinif_1a():
    bulgular = []
    katalog_disi = collections.Counter()
    for i, r in enumerate(KURALLAR):
        evler = [str(e) for e in (r.get("required") or {}).get("event_ids") or []]
        alanlar = {a for a, _, _ in kosullari_duzle(r.get("field_conditions"))
                   if a and a not in HAM_METIN_ALANLARI}
        if not alanlar:
            continue
        for ev in evler:
            tanim = OLAYLAR.get(ev)
            if tanim is None:
                katalog_disi[ev] += 1
                continue
            anlamli = set(tanim.get("anlamli_alanlar") or [])
            if not anlamli:
                continue
            if alanlar.isdisjoint(anlamli):
                bulgular.append((kural_adi(r, i), ev, sorted(alanlar), sorted(anlamli)))
    return bulgular, katalog_disi


def sinif_3():
    a, b, c = [], [], []
    for i, r in enumerate(KURALLAR):
        fc = r.get("field_conditions") or []
        if not fc:
            a.append((kural_adi(r, i), (r.get("required") or {}).get("event_ids")))
            continue
        duz = list(kosullari_duzle(fc))
        pozitif = [(al, mm) for al, mm, mn in duz if mm]
        negatif = [(al, mn) for al, mm, mn in duz if mn and not mm]
        if not pozitif and negatif:
            c.append((kural_adi(r, i), negatif))
            continue
        alanlar = {al for al, _ in pozitif if al}
        if alanlar and alanlar <= AD_ALANLARI:
            b.append((kural_adi(r, i), sorted(alanlar), [m for _, m in pozitif]))
    return a, b, c


BAYRAK = re.compile(r"(?<![\w:])[-/][a-zA-Z][\w-]{2,}")


def sinif_2_adaylari():
    bayrak_sahibi = collections.defaultdict(set)
    adaylar = []
    for i, r in enumerate(KURALLAR):
        for alan, mm, _ in kosullari_duzle(r.get("field_conditions")):
            if not mm:
                continue
            bayraklar = sorted(set(BAYRAK.findall(mm)))
            for b in bayraklar:
                bayrak_sahibi[b.lower()].add(r["technique_id"])
            if len(bayraklar) >= 2:
                adaylar.append((kural_adi(r, i), alan, bayraklar, mm))
    catisan = {b: t for b, t in bayrak_sahibi.items() if len(t) > 1}
    return adaylar, catisan


def main():
    print("=" * 74)
    print("K1 -- KURAL KATALOGU KALITE OLCUMU (statik tarama, duzeltme YOK)")
    print("=" * 74)
    print()
    print(f"  katalogdaki kural sayisi: {len(KURALLAR)}")
    print(f"  farkli teknik           : {len({r['technique_id'] for r in KURALLAR})}")

    b1a, katalog_disi = sinif_1a()
    print()
    print("-" * 74)
    print("SINIF 1a -- kosulun alani, beyan edilen olayin anlamli alanlarinda YOK")
    print("-" * 74)
    print(f"  bulgu: {len(b1a)} (kural, olay) cifti")
    for ad, ev, alanlar, anlamli in b1a:
        print(f"    {ad:<14} olay {ev:<6} bakiyor={alanlar}")
        print(f"    {'':<14} olayin anlamli alanlari={anlamli}")
    print()
    print(f"  SINAMA SINIRI: kurallarin bildirdigi {sum(katalog_disi.values())} (kural,olay)")
    print("  cifti event_semantics KATALOGUNDA YOK, yani 1a ile sinanamadi.")
    print(f"  Katalog disi olay ID'leri: {sorted(katalog_disi)}")

    a3, b3, c3 = sinif_3()
    print()
    print("-" * 74)
    print("SINIF 3 -- ayirt edici kosul tasimiyor")
    print("-" * 74)
    print(f"  3a hic field_conditions YOK (yalnizca olay ID): {len(a3)}")
    for ad, ev in a3:
        print(f"      {ad:<14} ev={ev}")
    print()
    print(f"  3b yalnizca AD tabanli kosul (komut satiri/nesne yok): {len(b3)}")
    for ad, alanlar, desenler in b3:
        print(f"      {ad:<14} {alanlar}")
        for d in desenler:
            print(f"      {'':<14}   {str(d)[:105]}")
    print()
    print(f"  3c yalnizca must_not_match (pozitif kanit YOK): {len(c3)}")
    for ad, neg in c3:
        print(f"      {ad:<14} {str(neg)[:120]}")

    ad2, catisan = sinif_2_adaylari()
    print()
    print("-" * 74)
    print("SINIF 2 -- baska teknigin gostergesini mal etme (ADAY uretimi)")
    print("-" * 74)
    print(f"  2a tek desende 2+ bayrak/alt komut alternatifi: {len(ad2)} aday")
    for ad, alan, bayraklar, mm in ad2:
        print(f"      {ad:<14} {alan}  bayraklar={bayraklar}")
    print()
    print(f"  2b ayni bayrak birden fazla teknikte: {len(catisan)}")
    for b, t in sorted(catisan.items()):
        print(f"      {b:<20} -> {sorted(t)}")

    ozet = {
        "kural_sayisi": len(KURALLAR),
        "sinif_1a": len(b1a),
        "sinif_3a": len(a3), "sinif_3b": len(b3), "sinif_3c": len(c3),
        "sinif_2a_aday": len(ad2), "sinif_2b": len(catisan),
    }
    print()
    print("=" * 74)
    print("OZET:", json.dumps(ozet, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
