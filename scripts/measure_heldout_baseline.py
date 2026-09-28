"""Gorev 13'un GIRDI olcumu: bugunku setler kriterleri ne kadar karsiliyor?

NEDEN BU BETIK VAR: Gorev 13'un kabul kriterleri (HANDOFF, "Gorev 13'un kabul
kriteri") sayilara dayaniyor -- "katalog 48 olay ID bekliyor", "set 6'sini
temsil ediyor", "60 senaryoda sifir registry yolu". Bu sayilar bugune kadar
HICBIR BETIGE BAGLI DEGILDI; elle olculup HANDOFF'a yazilmislardi. Elle
olculen sayi bayatlar ve bayatladigini kimse gormez.

Bu betik uc kaynagi ayni anda olcer ve Gorev 13'un UC kriterini tek tek
raporlar:

    KRITER    olay ID temsili  >= 24/48 (kataloğun required ID'lerinin yarisi)
    EK-1      registry yolu    critical + high + noise ailelerinden BIRER log
    EK-2      baseline cifti   ayni aktorun BEKLENEN ve BEKLENMEYEN varlik
                               ailesine yazdigi en az BIRER log

Olculen kaynaklar:
    A) rules/attack_mappings.yaml   -- katalogun NE BEKLEDIGI
    B) evaluation/test_scenarios.json (60 senaryo) -- bugunku olcum seti
    C) tests/fixtures/qradar_*.csv  -- gercek QRadar ornegi

LLM ve indeks GEREKMEZ: hepsi deterministik ayristirma katmanlarinda.

    .venv/Scripts/python.exe scripts/measure_heldout_baseline.py

Cikis kodu her zaman 0 -- bu bir DURUM olcumu, gecme/kalma sinavi degil.
Aday bir held-out seti sinamak icin --set <yol> verilir.
"""
from __future__ import annotations

import argparse
import collections
import json
import pathlib
import sys

KOK = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KOK))

import yaml  # noqa: E402

from app.batch.qradar_adapter import try_convert_qradar_export  # noqa: E402
from app.batch.serialize import row_to_kv_string  # noqa: E402
from app.normalization.asset_criticality import siniflandir  # noqa: E402
from app.normalization.formats import split_events  # noqa: E402
from app.normalization.input_parser import normalize_input  # noqa: E402

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

KATALOG = KOK / "rules" / "attack_mappings.yaml"
SENARYOLAR = KOK / "evaluation" / "test_scenarios.json"
QRADAR = KOK / "tests" / "fixtures" / "qradar_2026-08-06_51rows.csv"

KRITER_ID_ORANI = 0.5  # kataloğun required ID'lerinin en az yarisi
EK1_AILELER = ("critical", "high", "noise")


def _yaz(m: str = "") -> None:
    print(m, flush=True)


# --- A) KATALOG: ne bekleniyor -------------------------------------------


def katalog_beklentisi() -> dict:
    d = yaml.safe_load(KATALOG.read_text(encoding="utf-8"))
    teknikler = d["techniques"]
    required: set[int] = set()
    forbidden: set[int] = set()
    kosul = 0
    for t in teknikler:
        required |= set((t.get("required") or {}).get("event_ids") or [])
        forbidden |= set((t.get("forbidden") or {}).get("event_ids") or [])
        kosul += len(t.get("field_conditions") or [])
    return {
        "kural_sayisi": len(teknikler),
        "required_event_ids": sorted(required),
        "forbidden_event_ids": sorted(forbidden),
        "field_condition_sayisi": kosul,
    }


# --- ortak: bir log listesini olc ----------------------------------------


def olc(ad: str, girdiler: list[str], beklenen: set[int]) -> dict:
    """Bir log listesinin uc kriter acisindan durumunu olcer.

    Girdiler ham metin. Her biri once BOLUNUR (cok olayli bir kayit tek log
    sayilirsa olay ID cesitliligi oldugundan az gorunur), sonra projenin
    kendi ayristiricisindan gecer -- regex ile ayri bir okuma yazmak ikinci
    bir gerceklik demek olurdu."""
    ids: collections.Counter = collections.Counter()
    yollar: list[tuple[str, str, str]] = []  # (yol, seviye, aile)
    ciftler: collections.Counter = collections.Counter()  # (aile, aktor)
    idsiz = 0
    bolunen = 0

    for ham in girdiler:
        bolme = split_events(ham)
        olaylar = bolme.events or [ham]
        if len(olaylar) > 1:
            bolunen += 1
        bu_kayitta_id = False
        for olay in olaylar:
            r = normalize_input(olay)
            if r.get("event_id"):
                try:
                    ids[int(r["event_id"])] += 1
                    bu_kayitta_id = True
                except (TypeError, ValueError):
                    pass
            pf = r.get("parsed_fields") or {}
            # Alan SIRASI uretimdekiyle AYNI olmali (app/validation/decision.py
            # icindeki `_alan(parsed, "object.name", "registry.path",
            # "file.path")`). Once yalnizca `object.name` okunuyordu ve gercek
            # QRadar satirlarinin registry yolu `file.path`'e dustugu icin
            # olcum "0 registry yolu" diyordu -- set degil, OLCUM dardi.
            yol = None
            for anahtar in ("object.name", "registry.path", "file.path"):
                alan = pf.get(anahtar)
                if alan is not None and getattr(alan, "value", None):
                    yol = getattr(alan, "value")
                    break
            aile = ""
            if yol:
                k = siniflandir(str(yol))
                seviye = str(getattr(k, "seviye", k))
                aile = str(getattr(k, "aile", "") or "")
                yollar.append((str(yol), seviye, aile))
            aktor = r.get("user_account") or r.get("process_name")
            if aile and aktor:
                ciftler[(aile, str(aktor))] += 1
        if not bu_kayitta_id:
            idsiz += 1

    ortak = set(ids) & beklenen
    aileler = {a for _, _, a in yollar if a}
    seviyeler = {s for _, s, _ in yollar if s}
    aktor_basina_aile = collections.defaultdict(set)
    for (aile, aktor) in ciftler:
        aktor_basina_aile[aktor].add(aile)
    cok_aileli_aktor = {a: sorted(f) for a, f in aktor_basina_aile.items() if len(f) > 1}

    return {
        "ad": ad,
        "kayit_sayisi": len(girdiler),
        "bolunen_kayit": bolunen,
        "id_cikarilamayan_kayit": idsiz,
        "essiz_event_id": sorted(ids),
        "katalogla_ortak_id": sorted(ortak),
        "id_kapsama": f"{len(ortak)}/{len(beklenen)}",
        "registry_yolu_sayisi": len(yollar),
        "registry_seviyeleri": sorted(seviyeler),
        "registry_aileleri": sorted(aileler),
        "aktor_varlik_ciftleri": {f"{a}|{k}": v for (a, k), v in ciftler.items()},
        "cok_aileli_aktor": cok_aileli_aktor,
    }


def kriter_raporu(o: dict, beklenen_sayi: int) -> list[tuple[str, bool, str]]:
    """Uc kriteri o olcume uygular. GECME/KALMA yalnizca aday bir held-out
    seti icin anlamlidir; bugunku setler icin 'durum' olarak okunur."""
    ortak = len(o["katalogla_ortak_id"])
    esik = int(beklenen_sayi * KRITER_ID_ORANI)
    k1 = ortak >= esik

    seviyeler = set(o["registry_seviyeleri"])
    k2 = all(s in seviyeler for s in EK1_AILELER)

    k3 = bool(o["cok_aileli_aktor"])

    return [
        ("KRITER  olay ID temsili", k1, f"{ortak}/{beklenen_sayi} (esik >={esik})"),
        (
            "EK-1    registry yolu",
            k2,
            f"seviyeler={o['registry_seviyeleri'] or 'yok'} "
            f"(gereken {list(EK1_AILELER)})",
        ),
        (
            "EK-2    baseline cifti",
            k3,
            f"cok aileli aktor={o['cok_aileli_aktor'] or 'yok'}",
        ),
    ]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--set",
        dest="aday",
        help="Aday held-out set (JSON: [{'input': ...}] ya da satir satir metin)",
    )
    args = ap.parse_args()

    _yaz("=" * 74)
    _yaz("GOREV 13 -- GIRDI OLCUMU: bugunku setler kriterleri karsiliyor mu?")
    _yaz("=" * 74)

    k = katalog_beklentisi()
    beklenen = set(k["required_event_ids"])
    _yaz(f"\nA) KATALOG ({KATALOG.relative_to(KOK)})")
    _yaz(f"   kural sayisi        : {k['kural_sayisi']}")
    _yaz(f"   required event ID   : {len(beklenen)}")
    _yaz(f"   forbidden event ID  : {len(k['forbidden_event_ids'])} {k['forbidden_event_ids']}")
    _yaz(f"   field_condition     : {k['field_condition_sayisi']}")

    olcumler = []

    senaryolar = json.loads(SENARYOLAR.read_text(encoding="utf-8"))
    olcumler.append(olc("60 senaryo", [s.get("input") or "" for s in senaryolar], beklenen))

    if QRADAR.exists():
        satirlar = try_convert_qradar_export(QRADAR.read_bytes()) or []
        # `Message` kolonu DEGIL: adaptor EventID/FilePath'i AYRI kolonlara
        # cikariyor, Message yalnizca alt mesaj metnini tasiyor. Message ile
        # olcunce 51 satirin 51'i "olay ID yok" gorunuyordu -- olcum setin
        # kendisini degil, yanlis kolonu okuyordu. Toplu modun uretimde
        # kullandigi ayni serilestirme kullanilir (tek gerceklik).
        olcumler.append(
            olc("QRadar 51 satir", [row_to_kv_string(r) for r in satirlar], beklenen)
        )

    if args.aday:
        yol = pathlib.Path(args.aday)
        ham = yol.read_text(encoding="utf-8")
        try:
            veri = json.loads(ham)
            # Kol dosyalari IKI bicimde geliyor: duz liste, ya da ust duzey
            # dict icinde `kayitlar` (G ve H kollari boyle -- metadata
            # tasiyorlar). Dict SESSIZCE gezilirse `for x in veri` ANAHTARLARI
            # dolasir ve olcum log yerine "_UYARI", "kayitlar" dizelerini
            # olcer: hata yok, cikti makul, sonuc anlamsiz. Taninmayan bicim
            # artik sessizce gecmiyor.
            if isinstance(veri, dict):
                veri = veri.get("kayitlar")
                if not isinstance(veri, list):
                    raise SystemExit(
                        f"HATA: {yol.name} bir dict ama icinde `kayitlar` listesi yok. "
                        "Aday set ya duz liste ya da {'kayitlar': [...]} olmali."
                    )
            if not isinstance(veri, list):
                raise SystemExit(f"HATA: {yol.name} liste degil: {type(veri).__name__}")
            girdiler = [
                (x.get("input") or x.get("raw") or "") if isinstance(x, dict) else str(x)
                for x in veri
            ]
            if not any(g.strip() for g in girdiler):
                raise SystemExit(
                    f"HATA: {yol.name} icinden hicbir `input` okunamadi ({len(girdiler)} kayit). "
                    "Alan adi `input` ya da `raw` olmali."
                )
        except json.JSONDecodeError:
            girdiler = [s for s in ham.split("\n\n") if s.strip()]
        olcumler.append(olc(f"ADAY: {yol.name}", girdiler, beklenen))

    for o in olcumler:
        _yaz(f"\n{'-' * 74}")
        _yaz(f"{o['ad']}  ({o['kayit_sayisi']} kayit)")
        _yaz(f"{'-' * 74}")
        _yaz(f"   ID cikarilamayan kayit : {o['id_cikarilamayan_kayit']}/{o['kayit_sayisi']}")
        _yaz(f"   bolunen kayit          : {o['bolunen_kayit']}")
        _yaz(f"   essiz event ID         : {len(o['essiz_event_id'])} {o['essiz_event_id']}")
        _yaz(f"   katalogla ortak        : {o['id_kapsama']} {o['katalogla_ortak_id']}")
        _yaz(f"   registry yolu          : {o['registry_yolu_sayisi']}")
        _yaz(f"   registry seviyeleri    : {o['registry_seviyeleri'] or 'yok'}")
        _yaz(f"   registry aileleri      : {o['registry_aileleri'] or 'yok'}")
        _yaz(f"   (aile|aktor) ciftleri  : {o['aktor_varlik_ciftleri'] or 'yok'}")
        _yaz()
        for ad, gecti, ayrinti in kriter_raporu(o, len(beklenen)):
            _yaz(f"   {ad:26} {'KARSILIYOR' if gecti else 'KARSILAMIYOR':13} {ayrinti}")

    _yaz(f"\n{'=' * 74}")
    _yaz("NOT: bugunku iki set icin 'KARSILAMIYOR' beklenen sonuctur -- Gorev 13")
    _yaz("     tam da bu bosluk icin acildi. Sinav aday sette anlamlidir (--set).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
