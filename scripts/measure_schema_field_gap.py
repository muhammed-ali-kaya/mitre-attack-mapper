"""Gorev 24 -- sema alan bosluklarini olcer. DUZELTME YOK, yalnizca olcum.

NE OLCER (dort bagimsiz soru, hicbiri digerinin cevabini varsaymaz)

    A  rule_field_map.yaml'da HEDEF olarak yazili kanonik adlardan kaci
       field_schema.yaml'da TANIMLI degil? (2B'nin sessiz boslugu iddiasi)

    B  Gercek korpuslarda hangi ham alan adlari `unknown.*` altina dusuyor,
       kac kez? G (51 gercek QRadar satiri), S (60 sentetik log), H (15).

    C  Bir ham ad semaya BAGLANSA hangi kural kosullari ilk kez bir alan
       bulabilir hale gelir? (Kosul ATESLENIR demek DEGIL -- desen yine
       tutmayabilir; bu bir UST SINIR.)

    D  YAN ETKI: semaya ad eklemek space_kv TOKENIZASYONUNU degistirir.
       Sinir deseni (`_space_kv_boundary_pattern`) semadan turetiliyor,
       yani yeni bir ad yeni bir deger-bitis noktasi demek. Bu betik
       adaylari eklenmis bir sema ile korpusu YENIDEN ayristirip
       alan-alan karsilastirir.

NEDEN D AYRI BIR OLCUM
    field_schema.yaml satir 62'deki TargetUserName kaydi tam olarak bunun
    tersini gosteriyor: ad semada OLMADIGI icin onceki alanin degeri onu
    YUTUYORDU. Ayni mekanizma ters yonde de calisir -- yeni ad, mesru bir
    degerin ortasinda gecerse onu KESER. HANDOFF yontem maddesi 16: bir
    duzeltmenin yan etkisi, duzeltmenin kendisiyle ayni kosuda olculmeli.

BU BETIK DUZELTME ONCESI OLCUMDUR. Adaylar 2026-09-03'te uretim semasina
girdi, yani D ve E artik "sema degisirse ne olur" sorusunu SORAMAZ: iki sema
ayni. Duzeltme SONRASI yan etki olcumu ayri bir betiktedir --
`scripts/measure_task24_side_effect.py`, taban cizgisini git'ten okur.
D/E burada TARIHSEL kayit olarak duruyor; kararin hangi sayilara dayandigi
yeniden uretilebilsin diye silinmedi.

LLM ve indeks GEREKMEZ. Ayristirma ve tablo okuma, ikisi de deterministik.
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml

KOK = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KOK))

from app.batch.qradar_adapter import try_convert_qradar_export  # noqa: E402
from app.batch.serialize import row_to_kv_string  # noqa: E402
from app.normalization import formats  # noqa: E402
from app.normalization.formats import load_schema, parse_fields  # noqa: E402

SEMA = KOK / "config" / "field_schema.yaml"
KURAL_HARITA = KOK / "config" / "rule_field_map.yaml"
KURALLAR = KOK / "rules" / "attack_mappings.yaml"
G_CSV = KOK / "tests" / "fixtures" / "qradar_2026-08-06_51rows.csv"
S_SET = KOK / "evaluation" / "s_arm_set.json"
H_SET = KOK / "evaluation" / "heldout_set.json"
CIKTI = KOK / "evaluation" / "results" / "schema_field_gap.json"

# B ve D'de sinanan adaylar. Kaynak: kullanicinin powercfg kosusunda
# GORULEN iki ham ad. Tahminle buyutulmedi -- KANITSIZ sinifinin kurali
# (rule_field_map basligi) burada da gecerli.
ADAYLAR = {
    "Command": "process.command_line",
    "Parent Process Path": "parent.process.path",
}


# --------------------------------------------------------------------------
# A -- kural haritasinin hedefleri semada var mi
# --------------------------------------------------------------------------
def olcum_a() -> dict[str, Any]:
    sema_ham = yaml.safe_load(SEMA.read_text(encoding="utf-8"))
    alanlar = sema_ham.get("fields") or {}

    # HANGI ADLAR SATIRDA BULUNUR -- iki kez yanlis cevaplandi, ikisi de
    # kaydedildi:
    #
    #   1. yazim: hedefler KANONIK kumeyle karsilastirildi -> arac `Message`i
    #      "eksik" ilan etti. Oysa `event.message`in legacy adi `Message`.
    #   2. yazim: yalnizca LEGACY izdusumuyle karsilastirildi -> arac
    #      `process.command_line` dahil 11 hedefi "eksik" ilan etti. Oysa
    #      `text_to_row` (kanit kapisinin kullandigi yol, graph.py:209)
    #      IKI NAMESPACE'I BIRDEN yaziyor ve bunu ACIKCA gerekcelendiriyor
    #      (text_input.py: legacy anahtarlarin alti tuketicisi var).
    #
    # Dogru kume `text_to_row`un SOZLESMESIDIR: legacy izdusumu + kanonik
    # adlar + `Message`. Kaynaktan degil, kodun kendisinden dogrulaniyor.
    legacy_izdusumu = {(spec or {}).get("legacy") or kanonik
                       for kanonik, spec in alanlar.items()}
    kanonikler = set(alanlar)
    tanimli = legacy_izdusumu | kanonikler | {"Message"}

    harita = yaml.safe_load(KURAL_HARITA.read_text(encoding="utf-8"))
    # Hedef TEK ad ya da LISTE olabilir (12 kosulda liste). Duz sayim
    # listeyi tek anahtar sanip catlar; olcum aracinin sekizinci kusuru
    # tam burada olurdu.
    hedefler: dict[str, list[str]] = defaultdict(list)
    coklu = 0
    for kosul in harita.get("kosullar") or []:
        hedef = kosul.get("hedef")
        if not hedef:
            continue
        if isinstance(hedef, list):
            coklu += 1
        for h in (hedef if isinstance(hedef, list) else [hedef]):
            hedefler[h].append(kosul.get("teknik", "?"))

    # event_semantics bir alan degil, bir YONLENDIRME. Sema disi olmasi
    # bir boskluk degil; S sinifinin tanimi bu.
    alan_olmayan = {"event_semantics"}

    eksik = {
        h: sorted(set(t))
        for h, t in hedefler.items()
        if h not in tanimli and h not in alan_olmayan
    }
    return {
        "hedef_sayisi": len(hedefler),
        "coklu_hedefli_kosul": coklu,
        "alan_olmayan_hedefler": sorted(alan_olmayan & set(hedefler)),
        "semada_tanimli": sorted(h for h in hedefler if h in tanimli),
        "semada_EKSIK": eksik,
        "_namespace": "text_to_row sozlesmesi: legacy izdusumu + kanonik adlar + Message",
        "kanonik_adla_yazilmis_hedef": sorted(
            h for h in hedefler if h in kanonikler
        ),
        "yalnizca_legacy_adla_bulunabilir": sorted(
            h for h in hedefler if h not in kanonikler and h in tanimli
        ),
    }


# --------------------------------------------------------------------------
# Korpus yukleyicileri
# --------------------------------------------------------------------------
def _g_satirlari() -> list[str]:
    rows = try_convert_qradar_export(G_CSV.read_bytes())
    if rows is None:
        raise SystemExit("G korpusu okunamadi")
    return [row_to_kv_string(r) for r in rows]


def _set_loglari(yol: Path) -> list[str]:
    """S ve H setleri UST DUZEYDE metadata dict'i, loglar `kayitlar`
    listesinde. Ilk yazimda dict dogrudan gezildi ve iki korpus da 0 kayit
    dondu -- olcum SESSIZCE bos gecmisti. `measure_heldout_baseline`'in
    yedinci kusurunun aynisi; bu yuzden sayi burada ZORLANIYOR."""
    if not yol.exists():
        return []
    ham = json.loads(yol.read_text(encoding="utf-8"))
    kayitlar = ham["kayitlar"] if isinstance(ham, dict) else ham
    loglar = [k["input"] for k in kayitlar if isinstance(k, dict) and k.get("input")]
    beklenen = ham.get("kayit_sayisi") if isinstance(ham, dict) else len(kayitlar)
    if beklenen and len(loglar) != beklenen:
        raise SystemExit(
            f"{yol.name}: {beklenen} kayit bekleniyordu, {len(loglar)} okundu"
        )
    return loglar


def _korpuslar() -> dict[str, list[str]]:
    return {
        "G (51 gercek QRadar satiri)": _g_satirlari(),
        "S (60 sentetik log)": _set_loglari(S_SET),
        "H (15 held-out log)": _set_loglari(H_SET),
    }


# --------------------------------------------------------------------------
# B -- unknown.* dokumu
# --------------------------------------------------------------------------
def olcum_b(korpuslar: dict[str, list[str]]) -> dict[str, Any]:
    sonuc: dict[str, Any] = {}
    for ad, loglar in korpuslar.items():
        sayac: Counter[str] = Counter()
        kayit_sayaci: Counter[str] = Counter()
        for metin in loglar:
            alanlar, _ = parse_fields(metin)
            gorulen = set()
            for alan_adi in alanlar:
                if alan_adi.startswith("unknown."):
                    ham = alan_adi[len("unknown."):]
                    sayac[ham] += 1
                    gorulen.add(ham)
            for ham in gorulen:
                kayit_sayaci[ham] += 1
        sonuc[ad] = {
            "kayit_sayisi": len(loglar),
            "essiz_unknown_ad": len(sayac),
            "toplam_unknown_gecis": sum(sayac.values()),
            "adlar": [
                {"ad": a, "gecis": n, "kayit": kayit_sayaci[a]}
                for a, n in sayac.most_common()
            ],
        }
    return sonuc


# --------------------------------------------------------------------------
# C -- aday baglanirsa hangi kosullar bir alan bulabilir
# --------------------------------------------------------------------------
def olcum_c() -> dict[str, Any]:
    harita = yaml.safe_load(KURAL_HARITA.read_text(encoding="utf-8"))
    kurallar = yaml.safe_load(KURALLAR.read_text(encoding="utf-8"))

    hedefe_gore: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for kosul in harita.get("kosullar") or []:
        hedef = kosul.get("hedef")
        if not hedef:
            continue
        for h in (hedef if isinstance(hedef, list) else [hedef]):
            hedefe_gore[h].append(kosul)

    cikti: dict[str, Any] = {}
    for ham_ad, kanonik in ADAYLAR.items():
        etkilenen = [
            {
                "teknik": k.get("teknik"),
                "desen": k.get("desen"),
                "atesleme_60": k.get("atesleme_60"),
                "olay_id_veride_var": k.get("olay_id_veride_var"),
            }
            for k in hedefe_gore.get(kanonik, [])
        ]
        cikti[ham_ad] = {
            "kanonik": kanonik,
            "bu_hedefi_kullanan_kosul": len(etkilenen),
            "kosullar": etkilenen,
        }

    # Kural motoru tarafi: bu kanonik alani sart kosan kural sayisi.
    for ham_ad, veri in cikti.items():
        teknikler = {k["teknik"] for k in veri["kosullar"]}
        veri["kural_katalogunda_var_mi"] = sorted(
            t for t in teknikler
            if any(r.get("technique_id") == t for r in (kurallar.get("techniques") or []))
        )
    return cikti


# --------------------------------------------------------------------------
# D -- semaya ad eklemenin tokenizasyona yan etkisi
# --------------------------------------------------------------------------
def _adayli_sema() -> dict[str, Any]:
    ham = yaml.safe_load(SEMA.read_text(encoding="utf-8"))
    alanlar = ham["fields"]
    alanlar.setdefault("process.command_line", {}).setdefault("aliases", [])
    if "Command" not in alanlar["process.command_line"]["aliases"]:
        alanlar["process.command_line"]["aliases"].append("Command")
    alanlar.setdefault("parent.process.path", {"aliases": []})
    alanlar["parent.process.path"].setdefault("aliases", [])
    for a in ("Parent Process Path", "ParentProcessPath"):
        if a not in alanlar["parent.process.path"]["aliases"]:
            alanlar["parent.process.path"]["aliases"].append(a)

    alias_map: dict[str, str] = {}
    for kanonik, spec in alanlar.items():
        for alias in (spec.get("aliases") or []):
            alias_map[formats._normalise_key(alias)] = kanonik
        alias_map[formats._normalise_key(kanonik)] = kanonik
    return {
        "fields": alanlar,
        "alias_to_canonical": alias_map,
        "non_informative": {
            str(v).strip().lower() for v in (ham.get("non_informative_values") or [])
        },
    }


def _ayristir(metin: str, sema: dict[str, Any]) -> dict[str, str]:
    """ARAC KUSURU (olculdu, bu betigin ilk halinde vardi):
    `parse_fields(raw, schema)` verilen semayi space_kv TOKENIZASYONUNA
    UYGULAMIYOR -- `SpaceKeyValueFormat.extract_pairs` kendi icinde
    `load_schema()` cagiriyor ve modul onbellegini okuyor. Sonuc: aday sema
    parametreyle verildiginde sinir deseni URETIM semasindan kuruluyor,
    D "0 kayit degisti" diyor ve bu SESSIZ bir bos olcum oluyor.

    Kanit (ayni log, ayni cagri):
        parametreyle : event.id = '4688 Command=powershell -enc AAA'
        onbellekle   : event.id = '4688', process.command_line = 'powershell -enc AAA'

    Bu yuzden sema PARAMETREYLE degil ONBELLEK DEGISTIRILEREK uygulanir."""
    onceki = formats._SCHEMA_CACHE
    formats._SCHEMA_CACHE = sema
    try:
        alanlar, _ = parse_fields(metin, sema)
        return {k: v.text for k, v in alanlar.items()}
    finally:
        formats._SCHEMA_CACHE = onceki


def olcum_d(korpuslar: dict[str, list[str]]) -> dict[str, Any]:
    mevcut = load_schema()
    yeni = _adayli_sema()

    sonuc: dict[str, Any] = {}
    for ad, loglar in korpuslar.items():
        degisen = []
        for i, metin in enumerate(loglar):
            a_düz = _ayristir(metin, mevcut)
            b_düz = _ayristir(metin, yeni)
            if a_düz == b_düz:
                continue
            degisen.append({
                "kayit": i,
                "yalniz_eskide": {k: a_düz[k] for k in a_düz.keys() - b_düz.keys()},
                "yalniz_yenide": {k: b_düz[k] for k in b_düz.keys() - a_düz.keys()},
                "degeri_degisen": {
                    k: {"eski": a_düz[k], "yeni": b_düz[k]}
                    for k in a_düz.keys() & b_düz.keys()
                    if a_düz[k] != b_düz[k]
                },
            })
        sonuc[ad] = {
            "kayit_sayisi": len(loglar),
            "degisen_kayit": len(degisen),
            "ornekler": degisen[:10],
        }
    return sonuc


# --------------------------------------------------------------------------
# E -- MADDE 17 KONTROLU: aday bicim korpusta ORNEKLENIYOR mu
# --------------------------------------------------------------------------
def olcum_e(korpuslar: dict[str, list[str]]) -> dict[str, Any]:
    """D'nin "0 kayit degisti" sonucu iki AYRI seyin isareti olabilir:
    (a) ad korpusta VAR ve eklemek zarar vermiyor, (b) ad korpusta HIC YOK,
    yani D hicbir sey olcmedi. Ikisi ayrilmadan D okunamaz -- HANDOFF
    yontem maddesi 17'nin bu olcume uygulanmis hali."""
    desenler = {
        "Command=  (CommandLine haric)": re.compile(r"(?<![A-Za-z])Command\s*="),
        "CommandLine=": re.compile(r"(?i)commandline\s*=|command\s+line\s*="),
        "Parent Process Path": re.compile(r"(?i)parent\s*process\s*path"),
        "Parent Process Name": re.compile(r"(?i)parent\s*process\s*name"),
        "ParentImage": re.compile(r"(?i)parentimage"),
    }
    cikti: dict[str, Any] = {}
    for ad, loglar in korpuslar.items():
        cikti[ad] = {
            etiket: sum(1 for m in loglar if rx.search(m))
            for etiket, rx in desenler.items()
        }
    cikti["_hukum"] = (
        "Aday adin gectigi kayit sayisi 0 ise D BOS bir olcumdur: sema "
        "degisikligi hicbir kaydin bicimine dokunmamistir cunku o bicim "
        "korpusta yoktur. Bu 'yan etki yok' DEMEK DEGILDIR."
    )
    return cikti


# --------------------------------------------------------------------------
def main() -> int:
    korpuslar = _korpuslar()

    rapor = {
        "A_kural_haritasi_hedefleri": olcum_a(),
        "B_unknown_dokumu": olcum_b(korpuslar),
        "C_adaylarin_ust_siniri": olcum_c(),
        "D_tokenizasyon_yan_etkisi": olcum_d(korpuslar),
        "E_madde17_bicim_orneklemesi": olcum_e(korpuslar),
    }

    CIKTI.parent.mkdir(parents=True, exist_ok=True)
    CIKTI.write_text(json.dumps(rapor, indent=2, ensure_ascii=False), encoding="utf-8")

    a = rapor["A_kural_haritasi_hedefleri"]
    print(f"A  kural haritasi hedefi: {a['hedef_sayisi']} essiz")
    print(f"A  semada EKSIK hedef: {len(a['semada_EKSIK'])}")
    for h, teknikler in a["semada_EKSIK"].items():
        print(f"     {h}  <- {', '.join(teknikler)}")

    print()
    for ad, veri in rapor["B_unknown_dokumu"].items():
        print(f"B  {ad}: {veri['kayit_sayisi']} kayit, "
              f"{veri['essiz_unknown_ad']} essiz unknown ad, "
              f"{veri['toplam_unknown_gecis']} gecis")
        for satir in veri["adlar"][:15]:
            print(f"     {satir['gecis']:4d} gecis / {satir['kayit']:3d} kayit  {satir['ad']}")

    print()
    for ham_ad, veri in rapor["C_adaylarin_ust_siniri"].items():
        print(f"C  {ham_ad} -> {veri['kanonik']}: "
              f"{veri['bu_hedefi_kullanan_kosul']} kosul, "
              f"kural katalogunda {veri['kural_katalogunda_var_mi']}")

    print()
    for ad, veri in rapor["D_tokenizasyon_yan_etkisi"].items():
        print(f"D  {ad}: {veri['degisen_kayit']}/{veri['kayit_sayisi']} kayit degisti")

    print()
    for ad, veri in rapor["E_madde17_bicim_orneklemesi"].items():
        if ad.startswith("_"):
            continue
        print(f"E  {ad}:")
        for etiket, n in veri.items():
            isaret = "   <-- BICIM KORPUSTA YOK" if n == 0 else ""
            print(f"     {n:3d} kayit  {etiket}{isaret}")

    print(f"\nRapor: {CIKTI.relative_to(KOK)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
