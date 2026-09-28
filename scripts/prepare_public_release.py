#!/usr/bin/env python
"""Kamuya acik yayin kopyasini uretir ve SIZINTI DENETIMINDEN gecirir.

NEDEN AYRI BIR KOPYA: bu repo gercek bir ortamin QRadar telemetrisini tasiyor
(makine adi, ic ag adresleri, ham Windows Security govdeleri) ve bu veri 100
commit'lik GECMISTE de duruyor. Bugun silmek gecmisten okunmasini engellemez;
o yuzden yayin, gecmissiz AYRI bir kopyadir. Bu repoya remote EKLENMEZ.

IKI KURAL, birbirine karistirilmaz:

  1. BIREBIR gercek log iceren dosya KOPYALANMAZ -- temizlenmez. Cunku makine
     adini degistirmek ham govdeyi (komut satirlari, PID'ler, GUID'ler, zaman
     damgalari) yerinde birakir; o da telemetridir.
  2. Gercek adi yalnizca ODUNC ALAN turetilmis dosya (sentetik setler, testler,
     docs) TEMIZLENIR: ad ve adresler RFC 5737 karsiliklariyla degisir.

IKI KAPI, uretilen ciktiyi denetler:

  A. Yasakli jeton taramasi -- bilinen adlar ve adresler.
  B. Birebir ortak metin taramasi -- yayinlanan hicbir dosya gercek korpusla
     uzun kesintisiz ortak metin paylasmamali. (A)'nin listesi bir seyi gozden
     kacirirsa (B) yakalar: (A) BILDIGIMIZ adlari arar, (B) bilmediklerimizi.

KAPI B'NIN GEREKLILIGI OLCULDU, VARSAYILMADI. Gercek CSV once (A)'nin tum
jetonlari degistirilerek "temizlenip" yayin kopyasina kasten enjekte edildi:
(A) GECTI, (B) 4.000 karakterlik ortaklikla DUSURDU. Yakalanan metin sebebi
gosterdi: satirlar ayni govdeyi HEX olarak da tasiyor, yani jeton degistirmek
adi yalnizca duz metinde siler, kodlanmis kopyasi yerinde kalir. (A) tek
basina kalsaydi makine adi hex hâlinde yayinlanmis olurdu. Bulgunun ardindan
kodlanmis bicimler de (A)'ya eklendi -- ama ELLE YAZILMADAN, addan uretilerek:
bu dosyaya ornek olsun diye yazilan bir hex dizisi, gercek adin ta kendisidir
ve (A) onu -- hakli olarak -- bir ihlal sayar. Olculdu: sayti.

IKI KAPININ DA GOREMEDIGI SEY: GORUNTULER. Bir ekran goruntusu metin degil
PIKSELDIR; (A) icinde jeton bulamaz, (B) ortaklik olcemez. `docs/screenshots/`
altindaki her kare bu yuzden SENTETIK girdiyle uretilir ve iceregi insan
sorumlulugundadir. Kapi sayisini artirmak bu boslugu kapatmaz; bilmek kapatir.

Kullanim:
    python scripts/prepare_public_release.py --out ../mitre-attack-mapper-public
    python scripts/prepare_public_release.py --gates-only --out <dizin>
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import re
import shutil
import subprocess
import sys
from pathlib import Path

KOK = Path(__file__).resolve().parent.parent

# ------------------------------------------------------------- 1. kopyalanmaz

# Gercek tanimlayicilarin KENDISI de hassas veridir: makine adi ve alt ag o
# listede yazili. Bu yuzden liste betikte DEGIL, yayinlanmayan ayri bir
# dosyada durur -- yoksa betik ya adlari yayinlar ya da kendi temizleyicisi
# tarafindan bozulur (olculdu: `WINHOST-01` literali yayin kopyasinda
# `WINHOST-01`e cevrildi ve betik kendi kendini anlamsizlastirdi).
OZEL_YAPILANDIRMA = "config/release_private.yaml"

# Birebir gercek log iceren dosyalar. Temizlenmez, KOPYALANMAZ.
GERCEK_VERI = [
    "tests/fixtures/qradar_2026-08-06_51rows.csv",  # 51 ham QRadar satiri
    "evaluation/g_arm_qradar_labels.json",          # ayni satirlar + etiketleri
    OZEL_YAPILANDIRMA,                              # gercek adlarin listesi
]

# Sizinti degil, uretilebilir artefakt: 71 MB ikili indeks yedegi.
ARTEFAKT_DIZINLERI = ["data/indexes_backup_pre2c/"]

# Sizinti degil, yayinda isi olmayan dosyalar. Sizinti denetiminden temiz
# gectiler; cikarilma sebebi gizlilik degil, yayinin kapsami. Hicbiri
# SILINMIYOR -- ozel calisma kopyasinda yerlerinde duruyorlar, yalnizca yayin
# kopyasina kopyalanmiyorlar.
YAYINDA_GEREKSIZ = [
    # Sunum dosyalari
    "MITRE_ATTACK_Proje_Sunumu_TR.pptx",
    "MITRE_ATTACK_Sunum_v3.pptx",
    # Sunum / sozlu savunma hazirlik notlari: ikinci tekil sahis, slayt
    # numaralarina bagli, projeyi anlamak icin degil ANLATMAK icin yazilmis.
    "MITRE_ATTACK_Kavram_Sozlugu.md",
    "MITRE_ATTACK_Kod_Blogu_Rehberi.md",
    "MITRE_ATTACK_Sunum_Konusmasi.md",
    "MITRE_ATTACK_Proje_Analiz_ve_Sunum_Rehberi.md",
    "MITRE_ATTACK_Uygulama_Demo_Konusmasi.md",
    "MITRE_ATTACK_SOC_Demo_Akisi.md",
    "docs/demo_script.md",
    # Oturum devir-teslim defteri (2070 satir): gorev listeleri, "Sirada"
    # bolumu ve commit-commit anlatim iceriyor; yayin kopyasinda cozulmeyen
    # 32 commit SHA atfi var. Teknik ozu docs/engineering-notes.md'ye
    # damitildi; bu dosya ozel kopyada calisma belgesi olarak kaliyor.
    "HANDOFF.md",
]

# --------------------------------------------------------------- 2. temizlenir
#
# DEGISTIRMELER ve YASAKLI_JETONLAR calisma aninda OZEL_YAPILANDIRMA'dan
# yuklenir; dosya yoksa betik yayin URETMEZ (bkz. ozel_listeleri_yukle).

DEGISTIRMELER: list[tuple[str, str]] = []
YASAKLI_JETONLAR: list[bytes] = []


def ozel_listeleri_yukle() -> None:
    """Gercek adlari yayinlanmayan yapilandirmadan okur.

    Kodlanmis bicimler ELLE yazilmaz, addan URETILIR: elle yazilan bir hex
    dizisi betige gomulu bir gercek ad demektir ve betik yayinlanacak.
    """
    global DEGISTIRMELER, YASAKLI_JETONLAR
    import yaml

    p = KOK / OZEL_YAPILANDIRMA
    if not p.exists():
        raise SystemExit(
            f"HATA: {OZEL_YAPILANDIRMA} yok.\n"
            "Bu betik yalnizca ozel calisma kopyasindan kosar: gercek adlarin\n"
            "listesi yayinlanmaz, dolayisiyla yayin kopyasinda bu dosya olmaz.\n"
            "Yayin URETILMEDI."
        )
    veri = yaml.safe_load(p.read_text(encoding="utf-8"))

    # Sira onemli: uzun desen kisasindan once gelmeli ki kisa olan uzunu bozmasin.
    DEGISTIRMELER = sorted(
        ((d["eski"], d["yeni"]) for d in veri["degistirmeler"]),
        key=lambda ey: -len(ey[0]),
    )

    jetonlar: list[bytes] = []
    for eski, _ in DEGISTIRMELER:
        for bicim in (eski, eski.lower(), eski.upper(), eski.capitalize()):
            jetonlar.append(bicim.encode())
    for kalem in veri.get("kodlanmis_bicimler", []):
        ham = kalem["kaynak"].encode()
        for bicim in kalem["bicimler"]:
            if bicim == "hex":
                jetonlar += [ham.hex().encode(), ham.hex().upper().encode()]
            elif bicim == "hex_bosluklu":
                bosluklu = " ".join(f"{b:02x}" for b in ham)
                jetonlar += [bosluklu.encode(), bosluklu.upper().encode()]
            else:
                raise SystemExit(f"HATA: bilinmeyen kodlanmis bicim: {bicim}")
    YASAKLI_JETONLAR = sorted(set(jetonlar))

# ------------------------------------------------------------ B. metin kapisi

# Cipa uzunlugu: bulunan her cipa iki yone buyutulur, yani kapi bir KESIT
# degil ORTAKLIGIN TAM UZUNLUGUNU olcer. 60 karakterlik bir kesite bakip
# karar vermek Windows'un sabit ileti kalibini kopyalanmis logdan ayirmaz.
CIPA = 30

# Bu uzunluktan kisa ortaklik hicbir sey soylemez: alan adlari, JSON
# anahtarlari ve yol parcalari bu bandi zorunlu olarak paylasir.
ESIK = 60

# Gercek korpusla ortakligi MESRU olan metinler -- her biri GEREKCESIYLE.
# Bir dosyanin OLCULEN en uzun ortakligi bunlardan birinin ICINDE kaliyorsa
# gecer; tasarsa kapi onu gosterir. Karsilastirma kacis ve tirnak gurultusunu
# atarak yapilir (bkz. kacis_sagir), yani ayni metin JSON'da, Python
# kaynaginda ve duz metinde ayni kalemle karsilanir.
#
# Gerekcesiz kalem EKLENMEZ. Bir kalemin gerekcesi "testler gecsin" olamaz.
BEKLENEN_ORTAKLIK: list[tuple[str, str]] = [
    (
        r"process name: c:\windows\system32\svchost.exe access request "
        r"information: transaction id: {00000000-0000-0000-0000-000000000000} "
        r"accesses: read_control query key value set key value create sub-key "
        r"enumerate sub-keys notify about changes to keys access reasons: - "
        r"access mask: 0x2001f privileges used for access check: -",
        "Windows'un 4656 ileti govdesi: standart sistem yolu, sifir GUID, "
        "sabit Accesses listesi, maske. Her Windows makinesinde ayni; ortama "
        "ozgu tek bir deger (ad, adres, kullanici, PID, zaman) tasimiyor.",
    ),
    (
        r"pipe name=n/a, process path=n/a, file directory=n/a, filename=n/a, "
        r"user domain=nt, event id=4656, process name=svchost.exe, "
        r"user workstation=n/a, account name=local service, object type=key, "
        r"class=n/a, group id=n/a, user account control=n/a, file path=n/a,",
        "QRadar zarfinin alan ADLARI ve neredeyse hepsi n/a olan degerleri. "
        "Deger tasimayan bir zarf ortamdan bir sey soylemez.",
    ),
    (
        r"expected_attack_ids: [ t1059.001, t1564.003 ], expected_decision: "
        r"sufficient_suspicious, negative_case: false, review_flag: true, "
        r"rationale",
        "Projenin KENDI etiket semasinin anahtarlari. Ayni ureticiden cikan "
        "iki dosya YAPIYI paylasir; ortak olan icerik degil sema.",
    ),
    (
        r"account domain: workgroup logon id: 0x3e7 object: object server: "
        r"security object type: key object name: "
        r"\registry\machine\system\controlset001\services\w",
        "Windows ileti kalibi + bilinen SYSTEM logon id'si (0x3e7) + standart "
        "registry yolu. Ucu de her makinede ayni.",
    ),
    (
        r"filepath=\registry\machine\system\controlset001\services\w",
        "Ayni standart registry yolu, alan adi onunde.",
    ),
    (
        r"process name: c:\programdata\microsoft\windows defender\platform"
        r"\4.18.26070.9-0\mpdefendercoreservice.exe",
        "Microsoft Defender'in yayinlanmis platform surum yolu; milyonlarca "
        "makinede ayni. Surum numarasi Microsoft'un, ortamin degil.",
    ),
    (
        r"read_control query key value set key value create sub-key "
        r"enumerate sub-keys notify about changes to keys",
        "Windows'un sabit Accesses numaralandirmasi.",
    ),
    (
        r"\device\harddiskvolume3\program files\google\chrome\application"
        r"\chrome.exe",
        "Chrome'un standart kurulum yolu.",
    ),
    (
        r"success audit: the windows filtering platform has allowed a connection",
        "Windows Filtering Platform'un sabit ileti metni (5156), QRadar bicimi.",
    ),
    (
        r"message: the windows filtering platform has permitted a connection.",
        "Ayni sabit ileti metninin Windows bicimi.",
    ),
    (
        r"51 gercek qradar satirinin elle yazilmis beklenen cevaplari. "
        r"hat calistirilmadan",
        "Projenin KENDI Turkce aciklama cumlesi; ureten betik ile urettigi "
        "dosya ayni cumleyi tasiyor.",
    ),
    (
        r"attack_version: 19.1, labeled_without_running_pipeline: true",
        "Projenin kendi ust veri anahtarlari.",
    ),
]


def _git(*argv: str) -> str:
    return subprocess.check_output(["git", *argv], cwd=KOK).decode("utf-8", "replace")


def izlenen_dosyalar() -> list[str]:
    return [f for f in _git("ls-files", "-z").split("\0") if f]


def dislanma_sebebi(yol: str) -> str | None:
    if yol in GERCEK_VERI:
        return "gercek veri"
    if yol in YAYINDA_GEREKSIZ:
        return "yayinda gereksiz"
    for d in ARTEFAKT_DIZINLERI:
        if yol.startswith(d):
            return "uretilebilir artefakt"
    return None


def ikili_mi(veri: bytes) -> bool:
    return b"\0" in veri[:8192]


def normalize(veri: bytes) -> bytes:
    """Kucuk harf + bosluk sadelestirme: bicim farki ortakligi gizlemesin."""
    return re.sub(rb"\s+", b" ", veri.lower())


UC_NOKTALAMA = b" ,.:;\"'{}[]=\\"


def kacis_sagir(veri: bytes) -> bytes:
    """Ters bolu ve tirnaklari atar: ayni metin JSON'da, Python kaynaginda ve
    duz metinde farkli kaciyor (`\\`, `\\\\`, `\\\\\\\\`) -- karsilastirma bu
    farki gormemeli, yoksa beyaz liste bicime gore delinir."""
    return normalize(veri.replace(b"\\", b"").replace(b'"', b""))


def kirp(veri: bytes) -> bytes:
    """Uclardaki noktalamayi atar: olculen parca komsu virgulu/tirnagi da
    yutar, kalem metni onu tasimak zorunda kalmasin."""
    return veri.strip(UC_NOKTALAMA)


def ozet(pencere: bytes) -> str:
    return hashlib.blake2b(pencere, digest_size=8).hexdigest()


def gercek_korpus() -> bytes:
    """Gercek veri dosyalari + icindeki base64 govdelerin cozulmus hali.

    Base64 sarti onemli: ham satirlar dosyada kodlanmis duruyor, duz metin
    aramasi onlari GORMEZ.
    """
    parcalar: list[bytes] = []
    for yol in GERCEK_VERI:
        p = KOK / yol
        if not p.exists():
            print(f"  UYARI: {yol} yok -- (B) kapisi bu dosyayi denetlemiyor")
            continue
        veri = p.read_bytes()
        parcalar.append(veri)
        for blob in re.findall(rb"[A-Za-z0-9+/]{100,}={0,2}", veri):
            try:
                parcalar.append(base64.b64decode(blob))
            except Exception:
                pass
    return b"\n".join(parcalar)


def temizle_ama_gitigi_koru(cikti: Path) -> None:
    """Cikti dizinini bosaltir ama `.git`e DOKUNMAZ.

    Yayin kopyasi kendi gecmisi olan bir repodur: silinirse her guncelleme
    sifirdan bir repo olur ve yayinlanan tarih kaybolur. Ayrica `.git/objects`
    Windows'ta salt okunur -- rmtree orada zaten PermissionError veriyordu.

    Kalan her sey siliniyor, cunku ozel repodan KALDIRILAN bir dosya yayin
    kopyasinda da kaybolmali; yalnizca uzerine yazmak onu orada birakirdi.
    """
    for p in cikti.iterdir():
        if p.name == ".git":
            continue
        if p.is_dir():
            shutil.rmtree(p)
        else:
            p.unlink()


def kopyala(cikti: Path) -> None:
    dosyalar = izlenen_dosyalar()
    atlanan: list[tuple[str, str]] = []
    kopyalanan = 0
    gecis = {eski: 0 for eski, _ in DEGISTIRMELER}
    dosya_sayisi = {eski: 0 for eski, _ in DEGISTIRMELER}

    for yol in dosyalar:
        sebep = dislanma_sebebi(yol)
        if sebep:
            atlanan.append((yol, sebep))
            continue
        kaynak = KOK / yol
        if not kaynak.exists():
            continue
        veri = kaynak.read_bytes()
        if not ikili_mi(veri):
            for eski, yeni in DEGISTIRMELER:
                n = veri.count(eski.encode())
                if n:
                    veri = veri.replace(eski.encode(), yeni.encode())
                    gecis[eski] += n
                    dosya_sayisi[eski] += 1
        hedef = cikti / yol
        hedef.parent.mkdir(parents=True, exist_ok=True)
        hedef.write_bytes(veri)
        kopyalanan += 1

    print(f"\nKOPYALANAN   : {kopyalanan} dosya -> {cikti}")
    print(f"KOPYALANMAYAN: {len(atlanan)} dosya")
    for yol, sebep in atlanan:
        print(f"  - {yol}  ({sebep})")
    print("\nDEGISTIRME SAYILARI:")
    for eski, yeni in DEGISTIRMELER:
        print(f"  {eski:18s} -> {yeni:18s} {gecis[eski]:5d} gecis / "
              f"{dosya_sayisi[eski]:2d} dosya")


def kapi_a(ciktilar: list[Path], kok: Path) -> list[tuple[str, str, int]]:
    print("\n--- KAPI A: yasakli jeton taramasi ---")
    ihlal: list[tuple[str, str, int]] = []
    for p in ciktilar:
        veri = p.read_bytes()
        for jeton in YASAKLI_JETONLAR:
            n = veri.count(jeton)
            if n:
                ihlal.append((str(p.relative_to(kok)), jeton.decode(), n))
    if ihlal:
        print(f"  BASARISIZ -- {len(ihlal)} ihlal:")
        for yol, jeton, n in ihlal[:20]:
            print(f"    {yol}: {jeton} x{n}")
    else:
        print(f"  GECTI -- {len(ciktilar)} dosyada tek yasakli jeton yok")
    return ihlal


def en_uzun_ortak(metin: bytes, konum: dict[bytes, list[int]],
                  korpus: bytes) -> tuple[int, bytes]:
    """Metnin korpusla EN UZUN kesintisiz ortak parcasini bulur.

    Cipa eslesmesi bulununca iki yone buyutulur; boylece olculen sey cipa
    uzunlugu degil ortakligin gercek uzunlugudur.
    """
    en, ornek, i = 0, b"", 0
    while i <= len(metin) - CIPA:
        yerler = konum.get(metin[i : i + CIPA])
        if not yerler:
            i += 1
            continue
        best, span = 0, (i, i + CIPA)
        for k in yerler:
            a, b = i + CIPA, k + CIPA
            while a < len(metin) and b < len(korpus) and metin[a] == korpus[b]:
                a, b = a + 1, b + 1
            c, d = i - 1, k - 1
            while c >= 0 and d >= 0 and metin[c] == korpus[d]:
                c, d = c - 1, d - 1
            if a - (c + 1) > best:
                best, span = a - (c + 1), (c + 1, a)
        if best > en:
            en, ornek = best, metin[span[0] : span[1]]
        i = max(i + 1, span[1] - CIPA + 1)
    return en, ornek


def kapi_b(ciktilar: list[Path], kok: Path) -> list[tuple[int, str, str]]:
    print(f"\n--- KAPI B: birebir ortaklik olcumu (esik {ESIK} karakter) ---")
    korpus = normalize(gercek_korpus())
    if not korpus:
        print("  ATLANDI -- gercek korpus okunamadi, KAPI DENETLEMIYOR")
        return []
    konum: dict[bytes, list[int]] = {}
    for i in range(len(korpus) - CIPA + 1):
        konum.setdefault(korpus[i : i + CIPA], []).append(i)
    print(f"  korpus {len(korpus)} karakter, {len(konum)} ayri {CIPA}-cipa")

    beklenen = [kirp(kacis_sagir(m.encode())) for m, _ in BEKLENEN_ORTAKLIK]
    ihlal: list[tuple[int, str, str]] = []
    gecen: list[tuple[int, str]] = []
    for p in ciktilar:
        veri = p.read_bytes()
        if ikili_mi(veri):
            continue
        uz, ornek = en_uzun_ortak(normalize(veri), konum, korpus)
        if uz < ESIK:
            continue
        yol = str(p.relative_to(kok))
        olculen = kirp(kacis_sagir(ornek))
        if any(olculen in b for b in beklenen):
            gecen.append((uz, yol))
        else:
            ihlal.append((uz, yol, ornek.decode("utf-8", "replace")))

    gecen.sort(reverse=True)
    if gecen:
        print(f"  gerekceli beklenen ortaklik: {len(gecen)} dosya "
              f"(en uzun {gecen[0][0]} karakter)")
    ihlal.sort(reverse=True)
    if ihlal:
        print(f"  BASARISIZ -- {len(ihlal)} dosya GEREKCESIZ ortaklik tasiyor:")
        for uz, yol, ornek in ihlal[:15]:
            print(f"    {uz:5d} karakter  {yol}\n      >> {ornek[:300]}")
    else:
        print(f"  GECTI -- {ESIK}+ karakterlik her ortakligin yazili gerekcesi var")
    return ihlal


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=str(KOK.parent / "mitre-attack-mapper-public"))
    ap.add_argument("--force", action="store_true", help="varolan cikti dizinini sil")
    ap.add_argument("--gates-only", action="store_true",
                    help="kopyalamaz, varolan cikti dizinini yalnizca denetler")
    a = ap.parse_args()
    cikti = Path(a.out).resolve()

    if cikti == KOK:
        print("HATA: cikti dizini bu repo olamaz")
        return 2

    ozel_listeleri_yukle()
    print(f"ozel liste: {len(DEGISTIRMELER)} degistirme, "
          f"{len(YASAKLI_JETONLAR)} yasakli jeton ({OZEL_YAPILANDIRMA})")

    if not a.gates_only:
        if cikti.exists():
            if not a.force:
                print(f"HATA: {cikti} var. --force ile icerigi tazelenir.")
                return 2
            temizle_ama_gitigi_koru(cikti)
        kopyala(cikti)
    elif not cikti.exists():
        print(f"HATA: {cikti} yok")
        return 2

    ciktilar = [p for p in cikti.rglob("*")
                if p.is_file() and ".git" not in p.relative_to(cikti).parts]
    a_ihlal = kapi_a(ciktilar, cikti)
    b_ihlal = kapi_b(ciktilar, cikti)

    if a_ihlal or b_ihlal:
        print("\nSONUC: YAYINLANAMAZ")
        return 1
    print("\nSONUC: iki kapi da gecti")
    return 0


if __name__ == "__main__":
    sys.exit(main())
