"""Gorev 4 kapsama olcumu: ATT&CK'in registry yollarinin kaci siniflaniyor?

PAYDA NEDEN ATT&CK: test verisinin TAMAMINDA 3 registry yolu var (T1 SAM,
T2 Time Zones, T3 Defender) ve ucu de bu tablonun TASARIM HEDEFI. Orada
olcmek, tabloyu kendi hedeflerine karsi sinamak olurdu.
KISMEN DAIRESEL: tablo bu havuzdan besleniyor. Sinir raporda yazili.

PAYDA TEMIZLENIR (C kategorisi): cikplak kokler ("HKCU\\Software\\") ve
cumle ortasinda kirpilmis parcalar YOL DEGILDIR; cikarim aracinin
artefaktidir. Paydada sayilirlarsa unknown oranini YAPAY olarak sisirirler
ve "tablo yetersiz" hukmu fazla sert cikar.
"""
from __future__ import annotations

import argparse
import collections
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.normalization.asset_criticality import kapsam_disi_mi, siniflandir

YOL_RE = re.compile(
    r"(HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU)\\[\w\\ .$%{}-]{4,120}"
    r"|(?:SOFTWARE|SYSTEM)\\[\w\\ .$-]{6,120}",
    re.IGNORECASE,
)
HIVE = re.compile(r"^(HKLM|HKCU|HKCR|HKU|HKEY_)", re.I)
# Cumle icinden kirpilmis parca izleri
CUMLE_IZI = re.compile(r"\bor\b |such as|via tools| the |\{Unique|\bto\b ", re.I)


# Yol AGACININ ara dugumleri. Bir yol YALNIZCA bunlardan olusuyorsa
# ayirt edici yapragi yok demektir -- ATT&CK cumlesi yolu tamamlamadan
# kesilmis. "HKCU\Software\Microsoft" hangi varlik oldugunu soylemiyor.
JENERIK_KONTEYNER = {
    "software", "system", "microsoft", "windows", "windows nt", "office",
    "currentversion", "current version", "classes", "policies", "wow6432node",
    "currentcontrolset", "control", "services",
}


def _artefakt_mi(yol: str) -> str | None:
    """C kategorisi: bu bir YOL degil, cikarim artefakti mi?"""
    seg = [s for s in yol.split("\\") if s.strip()]
    if CUMLE_IZI.search(yol):
        return "cumle ortasindan kirpilmis"
    if HIVE.match(yol) and len(seg) <= 2:
        return "ciplak hive koku, yaprak yok"
    if not HIVE.match(yol) and len(seg) <= 2:
        return "hive'siz ve tek segment"
    # Hive disindaki TUM segmentler jenerik konteyner mi?
    govde = seg[1:] if HIVE.match(yol) else seg
    if govde and all(s.strip().casefold() in JENERIK_KONTEYNER for s in govde):
        return "yalnizca jenerik konteyner, ayirt edici yaprak yok"
    return None


def attack_yollari() -> set[str]:
    teknikler = json.loads((ROOT / "data/processed/techniques.json").read_text(encoding="utf-8"))
    canli = [t for t in teknikler if not t.get("revoked") and not t.get("deprecated")]
    yollar: set[str] = set()
    for t in canli:
        metin = " ".join(str(t.get(k) or "") for k in ("description", "detection"))
        metin += " ".join(str(p) for p in (t.get("procedure_examples") or []))
        for m in YOL_RE.finditer(metin):
            # Kacis karakterleri KATMANLI olabiliyor (\\\\ -> \\ -> \):
            # tek gecislik replace yetmiyor, sabit noktaya kadar tekrarla.
            y = m.group(0).rstrip(".,;) ")
            while "\\\\" in y:
                y = y.replace("\\\\", "\\")
            yollar.add(y)
    return yollar


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--liste", action="store_true", help="unknown aileleri listele")
    args = ap.parse_args()

    ham = attack_yollari()
    artefakt = {y: _artefakt_mi(y) for y in ham}
    temiz = sorted(y for y in ham if not artefakt[y])

    print("PAYDA")
    print(f"   ham cikarim          : {len(ham)}")
    print(f"   C -- artefakt        : {sum(1 for v in artefakt.values() if v)}")
    for sebep, n in collections.Counter(v for v in artefakt.values() if v).most_common():
        print(f"        {sebep:34s} {n}")
    print(f"   TEMIZ PAYDA          : {len(temiz)}")
    print()

    seviye = collections.Counter()
    hivesiz_kurtarilan = 0
    bilinmeyen = []
    for y in temiz:
        k = siniflandir(y)
        seviye[k.seviye] += 1
        if k.hive_varsayildi and not k.bilinmiyor:
            hivesiz_kurtarilan += 1
        if k.bilinmiyor:
            bilinmeyen.append(y)

    print("SINIFLANDIRMA (temiz payda uzerinde)")
    for s in ("critical", "high", "medium", "noise", "unknown"):
        n = seviye[s]
        print(f"   {s:9s} {n:4d}  %{100*n/len(temiz):.0f}")
    print()
    print(f"   A -- hive eklenerek kurtarilan: {hivesiz_kurtarilan}")

    gerekceli = [y for y in bilinmeyen if kapsam_disi_mi(y)]
    gerekcesiz = [y for y in bilinmeyen if not kapsam_disi_mi(y)]
    print()
    print(f"unknown                : {len(bilinmeyen)}")
    print(f"   gerekceli kapsam disi: {len(gerekceli)}")
    print(f"   GEREKCESIZ           : {len(gerekcesiz)}   <-- 0 olunca Gorev 4 biter")

    if args.liste and gerekcesiz:
        print()
        print("GEREKCESIZ UNKNOWN -- aile bazinda")
        gruplar = collections.defaultdict(list)
        for y in gerekcesiz:
            seg = [s for s in y.split("\\") if s]
            gruplar["\\".join(seg[:4])].append(y)
        for anahtar, uyeler in sorted(gruplar.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            print(f"  [{len(uyeler):2d}] {anahtar}")
            for u in sorted(uyeler)[:2]:
                print(f"        {u[:94]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
