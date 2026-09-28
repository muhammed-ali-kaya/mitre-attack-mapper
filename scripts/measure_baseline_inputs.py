"""Gorev 5 / bolum 5 olcumu: aktor baseline Yol B'yi bastirabilir mi?

Kod yazilmadan ONCE calistirildi. Uc soruyu olcer:

  1) AKTOR MEVCUDIYETI -- 60 senaryoda ve dort probda hesap/surec var mi?
     Yol B'nin bastiricisi ancak aktor varsa calisir.

  2) CIFT AYIRT EDILEBILIRLIGI -- ayni aktor (SYSTEM/TrustedInstaller) iki
     farkli varlik ailesine yaziyor. Mevcut detect_benign_signals ikisini
     ayirt edebiliyor mu? (Hayir. Bastirmanin neden AKTORE degil CIFTE
     bagli olmasi gerektiginin kaniti bu.)

  3) SPOOF -- baseline ham metinden beslenirse taklit edilebilir mi?
     T3'e, aktor OLMAYAN bir alana sahte dize konur ve sinyal izlenir.

Cikti docs/beklenti_5_karar_katmani.md bolum 5'e islenmistir. Sayilar
degisirse once burasi calistirilir, sonra beklenti guncellenir -- tersi
degil.
"""
from __future__ import annotations

import collections
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.normalization.asset_criticality import siniflandir
from app.normalization.event_semantics import describe
from app.normalization.input_parser import normalize_input
from app.validation.benign_signals import detect_benign_signals

B = chr(92)  # ters bolu
YOL_RE = re.compile(
    "(HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|" + B + B + "REGISTRY)"
    + B + B + "[" + B + "w" + B + B + " .$%{}-]{4,120}",
    re.IGNORECASE,
)


def _val(field):
    """Field(value=...) sarmalayicisini acar; N/A'yi yokluk sayar."""
    value = getattr(field, "value", field)
    if value is None:
        return None
    if isinstance(value, list):
        return value
    text = str(value).strip()
    return None if not text or text.upper() == "N/A" else text


def profil(raw: str) -> dict:
    """Bir girdinin karar katmanina verebilecegi bes girdiyi cikarir."""
    normalized = normalize_input(raw)
    fields = normalized.get("parsed_fields") or {}

    def get(*names):
        for name in names:
            value = _val(fields.get(name))
            if value:
                return value
        return None

    path = get("object.name", "file.path")
    criticality = siniflandir(path) if path else None
    semantics = describe(
        get("event.id") or normalized.get("event_id"),
        get("access.mask"),
        get("object.type"),
        get("access.list"),
    )
    return {
        "yol": path,
        "kritiklik": (
            "YOK" if not path
            else ("unknown" if criticality.bilinmiyor else criticality.seviye)
        ),
        "aile": (criticality.aile if criticality else None) or "-",
        "erisim": semantics.get("access_class"),
        "hesap": get("account.name", "user.name", "subject.user"),
        "surec": get("process.name", "process.path"),
    }


def olcum_1_aktor_mevcudiyeti() -> None:
    scenarios = json.loads(
        (ROOT / "evaluation/test_scenarios.json").read_text(encoding="utf-8")
    )
    say: collections.Counter = collections.Counter()
    for scenario in scenarios:
        p = profil(scenario.get("input") or "")
        if p["yol"]:
            say["yol"] += 1
        if p["erisim"]:
            say["erisim"] += 1
        if p["hesap"]:
            say["hesap"] += 1
        if p["surec"]:
            say["surec"] += 1
        if p["hesap"] or p["surec"]:
            say["aktor"] += 1
        if p["kritiklik"] in ("critical", "high") and p["erisim"] == "write":
            say["yolb"] += 1

    toplam = len(scenarios)
    print(f"1) AKTOR MEVCUDIYETI -- {toplam} senaryo")
    for anahtar, etiket in (
        ("yol", "yapisal varlik yolu"),
        ("erisim", "erisim sinifi"),
        ("hesap", "account.name"),
        ("surec", "process.name"),
        ("aktor", "AKTOR (hesap|surec)"),
        ("yolb", "YOL-B tetiklenir (krit+write)"),
    ):
        n = say[anahtar]
        print(f"   {etiket:32s} {n:3d}/{toplam}   %{100 * n / toplam:.0f}")

    # Yapisal alan 0 diye "hic yol yok" DENEMEZ: duzyazida geciyorlar.
    duzyazi = [
        YOL_RE.search(s.get("input") or "").group(0)
        for s in scenarios
        if YOL_RE.search(s.get("input") or "")
    ]
    print(f"   {'ham metinde yol gecen':32s} {len(duzyazi):3d}/{toplam}"
          "   <-- bolum 6, acik madde")
    for yol in duzyazi:
        print(f"        {yol[:78]}")


def olcum_2_cift_ayirt_edilebilirligi() -> None:
    print("\n2) CIFT AYIRT EDILEBILIRLIGI -- ayni aktor, farkli varlik ailesi")
    kaynaklar = [
        ("tests/fixtures/registry_object_access_logs.json", ""),
        ("tests/fixtures/baseline_suppression_logs.json", ""),
    ]
    print(f"   {'id':5s} {'kritiklik':10s} {'aile':17s} {'erisim':7s} "
          f"{'aktor':30s} benign_strong")
    for rel, _ in kaynaklar:
        data = json.loads((ROOT / rel).read_text(encoding="utf-8"))
        for log in data["logs"]:
            p = profil(log["raw"])
            strong = detect_benign_signals(log["raw"]).strong
            aktor = f"{p['hesap']}/{p['surec']}"
            print(f"   {log['id']:5s} {p['kritiklik']:10s} {p['aile']:17s} "
                  f"{str(p['erisim']):7s} {aktor:30s} {strong}")
    print("   BULGU: T4 ve T5 ayni sinyali aliyor -- mevcut katman ayirt EDEMIYOR.")


def olcum_3_spoof() -> None:
    print("\n3) SPOOF -- ham metin tabanli bastirma taklit edilebilir mi?")
    data = json.loads(
        (ROOT / "tests/fixtures/registry_object_access_logs.json").read_text(
            encoding="utf-8"
        )
    )
    t3 = next(log["raw"] for log in data["logs"] if log["id"] == "T3")
    sahte = "File Path=C:" + B + "Users" + B + "Public" + B + "trustedinstaller.exe.log"
    for etiket, raw in (("T3 (orijinal)", t3), ("T3 + sahte dize", t3.replace("Class=N/A", sahte))):
        strong = detect_benign_signals(raw).strong
        surec = _val(normalize_input(raw)["parsed_fields"].get("process.name"))
        print(f"   {etiket:18s} benign_strong={str(strong):5s}  process.name={surec!r}")
    print("   BULGU: davranis degismeden mesru ilan edildi -> baseline YAPISAL")
    print("          alandan okunacak, ham metinden degil.")


def olcum_4_komut_satiri_yol_siniri() -> None:
    """Gorev 6: yol cikariminin siniri -- naif desen vs kural tabanli.

    Bu olcum beklenti_6'nin '1. Olculen durum' tablosunu uretir. NAIF_RE
    burada BILEREK duruyor: duzeltmenin neyi degistirdigini gostermek icin
    eski davranisin calisir bir kopyasi gerekiyor."""
    from app.normalization.command_line_paths import extract_registry_paths

    vakalar = json.loads(
        (ROOT / "tests/fixtures/command_line_path_boundary.json").read_text(
            encoding="utf-8"
        )
    )["vakalar"]

    def krit(yol: str | None) -> str:
        if not yol:
            return "-"
        k = siniflandir(yol)
        return "unknown" if k.bilinmiyor else k.seviye

    print("\n4) KOMUT SATIRI YOL SINIRI -- naif desen vs kural (K1-K5)")
    print(f"   {'id':4s} {'ONCE':10s} {'SONRA':10s} beklenen yol")
    kurtarilan = 0
    for v in vakalar:
        m = YOL_RE.search(v["command_line"])
        once = m.group(0).strip() if m else None
        sonra = extract_registry_paths(v["command_line"])
        sonra_yol = sonra[0] if sonra else None
        beklenen = v["expected_paths"][0] if v["expected_paths"] else None
        if sonra_yol != beklenen:
            raise AssertionError(f"{v['id']} beklentiye uymuyor: {sonra_yol!r}")
        if krit(once) in ("-", "unknown") and krit(sonra_yol) not in ("-", "unknown"):
            kurtarilan += 1
        print(f"   {v['id']:4s} {krit(once):10s} {krit(sonra_yol):10s} {beklenen}")
    print(f"   unknown/kayip -> siniflanabilir: {kurtarilan} vaka")
    print("   BULGU: V1 (reg.exe save HKLM\\SAM ...) artik critical. Naif desen")
    print("          'HKLM\\SAM C' uretip amiral gemisi vakayi dusuruyordu.")


def main() -> int:
    olcum_1_aktor_mevcudiyeti()
    olcum_2_cift_ayirt_edilebilirligi()
    olcum_3_spoof()
    olcum_4_komut_satiri_yol_siniri()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
