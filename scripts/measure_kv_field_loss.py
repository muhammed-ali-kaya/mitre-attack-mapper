"""Gorev 15 -- toplu yolda sarmalanan Message'in alan kaybini olcer.

Beklenti: docs/beklenti_15_kv_alan_kaybi.md
Kaynak bulgu: docs/sonuc_13_g_kolu.md SS2

NE OLCER
    A yolu  parse_fields(satir["Message"])            -- ham Windows govdesi
    B yolu  parse_fields(row_to_kv_string(satir))     -- uretimin hatta verdigi
    ve ikisinin alan kumelerini karsilastirir.

    Ayrica dort kapanis olcutunu (O1..O4, beklenti SS4) hesaplar ve
    gerilemede cikis kodu 1 doner. LLM ve indeks GEREKMEZ.

NEDEN AYRI BIR BETIK
    G kolunun 89 dakikalik kosusu bu kaybi gosteremez: kosu yalnizca SONUCU
    yazar, alan kumesini yazmaz. Kayip ancak iki yol YAN YANA konunca
    gorunur -- HANDOFF dersi 7.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

KOK = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KOK))

from app.batch.qradar_adapter import try_convert_qradar_export  # noqa: E402
from app.batch.serialize import row_to_kv_string  # noqa: E402
from app.normalization.event_semantics import decode_access_mask  # noqa: E402
from app.normalization.formats import parse_fields  # noqa: E402
from app.validation.decision import erisim_sinifi  # noqa: E402

CSV = KOK / "tests" / "fixtures" / "qradar_2026-08-06_51rows.csv"
CIKTI = KOK / "evaluation" / "results" / "kv_field_loss.json"

BS = chr(92)

# O4 -- kacis gidis-donusu. Deger BOSLUK icermeli ki row_to_kv_string
# tirnaklasin; tirnaklama olmadan kacis da olmaz, yani olcut bos gecer.
GIDIS_DONUS_VAKALARI = [
    {
        "ad": "komut satiri, ters bolulu registry yolu",
        "kolon": "CommandLine",
        "alan": "process.command_line",
        "deger": "reg.exe save HKLM" + BS + "SAM C:" + BS + "Users" + BS
                 + "Public" + BS + "sam.hiv",
    },
    {
        "ad": "kernel gosterimli registry yolu",
        "kolon": "CommandLine",
        "alan": "process.command_line",
        "deger": "reg.exe export " + BS + "REGISTRY" + BS + "MACHINE" + BS
                 + "SAM C:" + BS + "out.reg",
    },
    {
        "ad": "cift tirnakli komut satiri",
        "kolon": "CommandLine",
        "alan": "process.command_line",
        "deger": 'cmd.exe /c "echo merhaba"',
    },
]


def _sema_ici(alanlar: dict) -> set[str]:
    return {a for a in alanlar if not a.startswith("unknown.")}


def olc() -> dict:
    satirlar = try_convert_qradar_export(CSV.read_bytes()) or []
    if len(satirlar) != 51:
        raise SystemExit(f"51 satir bekleniyordu, {len(satirlar)} bulundu")

    kayip: dict[str, int] = {}
    kayip_unknown: dict[str, int] = {}
    bilerek: dict[str, int] = {}
    mask_cozulen = 0
    mask_tasiyan = 0
    yazma_erisimi = 0
    satir_detay = []

    for i, satir in enumerate(satirlar):
        ham = str(satir.get("Message") or "")
        kv = row_to_kv_string(satir)
        a_alan, a_bicim = parse_fields(ham)
        b_alan, b_bicim = parse_fields(kv)

        for ad in set(a_alan) - set(b_alan):
            if ad.startswith("unknown."):
                kayip_unknown[ad] = kayip_unknown.get(ad, 0) + 1
            elif not a_alan[ad].informative:
                # BILEREK kurtarilmayan: degeri '-' / 'N/A' / 'NULL SID'.
                # Ic govde yalnizca BOSLUK DOLDURUR (setdefault) ve boslugu
                # bos bir degerle doldurmak boslugtan kotudur -- decision._alan
                # yalnizca 'N/A'yi yokluk sayiyor, '-' sayilmiyor, yani
                # object.name='-' iyi olan file.path'i GOLGELERDI.
                # Ayri sayilir ki "kayip 0" cumlesi bunu SAKLAMASIN.
                bilerek[ad] = bilerek.get(ad, 0) + 1
            else:
                kayip[ad] = kayip.get(ad, 0) + 1

        # O2/O3 -- yalnizca ham govdesinde maske TASIYAN satirlarda anlamli.
        if "access.mask" in a_alan:
            mask_tasiyan += 1
            b_mask = b_alan.get("access.mask")
            cozum = decode_access_mask(b_mask.text, "Key") if b_mask else None
            if cozum is not None:
                mask_cozulen += 1
            sinif = erisim_sinifi({"parsed_fields": b_alan})
            if sinif == "write":
                yazma_erisimi += 1
            satir_detay.append({
                "id": f"G-{i:03d}",
                "ham_yol_mask": a_alan["access.mask"].text,
                "kv_yol_mask": b_mask.text if b_mask else None,
                "decode": None if cozum is None else sorted(cozum.classes),
                "erisim_sinifi": sinif,
                "a_bicim": a_bicim,
                "b_bicim": b_bicim,
            })

    # O4 -- kacis gidis donusu
    gidis_donus = []
    for vaka in GIDIS_DONUS_VAKALARI:
        kv = row_to_kv_string({"EventID": 4688, vaka["kolon"]: vaka["deger"]})
        alanlar, _ = parse_fields(kv)
        alan = alanlar.get(vaka["alan"])
        cikan = alan.text if alan else None
        gidis_donus.append({
            "ad": vaka["ad"],
            "giren": vaka["deger"],
            "kv": kv,
            "cikan": cikan,
            "korundu": cikan == vaka["deger"],
        })

    return {
        "_aciklama": (
            "Gorev 15 -- KV yolunda sarmalanan Message'in alan kaybi. "
            "Beklenti: docs/beklenti_15_kv_alan_kaybi.md"
        ),
        "kaynak": str(CSV.relative_to(KOK)).replace(BS, "/"),
        "satir": len(satirlar),
        "O1_kaybolan_sema_ici_toplam": sum(kayip.values()),
        "O1_kaybolan_sema_ici": dict(sorted(kayip.items(), key=lambda x: -x[1])),
        "bilerek_kurtarilmayan_toplam": sum(bilerek.values()),
        "bilerek_kurtarilmayan": dict(sorted(bilerek.items(), key=lambda x: -x[1])),
        "kaybolan_unknown_toplam": sum(kayip_unknown.values()),
        "kaybolan_unknown": dict(sorted(kayip_unknown.items(), key=lambda x: -x[1])),
        "O2_mask_cozulen": f"{mask_cozulen}/{mask_tasiyan}",
        "O3_yazma_erisimi": f"{yazma_erisimi}/{mask_tasiyan}",
        "O4_kacis_gidis_donus": gidis_donus,
        "registry_satirlari": satir_detay,
    }


def main() -> int:
    sonuc = olc()
    CIKTI.parent.mkdir(parents=True, exist_ok=True)
    CIKTI.write_text(json.dumps(sonuc, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"kaynak: {sonuc['kaynak']}  ({sonuc['satir']} satir)")
    print()
    print(f"O1  kaybolan sema ici alan (toplam)  : {sonuc['O1_kaybolan_sema_ici_toplam']}")
    for ad, adet in sonuc["O1_kaybolan_sema_ici"].items():
        print(f"      {adet:3d}/51  {ad}")
    print(f"    kaybolan unknown.* (gosterim)    : {sonuc['kaybolan_unknown_toplam']}")
    print(f"    BILEREK kurtarilmayan (deger bos): {sonuc['bilerek_kurtarilmayan_toplam']}")
    for ad, adet in sonuc["bilerek_kurtarilmayan"].items():
        print(f"      {adet:3d}/51  {ad}")
    print(f"O2  decode_access_mask cozulen       : {sonuc['O2_mask_cozulen']}")
    print(f"O3  erisim_sinifi == write           : {sonuc['O3_yazma_erisimi']}")
    print("O4  kacis gidis-donusu:")
    for g in sonuc["O4_kacis_gidis_donus"]:
        print(f"      {'KORUNDU' if g['korundu'] else 'BOZULDU'}  {g['ad']}")
        if not g["korundu"]:
            print(f"                giren: {g['giren']!r}")
            print(f"                cikan: {g['cikan']!r}")
    print()
    print(f"yazildi: {CIKTI.relative_to(KOK)}")

    # -- kapanis olcutleri (beklenti SS4).
    #
    # 'bilerek_kurtarilmayan' O1'e SAYILMAZ ama AYRI BASILIR. Istisnayi
    # sessizce olcutun disina almak, olcutu kendi kendine gecirmek olurdu;
    # gorunur kalirsa bir gun o listeye bilgi tasiyan bir alan dusarse
    # farkedilir.
    basarisiz = []
    if sonuc["O1_kaybolan_sema_ici"]:
        basarisiz.append(
            f"O1: hala kaybolan sema ici alan var: {sonuc['O1_kaybolan_sema_ici']}")
    if sonuc["O2_mask_cozulen"].split("/")[0] != sonuc["O2_mask_cozulen"].split("/")[1]:
        basarisiz.append(f"O2: decode_access_mask {sonuc['O2_mask_cozulen']}")
    if sonuc["O3_yazma_erisimi"].split("/")[0] != sonuc["O3_yazma_erisimi"].split("/")[1]:
        basarisiz.append(f"O3: erisim_sinifi==write {sonuc['O3_yazma_erisimi']}")
    bozuk = [g["ad"] for g in sonuc["O4_kacis_gidis_donus"] if not g["korundu"]]
    if bozuk:
        basarisiz.append(f"O4: kacis gidis-donusu bozuk: {bozuk}")

    if basarisiz:
        print()
        print("KAPANMADI:")
        for b in basarisiz:
            print(f"  - {b}")
        return 1

    print()
    print("Dort olcut de gecti.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
