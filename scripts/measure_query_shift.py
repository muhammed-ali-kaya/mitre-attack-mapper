"""Gorev 15 -- ayristirma duzeltmesi SORGUYU kac satirda degistirdi?

    .venv/Scripts/python.exe scripts/measure_query_shift.py

NEDEN GEREKLI
    G kolunun yeniden kosusunda 51 satirin 35'inde teknik listesi degisti.
    Bu sayi TEK BASINA "sorgu degisti, retrieval degisti" diye okunamaz:
    kosular tek gecis ve teknik ekseninin VARYANSI hic olculmedi
    (docs/sonuc_13_g_kolu.md SS5 bunu acikca yaziyor). Yani 35, sorgu
    degisimi + kosudan kosuya varyansin TOPLAMIDIR.

    Bu betik toplamin sorgu bilesenini AYIRIR ve bunu LLM'siz, deterministik
    olarak yapar: ayni girdiler icin build_layered_query'nin ciktisi eski ve
    yeni ayristirma altinda karsilastirilir.

    Ustteki sinir mantigi: sorgusu DEGISMEYEN bir satirda teknik listesinin
    degismesi yalnizca varyansla aciklanabilir.

ESKI AYRISTIRMA NASIL TAKLIT EDILIYOR
    Uc duzeltme de geri alinir (K-A yuvalama, K-B kacis, K-C etiket siniri).
    Kod kopyalanmiyor; mevcut mekanizmalar gecici olarak kapatiliyor.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys

KOK = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KOK))

import app.normalization.formats as F  # noqa: E402
from app.batch.qradar_adapter import try_convert_qradar_export  # noqa: E402
from app.batch.serialize import row_to_kv_string  # noqa: E402

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

CSV = KOK / "tests" / "fixtures" / "qradar_2026-08-06_51rows.csv"
CIKTI = KOK / "evaluation" / "results" / "query_shift.json"

ESKI_ETIKET_RE = re.compile(r"(?:^|(?<=\s\s)|(?<=\n))([A-Z][A-Za-z ]{2,28}?):[ \t]+")


def _sorgular(satirlar: list[dict]) -> list[dict]:
    # Import BURADA: input_parser modul yuklenirken _MESSAGE_LABEL_RE'yi
    # okuyor, yani yamadan sonra yuklenmeli.
    from app.normalization.input_parser import (
        build_layered_query, discriminating_fields, normalize_input,
    )
    out = []
    for satir in satirlar:
        ham = row_to_kv_string(satir)
        n = normalize_input(ham)
        sorgu = build_layered_query(ham, n, include_raw=True)
        out.append({
            "sorgu": sorgu,
            "katman1": " ".join(
                d for _, d in discriminating_fields(n.get("parsed_fields") or {})
            ),
            # 3. katman ham metindir ve DEGISMEZ (row_to_kv_string'e
            # dokunulmadi); farkin 1./2. katmandan geldigini gostermek icin
            # ayrica tutuluyor.
            "katman12": sorgu[: sorgu.rfind(ham)] if ham in sorgu else sorgu,
        })
    return out


def main() -> int:
    satirlar = try_convert_qradar_export(CSV.read_bytes()) or []
    if len(satirlar) != 51:
        raise SystemExit(f"51 satir bekleniyordu, {len(satirlar)} bulundu")

    yeni = _sorgular(satirlar)

    # --- eski ayristirmayi taklit et -------------------------------------
    asil_etiket = F._MESSAGE_LABEL_RE
    asil_unescape = F.unescape_serialized
    asil_nested = F._yuvalanmis_govdeleri_coz

    F._MESSAGE_LABEL_RE = ESKI_ETIKET_RE                 # K-C geri
    F.unescape_serialized = lambda v: v                  # K-B geri
    F._yuvalanmis_govdeleri_coz = lambda alanlar, sema: alanlar   # K-A geri
    F.load_schema.__globals__["_SCHEMA_CACHE"] = None
    try:
        import app.normalization.input_parser as IP
        asil_ip_re = IP.MESSAGE_FIELD_RE
        IP.MESSAGE_FIELD_RE = ESKI_ETIKET_RE
        IP._unquote.__globals__["unescape_serialized"] = lambda v: v
        eski = _sorgular(satirlar)
    finally:
        F._MESSAGE_LABEL_RE = asil_etiket
        F.unescape_serialized = asil_unescape
        F._yuvalanmis_govdeleri_coz = asil_nested
        IP.MESSAGE_FIELD_RE = asil_ip_re
        IP._unquote.__globals__["unescape_serialized"] = asil_unescape

    degisen = [i for i in range(51) if eski[i]["sorgu"] != yeni[i]["sorgu"]]
    k1_degisen = [i for i in range(51) if eski[i]["katman1"] != yeni[i]["katman1"]]
    k12_degisen = [i for i in range(51) if eski[i]["katman12"] != yeni[i]["katman12"]]

    print("=" * 74)
    print("SORGU KAYMASI -- 51 QRadar satiri, LLM'siz, deterministik")
    print("=" * 74)
    print(f"  sorgusu degisen satir      : {len(degisen)}/51")
    print(f"  1. katmani degisen satir   : {len(k1_degisen)}/51")
    print(f"  1.+2. katmani degisen satir: {len(k12_degisen)}/51")
    print()
    print("  ornek (ilk 3 degisen satirin 1. katmani):")
    for i in degisen[:3]:
        print(f"    G-{i:03d}")
        print(f"       eski k1: {(eski[i]['katman1'] or '')[:96]!r}")
        print(f"       yeni k1: {(yeni[i]['katman1'] or '')[:96]!r}")

    sonuc = {
        "_aciklama": (
            "Ayristirma duzeltmesinin SORGU uzerindeki etkisi. G kolundaki "
            "teknik degisiminin sorgu bilesenini varyanstan ayirmak icin."
        ),
        "satir": 51,
        "sorgusu_degisen": [f"G-{i:03d}" for i in degisen],
        "katman1_degisen": [f"G-{i:03d}" for i in k1_degisen],
        "katman12_degisen": [f"G-{i:03d}" for i in k12_degisen],
    }
    CIKTI.parent.mkdir(parents=True, exist_ok=True)
    CIKTI.write_text(json.dumps(sonuc, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nyazildi: {CIKTI.relative_to(KOK)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
