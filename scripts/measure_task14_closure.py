"""Gorev 14'un UC KAPANIS KRITERINI olcer ve ayrica bolmenin YAN ETKISINI.

Testlerin yesil olmasi "acik kapandi" demek DEGILDIR: test, kendi baktigi
yolu gosterir. Bu betik kriterleri kaydin kendi dilinde (fixture'daki
`_kapanis_kriteri`) tek tek olcup yazar, ve ayrica bolmenin MEVCUT olcum
setlerini kimildatip kimildatmadigini raporlar -- ikincisi olculmezse
"duzeltme gecmis olcumleri gecersiz kildi mi" sorusu cevapsiz kalir.

LLM ve indeks GEREKMEZ: uc kriter de deterministik katmanlarda.

    python scripts/measure_task14_closure.py

Cikis kodu: kriterlerden biri saglanmiyorsa 1.
"""
from __future__ import annotations

import json
import pathlib
import sys

KOK = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KOK))

from app.agents.verification import (  # noqa: E402
    SOURCE_ROW_KEY,
    UnattributedMappingError,
    evidence_gate_decisions,
)
from app.mapping.text_input import text_to_row  # noqa: E402
from app.normalization.formats import split_events  # noqa: E402
from app.validation.decision import decide_alarm  # noqa: E402

FIXTURE = KOK / "tests" / "fixtures" / "merge_vulnerability_logs.json"
DATA = json.loads(FIXTURE.read_text(encoding="utf-8"))
VAKA = {v["id"]: v for v in DATA["vakalar"]}


def _olaylar(vaka_id: str) -> dict[str, dict]:
    return {o["ad"]: o for o in VAKA[vaka_id]["olaylar"]}


def _mapping(teknik: str, satir: int | None = None) -> dict:
    m = {"attack_id": teknik, "name": "x", "tactics": [], "confidence_level": "medium"}
    if satir is not None:
        m[SOURCE_ROW_KEY] = satir
    return m


def _kapi(teknik: str, satirlar: list[str], kaynak: int | None = None) -> str | None:
    kararlar = evidence_gate_decisions(
        [_mapping(teknik, kaynak)], [text_to_row(s) for s in satirlar]
    )
    if not kararlar:
        return None
    return getattr(kararlar[0].verdict, "value", kararlar[0].verdict)


def _satir(ad: str, once: str, simdi: str, hedef: str) -> bool:
    gecti = simdi == hedef
    print(f"  {'GECTI ' if gecti else 'KALDI '} {ad:<12} once={once:<22} "
          f"simdi={simdi:<22} hedef={hedef}")
    return gecti


def olc_bastirma() -> bool:
    vaka = VAKA["V-BASTIRMA"]
    o = _olaylar("V-BASTIRMA")
    tekil = [decide_alarm(o[ad]["raw"]).decision for ad in ("EV1", "EV2")]
    birlesik = decide_alarm(o["EV1"]["raw"] + "\n" + o["EV2"]["raw"]).decision
    print(f"     tek tek: EV1={tekil[0]}  EV2={tekil[1]}")
    return _satir(
        "V-BASTIRMA", vaka["birlesik_bugunku_cikti"], birlesik, vaka["birlesik_beklenen"]
    )


def olc_eleme() -> bool:
    vaka = VAKA["V-ELEME"]
    o = _olaylar("V-ELEME")
    metin, logon = o["METIN"]["raw"], o["LOGON"]["raw"]
    yalniz = _kapi(vaka["teknik"], [metin])
    birlesik = _kapi(vaka["teknik"], [metin, logon], kaynak=0)
    print(f"     METIN yalniz: {yalniz}")
    return _satir(
        "V-ELEME", vaka["birlesik_bugunku_kapi"], str(birlesik),
        vaka["birlesik_beklenen_kapi"],
    )


def olc_atif() -> bool:
    """Her bulgu YALNIZCA kendi kaynak satirini kanit sayiyor mu?"""
    o = _olaylar("V-CAPRAZ")
    satirlar = [o["METIN"]["raw"], o["SAM"]["raw"]]
    metinden = _kapi("T1003.002", satirlar, kaynak=0)
    samdan = _kapi("T1003.002", satirlar, kaynak=1)

    atifsiz_hata = False
    try:
        evidence_gate_decisions([_mapping("T1003.002")], [text_to_row(s) for s in satirlar])
    except UnattributedMappingError:
        atifsiz_hata = True

    print(f"     kaynak=METIN -> {metinden}   kaynak=SAM -> {samdan}   "
          f"atifsiz cagri hata veriyor: {atifsiz_hata}")
    gecti = metinden == "abstain" and samdan == "confirm" and atifsiz_hata
    return _satir(
        "V-ATIF", "range(len(rows)) — her satir",
        "yalnizca kaynak satir" if gecti else "eksik", "yalnizca kaynak satir",
    )


def olc_yan_etki() -> None:
    """Bolme MEVCUT olcum setlerini kimildatiyor mu?"""
    print("\nYAN ETKI — bolme gecmis olcumleri kimildatiyor mu?")

    senaryolar = json.loads(
        (KOK / "evaluation" / "test_scenarios.json").read_text(encoding="utf-8")
    )
    kumeler: list[tuple[str, list[tuple[str, str]]]] = [
        ("60 senaryo", [(s["test_id"], s["input"]) for s in senaryolar]),
    ]

    probe = json.loads(
        (KOK / "tests" / "fixtures" / "registry_object_access_logs.json").read_text(
            encoding="utf-8"
        )
    )
    kumeler.append(
        ("probe loglari", [(l.get("id", "?"), l["raw"]) for l in probe["logs"]])
    )

    try:
        import pandas as pd

        from app.batch.serialize import rows_to_batch_items

        df = pd.read_csv(
            KOK / "tests" / "fixtures" / "qradar_2026-08-06_51rows.csv",
            header=None, dtype=str,
        )
        df.columns = [f"c{i}" for i in range(len(df.columns))]
        items = [it for it in rows_to_batch_items(df.to_dict("records")) if not it["skipped"]]
        kumeler.append(
            ("QRadar CSV satirlari", [(str(i), it["raw_log"]) for i, it in enumerate(items)])
        )
    except Exception as e:  # pandas yoksa olcumun geri kalani yine anlamli
        print(f"  (QRadar CSV okunamadi: {e})")

    for ad, girdiler in kumeler:
        sonuclar = [(k, split_events(h)) for k, h in girdiler]
        bolunen = [k for k, s in sonuclar if s.split]
        uyarili = [(k, s.marker_count) for k, s in sonuclar if s.warning]
        print(f"  {ad:<22} n={len(sonuclar):<4} bolunen={len(bolunen)}  "
              f"uyarili={len(uyarili)}")
        for k in bolunen:
            print(f"      BOLUNDU: {k}")
        for k, n in uyarili:
            print(f"      UYARI  : {k} ({n} isaret, bolunemedi)")


def main() -> int:
    print("GOREV 14 — KAPANIS OLCUMU")
    print("kayit:", FIXTURE.relative_to(KOK))
    print("\nUC KRITER (ucu birden gecmeden acik KAPANMIS SAYILMAZ):")
    sonuclar = [olc_bastirma(), olc_eleme(), olc_atif()]
    olc_yan_etki()

    hepsi = all(sonuclar)
    print("\nSONUC:", "ACIK KAPANDI" if hepsi else "ACIK HALA ACIK")
    return 0 if hepsi else 1


if __name__ == "__main__":
    raise SystemExit(main())
