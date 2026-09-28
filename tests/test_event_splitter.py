"""Olay bolucusunun sozlesmesi (Gorev 14).

BOLUCU NEYE GORE BOLER: kural tablosu app/normalization/formats.py modul
basliginda yazili ve `tests/fixtures/event_split_cases.json` onu ornekle
kilitliyor. Bu dosya fixture'i kosturur + fixture'a yazilamayan iki
degismezi ayrica sinar:

  1. IDEMPOTENS -- bolmenin urettigi bir olay, yeniden bolunurse TEK kalir.
     Bu, hattin "her olay tek-olay yolundan gecer" varsayiminin ta kendisi:
     kirilirsa `decide` ikinci seviyede MultiEventDecisionError atardi ve
     hata bolucude degil karar katmaninda gorunurdu.

  2. KAYIPSIZLIK -- olaylarin icerigi girdinin icinde gecer; bolme metin
     UYDURMAZ ve gorunur icerik DUSURMEZ.

NEDEN OLCUM DOSYASI DEGIL: "bolme gercek QRadar CSV'sinde ne kadar dogru
calisiyor" sorusu Gorev 13'un held-out setine ait (beklenti §5). Burada
olculen sey davranisin SOZLESMESI, kalitesi degil.
"""
from __future__ import annotations

import json
import pathlib

import pytest

from app.normalization.formats import split_events
from tests.private_data import requires_qradar_export

FIXTURE = (
    pathlib.Path(__file__).resolve().parent / "fixtures" / "event_split_cases.json"
)
DATA = json.loads(FIXTURE.read_text(encoding="utf-8"))
VAKALAR = DATA["vakalar"]


def _idler() -> list[str]:
    return [v["id"] for v in VAKALAR]


@pytest.mark.parametrize("vaka", VAKALAR, ids=_idler())
def test_sinir_kurali_fixture_ile_sabit(vaka: dict) -> None:
    sonuc = split_events(vaka["raw"])
    assert len(sonuc.events) == vaka["beklenen_olay"], (
        f"{vaka['id']}: {len(sonuc.events)} olay uretildi, "
        f"{vaka['beklenen_olay']} bekleniyordu (kural: {sonuc.rule})"
    )
    assert sonuc.rule == vaka["beklenen_kural"], (
        f"{vaka['id']}: kural {sonuc.rule}, beklenen {vaka['beklenen_kural']}. "
        "Dogru olay sayisini YANLIS kuralla bulmak, dogru cevap/yanlis sebep."
    )


@pytest.mark.parametrize("vaka", VAKALAR, ids=_idler())
def test_bolunemeyen_durum_sessiz_gecilmiyor(vaka: dict) -> None:
    """Sinir bulunamiyorsa acik uyari; sessiz geri donus yok."""
    sonuc = split_events(vaka["raw"])
    assert bool(sonuc.warning) == vaka["uyari_bekleniyor"], (
        f"{vaka['id']}: uyari={sonuc.warning!r}, "
        f"beklenen uyari_bekleniyor={vaka['uyari_bekleniyor']} "
        f"({sonuc.marker_count} isaret / {len(sonuc.events)} olay)"
    )


@pytest.mark.parametrize("vaka", VAKALAR, ids=_idler())
def test_bolme_IDEMPOTENS(vaka: dict) -> None:
    """Uretilen her olay, yeniden bolunurse TEK kalir.

    Hattin sozlesmesi bu: `run_improved_query` boler ve her parcayi
    `_analyze_event`'e verir; `_analyze_event`'in gordugu sey her zaman tek
    olay olmali."""
    for olay in split_events(vaka["raw"]).events:
        tekrar = split_events(olay)
        assert len(tekrar.events) == 1, (
            f"{vaka['id']}: '{olay[:40]}...' yeniden bolununce "
            f"{len(tekrar.events)} olay verdi (kural: {tekrar.rule})"
        )


@pytest.mark.parametrize("vaka", VAKALAR, ids=_idler())
def test_bolme_metin_UYDURMUYOR(vaka: dict) -> None:
    """Her olay girdinin bir parcasidir.

    JSON dizisi haric: orada ogeler yeniden serilestirilir, o yuzden
    karsilastirma anahtar duzeyinde yapilir."""
    sonuc = split_events(vaka["raw"])
    if sonuc.rule == "json_array":
        for olay in sonuc.events:
            json.loads(olay)  # gecerli JSON uretildi mi
        return
    for olay in sonuc.events:
        assert olay.strip() in vaka["raw"] or not olay.strip()


def test_tek_olayli_girdi_de_LISTE_donuyor() -> None:
    """Cagiran taraf 'bolundu mu' diye dallanmaz.

    Iki kod yolu, bu oturumda uc kez isiran desendir: duzeltme bir yola
    iner, obur yol eski davranisi saklar ve testler yesil kalir."""
    sonuc = split_events("{Event ID=4656, Object Name=\\REGISTRY\\MACHINE\\SAM}")
    assert len(sonuc.events) == 1
    assert sonuc.split is False


def test_bolme_damgasi_normalize_input_ciktisinda() -> None:
    """Damga yazilip okunmuyorsa yok demektir: `decide` bu alani okuyor."""
    from app.normalization.input_parser import normalize_input

    tek = normalize_input("{Event ID=4656, Object Name=\\REGISTRY\\MACHINE\\SAM}")
    assert tek["split"]["event_count"] == 1

    cok = normalize_input(
        "{Event ID=4657, Process Name=a.exe}\n{Event ID=4624, Account Name=SYSTEM}"
    )
    assert cok["split"]["event_count"] == 2
    assert cok["split"]["rule"] == "brace_blocks"


@requires_qradar_export
def test_isaret_sayaci_gercek_QRadar_satirinda_yanlis_alarm_vermiyor() -> None:
    """OLCULDU: bir QRadar satiri ayni olayi IKI kodlamada tasiyor.

    Duz sayim 51/51 satirda uyari basiyordu. Her satirda yanan bir uyari,
    uyari degil gurultudur ve okunmamayi ogretir -- bu yuzden sayac bolge
    basina sayar."""
    import pandas as pd

    from app.batch.serialize import rows_to_batch_items

    csv = pathlib.Path(__file__).resolve().parent / "fixtures" / "qradar_2026-08-06_51rows.csv"
    df = pd.read_csv(csv, header=None, dtype=str)
    df.columns = [f"c{i}" for i in range(len(df.columns))]
    items = [it for it in rows_to_batch_items(df.to_dict("records")) if not it["skipped"]]
    assert items, "CSV fixture bos okundu"

    sonuclar = [split_events(it["raw_log"]) for it in items]
    uyarili = [s for s in sonuclar if s.warning]
    bolunen = [s for s in sonuclar if s.split]
    assert not uyarili, f"{len(uyarili)}/{len(sonuclar)} satirda yanlis uyari"
    assert not bolunen, f"{len(bolunen)}/{len(sonuclar)} satir yanlis bolundu"


def test_mevcut_olcum_setleri_KIMILDAMIYOR() -> None:
    """60 senaryo ve dort probe logu tek olay uretmeli.

    Aksi halde gecmis olcumler (katmanli sorgu D kolu, dedup, ablasyonlar)
    karsilastirilamaz hale gelirdi ve bu, duzeltmenin gorunmeyen maliyeti
    olurdu."""
    kok = pathlib.Path(__file__).resolve().parents[1]

    senaryolar = json.loads(
        (kok / "evaluation" / "test_scenarios.json").read_text(encoding="utf-8")
    )
    bolunen = [
        s["test_id"] for s in senaryolar if split_events(s["input"]).split
    ]
    assert not bolunen, f"60 senaryonun {len(bolunen)}'i bolundu: {bolunen}"

    probe = json.loads(
        (kok / "tests" / "fixtures" / "registry_object_access_logs.json").read_text(
            encoding="utf-8"
        )
    )
    for log in probe["logs"]:
        assert not split_events(log["raw"]).split, f"probe {log.get('id')} bolundu"


def test_multi_010_bolunemedigi_icin_UYARI_veriyor() -> None:
    """Gercek pozitif korunuyor: 60 senaryodaki tek cok olayli girdi.

    'EventID=4688 ... followed by EventID=4688 ...' tek satirda iki olay ve
    bolunecek bir sinir YOK. Sayac bunu yakalayip uyariyor; yakalayamasaydi
    isaret sayaci yalnizca gurultuyu susturmus olurdu."""
    kok = pathlib.Path(__file__).resolve().parents[1]
    senaryolar = json.loads(
        (kok / "evaluation" / "test_scenarios.json").read_text(encoding="utf-8")
    )
    multi_010 = next(s for s in senaryolar if s["test_id"] == "multi-010")

    sonuc = split_events(multi_010["input"])
    assert len(sonuc.events) == 1
    assert sonuc.warning, "bolunemeyen cok olayli girdi sessiz gecti"
    assert sonuc.marker_count == 2
