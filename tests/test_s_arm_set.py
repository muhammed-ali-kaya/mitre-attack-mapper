"""S kolunun (Gorev 13) sozlesmelerini kilitler.

Uretici script bu kontrolleri zaten yapiyor; buradaki testler URETILMIS
JSON'a bakiyor. Sebep: sadelestirmede `coverage.py` TESTI OLMADIGI icin
sessizce silinmisti. Bir sozlesme yalnizca uretim aninda kontrol ediliyorsa,
dosyayi elle duzenleyen biri onu sessizce bozabilir.

Beklenti: docs/beklenti_13_s_kolu.md
"""

from __future__ import annotations

import collections
import json
import pathlib

import pytest

KOK = pathlib.Path(__file__).resolve().parents[1]
SET = KOK / "evaluation" / "s_arm_set.json"

YAZMA_MASKESI = "0x2001F"


@pytest.fixture(scope="module")
def kayitlar() -> list[dict]:
    return json.loads(SET.read_text(encoding="utf-8"))["kayitlar"]


def test_kayit_sayisi_ve_essiz_id(kayitlar):
    assert len(kayitlar) >= 60
    assert len({k["id"] for k in kayitlar}) == len(kayitlar)


def test_b1_uc_ayri_anahtarda_ve_kararlari_farkli(kayitlar):
    """B1 baglayici sarti (beklenti §2). Tek anahtardaki fark o anahtarin
    kazasi olabilir; uc anahtar bunu ayirir."""
    ciftler: dict[str, dict[str, dict]] = collections.defaultdict(dict)
    for k in kayitlar:
        if k.get("b1_pair"):
            ciftler[k["b1_pair"]][k["b1_half"]] = k

    assert len(ciftler) >= 3, "B1 uc ayri kritik anahtarda tekrarlanmali"
    for ad, yarim in ciftler.items():
        assert set(yarim) == {"A", "B"}, f"{ad}: iki yarim da gerekli"
        assert yarim["A"]["event_id"] == "4656", f"{ad}: A yarisi TALEP olmali"
        assert yarim["B"]["event_id"] in ("4663", "4657"), \
            f"{ad}: B yarisi GERCEKLESEN erisim olmali"
        assert yarim["A"]["expected_decision"] != yarim["B"]["expected_decision"], \
            f"{ad}: ayni karar beklenen bir cift ayirt etme gucunu olcemez"


def test_b1_cifti_tek_degiskenli(kayitlar):
    """Anahtar, aktor, surec ve maske ayni; YALNIZCA olay ID degisir.
    Ikinci bir alan da degisirse sonucun sebebi ayrilamaz."""
    ciftler: dict[str, dict[str, dict]] = collections.defaultdict(dict)
    for k in kayitlar:
        if k.get("b1_pair"):
            ciftler[k["b1_pair"]][k["b1_half"]] = k

    for ad, yarim in ciftler.items():
        for alan in ("REGISTRY", "svchost.exe", YAZMA_MASKESI):
            assert alan in yarim["A"]["input"], f"{ad}/A: {alan} yok"
            assert alan in yarim["B"]["input"], f"{ad}/B: {alan} yok"


def test_bilinen_kusurun_dozu_tam_uc(kayitlar):
    """4656 + yazma maskesi + kritik anahtar ucluSU BILINEN yanlis alarm
    kaynagidir (Gorev 16). Serbest birakilirsa S'in yanlis alarm orani
    sistemi degil, o tek kusurun sikligini olcer."""
    doz = [k for k in kayitlar
           if k["event_id"] == "4656" and YAZMA_MASKESI in k["input"]]
    assert len(doz) == 3, f"doz siniri: tam 3 bekleniyor, {len(doz)} var"


def test_negatif_ornek_orani(kayitlar):
    negatif = sum(1 for k in kayitlar if k["negative_case"])
    assert negatif / len(kayitlar) >= 0.20


def test_beklenen_cift_actor_baseline_ile_eslesiyor(kayitlar):
    """EK-2'nin beklenen yarisi tabloyla eslesmezse bastirma tetiklenmez ve
    BENIGN beklentisi OLCULEN SEYLE ILGISIZ bir sebepten tutmaz."""
    yaml = pytest.importorskip("yaml")
    tablo = yaml.safe_load(
        (KOK / "config" / "actor_baseline.yaml").read_text(encoding="utf-8"))
    surecler, hesaplar = set(), set()
    for cift in tablo.get("beklenen_ciftler") or []:
        surecler |= {s.lower() for s in cift.get("surecler") or []}
        hesaplar |= {h.lower() for h in cift.get("hesaplar") or []}

    beklenen = [k for k in kayitlar if k["id"] in ("S-EK2-01", "S-EK2-02")]
    assert len(beklenen) == 2
    for k in beklenen:
        govde = k["input"].lower()
        assert any(f"\\{s}" in govde for s in surecler), f"{k['id']}: surec eslesmiyor"
        assert any(f"account name:  {h}" in govde for h in hesaplar), \
            f"{k['id']}: hesap eslesmiyor"


def test_ayni_aktor_iki_yonlu_kullanilmis(kayitlar):
    """EK-2 IKI YONLU olmali: yalniz beklenen konursa kor nokta gorulmez,
    yalniz beklenmeyen konursa yanlis alarm orani olculmez."""
    idler = {k["id"]: k for k in kayitlar}
    for beklenen_id in ("S-EK2-01", "S-EK2-02"):
        assert idler[beklenen_id]["expected_decision"] == "SUFFICIENT_BENIGN"
    for beklenmeyen_id in ("S-EK2-03", "S-EK2-04"):
        assert idler[beklenmeyen_id]["expected_decision"] == "SUFFICIENT_SUSPICIOUS"
        assert "trustedinstaller" in idler[beklenmeyen_id]["input"].lower(), \
            "beklenmeyen yarim AYNI aktoru tasimali -- bastirma anahtari (aile, aktor) ciftidir"


def test_hat_kosulmadan_etiketlendi(kayitlar):
    """Disiplin kurali: beklenen cevaplar hat calistirilmadan yazilir."""
    assert all(k.get("labeled_without_running_pipeline") for k in kayitlar)
    assert all(k.get("attack_source") for k in kayitlar)


def test_olay_id_zarfi_var(kayitlar):
    """Ham Windows govdesi olay ID tasimaz; toplayici zarfi tasir. Zarfsiz
    yazilan bir set 'daha ham' degil, uretimde hic gorulmeyen bir bicimdir."""
    for k in kayitlar:
        assert f"EventID={k['event_id']}" in k["input"], k["id"]
