"""config/rule_field_map.yaml sozlesmesi.

NEDEN VAR: tablo 2B'nin ilk teslimi ve TASIMA KODUNDAN ONCE yaziliyor.
Kod tabloyu okuyacak; tablo eksik ya da uydurma alan adi tasiyorsa
tasima sessizce yanlis calisir.

Bu dosya tabloyu KURAL DOSYASINA ve SEMAYA karsi dogrular:
  - her kosulun bir satiri var mi (57/57)
  - her hedef alan field_schema.yaml'da GERCEKTEN var mi
  - KANITSIZ satirlar alan adi UYDURMUYOR mu
"""
from __future__ import annotations

import pathlib

import pytest
import yaml

PROJE = pathlib.Path(__file__).resolve().parents[1]


def _yukle(yol: str):
    return yaml.safe_load((PROJE / yol).read_text(encoding="utf-8"))


HARITA = _yukle("config/rule_field_map.yaml")["kosullar"]
SEMA = set(_yukle("config/field_schema.yaml")["fields"])
KURALLAR = _yukle("rules/attack_mappings.yaml")["techniques"]

GECERLI_SINIFLAR = {"T", "KARMA", "S", "KANITSIZ"}
# Semada olmayan ama MESRU hedefler. IKI FARKLI SEY birbirinden ayrilir:
#
#   TABLODAKI `hedef`  = kosulun NEREYE AIT OLDUGU (niyet). `event_semantics`
#                        burada mesrudur: S sinifinin nihai varis yeri odur.
#   KURAL DOSYASINDAKI `field` = satirdan OKUNACAK anahtar (gercek). Orada
#                        yalnizca satirda var olan bir ad bulunabilir; bugun
#                        tasinmayan kollar `Message`'da bekler.
#
# Ayrimi karistirmak olculmus bir hataydi: T1070.001'in anlati kolu kural
# dosyasina `field: event_semantics` diye yazildi, satirda oyle bir anahtar
# olmadigi icin SESSIZCE hic eslesmedi (rawlog-009). Niyet dogruydu, yazildigi
# yer yanlisti.
ALAN_OLMAYAN = {"Message", "event_semantics"}


def _kural_kosullari() -> list[tuple[str, str]]:
    """(teknik, TABLODAKI desen) ciftleri.

    KARMA satirlar tasindiktan sonra kural dosyasinda `any_of` olarak
    duruyor ve ust seviyede must_match tasimiyorlar; onlarin tablodaki
    karsiligi ORIJINAL desendir. Eslestirme bu yuzden alt kollari birlestirip
    tablodaki `bolme` ile karsilastirir, ham desenle degil."""
    ciftler = []
    for r in KURALLAR:
        for fc in (r.get("field_conditions") or []):
            if "any_of" in fc:
                kollar = tuple(
                    (str(a.get("field")), str(a.get("must_match") or a.get("must_not_match")))
                    for a in fc["any_of"]
                )
                ciftler.append((r["technique_id"], kollar))
            else:
                ciftler.append(
                    (r["technique_id"], str(fc.get("must_match") or fc.get("must_not_match") or ""))
                )
    return ciftler


def _harita_kosullari() -> list[tuple[str, object]]:
    """Tablonun kural dosyasinda ne URETMESI gerektigi."""
    ciftler = []
    for s in HARITA:
        if s["sinif"] == "KARMA":
            ciftler.append((s["teknik"], tuple(
                (p["alan"], p["desen"]) for p in s["bolme"])))
        elif s["sinif"] == "T" and isinstance(s.get("hedef"), list):
            # Ayni desen, birden cok aday alan -> any_of
            ciftler.append((s["teknik"], tuple(
                (a, s["desen"]) for a in s["hedef"])))
        else:
            ciftler.append((s["teknik"], s["desen"]))
    return ciftler


def test_every_rule_condition_has_a_row():
    """57/57. Eksik satir, tasinmadan atlanan bir kosul demektir."""
    kosullar = _kural_kosullari()
    haritadaki = set(_harita_kosullari())
    eksik = [c for c in kosullar if c not in haritadaki]
    assert not eksik, f"haritada satiri olmayan kosul: {eksik}"
    assert len(HARITA) == len(kosullar), (
        f"harita {len(HARITA)} satir, kural dosyasinda {len(kosullar)} kosul var"
    )


def test_no_orphan_rows():
    """Kural dosyasindan silinen bir kosulun satiri haritada kalmamali."""
    kosullar = set(_kural_kosullari())
    artik = [c for c in _harita_kosullari() if c not in kosullar]
    assert not artik, f"kural dosyasinda karsiligi olmayan satir: {artik}"


@pytest.mark.parametrize("satir", HARITA, ids=lambda s: f"{s['teknik']}:{s['sinif']}")
def test_class_is_known(satir):
    assert satir["sinif"] in GECERLI_SINIFLAR


@pytest.mark.parametrize("satir", HARITA, ids=lambda s: f"{s['teknik']}:{s['sinif']}")
def test_target_field_exists_in_schema(satir):
    """UYDURMA ALAN ADI YAKALAYICI.

    Bu testin varlik sebebi olculdu: uc kosul semada olmayan alanlar
    ariyor (dns.question.name, auth.package, ticket.encryption) ve o
    alanlarin GERCEK yazimini gosteren tek bir log ornegi yok. Tahminle
    sema buyutmek yasak; o satirlar KANITSIZ ve hedef=None olmali."""
    hedefler = satir.get("hedef")
    if satir["sinif"] == "KANITSIZ":
        assert hedefler is None, (
            f"{satir['teknik']}: KANITSIZ satir hedef alan BELIRTEMEZ -- "
            f"gercek log ornegi olmadan alan adi tahmindir"
        )
        assert satir.get("onerilen_alan_adayi"), (
            f"{satir['teknik']}: aday alan adi yazilmali (baglami kaybetmemek icin)"
        )
        return

    assert hedefler is not None, f"{satir['teknik']}: hedef alan bos"
    if isinstance(hedefler, str):
        hedefler = [hedefler]
    for h in hedefler:
        assert h in SEMA or h in ALAN_OLMAYAN, (
            f"{satir['teknik']}: '{h}' field_schema.yaml'da YOK"
        )


@pytest.mark.parametrize(
    "satir", [s for s in HARITA if s["sinif"] == "KARMA"],
    ids=lambda s: s["teknik"],
)
def test_mixed_conditions_declare_their_split(satir):
    """KARMA = tek desen iki seyi ariyor. Nasil BOLUNECEGI yazili olmali,
    yoksa tasima sirasinda karar yeniden verilir ve gerekce kaybolur."""
    bolme = satir.get("bolme")
    assert bolme and len(bolme) >= 2, f"{satir['teknik']}: bolme tanimlanmamis"
    hedefler = satir["hedef"]
    for parca in bolme:
        assert parca["alan"] in hedefler, (
            f"{satir['teknik']}: bolme alani '{parca['alan']}' hedef listesinde yok"
        )
        assert parca.get("desen"), f"{satir['teknik']}: bolme deseni bos"


@pytest.mark.parametrize("satir", HARITA, ids=lambda s: s["teknik"])
def test_every_row_states_a_reason(satir):
    """Alti ay sonra bakan biri KARARIN GEREKCESINI gormeli.

    Gerekcesiz bir satir, 'buraya neden bu alan yazilmis' sorusunu
    cevapsiz birakir ve tasima sirasinda yeniden tartisilir."""
    gerekce = (satir.get("gerekce") or "").strip()
    assert len(gerekce) >= 40, f"{satir['teknik']}: gerekce yok ya da cok kisa"


def _kurallarda_gecen_alanlar() -> set[str]:
    adlar: set[str] = set()

    def gez(fc: dict):
        if "any_of" in fc:
            for alt in fc["any_of"]:
                gez(alt)
        elif "field" in fc:
            adlar.add(str(fc["field"]))

    for r in KURALLAR:
        for fc in (r.get("field_conditions") or []):
            gez(fc)
    return adlar


def test_no_rule_names_a_field_the_row_will_never_have():
    """SESSIZ BASARISIZLIK KORUYUCUSU -- olculmus vaka.

    Ilk tasimada T1070.001'in anlati kolu `field: event_semantics` aldi.
    event_semantics bir SATIR ALANI degil, ayri bir tablo. Satirda oyle bir
    anahtar olmadigi icin `row.get()` None doner, desen bos dizede aranir,
    kol HIC eslesmez -- ve hicbir sey hata vermez. rawlog-009'da atesleme
    kayboldu ve sebebi ilk bakista 'tasima calisti' gibi gorundu.

    Sartname: hicbir katman sessizce geri dusmesin. Kural bir alan adi
    yaziyorsa, o alan satirda GERCEKTEN uretilebiliyor olmali."""
    from app.mapping.text_input import text_to_row

    # Zengin bir ornek: yapisal alanlarin cogunu ureten bir log.
    ornek_satir = text_to_row(
        r"EventID=4688 NewProcessName=C:\Windows\System32\reg.exe "
        r"CommandLine=reg.exe save HKLM\SAM C:\Users\Public\sam.hive "
        r"SubjectUserName=admin.svc ObjectName=\REGISTRY\MACHINE\SAM"
    )
    # Satirin URETEBILECEGI anahtarlar: semadaki her sey + legacy + Message.
    uretilebilir = SEMA | set(ornek_satir) | {"Message", "EventID"}

    hayali = sorted(a for a in _kurallarda_gecen_alanlar() if a not in uretilebilir)
    assert not hayali, (
        f"kurallar satirda HIC olusmayacak alan adlari kullaniyor: {hayali}\n"
        f"bunlar sessizce eslesmez -- ya alan uretilmeli ya kosul Message'da kalmali"
    )


def test_firing_counts_are_recorded():
    """Atesleme sayisi OLCULEBILIR bir kolon ve her satirda olmali.

    atesleme_60 = 0 olan satirin tasinmasi TEST EDILEMEZ; kabul
    kriterinde ayri sayilmasi icin once kaydedilmesi gerekiyor."""
    for s in HARITA:
        assert "atesleme_60" in s, f"{s['teknik']}: atesleme_60 kolonu yok"
        assert isinstance(s["atesleme_60"], int)
        assert "olay_id_veride_var" in s, f"{s['teknik']}: olay_id kolonu yok"
