"""ATT&CK indirme betiginin SURUM SOZLESMESI.

Neden bu testler var: betik eskiden surumsuz `enterprise-attack.json`
adresini cekiyordu ve o adres MITRE'nin o anki en son surumunu dondurur.
2026-08-05'te 19.2'ye gecti; yani veri hattini yeniden calistirmak, kimse
istemeden bilgi tabanini baska bir surume tasiyabiliyordu. Uc sey kilitleniyor:

  1. adres surume sabitleniyor,
  2. indirilen bundle'in KENDI surumu istenenle karsilastiriliyor,
  3. uyusmazlikta HICBIR DOSYA YAZILMIYOR.

Ucuncusu en onemlisi ve eski davranisin asil kusuruydu: indirilen icerik
dogrulanmadan once uretim dosyasinin uzerine yaziliyordu. Bu testler ag'a
cikmaz; dogrulama mantigini saf fonksiyonlar uzerinden sinar.
"""

from __future__ import annotations

import json

import pytest

from scripts.download_attack_data import (
    DEFAULT_ATTACK_VERSION,
    VersionMismatch,
    build_metadata,
    build_source_url,
    extract_attack_version,
    resolve_source_url,
    verify_version,
)


def _bundle(version: str | None) -> dict:
    """x-mitre-collection tasiyan asgari bir STIX bundle."""
    koleksiyon: dict = {"type": "x-mitre-collection", "name": "Enterprise ATT&CK"}
    if version is not None:
        koleksiyon["x_mitre_version"] = version
    return {"type": "bundle", "objects": [koleksiyon, {"type": "attack-pattern"}]}


# ------------------------------------------------------------ surumlu adres

def test_url_surume_sabitlenir():
    assert build_source_url("19.1").endswith("/enterprise-attack-19.1.json")
    assert build_source_url("19.2").endswith("/enterprise-attack-19.2.json")


def test_url_resmi_mitre_deposunu_gosterir():
    url = build_source_url("19.2")
    assert url.startswith(
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    )


def test_surumsuz_adres_artik_uretilmiyor():
    """Asil gerileme testi: hicbir surum icin surumsuz dosya adi cikmamali."""
    for surum in ("19.1", "19.2", "7.2"):
        assert not build_source_url(surum).endswith("/enterprise-attack.json")


@pytest.mark.parametrize("gecersiz", ["", "latest", "master", "19", "19.1.1", "../gizli", "19.x"])
def test_gecersiz_surum_bicimi_reddedilir(gecersiz):
    """Surum yol parcasina giriyor; serbest dize adresi baska dosyaya kaydirir."""
    with pytest.raises(ValueError):
        build_source_url(gecersiz)


# ------------------------------------------------------- varsayilan davranis

def test_varsayilan_surum_en_son_degil_uretim_surumudur():
    """Argumansiz calistirma mevcut veriyi yeniden uretmeli, surum atlatmamali."""
    assert DEFAULT_ATTACK_VERSION == "19.2"
    assert resolve_source_url(DEFAULT_ATTACK_VERSION, env={}).endswith(
        "/enterprise-attack-19.2.json"
    )


def test_ortam_degiskeni_adresi_ezer_ama_dogrulamayi_ezmez():
    """ATTACK_STIX_URL destegi korundu (yerel ayna), ama bir ATLATMA degil:
    surum karsilastirmasi yine kosar (bkz. asagidaki uyusmazlik testleri)."""
    ayna = "http://localhost:8080/enterprise-attack-19.1.json"
    assert resolve_source_url("19.1", env={"ATTACK_STIX_URL": ayna}) == ayna


# --------------------------------------------------------- surum dogrulamasi

def test_istenen_ile_bundle_ayniysa_gecer():
    assert verify_version("19.1", "19.1", "http://ornek") is None


def test_uyusmazlik_hata_verir():
    with pytest.raises(VersionMismatch) as hata:
        verify_version("19.1", "19.2", "http://ornek")
    mesaj = str(hata.value)
    assert "19.1" in mesaj and "19.2" in mesaj
    assert "Hicbir dosya yazilmadi" in mesaj


def test_surumsuz_adresin_getirdigi_bundle_sessizce_kabul_edilmez():
    """2026-08-05'te yasanan senaryo (surumsuz adres 19.2 dondurmeye basladi,
    depo 19.1 istiyordu). Depo artik 19.2'de; ayni risk, surumsuz adres bir
    sonraki surumu dondurdugunde tekrar dogar. Eskiden bu sessizce uretim
    verisini degistirirdi."""
    bundle = _bundle("19.3")
    assert extract_attack_version(bundle) != DEFAULT_ATTACK_VERSION
    with pytest.raises(VersionMismatch):
        verify_version(DEFAULT_ATTACK_VERSION, extract_attack_version(bundle), "http://ornek")


def test_surumu_okunamayan_bundle_reddedilir():
    """None surum, metadata'ya None yazar ve parse_stix onu teknik kayitlarina
    tasir -- sessiz bosluk yerine gurultulu hata."""
    bundle = {"type": "bundle", "objects": [{"type": "attack-pattern"}]}
    assert extract_attack_version(bundle) is None
    with pytest.raises(VersionMismatch):
        verify_version("19.1", extract_attack_version(bundle), "http://ornek")


def test_surum_bundle_icinden_okunur():
    assert extract_attack_version(_bundle("19.2")) == "19.2"


# ------------------------------------------------------------------ metadata

def test_metadata_istenen_ve_gercek_surumu_birlikte_tasir():
    icerik = json.dumps(_bundle("19.2")).encode("utf-8")
    md = build_metadata(
        requested_version="19.2",
        actual_version="19.2",
        source_url=build_source_url("19.2"),
        content=icerik,
        object_count=2,
    )
    assert md["requested_version"] == "19.2"
    assert md["attack_version"] == "19.2"


def test_metadata_mevcut_anahtarlari_korur():
    """scripts/parse_stix.py `attack_version` anahtarini okuyup teknik
    kayitlarina yaziyor; anahtar adi degisirse veri hatti sessizce kirilir."""
    icerik = b'{"objects": []}'
    md = build_metadata(
        requested_version="19.1",
        actual_version="19.1",
        source_url="http://ornek",
        content=icerik,
        object_count=0,
    )
    for anahtar in (
        "source_url",
        "downloaded_at_utc",
        "sha256",
        "file_size_bytes",
        "attack_version",
        "object_count",
    ):
        assert anahtar in md, f"mevcut metadata anahtari kayboldu: {anahtar}"


def test_metadata_sha256_gercek_icerikten_hesaplanir():
    import hashlib

    icerik = b"abc"
    md = build_metadata(
        requested_version="19.1",
        actual_version="19.1",
        source_url="http://ornek",
        content=icerik,
        object_count=0,
    )
    assert md["sha256"] == hashlib.sha256(icerik).hexdigest()
    assert md["file_size_bytes"] == 3


def test_yayindaki_metadata_dosyasi_sozlesmeye_uyuyor():
    """Uretimdeki kayit, betigin urettigi bicimle ayni alanlari tasimali."""
    from pathlib import Path

    yol = Path(__file__).resolve().parent.parent / "data" / "metadata" / "attack_source_metadata.json"
    if not yol.exists():
        pytest.skip("uretim metadata dosyasi yok (veri hatti henuz kurulmamis)")
    md = json.loads(yol.read_text(encoding="utf-8"))
    for anahtar in ("source_url", "sha256", "attack_version", "object_count"):
        assert anahtar in md
    assert md["attack_version"] == DEFAULT_ATTACK_VERSION, (
        "uretimdeki bundle surumu ile betigin varsayilan surumu ayrildi -- "
        "biri digerini haberi olmadan gecmis olabilir"
    )
