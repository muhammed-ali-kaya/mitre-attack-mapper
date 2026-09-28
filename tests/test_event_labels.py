"""Gorev 25 — olay adi + gerekli log kaynagi sozlesmesi."""

from __future__ import annotations

import yaml

from app.mapping.event_labels import (
    LOG_SOURCES_FILE,
    event_label,
    event_name,
    log_source,
    required_log_sources,
    required_sources_sentence,
)
from app.normalization.event_semantics import EVENT_FILE, event_semantics


def test_ad_KATALOGTAN_gelir_ikinci_tablo_yok():
    """Ad tek kaynaktan okunur: event_semantics.yaml. Ikinci bir ad
    tablosu, ayni gercegin iki kaynagi demek olurdu (madde 7)."""
    for event_id in ("4657", "7045", "4720", "11", "4104"):
        assert event_name(event_id) == event_semantics(event_id)["anlam"]


def test_bilinen_ID_adiyla_birlikte_basilir():
    assert event_label("4657") == "4657 (Registry degeri degistirildi)"
    assert event_label("4720").startswith("4720 (")


def test_katalogda_olmayan_ID_CIPLAK_kalir():
    """Kullanici acikca boyle istedi; uydurma ad basmak, analistin
    dogrulayamayacagi bir bilgi vermek olurdu."""
    assert event_semantics("4698") is None, "test onculu"
    assert event_label("4698") == "4698"
    assert event_label(None) == ""


def test_log_kaynagi_ARALIK_kurali():
    assert "Sysmon" in log_source("11")
    assert "Güvenlik" in log_source("4657")
    assert "System" in log_source("7045")


def test_4104_ARALIK_KURALINA_RAGMEN_powershell_kanalina_gider():
    """Ö6 olculdu ve dogrulandi: kullanicinin onerdigi `4xxx -> Security`
    kurali 4104'u YANLIS kaynaga yollar. 4104 PowerShell script block
    olayidir ve Security kanalinda degildir -- analist yanlis logu acardi."""
    assert "PowerShell" in log_source("4104")
    assert "Güvenlik" not in log_source("4104")


def test_istisnalar_araliklardan_ONCE_bakilir():
    data = yaml.safe_load(LOG_SOURCES_FILE.read_text(encoding="utf-8"))
    for event_id, kaynak in data["istisnalar"].items():
        assert log_source(event_id) == kaynak


def test_bilinmeyen_ID_sessizce_bir_kaynaga_ATANMAZ():
    assert log_source("9999") == "kaynağı bilinmiyor"
    assert log_source("abc") == "kaynağı bilinmiyor"


def test_kaynaklar_ID_lere_gore_gruplanir():
    grouped = required_log_sources(["11", "13", "4657", "7045"])

    assert grouped[log_source("11")] == ["11", "13"]
    assert grouped[log_source("4657")] == ["4657"]


def test_cumle_kaynagi_ve_ID_leri_birlikte_verir():
    sentence = required_sources_sentence(["11", "4657"])

    assert sentence.startswith("Gerekli log kaynağı:")
    assert "11" in sentence and "4657" in sentence
    assert "Sysmon" in sentence


def test_bos_liste_ICERIKSIZ_SATIR_uretmez():
    """Gorev 24'un iceriksiz madde isareti dersi."""
    assert required_sources_sentence([]) == ""


def test_istisna_tablosu_ARALIKLARLA_CELISMEYEN_kayit_TASIMAZ():
    """Istisna, aralik kuralinin yanlis sonuc verdigi ID icindir. Aralikla
    AYNI sonucu veren bir istisna satiri olu koddur."""
    data = yaml.safe_load(LOG_SOURCES_FILE.read_text(encoding="utf-8"))
    for event_id, kaynak in data["istisnalar"].items():
        aralik_sonucu = None
        if str(event_id).isdigit():
            for band in data["araliklar"]:
                if band["min"] <= int(event_id) <= band["max"]:
                    aralik_sonucu = band["kaynak"]
                    break
        assert aralik_sonucu != kaynak, str(event_id) + " istisnasi aralikla ayni sonucu veriyor"


def test_katalogdaki_her_olay_bir_kaynaga_baglanabiliyor():
    """Adi bilinen bir olayin kaynagi 'bilinmiyor' cikiyorsa, analist adi
    goruyor ama ne yapacagini yine bilemiyor demektir."""
    catalog = yaml.safe_load(EVENT_FILE.read_text(encoding="utf-8"))["events"]
    kaynaksiz = [e for e in catalog if log_source(e) == "kaynağı bilinmiyor"]

    assert not kaynaksiz, "adi bilinen ama kaynagi bilinmeyen olaylar: " + str(kaynaksiz)
