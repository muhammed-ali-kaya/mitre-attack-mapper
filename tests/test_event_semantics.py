"""Olay ID'si ve erisim maskesi anlambilimi (Gorev 3).

Kilitlenen sey: sistem olay ID'sini ETIKET, maskeyi STRING olarak tasiyordu.
Ikisinin de ANLAMI vardi ve hicbiri kullanilmiyordu."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.normalization.event_semantics import (
    decode_access_mask,
    describe,
    event_semantics,
    meaningful_fields,
    missing_critical_fields,
)
from app.normalization.input_parser import normalize_input

FIXTURE = Path(__file__).parent / "fixtures" / "registry_object_access_logs.json"
LOGS = {log["id"]: log for log in json.loads(FIXTURE.read_text(encoding="utf-8"))["logs"]}


def _semantics_for(log_id: str) -> dict:
    normalized = normalize_input(LOGS[log_id]["raw"])
    fields = normalized["parsed_fields"]

    def value(name):
        return fields[name].value if name in fields else None

    return describe(
        normalized["event_id"],
        value("access.mask"),
        value("object.type"),
        value("access.list"),
    )


# ---------------------------------------------------------------- olay anlami

def test_4657_is_a_write_by_definition():
    """T3'un tasiyip da kullanilmayan sinyali.

    'Registry degeri degistirildi' tanimi geregi yazmadir; bu logda Access
    Mask alani HIC YOK, yani sinif yalnizca olay turunden turetilebilir."""
    result = _semantics_for("T3")

    assert result["event_class"] == "write"
    assert result["mask_class"] is None
    assert result["access_class"] == "write"


def test_4656_is_only_a_handle_request_not_an_access():
    """4656 handle TALEBIDIR. Gerceklesen erisim 4663'tur; ikisini ayni
    saymak 'acmayi denedi' ile 'okudu' arasindaki farki siler."""
    assert "talep" in event_semantics("4656")["anlam"].lower()
    assert "4663" in (event_semantics("4656").get("not") or "")


def test_5156_is_recorded_as_a_control_that_worked():
    """Projenin en pahali halusinasyonunun kaynagi: 5156 IZIN VERILDI
    kaydidir, yani kontrolun CALISTIGINI gosterir."""
    semantics = event_semantics("5156")
    assert semantics["islem_sinifi"] == "audit"
    assert "IZIN VERILDI" in semantics["not"]


# ---------------------------------------------------------------- maske cozumu

def test_mask_write_bit_is_reported_as_REQUESTED_on_a_handle_request():
    """OLCULMUS VAKA (T1): olay turu 4656 'read' der, maske 0x2000d
    KEY_CREATE_SUB_KEY tasir -- bu bir YAZMA bitidir.

    GOREV 18'DE DEGISTI. Eskiden "celiskide maske kazanir" kurali kosulsuz
    uygulaniyordu ve access_class 'write' cikiyordu. 4656 bir HANDLE
    TALEBIDIR; maske orada TALEP EDILEN hakki anlatir, gerceklesen erisimi
    degil. Maske hala cozuluyor ve hala raporlaniyor -- yalnizca
    requested_class olarak. Bilgi kaybolmuyor; karara girdigi sifat
    degisiyor."""
    result = _semantics_for("T1")

    assert result["event_class"] == "read"
    assert result["mask_class"] == "write"
    assert result["access_realized"] is False
    assert result["requested_class"] == "write"
    assert result["access_class"] == "read"
    assert "KEY_CREATE_SUB_KEY" in result["mask_bits"]


def test_mask_write_bit_STILL_overrides_the_event_default_when_access_realized():
    """Kural OLMEDI, kapsami daraldi -- ve bu ayrica sinaniyor.

    T1'in maskesinin aynisi 4663'e (erisim GERCEKLESTIRILDI) verildiginde
    eski davranis aynen duruyor: olay turu 'read' der, maske 'write' der,
    maske kazanir. Bu test olmadan Gorev 18'in duzeltmesi kurali topyekun
    kaldirmis gibi gorunurdu ve kimse farki fark etmezdi."""
    result = describe("4663", "0x2000d", "Key", None)

    assert result["event_class"] == "read"
    assert result["mask_class"] == "write"
    assert result["access_realized"] is True
    assert result["requested_class"] is None
    assert result["access_class"] == "write"
    assert result["class_conflict"] is True


def test_only_4656_is_a_request_in_the_catalogue():
    """Katalog taramasi: talep olayi TEK. Ikinci bir tane eklenirse bu test
    duser ve ekleyen kisi Gorev 18'in kararini bilerek genisletmis olur --
    sessizce degil."""
    import yaml

    from app.normalization.event_semantics import EVENT_FILE  # noqa: PLC0415

    katalog = yaml.safe_load(EVENT_FILE.read_text(encoding="utf-8"))["events"]
    talepler = {str(eid) for eid, tanim in katalog.items()
                if tanim.get("erisim_gerceklesti") is False}
    assert talepler == {"4656"}


def test_mask_and_access_text_disagreement_is_reported_not_hidden():
    """T1'de Accesses metni uc erisim listeliyor, maskede dorduncu var.
    Gercek loglarda olur; sessizce birini secmek bilgi kaybidir."""
    result = _semantics_for("T1")

    assert result["mask_inconsistent_with_text"] is True
    assert "keycreatesubkey" in result["mask_only_bits"]


def test_read_only_mask_stays_read():
    result = _semantics_for("T2")

    assert result["mask_bits"] == ["KEY_QUERY_VALUE"]
    assert result["access_class"] == "read"
    assert result["class_conflict"] is False


def test_mask_matches_the_hand_written_expectation():
    """Fixture'daki beklenti TABLODAN turetildi; ikisi ayrismamali."""
    expected = LOGS["T1"]
    result = _semantics_for("T1")

    assert result["access_class"] == expected["expected_access_class"]
    assert result["requested_class"] == expected["expected_requested_class"]
    assert result["mask_bits"] == expected["expected_mask_bits"]
    assert result["mask_inconsistent_with_text"] == expected["expected_mask_text_inconsistency"]


def test_object_type_key_means_registry_not_a_cryptographic_key():
    """'Key' ayrimi yapilmadigi icin T0'da T1552.004 (Private Keys) aday
    olmustu. Bit tablosu registry ailesinden secilmeli."""
    decoded = decode_access_mask("0x2", object_type="Key")
    assert decoded is not None
    assert "KEY_SET_VALUE" in decoded.bits


def test_unparseable_mask_returns_none_instead_of_guessing():
    assert decode_access_mask("bozuk-deger") is None
    assert decode_access_mask(None) is None


# ---------------------------------------------------------------- anlamli alanlar

def test_meaningful_fields_are_event_specific():
    """4657'de kritik olan deger degisimi, 4656'da erisilen nesne."""
    assert "value.new" in meaningful_fields("4657")
    assert "value.new" not in meaningful_fields("4656")
    assert "access.mask" in meaningful_fields("4656")


def test_missing_critical_fields_catches_what_a_plain_count_cannot():
    """T0'da 15 alanin 5'i doludur -- genel bir 'bilgilendirici alan sayisi'
    esigi bunu yeterli sayabilir. Oysa 4656 icin KRITIK olan object.name
    ve access.list eksik. Gorev 12'nin on kapisi bu farki gormeli."""
    normalized = normalize_input(LOGS["T0"]["raw"])
    missing = missing_critical_fields(normalized["event_id"], set(normalized["parsed_fields"]))

    assert "object.name" in missing
    assert "access.list" in missing


def test_a_complete_log_reports_no_missing_critical_fields():
    normalized = normalize_input(LOGS["T3"]["raw"])
    assert missing_critical_fields(normalized["event_id"], set(normalized["parsed_fields"])) == []


def test_missing_fields_match_the_fixture_expectation():
    normalized = normalize_input(LOGS["T0"]["raw"])
    missing = set(missing_critical_fields(normalized["event_id"], set(normalized["parsed_fields"])))

    assert set(LOGS["T0"]["expected_missing_fields"]) <= missing


# ---------------------------------------------------------------- tablo kapsami

@pytest.mark.parametrize("event_id", [
    "4624", "4625", "4648", "4672",          # oturum acma
    "4688", "4689", "1",                     # surec
    "4720", "4726", "4732", "4738",          # hesap yonetimi
    "7045", "4697",                          # servis
    "4656", "4657", "4658", "4660", "4663", "4670",  # nesne erisimi
    "4719", "1102",                          # politika
])
def test_common_windows_events_are_covered(event_id):
    """Tablo dort Object Access olayiyla sinirli kalmamali."""
    semantics = event_semantics(event_id)
    assert semantics is not None, f"{event_id} tabloda yok"
    assert semantics.get("anlam")
    assert semantics.get("islem_sinifi")
    assert semantics.get("anlamli_alanlar")


def test_unknown_event_id_returns_none_rather_than_a_guess():
    assert event_semantics("9999") is None
    assert meaningful_fields("9999") == []
