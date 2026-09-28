"""Incident seviyesi QRadar taslak kuralinin testleri.

Bu kuralin tekli kuraldan farki CAKISMA aramasi: ayni makinede, ayni zaman
penceresinde, birden fazla asamaya ait olay. Testler asil olarak o iddianin
hakli olup olmadigini kolluyor -- yeterli malzeme yoksa kural URETILMEMELI."""

from __future__ import annotations

from datetime import datetime, timedelta

from app.reporting.qradar_rule import build_incident_qradar_rule

T0 = datetime(2026, 8, 15, 10, 0, 0)


def _technique(attack_id: str, name: str, count: int = 2, level: str = "high") -> dict:
    return {
        "attack_id": attack_id,
        "name": name,
        "occurrence_count": count,
        "confidence_level": level,
    }


def _incident(**overrides) -> dict:
    base = {
        "id": "INC-1",
        "hostname": "WS-014",
        "primary_user": "jdoe",
        "row_indices": [0, 1],
        "techniques": [
            _technique("T1053.005", "Scheduled Task"),
            _technique("T1059.001", "PowerShell"),
        ],
        "weak_techniques": [],
        "timeline": [
            {"row_index": 0, "timestamp": T0},
            {"row_index": 1, "timestamp": T0 + timedelta(minutes=40)},
        ],
    }
    base.update(overrides)
    return base


ROWS = {
    0: {"EventID": "4688", "NewProcessName": "C:\\Windows\\System32\\schtasks.exe", "Hostname": "WS-014"},
    1: {"EventID": "4104", "NewProcessName": "C:\\Windows\\System32\\powershell.exe", "Hostname": "WS-014"},
}


# ------------------------------------------------------ uretilmemesi gereken

def test_single_technique_incident_gets_no_correlation_rule():
    """Tek teknikli incident'te 'birden fazla asama' iddiasi YOK.

    Korelasyon kurali kurmak burada yanlis olurdu -- tekli log kurali
    (build_qradar_rule_draft) zaten bu isi yapiyor."""
    incident = _incident(techniques=[_technique("T1053.005", "Scheduled Task")])
    assert build_incident_qradar_rule(incident, ROWS) is None


def test_incident_without_any_concrete_artifact_gets_no_rule():
    """Olay ID'si de surec adi da yoksa kural bos bir iskelet olurdu."""
    rows = {0: {"Hostname": "WS-014"}, 1: {"Hostname": "WS-014"}}
    assert build_incident_qradar_rule(_incident(), rows) is None


def test_missing_rows_produce_no_rule():
    assert build_incident_qradar_rule(_incident(), {}) is None


# ------------------------------------------------------------- kural icerigi

def test_rule_correlates_on_hostname_when_it_is_constant():
    draft = build_incident_qradar_rule(_incident(), ROWS)

    assert draft["correlation_field"] == "Hostname"
    assert draft["correlation_value"] == "WS-014"
    assert "same Hostname" in draft["rule_text"]


def test_hostname_wins_over_username_as_correlation_key():
    """Saldirinin asamalari cogunlukla ayni makinede; hesap degisebilir."""
    rows = {
        0: {"EventID": "4688", "NewProcessName": "a.exe", "Hostname": "WS-014", "SubjectUserName": "jdoe"},
        1: {"EventID": "4104", "NewProcessName": "b.exe", "Hostname": "WS-014", "SubjectUserName": "jdoe"},
    }
    draft = build_incident_qradar_rule(_incident(), rows)
    assert draft["correlation_field"] == "Hostname"


def test_username_is_used_when_hostname_varies():
    rows = {
        0: {"EventID": "4688", "NewProcessName": "a.exe", "Hostname": "WS-014", "SubjectUserName": "jdoe"},
        1: {"EventID": "4104", "NewProcessName": "b.exe", "Hostname": "WS-099", "SubjectUserName": "jdoe"},
    }
    draft = build_incident_qradar_rule(_incident(), rows)
    assert draft["correlation_field"] == "Username"


def test_no_constant_key_still_produces_a_rule_but_warns_loudly():
    """Anahtarsiz kural tum ortamda sayim yapar -- sessizce uretilemez."""
    rows = {
        0: {"EventID": "4688", "NewProcessName": "a.exe", "Hostname": "WS-014", "SubjectUserName": "jdoe"},
        1: {"EventID": "4104", "NewProcessName": "b.exe", "Hostname": "WS-099", "SubjectUserName": "asmith"},
    }
    draft = build_incident_qradar_rule(_incident(), rows)

    assert draft["correlation_field"] is None
    assert any("UYARI" in note for note in draft["notes"])
    assert "korelasyon alanini elle secin" in draft["rule_text"]


def test_event_ids_and_process_names_are_collected_across_rows():
    draft = build_incident_qradar_rule(_incident(), ROWS)

    assert "4104, 4688" in draft["rule_text"]
    assert '"powershell.exe"' in draft["rule_text"]
    assert '"schtasks.exe"' in draft["rule_text"]


# -------------------------------------------------------- pencere ve esik

def test_window_is_derived_from_the_observed_span_not_hardcoded():
    """40 dakikaya yayilan incident icin 15 dakikalik pencere kurali
    tetiklenemez hale getirirdi."""
    draft = build_incident_qradar_rule(_incident(), ROWS)
    assert draft["window_minutes"] == 61  # 40 dk * 1.5 + 1


def test_window_has_a_floor_for_instantaneous_incidents():
    """Saat kaymasi olan gercek ortamda 0 dakikalik pencere hic tetiklenmez."""
    incident = _incident(timeline=[{"row_index": 0, "timestamp": T0}, {"row_index": 1, "timestamp": T0}])
    draft = build_incident_qradar_rule(incident, ROWS)
    assert draft["window_minutes"] == 15


def test_window_is_capped_for_very_long_incidents():
    incident = _incident(timeline=[
        {"row_index": 0, "timestamp": T0},
        {"row_index": 1, "timestamp": T0 + timedelta(days=10)},
    ])
    draft = build_incident_qradar_rule(incident, ROWS)
    assert draft["window_minutes"] == 24 * 60


def test_timeline_without_timestamps_falls_back_to_the_floor():
    incident = _incident(timeline=[{"row_index": 0}, {"row_index": 1}])
    draft = build_incident_qradar_rule(incident, ROWS)
    assert draft["window_minutes"] == 15


def test_threshold_is_capped_at_three_so_the_rule_stays_triggerable():
    """Ucten yukarisi kurali fazla ozel yapar: saldirinin bir asamasi
    gorulmedigi anda kural hic tetiklenmez."""
    incident = _incident(techniques=[
        _technique(f"T10{i}", f"teknik {i}") for i in range(6)
    ])
    draft = build_incident_qradar_rule(incident, ROWS)
    assert draft["threshold"] == 3


# ------------------------------------------------------------ zayif sinyaller

def test_weak_signals_are_excluded_but_disclosed():
    """Analist dogrulamasi bekleyen sinyalden production alarmi uretilmez --
    ama gizlenmez de."""
    incident = _incident(weak_techniques=[_technique("T1105", "Ingress Tool Transfer", level="low")])
    draft = build_incident_qradar_rule(incident, ROWS)

    assert "T1105" not in draft["rule_text"]
    assert not any("T1105" in line for line in draft["techniques"])
    assert any("zayıf sinyal" in note for note in draft["notes"])


def test_technique_list_documents_what_the_rule_is_based_on():
    draft = build_incident_qradar_rule(_incident(), ROWS)

    joined = " ".join(draft["techniques"])
    assert "T1053.005" in joined and "T1059.001" in joined
    assert "güven: high" in joined


def test_rule_is_always_marked_as_a_draft():
    draft = build_incident_qradar_rule(_incident(), ROWS)
    assert "Taslak" in draft["rule_name"]
    assert any("TASLAKTIR" in note for note in draft["notes"])
