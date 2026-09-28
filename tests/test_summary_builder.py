from __future__ import annotations

from datetime import datetime

from app.correlation.summary_builder import build_attack_summary


def _technique(attack_id, name, tactics, occurrence_count=1) -> dict:
    return {
        "attack_id": attack_id,
        "name": name,
        "tactics": tactics,
        "occurrence_count": occurrence_count,
    }


def _entry(attack_id, timestamp=None) -> dict:
    return {"attack_id": attack_id, "timestamp": timestamp}


def test_no_techniques_returns_fallback_message():
    assert "yetecek doğrulanmış teknik bulunamadı" in build_attack_summary([], [])


def test_summary_is_turkish_and_names_the_technique():
    deduped = [_technique("T1078", "Valid Accounts", ["Initial Access"])]
    summary = build_attack_summary([_entry("T1078")], deduped)
    assert "İlk Erişim" in summary
    assert "sisteme ilk erişimi sağladı" in summary
    # Teknik adi ve ATT&CK ID cevrilmeden korunur.
    assert "Valid Accounts (T1078, 1 kayıt)" in summary


def test_every_technique_is_traceable_in_summary():
    deduped = [
        _technique("T1078", "Valid Accounts", ["Initial Access"]),
        _technique("T1543.003", "Windows Service", ["Persistence"]),
        _technique("T1003.001", "LSASS Memory", ["Credential Access"]),
    ]
    summary = build_attack_summary([_entry(t["attack_id"]) for t in deduped], deduped)
    for technique in deduped:
        assert technique["name"] in summary
        assert technique["attack_id"] in summary


def test_phases_follow_canonical_kill_chain_order_not_input_order():
    deduped = [
        _technique("T1489", "Service Stop", ["Impact"]),
        _technique("T1078", "Valid Accounts", ["Initial Access"]),
        _technique("T1059.001", "PowerShell", ["Execution"]),
    ]
    summary = build_attack_summary([_entry(t["attack_id"]) for t in deduped], deduped)
    assert summary.index("İlk Erişim") < summary.index("Çalıştırma") < summary.index("Etki")


def test_technique_with_multiple_tactics_is_reported_once_in_primary_phase():
    """T1053.005 hem Execution hem Persistence -- anlatida bir kez gecmeli."""
    deduped = [_technique("T1053.005", "Scheduled Task", ["Persistence", "Execution"])]
    summary = build_attack_summary([_entry("T1053.005")], deduped)
    assert summary.count("Scheduled Task (T1053.005") == 1
    assert "Çalıştırma" in summary


def test_long_phase_truncates_technique_list_with_remainder_note():
    deduped = [
        _technique(f"T10{i}", f"Technique {i}", ["Execution"]) for i in range(6)
    ]
    summary = build_attack_summary([_entry(t["attack_id"]) for t in deduped], deduped)
    assert "ve 3 teknik daha" in summary


def test_high_risk_tactics_get_a_highlight_line():
    deduped = [
        _technique("T1003.001", "LSASS Memory", ["Credential Access"]),
        _technique("T1082", "System Information Discovery", ["Discovery"]),
    ]
    summary = build_attack_summary([_entry(t["attack_id"]) for t in deduped], deduped)
    assert "Öne çıkan bulgular" in summary
    assert "LSASS Memory" in summary.split("Öne çıkan bulgular")[1]
    # Discovery yuksek riskli degil -- vurgu satirina girmemeli.
    assert "System Information Discovery" not in summary.split("Öne çıkan bulgular")[1]


def test_scope_sentence_reports_host_user_and_time_window():
    timeline = [
        _entry("T1078", datetime(2026, 8, 6, 11, 45, 39)),
        _entry("T1078", datetime(2026, 8, 6, 11, 48, 50)),
    ]
    summary = build_attack_summary(
        timeline,
        [_technique("T1078", "Valid Accounts", ["Initial Access"])],
        hostname="WINHOST-01",
        primary_user="svc_backup",
    )
    assert "WINHOST-01" in summary
    assert "svc_backup" in summary
    assert "11:45:39–11:48:50" in summary
    assert "2 log kaydı" in summary


def test_weak_signal_count_is_disclosed():
    summary = build_attack_summary(
        [_entry("T1078")],
        [_technique("T1078", "Valid Accounts", ["Initial Access"])],
        weak_technique_count=13,
    )
    assert "13 sinyal" in summary
    assert "Zayıf Sinyaller" in summary


def test_summary_states_it_is_not_llm_generated():
    summary = build_attack_summary(
        [_entry("T1078")], [_technique("T1078", "Valid Accounts", ["Initial Access"])]
    )
    assert "dil modeli tarafından üretilmemiştir" in summary


def test_unknown_tactic_still_appears_without_inventing_a_verb():
    deduped = [_technique("T1000", "Made Up Technique", ["Nonexistent Tactic"])]
    summary = build_attack_summary([_entry("T1000")], deduped)
    assert "Nonexistent Tactic" in summary
    assert "Made Up Technique (T1000, 1 kayıt)" in summary
