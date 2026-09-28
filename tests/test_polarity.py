from __future__ import annotations

import pytest

from app.mapping.polarity import (
    Polarity,
    classify,
    evidence_allowed,
    is_impair_defenses,
)


@pytest.mark.parametrize(
    "text",
    [
        "The Windows Filtering Platform has permitted a connection.",
        "The Windows Filtering Platform has permitted a bind to a local port.",
        "Success Audit: The Windows Filtering Platform has allowed a connection",
        # Sezgiye aykiri ama dogru: ENGELLEME de kontrolun CALISTIGI kanitidir.
        "The Windows Filtering Platform has blocked a connection.",
        "Access denied by policy.",
    ],
)
def test_control_working_is_enforcing(text):
    assert classify(text) is Polarity.ENFORCING


@pytest.mark.parametrize(
    "text",
    [
        "Windows Defender Real-time Protection was disabled.",
        "A rule was deleted from the Windows Firewall exception list.",
        "The audit policy was changed.",
        "Windows Firewall settings were changed.",
        "The service was stopped.",
    ],
)
def test_control_broken_is_breaking(text):
    assert classify(text) is Polarity.BREAKING


def test_both_signals_are_ambiguous_not_breaking():
    """Karar veremiyorsak Impair Defenses tetiklenmemeli."""
    text = "A rule was deleted; the connection was subsequently permitted."
    assert classify(text) is Polarity.AMBIGUOUS


def test_unrelated_text_is_neutral():
    assert classify("A handle to an object was requested.") is Polarity.NEUTRAL
    assert classify(None) is Polarity.NEUTRAL
    assert classify("") is Polarity.NEUTRAL


def test_impair_defenses_family_membership_is_derived_from_id():
    assert is_impair_defenses("T1562.001")
    assert is_impair_defenses("T1686.003")
    assert is_impair_defenses("T1685")
    assert not is_impair_defenses("T1059.001")


def test_impair_defenses_rejects_enforcing_evidence():
    """Projenin en pahali hatasi: 'permitted a connection' -> T1686.003."""
    assert not evidence_allowed("T1686.003", Polarity.ENFORCING)
    assert not evidence_allowed("T1686.003", Polarity.AMBIGUOUS)
    assert not evidence_allowed("T1686.003", Polarity.NEUTRAL)
    assert evidence_allowed("T1686.003", Polarity.BREAKING)


def test_other_techniques_are_not_constrained_by_polarity():
    for polarity in Polarity:
        assert evidence_allowed("T1059.001", polarity)
