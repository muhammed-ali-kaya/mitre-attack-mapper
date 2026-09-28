from __future__ import annotations

from datetime import datetime

from app.ui.diagrams import (
    build_attack_chain_diagram,
    build_timeline_diagram,
    format_timestamp,
)

NBSP = " "


def _timeline_entry(evidence, attack_id="T1059.001", name="PowerShell", ts=None, event_id=4104):
    return {
        "timestamp": ts,
        "event_id": event_id,
        "evidence": evidence,
        "attack_id": attack_id,
        "technique_name": name,
    }


def _phase(tactic, techniques):
    return {"tactic": tactic, "techniques": techniques}


def _technique(attack_id="T1059.001", name="PowerShell", count=1):
    return {"attack_id": attack_id, "name": name, "occurrence_count": count}


def test_empty_inputs_produce_no_diagram():
    assert build_timeline_diagram([]) == ""
    assert build_attack_chain_diagram([]) == ""


def test_labels_contain_no_padding_whitespace_hacks():
    """Regresyon: kisa dugumleri genisletmek icin kullanilan bolunmez bosluk
    dolgusu tarayicida HARFI HARFINE '&nbsp;&nbsp;...' olarak yaziliyordu.
    '#nbsp;', sayisal '#160;' ve gercek U+00A0 karakteri denendi; ucu de ayni
    bozuk ciktiyi verdi. Dolgu kaldirildi -- hicbiri geri gelmemeli."""
    for evidence in ("Kısa kanıt", "x", "Oturum açıldı"):
        diagram = build_timeline_diagram([_timeline_entry(evidence)])
        assert "#nbsp;" not in diagram
        assert "#160;" not in diagram
        assert NBSP not in diagram
        assert "&nbsp;" not in diagram


def test_chain_labels_contain_no_padding_whitespace_hacks():
    diagram = build_attack_chain_diagram([_phase("Execution", [_technique()])])
    assert "#nbsp;" not in diagram
    assert "#160;" not in diagram
    assert NBSP not in diagram


def test_timeline_nodes_are_linked_in_order():
    diagram = build_timeline_diagram([
        _timeline_entry("bir"), _timeline_entry("iki"), _timeline_entry("üç"),
    ])
    assert "n0 --> n1" in diagram
    assert "n1 --> n2" in diagram


def test_unmapped_rows_are_marked_but_kept_in_the_chain():
    diagram = build_timeline_diagram([
        _timeline_entry("eşleşmiş"),
        _timeline_entry("eşleşmemiş", attack_id=None, name=None),
    ])
    assert "classDef unmapped" in diagram
    assert "class n1 unmapped" in diagram


def test_quotes_are_escaped_so_the_label_does_not_break():
    diagram = build_timeline_diagram([_timeline_entry('içinde "tırnak" geçen kanıt')])
    assert "#quot;" in diagram
    # Ham tirnak etiketi kapatip Mermaid'i bozar.
    assert '"içinde' not in diagram


def test_chain_phase_titles_are_turkish_with_english_in_parentheses():
    diagram = build_attack_chain_diagram([
        _phase("Credential Access", [_technique("T1003.001", "LSASS Memory", 3)]),
    ])
    assert "Kimlik Bilgisi Erişimi (Credential Access)" in diagram
    # Teknik adi ve ATT&CK ID cevrilmez.
    assert "LSASS Memory" in diagram
    assert "T1003.001 (3)" in diagram


def test_chain_phases_are_linked_in_given_order():
    diagram = build_attack_chain_diagram([
        _phase("Execution", [_technique()]),
        _phase("Impact", [_technique("T1489", "Service Stop")]),
    ])
    assert "p0 --> p1" in diagram


def test_format_timestamp_handles_missing_value():
    assert format_timestamp(None) == "-"
    assert format_timestamp(datetime(2026, 8, 6, 11, 45, 39)) == "11:45:39"
