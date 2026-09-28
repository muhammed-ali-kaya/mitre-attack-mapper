from __future__ import annotations

from app.correlation.attack_chain import TACTIC_ORDER, build_attack_chain, primary_tactic


def _technique(attack_id, tactics) -> dict:
    return {"attack_id": attack_id, "name": attack_id, "tactics": tactics, "occurrence_count": 1}


def test_tactic_order_follows_canonical_kill_chain():
    order = {name: i for i, name in enumerate(TACTIC_ORDER)}
    assert order["Initial Access"] < order["Execution"] < order["Persistence"]
    assert order["Persistence"] < order["Credential Access"] < order["Lateral Movement"]


def test_build_attack_chain_orders_phases_canonically_not_input_order():
    deduped = [
        _technique("T1543.003", ["Persistence"]),
        _technique("T1059.001", ["Execution"]),
        _technique("T1078", ["Initial Access", "Persistence", "Defense Impairment", "Privilege Escalation"]),
    ]
    chain = build_attack_chain(deduped)
    tactics_in_order = [phase["tactic"] for phase in chain]
    # T1078 yalnizca birincil taktigine (Initial Access) dusuyor, bu yuzden
    # Privilege Escalation ve Defense Impairment fazlari hic acilmiyor.
    assert tactics_in_order == ["Initial Access", "Execution", "Persistence"]


def test_build_attack_chain_omits_empty_phases():
    deduped = [_technique("T1059.001", ["Execution"])]
    chain = build_attack_chain(deduped)
    assert len(chain) == 1
    assert chain[0]["tactic"] == "Execution"


def test_technique_with_multiple_tactics_is_drawn_once_at_primary_tactic():
    """Varsayilan gorunum: teknik yalnizca kill chain'de EN ERKEN taktiginde."""
    deduped = [_technique("T1053", ["Persistence", "Execution"])]
    chain = build_attack_chain(deduped)
    assert [phase["tactic"] for phase in chain] == ["Execution"]
    assert chain[0]["techniques"] == deduped


def test_every_tactic_mode_still_repeats_technique_in_each_phase():
    """primary_tactic_only=False eski (MITRE'ye birebir sadik) gorunumu verir."""
    deduped = [_technique("T1053", ["Execution", "Persistence"])]
    chain = build_attack_chain(deduped, primary_tactic_only=False)
    assert {phase["tactic"] for phase in chain} == {"Execution", "Persistence"}
    for phase in chain:
        assert deduped[0] in phase["techniques"]


def test_primary_tactic_picks_earliest_in_kill_chain_regardless_of_input_order():
    assert primary_tactic(_technique("T1053", ["Persistence", "Execution"])) == "Execution"
    assert primary_tactic(_technique("T1078", ["Persistence", "Initial Access"])) == "Initial Access"


def test_primary_tactic_falls_back_to_first_unknown_tactic():
    assert primary_tactic(_technique("T1000", ["Nonexistent Tactic"])) == "Nonexistent Tactic"
    assert primary_tactic(_technique("T1000", [])) is None


def test_build_attack_chain_empty_input_returns_empty_chain():
    assert build_attack_chain([]) == []
