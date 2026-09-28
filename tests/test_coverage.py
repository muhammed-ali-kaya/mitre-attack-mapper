"""Tespit boslugu (kapsam) beyaninin testleri.

Bu modul bir kez zaten sessizce silindi (sadelestirme commit'i 2295e08) --
cunku testi yoktu. Testler bu yuzden yalnizca davranisi degil, modulun
VARLIK SEBEBINI de kilitliyor: "bulgu yok" ile "bakilamadi" ayri seylerdir."""

from __future__ import annotations

from app.batch.serialize import canonicalize_row
from app.mapping.coverage import build_coverage_report
from app.mapping.rule_engine import Rule


def _rule(technique_id: str, tactic: str, event_ids: list[str]) -> Rule:
    return Rule(
        technique_id=technique_id,
        tactic=tactic,
        name=technique_id,
        confidence="high",
        required_event_ids=event_ids,
        forbidden_event_ids=[],
        field_conditions=[],
        min_events=1,
    )


RULES = [
    _rule("T1059.001", "TA0002", ["4104", "4688"]),   # Execution
    _rule("T1053.005", "TA0003", ["4698"]),            # Persistence
    _rule("T1021.001", "TA0008", ["4624"]),            # Lateral Movement
]


def test_tactic_with_a_present_event_id_is_assessable():
    report = build_coverage_report([{"EventID": "4688"}], rules=RULES)

    execution = next(t for t in report.tactics if t.tactic == "TA0002")
    assert execution.assessable
    assert execution.present_event_ids == ("4688",)
    # Kismen gorunur: 4104 yok ama 4688 var -- taktik yine de degerlendirilebilir.
    assert execution.missing_event_ids == ("4104",)


def test_tactic_with_no_present_event_id_is_a_blind_spot():
    """Asil mesele bu: Persistence'ta bulgu yok DEGIL, Persistence'a
    BAKILAMADI."""
    report = build_coverage_report([{"EventID": "4688"}], rules=RULES)

    persistence = next(t for t in report.tactics if t.tactic == "TA0003")
    assert not persistence.assessable
    assert persistence.missing_event_ids == ("4698",)
    assert "değerlendirilemedi" in persistence.statement


def test_statement_distinguishes_assessed_from_unassessable():
    """Rapora dogrudan yazilabilecek cumleler birbirine karismamali."""
    report = build_coverage_report([{"EventID": "4624"}], rules=RULES)

    statements = report.statements()
    assessed = [s for s in statements if "değerlendirildi" in s]
    blind = [s for s in statements if "değerlendirilemedi" in s]

    assert len(assessed) == 1, "yalnizca Lateral Movement gorulebilir durumda"
    assert len(blind) == 2


def test_coverage_is_derived_from_the_rule_catalog_not_hardcoded():
    """Kataloga kural eklendiginde kapsam kendiliginden genislemeli --
    ikinci bir liste elle guncellenmemeli."""
    extended = [*RULES, _rule("T1078", "TA0004", ["4672"])]  # Privilege Escalation

    base = build_coverage_report([{"EventID": "4688"}], rules=RULES)
    grown = build_coverage_report([{"EventID": "4688"}], rules=extended)

    assert len(grown.tactics) == len(base.tactics) + 1
    assert any(t.tactic == "TA0004" for t in grown.tactics)


def test_rules_without_event_ids_do_not_claim_visibility():
    """Yalnizca metin kosullu bir kural, bir taktigin GORULEBILIRLIGI
    hakkinda bilgi tasimaz -- kapsam beyanina girmemeli."""
    text_only = _rule("T1027", "TA0005", [])
    report = build_coverage_report([{"EventID": "4688"}], rules=[*RULES, text_only])

    assert not any(t.tactic == "TA0005" for t in report.tactics)


def test_dataset_event_ids_are_collected_from_every_row():
    rows = [{"EventID": "4688"}, {"EventID": "4104"}, {"EventID": "4688"}]
    report = build_coverage_report(rows, rules=RULES)

    assert report.dataset_event_ids == ("4104", "4688")


def test_rows_without_event_id_are_ignored_not_counted_as_zero():
    rows = [{"Message": "bir sey oldu"}, {"EventID": "4688"}]
    report = build_coverage_report(rows, rules=RULES)

    assert report.dataset_event_ids == ("4688",)


# ------------------------------------------------ arayuze baglanma noktasi

def test_csv_column_name_variants_reach_the_coverage_report():
    """Kullanicinin CSV'sinde kolon adi 'event_id' de olsa kapsam calismali.

    Kapsam raporu satira SOZLUK olarak bakiyor; toplu mod ham CSV satirini
    canonicalize_row'dan gecirerek veriyor. Bu test o koprunun kopmadigini
    kilitliyor -- koptugunda tablo sessizce bos gorunurdu."""
    raw_rows = [{"event_id": "4688", "process": "schtasks.exe"}]
    canonical = [canonicalize_row(r) for r in raw_rows]

    report = build_coverage_report(canonical, rules=RULES)

    assert report.dataset_event_ids == ("4688",)
