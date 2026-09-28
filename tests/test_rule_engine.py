from __future__ import annotations

import pytest

from app.mapping.rule_engine import (
    RuleValidationError,
    evaluate_rules,
    load_review_rules,
    load_rules,
    parse_review_rule,
    parse_rule,
)


def _rule(**overrides) -> dict:
    base = {
        "technique_id": "T1059.001",
        "tactic": "TA0002",
        "confidence": "high",
        "required": {"event_ids": [4104]},
    }
    base.update(overrides)
    return base


def _row(event_id="4104", message="script block logging"):
    return {"EventID": event_id, "Message": message}


# --------------------------------------------------------------- sema dogrulama

def test_rule_without_technique_id_is_rejected():
    with pytest.raises(RuleValidationError):
        parse_rule({"tactic": "TA0002", "confidence": "high"})


def test_invalid_confidence_is_rejected():
    with pytest.raises(RuleValidationError):
        parse_rule(_rule(confidence="cok-yuksek"))


def test_rule_without_any_condition_is_rejected():
    """Kosulsuz kural her satiri kanit sayardi -- tam da kacindigimiz sey."""
    with pytest.raises(RuleValidationError):
        parse_rule({"technique_id": "T1", "tactic": "TA0002", "confidence": "high"})


def test_invalid_regex_is_rejected_at_load_time():
    with pytest.raises(RuleValidationError):
        parse_rule(_rule(field_conditions=[{"field": "Message", "must_match": "(("}]))


def test_review_rule_requires_conditions():
    with pytest.raises(RuleValidationError):
        parse_review_rule({"id": "x", "title": "y"})


# --------------------------------------------------------------- kanit kapisi

def test_technique_fires_when_all_conditions_hold():
    rules = [parse_rule(_rule(field_conditions=[{"field": "Message", "must_match": "script block"}]))]
    findings = evaluate_rules([_row()], rules)
    assert len(findings) == 1
    assert findings[0].technique_id == "T1059.001"
    assert findings[0].evidence_row_ids == [0]


def test_missing_required_event_id_produces_nothing():
    rules = [parse_rule(_rule())]
    assert evaluate_rules([_row(event_id="5156")], rules) == []


def test_failing_field_condition_produces_nothing():
    rules = [parse_rule(_rule(field_conditions=[{"field": "Message", "must_match": "asla-yok"}]))]
    assert evaluate_rules([_row()], rules) == []


def test_forbidden_event_id_beats_required():
    """Yasak liste, celiskide kazanmali."""
    rules = [parse_rule(_rule(required={"event_ids": [4104]}, forbidden={"event_ids": [4104]}))]
    assert evaluate_rules([_row()], rules) == []


def test_min_events_threshold_is_enforced():
    rules = [parse_rule(_rule(min_events=3))]
    assert evaluate_rules([_row(), _row()], rules) == []
    assert len(evaluate_rules([_row(), _row(), _row()], rules)) == 1


def test_must_not_match_excludes_a_row():
    rules = [parse_rule(_rule(field_conditions=[
        {"field": "Message", "must_not_match": "(?i)defender"},
    ]))]
    assert evaluate_rules([_row(message="Windows Defender platform")], rules) == []


def test_occurrence_count_deduplicates_rows():
    """Ayni satir iki kez sayilmamali (cift sayim kontrolu)."""
    rules = [parse_rule(_rule())]
    finding = evaluate_rules([_row(), _row()], rules)[0]
    finding.evidence_row_ids = [0, 0, 1]
    assert finding.occurrence_count == 2


# --------------------------------------------------------------- kutupsallik entegrasyonu

def test_impair_defenses_rule_cannot_fire_from_permitted_event():
    """5156 'permitted' satiri T1686.003'e kanit olamaz -- kural yazari
    yanlislikla o olayi required'a koysa bile motor engeller."""
    rules = [parse_rule({
        "technique_id": "T1686.003",
        "tactic": "TA0112",
        "confidence": "high",
        "required": {"event_ids": [5156]},
    })]
    rows = [_row(event_id="5156", message="The Windows Filtering Platform has permitted a connection.")]
    assert evaluate_rules(rows, rules) == []


def test_impair_defenses_rule_fires_from_breaking_event():
    rules = [parse_rule({
        "technique_id": "T1686.003",
        "tactic": "TA0112",
        "confidence": "high",
        "required": {"event_ids": [4948]},
    })]
    rows = [_row(event_id="4948", message="A rule was deleted from the Windows Firewall exception list.")]
    assert len(evaluate_rules(rows, rules)) == 1


# --------------------------------------------------------------- gercek katalog

def test_shipped_catalogue_loads_and_validates():
    rules = load_rules()
    assert rules, "kural katalogu bos"
    assert all(r.confidence in {"high", "medium", "low"} for r in rules)
    assert load_review_rules()


def test_shipped_firewall_rule_forbids_traffic_audit_events():
    rule = next(r for r in load_rules() if r.technique_id == "T1686.003")
    assert {"5156", "5158"} <= rule.forbidden_event_ids


# ------------------------------------------------- registry lehce normalizasyonu

def test_a_kernel_namespace_path_matches_a_win32_pattern():
    """OLCULMUS VAKA -- known_regression T1-T1003.002-gate-notation'in 2B yarisi.

    4656 Object Access olaylari cekirdek ad-uzayini yaziyor:
        ObjectName=\REGISTRY\MACHINE\SAM
    Kural ise Win32 gosterimini ariyor:
        HKLM\SAM
    Ayni anahtar, sifir eslesme. Kosulu object.name'e TASIMAK yetmiyordu --
    kayit 'object.name'e baksin VE cekirdek ad-uzayini TANISIN' diyordu.
    """
    kural = parse_rule(_rule(
        required={"event_ids": [4656]},
        field_conditions=[{"field": "object.name", "must_match": r"HKLM\\SAM"}],
    ))
    satir = {"EventID": "4656", "object.name": r"\REGISTRY\MACHINE\SAM"}
    assert evaluate_rules([satir], [kural])


def test_win32_notation_still_matches_after_normalisation():
    """Normalizasyon IKAME degil EKLEME: zaten Win32 yazan loglar bozulmamali."""
    kural = parse_rule(_rule(
        required={"event_ids": [4656]},
        field_conditions=[{"field": "object.name", "must_match": r"HKLM\\SAM"}],
    ))
    assert evaluate_rules([{"EventID": "4656", "object.name": r"HKLM\SAM"}], [kural])


def test_normalisation_does_not_turn_a_non_registry_value_into_a_match():
    """Alan ADINA degil DEGERIN BICIMINE bakiliyor; duz metin normalize
    edilmez ve yanlis eslesme uretmez."""
    kural = parse_rule(_rule(
        required={"event_ids": [4656]},
        field_conditions=[{"field": "object.name", "must_match": r"HKLM\\SAM"}],
    ))
    assert not evaluate_rules(
        [{"EventID": "4656", "object.name": "kullanici SAM dosyasini sordu"}], [kural]
    )


def test_a_field_agnostic_any_of_matches_in_the_wrong_field_for_the_event():
    """K2'NIN MALIYETI -- yapilmayan isin bedeli olculebilir olsun diye
    sabitleniyor. Kayit tek basina yetmez.

    ID          : k2-field-agnostic-any-of
    TESPIT      : 2026-08-18, 2B tasimasi sonrasi
    BELIRTI     : T1003.002, 4656 olayinda NESNE zararsizken KOMUT
                  SATIRINDA SAM gectigi icin atesliyor.

    Vaka ironik: komut satiri `backup.exe --exclude HKLM\\SAM` diyor, yani
    aracin SAM'e DOKUNMADIGINI soyluyor. Kural bunu kanit sayiyor.

    KOK NEDEN: tablo `(teknik) -> alan` tutuyor. Ayni kanit dizesi olay
    turune gore baska alanda yasadigi icin gecici cozum `hedef`i LISTE
    yapmak ve `any_of` ile hepsine bakmak oldu. Bu, AYRIM BILGISINI
    SILIYOR: "4656'da object.name, 4688'de komut satiri" yerine
    "ikisinden biri" deniyor. 4656'da olayin KONUSU erisilen nesnedir;
    komut satiri tesadufidir.

    KAPANIS KRITERI: tablo `(teknik, olay_id) -> alan` yapisina gecince
    4656 kolu yalnizca object.name'e bakacak ve bu test KIRILACAK.
    Kirildiginda kayit silinir.

    NEDEN SIMDI YAPILMIYOR: 57 satir o cifte acilirsa birkac yuz satir
    olur ve cogu ateslenmedigi icin dogrulanamaz (bkz. Gorev 13 kriteri:
    held-out set >=24 olay ID temsil etmeli)."""
    from app.mapping.text_input import text_to_row

    kural = {k.technique_id: k for k in load_rules()}["T1003.002"]
    zararsiz = text_to_row(
        r"EventID=4656 ObjectName=\REGISTRY\MACHINE\SOFTWARE\Policies "
        r"CommandLine=backup.exe --exclude HKLM\SAM --verbose"
    )
    assert kural.row_matches(zararsiz), (
        "artik atesleMIYORSA K2 yapilmis demektir -- kayit "
        "(k2-field-agnostic-any-of) silinmeli"
    )
    # ...ve dogru vakalar bozulmamis olmali
    assert kural.row_matches(text_to_row(
        r"EventID=4656 ObjectName=\REGISTRY\MACHINE\SAM AccessMask=0x20019"))
    assert kural.row_matches(text_to_row(
        r"EventID=4688 NewProcessName=reg.exe CommandLine=reg.exe save HKLM\SAM C:\out.hive"))


def test_a_forbidding_condition_is_not_bypassed_by_notation():
    """must_not_match VARYANTLARIN HEPSINE bakmali: yasak bir yol, baska
    lehcede yazildi diye gecerli hale gelmemeli."""
    kural = parse_rule(_rule(
        required={"event_ids": [4656]},
        field_conditions=[{"field": "object.name", "must_not_match": r"HKLM\\SAM"}],
    ))
    assert not evaluate_rules(
        [{"EventID": "4656", "object.name": r"\REGISTRY\MACHINE\SAM"}], [kural]
    )
