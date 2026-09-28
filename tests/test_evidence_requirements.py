from __future__ import annotations

from app.validation.evidence_requirements import (
    build_evidence_summary,
    check_required_evidence,
)


# -- check_required_evidence: techniques outside the catalog -------------------

def test_check_required_evidence_not_applicable_for_uncatalogued_technique():
    result = check_required_evidence("T1053.005", "anything at all")
    assert result.applicable is False
    assert result.satisfied is True


# -- check_required_evidence: T1685.005 (Clear Windows Event Logs) -------------

def test_check_required_evidence_rejects_t1685_005_without_required_terms():
    raw_input = "EventID=5140 ShareName=\\\\*\\ADMIN$ AccessMask=0x1 AccessList=ReadData"
    result = check_required_evidence("T1685.005", raw_input)
    assert result.applicable is True
    assert result.satisfied is False
    assert result.found == []
    assert set(result.missing) == {"wevtutil", "Remove-EventLog", "EventID 1102", "winevt", "*.evtx deletion"}


def test_check_required_evidence_accepts_t1685_005_with_eventid_1102():
    raw_input = 'EventID=1102 SubjectUserName=administrator Message="The audit log was cleared."'
    result = check_required_evidence("T1685.005", raw_input)
    assert result.applicable is True
    assert result.satisfied is True
    assert "EventID 1102" in result.found


def test_check_required_evidence_accepts_t1685_005_with_wevtutil():
    result = check_required_evidence("T1685.005", "CommandLine=wevtutil cl security")
    assert result.satisfied is True
    assert "wevtutil" in result.found


# -- check_required_evidence: T1047 (WMI) ---------------------------------------

def test_check_required_evidence_accepts_t1047_with_wmic_exe_case_insensitive():
    raw_input = (
        "EventID=4688 NewProcessName=C:\\Windows\\System32\\wbem\\WMIC.exe "
        'CommandLine=wmic /node:10.10.5.20 process call create "cmd.exe /c whoami" '
        "SubjectUserName=admin.svc"
    )
    result = check_required_evidence("T1047", raw_input)
    assert result.applicable is True
    assert result.satisfied is True
    assert "wmic.exe" in result.found


def test_check_required_evidence_rejects_t1047_without_wmi_terms():
    raw_input = "EventID=5140 ShareName=\\\\*\\ADMIN$ AccessMask=0x1 AccessList=ReadData"
    result = check_required_evidence("T1047", raw_input)
    assert result.satisfied is False


# -- check_required_evidence: T1021.006 (WinRM) ---------------------------------

def test_check_required_evidence_accepts_t1021_006_with_port_5985():
    result = check_required_evidence("T1021.006", "Destination port 5985 connection observed")
    assert result.satisfied is True
    assert "port 5985" in result.found


def test_check_required_evidence_rejects_t1021_006_without_winrm_terms():
    raw_input = "EventID=5140 ShareName=\\\\*\\ADMIN$ AccessMask=0x1 AccessList=ReadData"
    result = check_required_evidence("T1021.006", raw_input)
    assert result.satisfied is False


# -- build_evidence_summary ------------------------------------------------------

def test_build_evidence_summary_uses_only_code_derived_facts():
    extracted_facts = {"EventID": "5140", "ShareName": "ADMIN$"}
    rejected = [
        {
            "attack_id": "T1047",
            "evidence_check": {"applicable": True, "found": [], "missing": ["wmic.exe", "WMI"]},
        }
    ]
    summary = build_evidence_summary(extracted_facts, [], rejected)

    assert "Olay kimligi: 5140" in summary["detected"]
    assert "Paylasim adi: ADMIN$" in summary["detected"]
    assert "T1047 icin beklenen kanit: wmic.exe" in summary["not_detected"]
    assert "T1047 icin beklenen kanit: WMI" in summary["not_detected"]
    assert summary["assumed"] == []


def test_build_evidence_summary_keeps_unknown_field_names_as_is():
    """Sozlukte olmayan alana uydurma Turkce karsilik uretilmemeli."""
    summary = build_evidence_summary({"SomeVendorField": "42"}, [], [])
    assert summary["detected"] == ["SomeVendorField: 42"]


def test_build_evidence_summary_never_shows_the_raw_key_value_form():
    """Bolumun amaci ham log'u degil, okunabilir aciklamayi gostermek."""
    summary = build_evidence_summary({"NewProcessName": "schtasks.exe"}, [], [])
    assert summary["detected"] == ["Calistirilan surec: schtasks.exe"]
    assert not any("NewProcessName=" in item for item in summary["detected"])


def test_build_evidence_summary_ignores_mappings_without_applicable_catalog_entry():
    mappings = [{"attack_id": "T1053.005", "evidence_check": {"applicable": False}}]
    summary = build_evidence_summary({}, mappings, [])
    assert summary == {"detected": [], "not_detected": [], "assumed": []}
