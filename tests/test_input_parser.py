from __future__ import annotations

import json
import pathlib

import pytest

from app.normalization.input_parser import (
    build_enriched_query,
    build_layered_query,
    normalize_input,
)
from tests.generated_data import requires_attack_data

PROJE = pathlib.Path(__file__).resolve().parents[1]


def test_normalize_input_extracts_windows_raw_log_fields():
    raw = (
        "EventID=4688 NewProcessName=C:\\Windows\\System32\\schtasks.exe "
        "CommandLine=schtasks /create /s 10.10.20.15 /tn UpdateCheck /tr powershell.exe /sc onlogon "
        "SubjectUserName=service.admin"
    )
    result = normalize_input(raw)

    assert result["platform"] == "Windows"
    assert result["event_id"] == "4688"
    assert result["process_name"] == "C:\\Windows\\System32\\schtasks.exe"
    assert result["user_account"] == "service.admin"
    assert result["remote_ips"] == ["10.10.20.15"]
    assert result["is_remote"] is True
    assert "schtasks.exe" in result["detected_tools"]
    assert "powershell.exe" in result["detected_tools"]


def test_normalize_input_detects_linux_platform():
    raw = "New cron job added to /etc/cron.d/ by user via systemd timer unit"
    result = normalize_input(raw)
    assert result["platform"] == "Linux"


def test_normalize_input_no_platform_when_no_keywords_match():
    result = normalize_input("Something happened but no clear indicators here")
    assert result["platform"] is None


def test_normalize_input_local_process_not_flagged_remote():
    result = normalize_input("NewProcessName=C:\\Windows\\System32\\notepad.exe CommandLine=notepad.exe")
    assert result["is_remote"] is False
    assert result["remote_ips"] == []


def test_normalize_input_observed_actions_includes_process_and_user():
    raw = "NewProcessName=powershell.exe SubjectUserName=alice"
    result = normalize_input(raw)
    assert "powershell.exe calistirildi" in result["observed_actions"]
    assert "Kullanici hesabi: alice" in result["observed_actions"]


@pytest.mark.parametrize(
    "kurucu",
    [
        pytest.param(
            lambda raw, n: build_layered_query(raw, n, include_raw=True),
            id="build_layered_query__URETIM_YOLU",
        ),
        pytest.param(build_enriched_query, id="build_enriched_query__olcum_kolu"),
    ],
)
@requires_attack_data
def test_enrichment_never_emits_a_technique_name(kurucu):
    """Ö1 KORUMASI -- ORNEK degil MEKANIZMA seviyesinde.

    IKI KURUCUDA DA kosuluyor. 2A(b)'den sonra uretim yolu
    build_layered_query; testi yalnizca build_enriched_query'ye bakarak
    birakmak, KOSMAYAN bir yolu korumak olurdu. Bu tam olarak Gorev 1'de
    yapilan hata: sozlesme testleri yalnizca brace_kv fixture'larina
    bakiyordu ve space_kv'deki ayni bug iki olcumu kirletti.

    Kaldirilan tablo, ham logda "certutil" gorunce sorguya "ingress tool
    transfer" yaziyordu; beklenen teknik T1105 Ingress Tool Transfer.
    Bu retrieval degil, KOPYA. Olculdu: 60 senaryodaki net katkisi tek
    senaryoydu ve o senaryoda yaptigi tam olarak buydu.

    Test tek tek anahtar aramaz -- 'certutil yok' demek ayni tabloyu
    baska bir araçla geri yazmayi engellemez. Onun yerine SINIRI test
    eder: uretilen HICBIR terim, canli bir teknigin ADI olamaz. Tablo
    hangi araçla, hangi kaynaktan (elle, bundle'dan, 821 kayitla) geri
    gelirse gelsin bu test yakalar.

    SINIRI ACIKCA YAZILIYOR: yalnizca TAM AD eslesmesini yakalar.
    Kaldirilan tablonun 17 teriminden 10'u teknik adiydi ("ingress tool
    transfer", "OS Credential Dumping", "LSASS Memory"...) ve bunlar
    yakalanir. Kalan 7'si PARAFRAZDI ("scheduled task creation",
    "task scheduler") -- ayni kopyanin daha zayif hali, ve bu test onlari
    goremez. Parafraz eslesmesi denenmedi cunku esik keyfi olur ve yanlis
    pozitif uretir. Bu bosluk bilincli birakildi, kayitli."""
    teknik_adlari = {
        t["name"].casefold()
        for t in json.loads(
            (PROJE / "data/processed/techniques.json").read_text(encoding="utf-8")
        )
        if not t.get("revoked") and not t.get("deprecated")
    }
    assert len(teknik_adlari) > 500, "teknik listesi yuklenemedi -- test anlamsiz"

    senaryolar = json.loads(
        (PROJE / "evaluation/test_scenarios.json").read_text(encoding="utf-8")
    )
    ihlaller = []
    for s in senaryolar:
        raw = s["input"]
        sorgu = kurucu(raw, normalize_input(raw))
        # Ham logun KENDISI aranmaz -- log zaten "PowerShell" yazabilir ve bu
        # enjeksiyon degil, girdinin ta kendisidir. Yalnizca EKLENEN kisim.
        ek = sorgu.replace(raw, "")
        if ":" not in ek:
            continue
        for terim in ek.split(":", 1)[1].split(","):
            if terim.strip().casefold() in teknik_adlari:
                ihlaller.append((s["test_id"], terim.strip()))
    assert not ihlaller, f"zenginlestirme teknik ADI enjekte ediyor: {ihlaller}"


def test_build_enriched_query_adds_remote_and_platform_terms():
    raw = "powershell.exe -computername 10.1.1.1"
    normalized = normalize_input(raw)
    enriched = build_enriched_query(raw, normalized)
    assert "remote execution" in enriched
    assert "lateral movement" in enriched
    assert "Windows" in enriched


def test_build_enriched_query_returns_raw_text_unchanged_when_no_matches():
    raw = "nothing interesting here at all"
    normalized = normalize_input(raw)
    enriched = build_enriched_query(raw, normalized)
    assert enriched == raw


def test_build_enriched_query_deduplicates_terms():
    raw = "powershell.exe -computername 10.1.1.1 winrm"
    normalized = normalize_input(raw)
    enriched = build_enriched_query(raw, normalized)
    assert enriched.count("remote execution") == 1
    assert enriched.count("Windows") == 1


# -- extracted_facts: generic Key=Value capture ----------------------------------

def test_normalize_input_extracts_facts_from_share_access_log_not_covered_by_specific_fields():
    raw = "EventID=5140 ShareName=\\\\*\\ADMIN$ AccessMask=0x1 AccessList=ReadData"
    result = normalize_input(raw)

    facts = result["extracted_facts"]
    assert facts["EventID"] == "5140"
    assert facts["ShareName"] == "\\\\*\\ADMIN$"
    assert facts["AccessMask"] == "0x1"
    assert facts["AccessList"] == "ReadData"


def test_normalize_input_extracted_facts_strips_quotes_from_quoted_values():
    raw = 'EventID=1102 SubjectUserName=administrator Message="The audit log was cleared."'
    result = normalize_input(raw)

    facts = result["extracted_facts"]
    assert facts["EventID"] == "1102"
    assert facts["Message"] == "The audit log was cleared."


def test_normalize_input_extracted_facts_first_occurrence_wins_on_duplicate_keys():
    raw = "EventID=4688 EventID=9999"
    result = normalize_input(raw)
    assert result["extracted_facts"]["EventID"] == "4688"


# -- arac tespiti: kelime siniri ------------------------------------------------

def test_detected_tools_ignores_tool_name_embedded_in_unrelated_word():
    """5156 loglarindaki "Network Information" basligi net.exe olarak
    raporlaniyordu: stem substring olarak araniyordu."""
    raw = 'EventID=5156 Message="Network Information: Direction: Outbound Interface Index: 12"'
    result = normalize_input(raw)
    assert result["detected_tools"] == []


def test_detected_tools_does_not_confuse_netsh_with_net():
    result = normalize_input("CommandLine=netsh advfirewall set allprofiles state off")
    assert "netsh" in result["detected_tools"]
    assert "net.exe" not in result["detected_tools"]


def test_detected_tools_still_matches_bare_and_exe_forms():
    assert "net.exe" in normalize_input("CommandLine=net use \\\\host\\c$")["detected_tools"]
    assert "net.exe" in normalize_input("NewProcessName=C:\\Windows\\System32\\net.exe")["detected_tools"]


# -- bosluk iceren tirnakli yollar ----------------------------------------------

def test_normalize_input_keeps_full_quoted_process_path_with_spaces():
    """"program files" bosluk icerdigi icin yol ilk bosluktan kesiliyordu."""
    raw = 'EventID=5156 NewProcessName="\\device\\harddiskvolume3\\program files\\google\\chrome.exe"'
    result = normalize_input(raw)
    assert result["process_name"] == "\\device\\harddiskvolume3\\program files\\google\\chrome.exe"


def test_normalize_input_strips_quotes_from_command_line():
    raw = 'EventID=4104 CommandLine="powershell.exe -enc ZQBjAGgAbwA="'
    result = normalize_input(raw)
    assert result["command_line"] == "powershell.exe -enc ZQBjAGgAbwA="


# -- EventID'ye gore eylem tarifi -----------------------------------------------

def test_observed_action_uses_event_semantics_instead_of_assuming_execution():
    """4656 bir handle talebidir; lsass.exe'yi "calistirildi" diye anlatmak
    LLM'e olayin yanlis fiilini veriyordu."""
    raw = (
        "EventID=4656 NewProcessName=C:\\Windows\\System32\\lsass.exe "
        "FilePath=\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\W32Time"
    )
    action = normalize_input(raw)["observed_actions"][0]
    assert "calistirildi" not in action
    assert "handle" in action
    assert "W32Time" in action


def test_observed_action_reports_network_peer_for_connection_events():
    raw = "EventID=5156 NewProcessName=chrome.exe DestinationIp=203.0.113.103 DestinationPort=8888"
    action = normalize_input(raw)["observed_actions"][0]
    assert "203.0.113.103" in action
    assert "8888" in action


def test_observed_action_falls_back_to_execution_wording_for_process_creation():
    raw = "EventID=4688 NewProcessName=powershell.exe"
    assert "powershell.exe calistirildi" in normalize_input(raw)["observed_actions"]


# -- uzaklik cikarimi -----------------------------------------------------------

def test_escaped_windows_path_alone_does_not_imply_remote_system():
    """Kacisli loglardaki \\\\REGISTRY\\\\... yollari her olayi uzak gosteriyordu."""
    raw = (
        "EventID=4656 NewProcessName=C:\\Windows\\System32\\lsass.exe "
        'Message="Object Name: \\\\REGISTRY\\\\MACHINE\\\\SYSTEM\\\\ControlSet001"'
    )
    assert normalize_input(raw)["is_remote"] is False


def test_remote_peer_prefers_destination_over_source_address():
    raw = "EventID=5156 SourceIp=198.51.100.185 DestinationIp=203.0.113.103"
    actions = normalize_input(raw)["observed_actions"]
    assert any("hedef: 203.0.113.103" in a for a in actions)


# -- zenginlestirme: ag baglantisi != uzaktan calistirma -------------------------

def test_plain_network_connection_is_not_enriched_as_lateral_movement():
    """5156 govdesindeki "Remote User ID" basligi her outbound baglantiyi
    lateral movement'a dogru cekiyordu."""
    raw = (
        'EventID=5156 NewProcessName="C:\\program files\\google\\chrome.exe" '
        'Message="Remote User ID: NULL SID Remote Machine ID: NULL SID" '
        "SourceIp=198.51.100.185 DestinationIp=203.0.113.103"
    )
    normalized = normalize_input(raw)
    enriched = build_enriched_query(raw, normalized)

    assert normalized["remote_execution"] is False
    assert normalized["is_remote"] is True  # baska bir hostla konusuyor -- bu dogru
    assert "lateral movement" not in enriched


def test_explicit_remote_execution_still_enriched():
    raw = "CommandLine=schtasks /create /s 10.10.20.15 /tn UpdateCheck"
    normalized = normalize_input(raw)
    assert normalized["remote_execution"] is True
    assert "lateral movement" in build_enriched_query(raw, normalized)


def test_admin_share_access_counts_as_remote_execution_signal():
    raw = "EventID=5140 ShareName=\\\\*\\ADMIN$ SubjectUserName=svc_backup"
    assert normalize_input(raw)["remote_execution"] is True


# -- zenginlestirme: lsass ozne mi nesne mi -------------------------------------
#
# Ü ic test buradaydi ve hepsi KALDIRILAN tablonun "lsass" anahtarini test
# ediyordu (Ö1). Anahtar gidince onu bastiran `_lsass_is_subject_only` de
# gitti -- bastiricinin varligi zaten anahtar kelime -> teknik adi
# enjeksiyonunun fazla atesledigini gosteriyordu.
#
# Ozne/nesne ayrimi FIKIR olarak gecerli ve olu degil: lsass.exe'nin kendi
# anahtarini actigi 4656 ile bellegi okunan 4656 farkli olaylardir. Ama bu
# ayrimin yeri sorgu zenginlestirme degil, KANIT degerlendirmesi (2B'deki
# yapisal alan kosullari). Oraya tasinana kadar test yazilacak davranis yok.

def test_lsass_log_does_not_get_technique_terms_injected():
    """Bastirici gitti ama davranis korunuyor: hicbir yol teknik adi
    enjekte etmemeli. Ozne olan lsass de nesne olan lsass da ayni."""
    for raw in (
        "EventID=4656 NewProcessName=C:\\Windows\\System32\\lsass.exe "
        "FilePath=\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\W32Time",
        "EventID=10 NewProcessName=C:\\temp\\evil.exe "
        "TargetImage=C:\\Windows\\System32\\lsass.exe",
    ):
        enriched = build_enriched_query(raw, normalize_input(raw))
        assert "OS Credential Dumping" not in enriched
        assert "LSASS Memory" not in enriched


# -- "ne calistirildi" sorusunun cevabi ----------------------------------------

def test_process_creation_reports_what_was_actually_executed():
    """"cmd.exe calistirildi" tek basina NE yapildigini soylemiyor -- komut
    satiri elde varken susmak bilginin yarisini atmak demekti."""
    raw = 'EventID=4688 NewProcessName=C:\\Windows\\System32\\cmd.exe CommandLine="cmd.exe /c whoami /all"'
    action = normalize_input(raw)["observed_actions"][0]
    assert "calistirildi" in action
    assert "whoami /all" in action


def test_command_line_quoted_value_does_not_swallow_following_fields():
    raw = 'EventID=4688 NewProcessName=cmd.exe CommandLine="cmd.exe /c whoami" SubjectUserName=jdoe'
    result = normalize_input(raw)
    assert result["command_line"] == "cmd.exe /c whoami"
    assert result["user_account"] == "jdoe"


def test_script_block_content_is_reported_for_4104():
    raw = 'EventID=4104 NewProcessName=powershell.exe ScriptBlockText="Invoke-WebRequest -Uri http://10.1.1.5/a.ps1"'
    action = normalize_input(raw)["observed_actions"][0]
    assert "Invoke-WebRequest" in action


# -- surec adi olmayan olaylar --------------------------------------------------

def test_service_installation_is_described_without_a_process_name():
    """7045'te logda hic surec adi yok; olay tarifi surece bagli oldugu icin
    servis kurulumu tamamen sessiz geciyordu."""
    raw = 'EventID=7045 ServiceName=UpdaterSvc ImagePath="C:\\Windows\\Temp\\svc.exe"'
    actions = normalize_input(raw)["observed_actions"]
    assert any("Servis kuruldu" in a for a in actions)
    assert any("C:\\Windows\\Temp\\svc.exe" in a for a in actions)


def test_log_clearing_is_described_without_a_process_name():
    actions = normalize_input("EventID=1102 SubjectUserName=administrator")["observed_actions"]
    assert any("Denetim gunlugu temizlendi" in a for a in actions)


def test_unknown_event_without_process_produces_no_invented_action():
    """Bilinmeyen olayda uydurma cumle uretilmemeli."""
    actions = normalize_input("EventID=4634 SubjectUserName=jdoe")["observed_actions"]
    assert actions == ["Kullanici hesabi: jdoe"]


# -- gercek Windows export'lari: her sey Message govdesinde ---------------------

def test_fields_are_recovered_from_windows_message_body():
    """Gercek export'larda alanlar Key=Value degil, Message govdesinde
    "Etiket:  Deger" olarak gelir -- bu loglar parser'a bombos gorunuyordu."""
    raw = (
        'EventID=4688 Message="A new process has been created.  Creator Subject:  '
        "Account Name:  jdoe  Process Information:  New Process Name:  "
        'C:\\Windows\\System32\\schtasks.exe  Command Line:  schtasks /create /tn Updater"'
    )
    result = normalize_input(raw)
    assert result["process_name"] == "C:\\Windows\\System32\\schtasks.exe"
    assert result["command_line"] == "schtasks /create /tn Updater"
    assert result["user_account"] == "jdoe"


def test_message_body_section_headers_are_not_treated_as_fields():
    """"Process Information:" bir bolum basligi -- degeri diye kendinden
    sonraki alt alani yutuyordu."""
    raw = (
        'EventID=4688 Message="Process Information:  New Process Name:  C:\\Windows\\notepad.exe"'
    )
    assert normalize_input(raw)["process_name"] == "C:\\Windows\\notepad.exe"


def test_top_level_fields_win_over_message_body():
    raw = (
        'EventID=4688 NewProcessName=C:\\real.exe '
        'Message="Process Information:  New Process Name:  C:\\from-message.exe"'
    )
    assert normalize_input(raw)["process_name"] == "C:\\real.exe"


def test_windows_placeholder_values_are_ignored_in_message_body():
    raw = 'EventID=5156 Message="Remote User ID:  NULL SID  Source Address:  -"'
    facts = normalize_input(raw)["extracted_facts"]
    assert "SourceIp" not in facts


# -- platform cikarimi ----------------------------------------------------------

def test_windows_event_id_alone_determines_platform():
    """4624/7045/1102 gibi saf alan-tabanli loglarda metinde ".exe"/"c:\\"
    gecmedigi icin platform None kaliyor, platform filtresi bosa dusuyordu."""
    assert normalize_input("EventID=1102 SubjectUserName=administrator")["platform"] == "Windows"
    assert normalize_input("EventID=4624 LogonType=3")["platform"] == "Windows"


def test_non_windows_input_platform_detection_unchanged():
    assert normalize_input("New cron job added to /etc/cron.d/ via systemd")["platform"] == "Linux"
    assert normalize_input("nothing identifiable here")["platform"] is None


def test_free_text_threat_intel_keeps_tactic_terms_but_no_technique_name():
    """Serbest metin (UI'daki Ornek 3) zenginlestirilmeye devam eder, ama
    kalan terimler TAKTIK duzeyinde -- teknik adi degil (Ö1)."""
    raw = (
        "The actor dumped credentials from LSASS and later authenticated to "
        "remote systems using stolen administrative credentials."
    )
    enriched = build_enriched_query(raw, normalize_input(raw))
    assert "lateral movement" in enriched
    assert "OS Credential Dumping" not in enriched
