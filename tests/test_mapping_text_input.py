from __future__ import annotations

from app.mapping.text_input import text_to_row


# ------------------------------------------------------------------ normalizasyon

def test_key_value_log_becomes_a_structured_row():
    row = text_to_row(
        "EventID=4688 NewProcessName=C:\\Windows\\System32\\schtasks.exe "
        "CommandLine=schtasks /create /tn X /tr powershell.exe SubjectUserName=service.admin"
    )
    assert row["EventID"] == "4688"
    assert row["NewProcessName"].endswith("schtasks.exe")
    assert row["SubjectUserName"] == "service.admin"


def test_message_is_always_the_full_raw_text():
    """Kanit kosullari girdinin TAMAMINDA aranmali."""
    text = 'EventID=4104 Message="Creating Scriptblock text"'
    assert text_to_row(text)["Message"] == text


def test_plain_prose_has_no_event_id():
    """'Bir PowerShell süreci kod indirdi' bir IDDIADIR, kanit degildir --
    EventID uretilmedigi icin EventID sart kosan bir kanit kosulu
    saglanamaz (bkz. app/agents/verification.py, kanit kapisi)."""
    row = text_to_row("Bir PowerShell süreci internetten kod indirdi.")
    assert not row.get("EventID")
    assert row["Message"].startswith("Bir PowerShell")
