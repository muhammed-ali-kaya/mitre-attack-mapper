from __future__ import annotations

from app.enrichment.virustotal import IpReputation, LookupResult
from app.reporting.incident_report import _ip_reputation_section


def test_no_section_when_lookup_was_never_run():
    """Sorgu yapilmadiysa rapor eskisi gibi, fazladan bir bolum olmadan uretilir."""
    assert _ip_reputation_section(None) == []


def test_disabled_lookup_says_why():
    section = "\n".join(_ip_reputation_section(LookupResult(enabled=False)))
    assert "API anahtarı tanımlı değil" in section


def test_reputations_render_as_table_rows():
    lookup = LookupResult(
        reputations=[IpReputation("8.8.8.8", "ok", malicious=3, harmless=60, country="US", as_owner="Google")],
    )
    section = "\n".join(_ip_reputation_section(lookup))
    assert "| 8.8.8.8 | Zararli (3 motor) | 3 | 0 | 60 | US | Google |" in section


def test_private_addresses_are_listed_as_deliberately_skipped():
    """'Temiz cikti' ile 'hic bakilmadi' ayrimi bir olay raporunda kritik."""
    lookup = LookupResult(skipped_private=["10.10.20.15", "192.168.1.1"])
    section = "\n".join(_ip_reputation_section(lookup))

    assert "10.10.20.15" in section and "192.168.1.1" in section
    assert "kasıtlı olarak gönderilmedi" in section
    assert "Sorgulanabilecek public IP bulunamadı" in section


def test_quota_skipped_addresses_are_reported_separately():
    lookup = LookupResult(
        reputations=[IpReputation("8.8.8.8", "ok")],
        skipped_over_limit=["1.1.1.1"],
    )
    section = "\n".join(_ip_reputation_section(lookup))
    assert "Kota nedeniyle sorgulanamayan (1)" in section
    assert "1.1.1.1" in section
