from __future__ import annotations

import pytest
import requests

from app.enrichment import virustotal
from app.enrichment.virustotal import (
    IpReputation,
    is_public_ip,
    lookup_ip,
    lookup_ips,
)


@pytest.fixture(autouse=True)
def clean_state(monkeypatch):
    virustotal.clear_cache()
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")


def fake_response(status_code=200, payload=None):
    class R:
        def __init__(self):
            self.status_code = status_code

        def json(self):
            if payload is None:
                raise ValueError("gecersiz JSON")
            return payload

    return R()


OK_PAYLOAD = {
    "data": {
        "attributes": {
            "last_analysis_stats": {"malicious": 3, "suspicious": 1, "harmless": 60},
            "reputation": -14,
            "country": "RU",
            "as_owner": "Example AS",
        }
    }
}


# -- public/private ayrimi: modulun en kritik guvenlik kurali -----------------

@pytest.mark.parametrize("ip", [
    "10.10.20.15", "192.168.1.1", "172.16.0.5", "172.31.255.254",
    "127.0.0.1", "169.254.1.1", "224.0.0.1", "0.0.0.0", "::1", "fe80::1",
])
def test_private_and_special_addresses_are_not_public(ip):
    assert is_public_ip(ip) is False


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "9.9.9.9", "93.184.216.34", "2001:4860:4860::8888"])
def test_public_addresses_are_recognised(ip):
    assert is_public_ip(ip) is True


@pytest.mark.parametrize("ip", ["192.0.2.1", "198.51.100.7", "203.0.113.9"])
def test_documentation_ranges_are_not_public(ip):
    """RFC 5737 ornek/dokumantasyon araliklari (TEST-NET-1/2/3). Gercek trafikte
    gorunmezler; VT'ye sorulmalari bosa kota harcar."""
    assert is_public_ip(ip) is False


@pytest.mark.parametrize("value", ["", "   ", "not-an-ip", "999.1.1.1", "schtasks.exe"])
def test_malformed_values_are_never_treated_as_public(value):
    assert is_public_ip(value) is False


def test_private_ips_are_never_sent_to_the_network(monkeypatch):
    """Ic ag adreslerinin disari sizmamasi bu modulun en onemli garantisi."""
    def explode(*args, **kwargs):
        raise AssertionError("ozel IP icin ag istegi yapildi")

    monkeypatch.setattr(virustotal.requests, "get", explode)

    result = lookup_ips(["10.10.20.15", "192.168.1.1", "127.0.0.1"])
    assert result.reputations == []
    assert result.skipped_private == ["10.10.20.15", "192.168.1.1", "127.0.0.1"]


# -- anahtar yoksa ozellik sessizce kapanir -----------------------------------

def test_disabled_without_api_key(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.setattr(virustotal, "dotenv_values", lambda *a, **k: {})
    monkeypatch.setattr(virustotal.requests, "get", lambda *a, **k: pytest.fail("istek yapilmamaliydi"))

    assert virustotal.is_enabled() is False
    result = lookup_ips(["8.8.8.8"])
    assert result.enabled is False
    assert result.reputations == []


def test_blank_key_in_env_file_is_treated_as_missing(monkeypatch):
    """Ornek dosyadan kopyalanan bos 'VIRUSTOTAL_API_KEY=' satiri ozelligi
    acik gostermemeli."""
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.setattr(virustotal, "dotenv_values", lambda *a, **k: {"VIRUSTOTAL_API_KEY": "   "})
    assert virustotal.is_enabled() is False


def test_key_added_to_env_file_is_picked_up_without_restart(monkeypatch):
    """Kullanici .env'i uygulama calisirken doldurdugunda yeniden baslatmaya
    gerek kalmamali -- dosya her cagride taze okunuyor."""
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    file_contents = {"VIRUSTOTAL_API_KEY": ""}
    monkeypatch.setattr(virustotal, "dotenv_values", lambda *a, **k: dict(file_contents))

    assert virustotal.is_enabled() is False
    file_contents["VIRUSTOTAL_API_KEY"] = "sonradan-eklendi"
    assert virustotal.is_enabled() is True
    assert virustotal.get_api_key() == "sonradan-eklendi"


def test_environment_variable_beats_env_file(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "ortamdan")
    monkeypatch.setattr(virustotal, "dotenv_values", lambda *a, **k: {"VIRUSTOTAL_API_KEY": "dosyadan"})
    assert virustotal.get_api_key() == "ortamdan"


# -- basarili sorgu ve verdict ------------------------------------------------

def test_successful_lookup_parses_stats(monkeypatch):
    monkeypatch.setattr(virustotal.requests, "get", lambda *a, **k: fake_response(200, OK_PAYLOAD))

    rep = lookup_ip("8.8.8.8")
    assert rep.status == "ok"
    assert (rep.malicious, rep.suspicious, rep.harmless) == (3, 1, 60)
    assert rep.country == "RU"
    assert rep.verdict == "Zararli (3 motor)"


def test_verdict_prefers_malicious_then_suspicious_then_clean():
    assert IpReputation("x", "ok", malicious=2, suspicious=5).verdict == "Zararli (2 motor)"
    assert IpReputation("x", "ok", malicious=0, suspicious=5).verdict == "Supheli (5 motor)"
    assert IpReputation("x", "ok").verdict == "Temiz"


# -- hatalar akisi kesmemeli ---------------------------------------------------

def test_network_error_returns_error_status_without_raising(monkeypatch):
    def boom(*args, **kwargs):
        raise requests.ConnectionError("ag yok")

    monkeypatch.setattr(virustotal.requests, "get", boom)
    rep = lookup_ip("8.8.8.8")
    assert rep.status == "error"
    assert rep.verdict == "Sorgulanamadi"


def test_unparseable_response_is_reported_as_error(monkeypatch):
    monkeypatch.setattr(virustotal.requests, "get", lambda *a, **k: fake_response(200, None))
    assert lookup_ip("8.8.8.8").status == "error"


def test_not_found_is_distinct_from_error(monkeypatch):
    monkeypatch.setattr(virustotal.requests, "get", lambda *a, **k: fake_response(404))
    assert lookup_ip("8.8.8.8").verdict == "VirusTotal'de kayit yok"


# -- onbellek ve kota ----------------------------------------------------------

def test_successful_result_is_cached(monkeypatch):
    calls = []

    def counting_get(*args, **kwargs):
        calls.append(args)
        return fake_response(200, OK_PAYLOAD)

    monkeypatch.setattr(virustotal.requests, "get", counting_get)
    lookup_ip("8.8.8.8")
    lookup_ip("8.8.8.8")
    assert len(calls) == 1


def test_transient_failures_are_not_cached(monkeypatch):
    """Kota/ag hatasi onbellege girerse IP kalici olarak hatali gorunurdu."""
    monkeypatch.setattr(virustotal.requests, "get", lambda *a, **k: fake_response(429))
    assert lookup_ip("8.8.8.8").status == "rate_limited"

    monkeypatch.setattr(virustotal.requests, "get", lambda *a, **k: fake_response(200, OK_PAYLOAD))
    assert lookup_ip("8.8.8.8").status == "ok"


def test_max_lookups_caps_network_requests(monkeypatch):
    calls = []
    monkeypatch.setattr(virustotal.requests, "get",
                        lambda *a, **k: (calls.append(a), fake_response(200, OK_PAYLOAD))[1])

    ips = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "93.184.216.34"]
    result = lookup_ips(ips, max_lookups=2)

    assert len(calls) == 2
    assert len(result.reputations) == 2
    assert result.skipped_over_limit == ["9.9.9.9", "93.184.216.34"]


def test_rate_limit_stops_further_lookups(monkeypatch):
    monkeypatch.setattr(virustotal.requests, "get", lambda *a, **k: fake_response(429))
    result = lookup_ips(["8.8.8.8", "1.1.1.1", "9.9.9.9"])

    assert len(result.reputations) == 1
    assert result.skipped_over_limit == ["1.1.1.1", "9.9.9.9"]


def test_duplicate_ips_are_queried_once(monkeypatch):
    calls = []
    monkeypatch.setattr(virustotal.requests, "get",
                        lambda *a, **k: (calls.append(a), fake_response(200, OK_PAYLOAD))[1])

    result = lookup_ips(["8.8.8.8", "8.8.8.8", " 8.8.8.8 "])
    assert len(calls) == 1
    assert len(result.reputations) == 1


def test_api_key_is_sent_in_header_not_url(monkeypatch):
    """Anahtar URL'e girerse proxy/sunucu loglarina duser."""
    seen = {}

    def capture(url, headers=None, timeout=None):
        seen["url"] = url
        seen["headers"] = headers or {}
        return fake_response(200, OK_PAYLOAD)

    monkeypatch.setattr(virustotal.requests, "get", capture)
    lookup_ip("8.8.8.8")

    assert seen["headers"].get("x-apikey") == "test-key"
    assert "test-key" not in seen["url"]
