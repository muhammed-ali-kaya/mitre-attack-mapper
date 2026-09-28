from __future__ import annotations

import requests

from app.llm import ollama_client


class FakeResponse:
    def __init__(self, payload, status_ok=True):
        self._payload = payload
        self._status_ok = status_ok

    def raise_for_status(self):
        if not self._status_ok:
            raise requests.exceptions.HTTPError("bad status")

    def json(self):
        return self._payload


def _no_sleep(monkeypatch):
    monkeypatch.setattr(ollama_client.time, "sleep", lambda seconds: None)


def test_chat_returns_response_json_on_first_success(monkeypatch):
    _no_sleep(monkeypatch)
    calls = []

    def fake_post(url, json, timeout):
        calls.append((url, json, timeout))
        return FakeResponse({"message": {"content": "ok"}})

    monkeypatch.setattr(ollama_client.requests, "post", fake_post)

    result = ollama_client.chat(model="qwen3:8b", system="sys", user="hello")

    assert result == {"message": {"content": "ok"}}
    assert len(calls) == 1


def test_chat_builds_expected_payload(monkeypatch):
    _no_sleep(monkeypatch)
    captured = {}

    def fake_post(url, json, timeout):
        captured["url"] = url
        captured["json"] = json
        captured["timeout"] = timeout
        return FakeResponse({"ok": True})

    monkeypatch.setattr(ollama_client.requests, "post", fake_post)

    schema = {"type": "object"}
    options = {"temperature": 0}
    ollama_client.chat(
        model="qwen3:8b", system="sys", user="hello",
        json_schema=schema, options=options, timeout=42, think=True,
    )

    assert captured["url"] == f"{ollama_client.OLLAMA_HOST}/api/chat"
    assert captured["timeout"] == 42
    payload = captured["json"]
    assert payload["model"] == "qwen3:8b"
    assert payload["messages"] == [{"role": "system", "content": "sys"}, {"role": "user", "content": "hello"}]
    assert payload["stream"] is False
    assert payload["think"] is True
    assert payload["format"] == schema
    assert payload["options"] == options


def test_chat_omits_format_but_applies_deterministic_options_by_default(monkeypatch):
    """Options gonderilmedigi surece model kendi varsayilan sicakligiyla
    orneklem yapiyordu; ayni girdi kosudan kosuya farkli sonuc veriyor ve
    evaluation karsilastirmalarini olcuemez hale getiriyordu."""
    _no_sleep(monkeypatch)
    captured = {}

    def fake_post(url, json, timeout):
        captured["json"] = json
        return FakeResponse({"ok": True})

    monkeypatch.setattr(ollama_client.requests, "post", fake_post)
    ollama_client.chat(model="m", system="s", user="u")

    assert "format" not in captured["json"]
    assert captured["json"]["options"] == ollama_client.DETERMINISTIC_OPTIONS
    assert captured["json"]["options"]["temperature"] == 0


def test_chat_retries_on_read_timeout_then_succeeds(monkeypatch):
    _no_sleep(monkeypatch)
    attempts = {"count": 0}

    def fake_post(url, json, timeout):
        attempts["count"] += 1
        if attempts["count"] < 2:
            raise requests.exceptions.ReadTimeout("timed out")
        return FakeResponse({"message": "recovered"})

    monkeypatch.setattr(ollama_client.requests, "post", fake_post)

    result = ollama_client.chat(model="m", system="s", user="u", max_retries=2)

    assert result == {"message": "recovered"}
    assert attempts["count"] == 2


def test_chat_retries_on_connection_error(monkeypatch):
    _no_sleep(monkeypatch)
    attempts = {"count": 0}

    def fake_post(url, json, timeout):
        attempts["count"] += 1
        if attempts["count"] < 2:
            raise requests.exceptions.ConnectionError("refused")
        return FakeResponse({"ok": True})

    monkeypatch.setattr(ollama_client.requests, "post", fake_post)

    result = ollama_client.chat(model="m", system="s", user="u", max_retries=2)
    assert result == {"ok": True}


def test_chat_raises_after_exhausting_retries(monkeypatch):
    _no_sleep(monkeypatch)
    attempts = {"count": 0}

    def fake_post(url, json, timeout):
        attempts["count"] += 1
        raise requests.exceptions.ReadTimeout("still timing out")

    monkeypatch.setattr(ollama_client.requests, "post", fake_post)

    try:
        ollama_client.chat(model="m", system="s", user="u", max_retries=2)
        assert False, "expected ReadTimeout to propagate"
    except requests.exceptions.ReadTimeout:
        pass

    assert attempts["count"] == 3  # initial attempt + 2 retries


def test_chat_does_not_retry_non_network_errors(monkeypatch):
    _no_sleep(monkeypatch)
    attempts = {"count": 0}

    def fake_post(url, json, timeout):
        attempts["count"] += 1
        return FakeResponse({}, status_ok=False)

    monkeypatch.setattr(ollama_client.requests, "post", fake_post)

    try:
        ollama_client.chat(model="m", system="s", user="u", max_retries=2)
        assert False, "expected HTTPError to propagate immediately"
    except requests.exceptions.HTTPError:
        pass

    assert attempts["count"] == 1


def test_chat_backoff_grows_with_attempt_number(monkeypatch):
    sleeps = []
    monkeypatch.setattr(ollama_client.time, "sleep", lambda seconds: sleeps.append(seconds))
    attempts = {"count": 0}

    def fake_post(url, json, timeout):
        attempts["count"] += 1
        if attempts["count"] < 3:
            raise requests.exceptions.ReadTimeout("timeout")
        return FakeResponse({"ok": True})

    monkeypatch.setattr(ollama_client.requests, "post", fake_post)

    ollama_client.chat(model="m", system="s", user="u", max_retries=2, retry_backoff_seconds=5.0)

    assert sleeps == [5.0, 10.0]


def test_chat_turn_returns_reply_text_not_raw_response(monkeypatch):
    _no_sleep(monkeypatch)

    def fake_post(url, json, timeout):
        return FakeResponse({"message": {"role": "assistant", "content": "Bu T1053 cunku..."}})

    monkeypatch.setattr(ollama_client.requests, "post", fake_post)

    reply = ollama_client.chat_turn(model="m", system="s", history=[{"role": "user", "content": "neden bu teknik?"}])

    assert reply == "Bu T1053 cunku..."


def test_chat_turn_sends_system_plus_full_history_without_json_schema(monkeypatch):
    _no_sleep(monkeypatch)
    captured = {}

    def fake_post(url, json, timeout):
        captured["json"] = json
        return FakeResponse({"message": {"content": "ok"}})

    monkeypatch.setattr(ollama_client.requests, "post", fake_post)

    history = [
        {"role": "user", "content": "ilk soru"},
        {"role": "assistant", "content": "ilk cevap"},
        {"role": "user", "content": "ikinci soru"},
    ]
    ollama_client.chat_turn(model="m", system="sistem talimati", history=history)

    payload = captured["json"]
    assert payload["messages"][0] == {"role": "system", "content": "sistem talimati"}
    assert payload["messages"][1:] == history
    assert "format" not in payload


def test_chat_turn_retries_on_read_timeout(monkeypatch):
    _no_sleep(monkeypatch)
    attempts = {"count": 0}

    def fake_post(url, json, timeout):
        attempts["count"] += 1
        if attempts["count"] < 2:
            raise requests.exceptions.ReadTimeout("timed out")
        return FakeResponse({"message": {"content": "recovered"}})

    monkeypatch.setattr(ollama_client.requests, "post", fake_post)

    reply = ollama_client.chat_turn(model="m", system="s", history=[{"role": "user", "content": "?"}], max_retries=2)

    assert reply == "recovered"
    assert attempts["count"] == 2


# -- token muhasebesi ----------------------------------------------------------

def test_usage_since_counts_prompt_and_completion_tokens(monkeypatch):
    _no_sleep(monkeypatch)
    monkeypatch.setattr(
        ollama_client.requests, "post",
        lambda url, json, timeout: FakeResponse(
            {"message": {"content": "ok"}, "prompt_eval_count": 4200, "eval_count": 180}
        ),
    )

    snapshot = ollama_client.usage_snapshot()
    ollama_client.chat(model="m", system="s", user="u")
    usage = ollama_client.usage_since(snapshot)

    assert usage == {
        "prompt_tokens": 4200, "completion_tokens": 180, "calls": 1, "total_tokens": 4380,
    }


def test_usage_since_toplar_birden_fazla_cagriyi(monkeypatch):
    """Tek bir kullanici girdisi eslestirme + ceviri gibi birden fazla LLM
    cagrisi tetikleyebiliyor; arayuzde gosterilen sayi bunlarin toplami."""
    _no_sleep(monkeypatch)
    monkeypatch.setattr(
        ollama_client.requests, "post",
        lambda url, json, timeout: FakeResponse(
            {"message": {"content": "ok"}, "prompt_eval_count": 100, "eval_count": 20}
        ),
    )

    snapshot = ollama_client.usage_snapshot()
    ollama_client.chat(model="m", system="s", user="u")
    ollama_client.chat_turn(model="m", system="s", history=[{"role": "user", "content": "?"}])

    assert ollama_client.usage_since(snapshot) == {
        "prompt_tokens": 200, "completion_tokens": 40, "calls": 2, "total_tokens": 240,
    }


def test_usage_eksik_alanlari_sifir_sayar(monkeypatch):
    """Token alanlari gelmezse analiz dusmemeli -- gosterim bir raporlama detayi."""
    _no_sleep(monkeypatch)
    monkeypatch.setattr(
        ollama_client.requests, "post",
        lambda url, json, timeout: FakeResponse({"message": {"content": "ok"}}),
    )

    snapshot = ollama_client.usage_snapshot()
    ollama_client.chat(model="m", system="s", user="u")

    assert ollama_client.usage_since(snapshot)["total_tokens"] == 0


def test_basarisiz_deneme_token_saymaz(monkeypatch):
    """Timeout ile dusen deneme token uretmedi; yalnizca basarili yanit sayilir."""
    _no_sleep(monkeypatch)
    attempts = {"count": 0}

    def fake_post(url, json, timeout):
        attempts["count"] += 1
        if attempts["count"] < 2:
            raise requests.exceptions.ReadTimeout("timed out")
        return FakeResponse({"message": {"content": "ok"}, "prompt_eval_count": 50, "eval_count": 10})

    monkeypatch.setattr(ollama_client.requests, "post", fake_post)

    snapshot = ollama_client.usage_snapshot()
    ollama_client.chat(model="m", system="s", user="u", max_retries=2)

    assert ollama_client.usage_since(snapshot)["calls"] == 1


# -- gecici sunucu hatalari (5xx) ---------------------------------------------

class FakeHttpErrorResponse:
    """raise_for_status'u gercek requests gibi, status kodu tasiyan bir
    HTTPError ile patlatir."""

    def __init__(self, status_code):
        self.status_code = status_code

    def raise_for_status(self):
        raise requests.exceptions.HTTPError(f"HTTP {self.status_code}", response=self)

    def json(self):
        raise AssertionError("hatali yanitin govdesi okunmamali")


def test_chat_retries_on_server_error_then_succeeds(monkeypatch):
    """Eval kosusunda Ollama tek bir senaryoda 500 dondurup senaryoyu tamamen
    dusurmustu; 5xx tam olarak retry'in var olma sebebi."""
    _no_sleep(monkeypatch)
    responses = [FakeHttpErrorResponse(500), FakeResponse({"message": {"content": "ok"}})]
    calls = []

    def fake_post(url, json, timeout):
        calls.append(url)
        return responses[len(calls) - 1]

    monkeypatch.setattr(ollama_client.requests, "post", fake_post)

    assert ollama_client.chat(model="m", system="s", user="u") == {"message": {"content": "ok"}}
    assert len(calls) == 2


def test_chat_does_not_retry_client_errors(monkeypatch):
    """4xx istegin kendisinin bozuk oldugunu soyler -- tekrar gondermek ayni
    sonucu verir, kotu bir istegi 3 kez yollamis oluruz."""
    _no_sleep(monkeypatch)
    attempts = {"count": 0}

    def fake_post(url, json, timeout):
        attempts["count"] += 1
        return FakeHttpErrorResponse(400)

    monkeypatch.setattr(ollama_client.requests, "post", fake_post)

    try:
        ollama_client.chat(model="m", system="s", user="u", max_retries=2)
        assert False, "4xx hemen yukselmeliydi"
    except requests.exceptions.HTTPError:
        pass

    assert attempts["count"] == 1


def test_chat_raises_after_exhausting_server_error_retries(monkeypatch):
    _no_sleep(monkeypatch)
    attempts = {"count": 0}

    def fake_post(url, json, timeout):
        attempts["count"] += 1
        return FakeHttpErrorResponse(503)

    monkeypatch.setattr(ollama_client.requests, "post", fake_post)

    try:
        ollama_client.chat(model="m", system="s", user="u", max_retries=2)
        assert False, "denemeler bitince hata yukselmeliydi"
    except requests.exceptions.HTTPError:
        pass

    assert attempts["count"] == 3
