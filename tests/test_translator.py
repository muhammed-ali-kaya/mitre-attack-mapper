from __future__ import annotations

import json

from app.llm import translator
from app.llm.translator import (
    apply_translations,
    build_translation_items,
    translate_llm_output_to_turkish,
    translate_reference_texts,
    translate_texts_to_turkish,
)

SAMPLE_LLM_OUTPUT = {
    "observed_behaviors": ["schtasks.exe was executed", "remote target detected"],
    "mappings": [
        {"attack_id": "T1053", "name": "Scheduled Task/Job", "reasoning_summary": "Because of the command."},
        {"attack_id": "T1059.001", "name": "PowerShell", "reasoning_summary": "PowerShell was used."},
    ],
    "alternative_candidates": [
        {"attack_id": "T1027", "name": "Obfuscation", "reason_not_selected": "No evidence of obfuscation."},
    ],
    "additional_data_needed": ["Process parent chain"],
}


# -- build_translation_items / apply_translations (pure, no network) ---------

def test_build_translation_items_collects_all_free_text_fields_in_order():
    items = build_translation_items(SAMPLE_LLM_OUTPUT)
    assert items == [
        "schtasks.exe was executed",
        "remote target detected",
        "Because of the command.",
        "PowerShell was used.",
        "No evidence of obfuscation.",
        "Process parent chain",
    ]


def test_build_translation_items_handles_missing_optional_lists():
    minimal = {"mappings": [{"attack_id": "T1053", "reasoning_summary": "x"}]}
    assert build_translation_items(minimal) == ["x"]


def test_apply_translations_writes_back_in_the_same_order():
    turkish = [
        "schtasks.exe calistirildi",
        "uzak hedef tespit edildi",
        "Komut nedeniyle.",
        "PowerShell kullanildi.",
        "Gizleme kaniti yok.",
        "Process parent zinciri",
    ]

    result = apply_translations(SAMPLE_LLM_OUTPUT, turkish)

    assert result["observed_behaviors"] == ["schtasks.exe calistirildi", "uzak hedef tespit edildi"]
    assert result["mappings"][0]["reasoning_summary"] == "Komut nedeniyle."
    assert result["mappings"][1]["reasoning_summary"] == "PowerShell kullanildi."
    assert result["alternative_candidates"][0]["reason_not_selected"] == "Gizleme kaniti yok."
    assert result["additional_data_needed"] == ["Process parent zinciri"]


def test_apply_translations_does_not_touch_attack_ids_or_names():
    turkish = ["a", "b", "c", "d", "e", "f"]
    result = apply_translations(SAMPLE_LLM_OUTPUT, turkish)
    assert result["mappings"][0]["attack_id"] == "T1053"
    assert result["mappings"][0]["name"] == "Scheduled Task/Job"


def test_apply_translations_does_not_mutate_original_dict():
    turkish = ["a", "b", "c", "d", "e", "f"]
    apply_translations(SAMPLE_LLM_OUTPUT, turkish)
    assert SAMPLE_LLM_OUTPUT["mappings"][0]["reasoning_summary"] == "Because of the command."


# -- translate_texts_to_turkish (mocked network) ------------------------------

def test_translate_texts_to_turkish_returns_translations_on_success(monkeypatch):
    def fake_chat(model, system, user, json_schema=None, think=False):
        return {"message": {"content": json.dumps({"translations": ["merhaba", "dunya"]})}}

    monkeypatch.setattr(translator, "chat", fake_chat)

    result = translate_texts_to_turkish(["hello", "world"])
    assert result == ["merhaba", "dunya"]


def test_translate_texts_to_turkish_returns_none_on_length_mismatch(monkeypatch):
    def fake_chat(model, system, user, json_schema=None, think=False):
        return {"message": {"content": json.dumps({"translations": ["sadece-bir-tane"]})}}

    monkeypatch.setattr(translator, "chat", fake_chat)

    result = translate_texts_to_turkish(["hello", "world"])
    assert result is None


def test_translate_texts_to_turkish_returns_none_on_network_error(monkeypatch):
    def fake_chat(model, system, user, json_schema=None, think=False):
        raise ConnectionError("ollama down")

    monkeypatch.setattr(translator, "chat", fake_chat)

    result = translate_texts_to_turkish(["hello"])
    assert result is None


def test_translate_texts_to_turkish_skips_call_for_all_empty_input(monkeypatch):
    calls = []
    monkeypatch.setattr(translator, "chat", lambda *a, **k: calls.append(1))

    result = translate_texts_to_turkish(["", ""])
    assert result == ["", ""]
    assert calls == []


# -- translate_llm_output_to_turkish (end-to-end wiring, mocked network) -----

def test_translate_llm_output_to_turkish_applies_successful_translation(monkeypatch):
    def fake_chat(model, system, user, json_schema=None, think=False):
        return {"message": {"content": json.dumps({"translations": [
            "schtasks.exe calistirildi", "uzak hedef tespit edildi",
            "Komut nedeniyle.", "PowerShell kullanildi.",
            "Gizleme kaniti yok.", "Process parent zinciri",
        ]})}}

    monkeypatch.setattr(translator, "chat", fake_chat)

    result = translate_llm_output_to_turkish(SAMPLE_LLM_OUTPUT)
    assert result["mappings"][0]["reasoning_summary"] == "Komut nedeniyle."


def test_translate_llm_output_to_turkish_falls_back_to_original_on_failure(monkeypatch):
    def fake_chat(model, system, user, json_schema=None, think=False):
        raise ConnectionError("ollama down")

    monkeypatch.setattr(translator, "chat", fake_chat)

    result = translate_llm_output_to_turkish(SAMPLE_LLM_OUTPUT)
    assert result == SAMPLE_LLM_OUTPUT


def test_translate_llm_output_to_turkish_noop_when_nothing_to_translate():
    calls = []
    result = translate_llm_output_to_turkish({"mappings": []})
    assert result == {"mappings": []}


# -- translate_reference_texts (resmi MITRE metinleri, onbellekli) ------------

def test_translate_reference_texts_caches_per_text(monkeypatch):
    """Ayni teknigin detection metni her sorguda ayni geldigi icin ikinci
    cagri LLM'e hic gitmemeli."""
    translator._REFERENCE_CACHE.clear()
    calls = []

    def fake_chat(*args, **kwargs):
        calls.append(args)
        return {"message": {"content": json.dumps({"translations": ["Turkce metin"]})}}

    monkeypatch.setattr(translator, "chat", fake_chat)

    assert translate_reference_texts(["Monitor process creation"]) == ["Turkce metin"]
    assert translate_reference_texts(["Monitor process creation"]) == ["Turkce metin"]
    assert len(calls) == 1


def test_translate_reference_texts_returns_none_on_failure(monkeypatch):
    translator._REFERENCE_CACHE.clear()
    monkeypatch.setattr(translator, "chat", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("ag hatasi")))
    assert translate_reference_texts(["Monitor process creation"]) is None


def test_translate_reference_texts_deduplicates_repeated_texts(monkeypatch):
    """Ayni metin listede iki kez gecerse cevirmene bir kez gonderilmeli."""
    translator._REFERENCE_CACHE.clear()
    sent = []

    def fake_chat(model, system, user, **kwargs):
        sent.append(json.loads(user.split("\n", 1)[1]))
        return {"message": {"content": json.dumps({"translations": ["A-tr", "B-tr"]})}}

    monkeypatch.setattr(translator, "chat", fake_chat)

    result = translate_reference_texts(["A", "B", "A"])
    assert result == ["A-tr", "B-tr", "A-tr"]
    assert sent == [["A", "B"]]
