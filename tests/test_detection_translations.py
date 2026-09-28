from __future__ import annotations

import json

from app.llm import translator
from app.llm.detection_translations import load_curated_translations
from tests.generated_data import requires_attack_data


def _write(tmp_path, payload):
    path = tmp_path / "detection_tr.json"
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return path


def test_load_returns_english_to_turkish_mapping(tmp_path):
    path = _write(tmp_path, {"entries": {"T1053.005": {"en": "Detects scheduled tasks", "tr": "Zamanlanmis gorevleri tespit eder"}}})
    assert load_curated_translations(path) == {"Detects scheduled tasks": "Zamanlanmis gorevleri tespit eder"}


def test_load_skips_untranslated_entries(tmp_path):
    """Yarim doldurulmus dosya bos metin gostermemeli -- cevirisi olmayan kayit
    yok sayilir ve LLM cevirisine duser."""
    path = _write(tmp_path, {"entries": {
        "T1078": {"en": "Detects valid accounts", "tr": ""},
        "T1110": {"en": "Detects brute force", "tr": "Kaba kuvveti tespit eder"},
    }})
    assert load_curated_translations(path) == {"Detects brute force": "Kaba kuvveti tespit eder"}


def test_load_returns_empty_when_file_missing(tmp_path):
    assert load_curated_translations(tmp_path / "yok.json") == {}


def test_load_returns_empty_on_corrupt_file(tmp_path):
    """Ceviri bir sunum detayi; bozuk dosya analizi dusurmemeli."""
    path = tmp_path / "bozuk.json"
    path.write_text("{ bu json degil", encoding="utf-8")
    assert load_curated_translations(path) == {}


# -- translator ile birlikte ---------------------------------------------------

def _reset_translator_state(monkeypatch, curated):
    monkeypatch.setattr(translator, "_REFERENCE_CACHE", {})
    monkeypatch.setattr(translator, "_curated_loaded", False)
    monkeypatch.setattr(translator, "load_curated_translations", lambda: curated)


def test_curated_translation_skips_llm_call(monkeypatch):
    """Asil kazanc bu: dosyada karsiligi olan metin icin LLM'e hic gidilmiyor."""
    _reset_translator_state(monkeypatch, {"Detects scheduled tasks": "Zamanlanmis gorevleri tespit eder"})

    def fail_if_called(*args, **kwargs):
        raise AssertionError("elle hazirlanmis ceviri varken LLM cagrilmamali")

    monkeypatch.setattr(translator, "chat", fail_if_called)

    assert translator.translate_reference_texts(["Detects scheduled tasks"]) == [
        "Zamanlanmis gorevleri tespit eder"
    ]


def test_falls_back_to_llm_for_texts_not_in_file(monkeypatch):
    _reset_translator_state(monkeypatch, {"Detects scheduled tasks": "Zamanlanmis gorevleri tespit eder"})
    monkeypatch.setattr(
        translator, "chat",
        lambda *args, **kwargs: {"message": {"content": json.dumps({"translations": ["LLM cevirisi"]})}},
    )

    result = translator.translate_reference_texts(["Detects scheduled tasks", "Detects something new"])

    assert result == ["Zamanlanmis gorevleri tespit eder", "LLM cevirisi"]


def test_curated_file_is_loaded_only_once(monkeypatch):
    loads = {"count": 0}

    def counting_loader():
        loads["count"] += 1
        return {"Detects scheduled tasks": "Zamanlanmis gorevleri tespit eder"}

    monkeypatch.setattr(translator, "_REFERENCE_CACHE", {})
    monkeypatch.setattr(translator, "_curated_loaded", False)
    monkeypatch.setattr(translator, "load_curated_translations", counting_loader)

    translator.translate_reference_texts(["Detects scheduled tasks"])
    translator.translate_reference_texts(["Detects scheduled tasks"])

    assert loads["count"] == 1


def test_lookup_never_calls_llm_even_when_translation_missing(monkeypatch):
    """Cizim yolunun degismez kurali: LLM'e GIDILMEZ. Eskiden cizim sirasinda
    yapilan ceviri cagrisi (190 sn'ye kadar) toplu analizde sayfayi pratikte
    cizilemez hale getiriyordu."""
    _reset_translator_state(monkeypatch, {"Detects scheduled tasks": "Zamanlanmis gorevleri tespit eder"})

    def fail_if_called(*args, **kwargs):
        raise AssertionError("cizim sirasinda LLM cagrilmamali")

    monkeypatch.setattr(translator, "chat", fail_if_called)

    assert translator.lookup_reference_translation("Detects scheduled tasks") == "Zamanlanmis gorevleri tespit eder"
    assert translator.lookup_reference_translation("Bu metnin cevirisi yok") is None


def test_lookup_sees_translations_made_earlier_in_the_session(monkeypatch):
    """Kullanici bir metni acikca cevirtince sonuc onbellege giriyor; ayni
    metin baska bir satirda gorununce artik hazir geliyor."""
    _reset_translator_state(monkeypatch, {})
    monkeypatch.setattr(
        translator, "chat",
        lambda *args, **kwargs: {"message": {"content": json.dumps({"translations": ["Ceviri"]})}},
    )

    assert translator.lookup_reference_translation("Detects something") is None
    translator.translate_reference_texts(["Detects something"])
    assert translator.lookup_reference_translation("Detects something") == "Ceviri"


# -- gercek dosya --------------------------------------------------------------

@requires_attack_data
def test_shipped_file_matches_current_attack_data():
    """Dosyadaki 'en' metinleri ATT&CK verisiyle birebir eslesmezse ceviriler
    calisma aninda sessizce devre disi kalir -- bu testin amaci o sessiz
    bozulmayi yakalamak."""
    from app.llm.detection_translations import TRANSLATIONS_PATH
    from app.validation.validator import AttackKnowledgeBase

    document = json.loads(TRANSLATIONS_PATH.read_text(encoding="utf-8"))
    kb = AttackKnowledgeBase()

    mismatched = [
        attack_id for attack_id, entry in document["entries"].items()
        if (kb.by_id.get(attack_id, {}).get("detection") or "").strip() != entry["en"].strip()
    ]
    assert mismatched == []
