"""LLM ciktisindaki serbest metin alanlarini (reasoning_summary, observed_behaviors,
reason_not_selected, additional_data_needed) ayri, dar kapsamli bir LLM cagrisiyla
Turkce'ye cevirir.

Neden ayri bir adim: SYSTEM_PROMPT icinde "Turkce yaz" talimati (bkz.
app/llm/prompts.py) kucuk local modelde (qwen3:8b) guvenilir calismiyor -- KAYNAK
VERI blogu Ingilizce oldugu icin model baskin dile kayiyor (gercek testte
dogrulandi). Ceviri, "serbest metin URET" gorevinden daha dar/basit bir gorev
oldugu icin ayri bir cagriyla daha guvenilir calismasi beklenir.

Guvenlik agi: ceviri sayisi girdi sayisiyla eslesmezse (model format hatasi
yaparsa), orijinal Ingilizce metinler DEGISTIRILMEDEN birakilir -- yanlis
hizalanmis/karisik bir ceviri, hic ceviri olmamasindan daha kotudur.

"evidence" (girdiden birebir alinti) ve ATT&CK teknik adlari/ID'leri/resmi
terminoloji bu modulun kapsami DISINDA -- hic dokunulmaz.
"""

from __future__ import annotations

import json
from typing import Any

from app.llm.detection_translations import load_curated_translations
from app.llm.ollama_client import chat

TRANSLATION_MODEL = "qwen3:8b"

TRANSLATION_SCHEMA = {
    "type": "object",
    "properties": {"translations": {"type": "array", "items": {"type": "string"}}},
    "required": ["translations"],
}

TRANSLATION_SYSTEM_PROMPT = """Sana bir JSON dizi icinde Ingilizce metin parcalari \
verilecek. Her birini Turkce'ye cevir.

KURALLAR:
- MITRE ATT&CK teknik adlarini, ID'lerini (orn. "T1053", "Scheduled Task/Job",
  "M1028"), dosya/komut/arac adlari gibi ozel adlari/terminolojiyi CEVIRME,
  oldugu gibi birak.
- Metnin anlamini ve uzunlugunu koru -- yeniden yazma veya ozetleme, sadece
  cevir.
- Girdide bos string varsa ciktida da o pozisyonda bos string birak.
- Cikti (translations) girdiyle AYNI SAYIDA ve AYNI SIRADA metin icermeli --
  hicbirini atlama, birlestirme, veya yeniden siralama.

TERIM SOZLUGU (bu kaliplari asagidaki gibi cevir):
- scheduled task -> zamanlanmis gorev
- credential dumping -> kimlik bilgisi cikarma
- lateral movement -> yanal hareket
- privilege escalation -> yetki yukseltme
- persistence -> kalicilik
- payload -> zararli yuk
- process creation -> surec olusturma
- command line -> komut satiri
- registry key -> kayit defteri anahtari
- event log -> olay gunlugu
- endpoint -> uc nokta
- threat actor -> tehdit aktoru
- detection -> tespit"""


def build_translation_items(llm_output: dict[str, Any]) -> list[str]:
    """LLM cikti sozlugunden, Turkce'ye cevrilecek serbest metinleri sabit bir
    sirada cikarir (apply_translations ile bire bir eslesmesi gerekir)."""
    items: list[str] = []
    items.extend(llm_output.get("observed_behaviors") or [])
    for m in llm_output.get("mappings") or []:
        items.append(m.get("reasoning_summary") or "")
    for alt in llm_output.get("alternative_candidates") or []:
        items.append(alt.get("reason_not_selected") or "")
    items.extend(llm_output.get("additional_data_needed") or [])
    return items


def apply_translations(llm_output: dict[str, Any], translations: list[str]) -> dict[str, Any]:
    """Cevirileri, build_translation_items ile ayni sirayla llm_output'a geri yazar.
    len(translations) != len(build_translation_items(llm_output)) ise cagiran
    taraf bu fonksiyonu hic cagirmamalidir (bkz. translate_texts_to_turkish)."""
    result = dict(llm_output)
    idx = 0

    behaviors = result.get("observed_behaviors") or []
    result["observed_behaviors"] = list(translations[idx : idx + len(behaviors)])
    idx += len(behaviors)

    mappings = [dict(m) for m in (result.get("mappings") or [])]
    for m in mappings:
        m["reasoning_summary"] = translations[idx]
        idx += 1
    result["mappings"] = mappings

    alternatives = [dict(a) for a in (result.get("alternative_candidates") or [])]
    for a in alternatives:
        a["reason_not_selected"] = translations[idx]
        idx += 1
    result["alternative_candidates"] = alternatives

    additional = result.get("additional_data_needed") or []
    result["additional_data_needed"] = list(translations[idx : idx + len(additional)])
    idx += len(additional)

    return result


def translate_texts_to_turkish(texts: list[str]) -> list[str] | None:
    """Ceviriyi dener. Basarisiz olursa (agdan hata, ya da model uzunluk
    kurallarina uymazsa) None doner -- cagiran taraf orijinal Ingilizce
    metinleri degistirmeden kullanmali."""
    if not texts or not any(t.strip() for t in texts):
        return texts

    user_prompt = "Cevrilecek metinler (JSON dizi, ayni sirayla cevir):\n" + json.dumps(texts, ensure_ascii=False)
    try:
        response = chat(
            TRANSLATION_MODEL, TRANSLATION_SYSTEM_PROMPT, user_prompt,
            json_schema=TRANSLATION_SCHEMA, think=False,
        )
        translated = json.loads(response["message"]["content"])["translations"]
    except Exception:
        return None

    if len(translated) != len(texts):
        return None
    return translated


# MITRE'nin resmi "detection" metni Ingilizce geliyor ve arayuzde oldugu gibi
# gosteriliyordu. Bu metin modulun geri kalanindan farkli bir sey: LLM'in
# URETTIGI degil, otoriter kaynak veri. Bu yuzden ceviri orijinalin YERINE
# gecmiyor, yanina konuyor -- cagiran taraf ikisini de saklayip arayuzde
# orijinale erisim birakmali (bkz. app/ui/render.py).
_REFERENCE_CACHE: dict[str, str] = {}
_curated_loaded = False


def _ensure_curated_loaded() -> None:
    """Elle hazirlanmis cevirileri onbellege bir kez yukler.

    Onbellege yuklemek, "once dosyaya bak, sonra LLM'e sor" mantigini ayrica
    yazmaktan daha basit: asagidaki 'missing' hesabi zaten onbellekte olmayani
    ariyor, dolayisiyla dosyadan gelen her kayit otomatik olarak LLM cagrisini
    engeller. Dosyada olmayan teknikler icin LLM yolu aynen devrede kalir."""
    global _curated_loaded
    if _curated_loaded:
        return
    _REFERENCE_CACHE.update(load_curated_translations())
    _curated_loaded = True


def lookup_reference_translation(text: str) -> str | None:
    """Hazir ceviriyi dondurur; yoksa None -- LLM'E GITMEZ, aninda doner.

    Neden ayri bir fonksiyon: ekran cizimi sirasinda LLM cagirmak arayuz
    gecikmesini sinirsiz hale getiriyordu. Olculdu: elle cevrilmemis tek bir
    teknigin cevirisi 190 saniye surebiliyor (model yeniden yuklenmesiyle).
    Toplu analizde 51 satirin her biri icin bu tekrarlanınca sayfa saatlerce
    cizilemiyor, satirlar tek tek dusuyor ve arkadaki incident sekmesine hic
    sira gelmiyordu. Cizim artik yalnizca HAZIR olani gosteriyor; ceviri
    gerekiyorsa kullanici acikca istiyor (bkz. app/ui/render.py)."""
    _ensure_curated_loaded()
    return _REFERENCE_CACHE.get(text)


def translate_reference_texts(texts: list[str]) -> list[str] | None:
    """Resmi MITRE metinlerini cevirir; basarisiz olursa None doner.

    Once elle hazirlanmis ceviri dosyasina bakar (bkz.
    app/llm/detection_translations.py), orada bulunmayan metinleri LLM'e cevirtir.

    Ayni teknigin detection metni her sorguda birebir ayni geldigi icin sonuc
    onbellege alinir -- aksi halde her sorgu, degismeyecek bir metin icin
    yeniden LLM cagiriyor olurdu."""
    if not texts:
        return texts

    _ensure_curated_loaded()

    missing = [t for t in dict.fromkeys(texts) if t and t not in _REFERENCE_CACHE]
    if missing:
        translated = translate_texts_to_turkish(missing)
        if translated is None:
            return None
        _REFERENCE_CACHE.update(zip(missing, translated))

    return [_REFERENCE_CACHE.get(t, t) if t else t for t in texts]


def translate_llm_output_to_turkish(llm_output: dict[str, Any]) -> dict[str, Any]:
    """build_translation_items + translate_texts_to_turkish + apply_translations'i
    zincirler. Ceviri basarisiz olursa llm_output'u degistirmeden doner."""
    items = build_translation_items(llm_output)
    if not items:
        return llm_output

    translations = translate_texts_to_turkish(items)
    if translations is None:
        return llm_output

    return apply_translations(llm_output, translations)
