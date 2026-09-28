"""Mevcut analiz sonucunu aciklayan, ona bagli kalan sohbet asistani.

Felsefe: bu asistan YENI bir ATT&CK eslestirmesi yapmiyor, yeni teknik/ID
uydurmuyor -- yalnizca ekranda zaten gosterilen, dogrulanmis analiz sonucunu
(mappings, kanitlar, tespit onerileri, QRadar taslagi) baglam olarak alip
kullanicinin bu baglamdaki sorularini yanitliyor. Serbest/sinirsiz bir sohbet
degil -- projenin genel ilkesiyle (bkz. app/validation/validator.py) tutarli
olarak, sistem promptu kapsam disina cikmamasi icin acikca sinirlandirir.

Bu modul sadece baglam/prompt insa eder (LLM cagrisi yapmaz) -- boylece agdan
bagimsiz test edilebilir. Gercek cagri icin app/llm/ollama_client.chat_turn
kullanilir (bkz. app/ui/streamlit_app.py).
"""

from __future__ import annotations

from typing import Any

CHAT_MODEL = "qwen3:8b"

CHAT_SYSTEM_PROMPT_TEMPLATE = """Sen, asagida verilen MITRE ATT&CK analiz sonucunu \
kullaniciya aciklayan bir asistansin. Kullanici, SIEM log/kural okumayi yeni \
ogreniyor -- aciklamalarini temelden, somut ornekler vererek yap.

KURALLAR:
- Yalnizca asagidaki ANALIZ SONUCU baglaminda soru cevapla.
- Ekranda gosterilenin OTESINDE yeni bir ATT&CK teknigi/ID iddia etme veya
  uydurma. "Bu neden X degil de Y" gibi bir soru gelirse, ANALIZ SONUCU'ndaki
  kanit/gerekce/guven seviyesine dayanarak acikla -- yeni bir kesin iddiada
  bulunma.
- Bu analizle ilgisiz genel bir soru gelirse (orn. yeni bir log analizi
  istegi, ya da tamamen alakasiz bir MITRE konusu), bunu belirt ve kullaniciyi
  ana "Analiz Et" akisina yonlendir.
- QRadar kural taslagi hakkinda soru gelirse, bunun bir TASLAK oldugunu ve
  production oncesi QRadar ortaminda dogrulanmasi gerektigini hatirlat.
- Kisa ve net yanit ver. Turkce yaz. Teknik adlarini, ATT&CK ID'lerini, MITRE
  terminolojisini (orn. "Scheduled Task/Job", "M1028") oldugu gibi birak,
  cevirme.

ANALIZ SONUCU:
{context}
"""


def _format_mapping(m: dict[str, Any]) -> str:
    lines = [
        f"- {m.get('attack_id')} ({m.get('name')}, {m.get('object_type')}), "
        f"guven: {m.get('confidence_level')}, taktikler: {', '.join(m.get('tactics') or [])}",
        f"  Gerekce: {m.get('reasoning_summary', '-')}",
    ]
    if m.get("evidence"):
        lines.append("  Kanitlar: " + " | ".join(m["evidence"]))
    if m.get("detection_recommendation"):
        lines.append(f"  Tespit onerisi (resmi MITRE verisi): {m['detection_recommendation']}")
    if m.get("mitigation_recommendations"):
        mit_names = ", ".join(f"{x.get('attack_id')}: {x.get('name')}" for x in m["mitigation_recommendations"])
        lines.append(f"  Onleme onerileri: {mit_names}")
    if m.get("validation_notes"):
        lines.append("  Dogrulama katmani notlari: " + "; ".join(m["validation_notes"]))
    qr = m.get("qradar_rule_draft")
    if qr:
        lines.append(f"  QRadar taslak kural adi: {qr['rule_name']}")
    return "\n".join(lines)


def build_chat_context(result: dict[str, Any]) -> str:
    """Analiz sonucunu (pipeline'lardan donen 'result' dict'i) chatbot sistem
    promptuna gomulecek kompakt, okunabilir bir metne cevirir -- ham JSON degil,
    modelin kolay okuyacagi bir ozet."""
    parts = [f"Girdi: {result.get('input_summary', {}).get('raw_input', '-')}"]

    mappings = result.get("mappings") or []
    if mappings:
        parts.append("Kabul edilen eslestirmeler:")
        parts.extend(_format_mapping(m) for m in mappings)
    else:
        parts.append("Kabul edilen eslestirme yok (yeterli kanit bulunamadi).")

    rejected = result.get("rejected_mappings") or []
    if rejected:
        parts.append("Reddedilen eslestirmeler (dogrulama katmani tarafindan):")
        for m in rejected:
            parts.append(f"- {m.get('attack_id')} ({m.get('name')}): {'; '.join(m.get('validation_issues') or [])}")

    return "\n".join(parts)


def build_chat_system_prompt(result: dict[str, Any]) -> str:
    return CHAT_SYSTEM_PROMPT_TEMPLATE.format(context=build_chat_context(result))
