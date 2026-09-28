"""Gorev 26 olcumu — toplu mod sohbeti icin BAGLAM BUTCESI.

SORU: kullanicinin onerdigi baglam (incident ozeti + teknik listesi +
timeline + risk breakdown + kapsam tablosu) num_ctx=6144 sinirina
siğiyor mu? Sigmiyorsa neyi kesmeli?

TOKEN SAYIMI TAHMIN DEGIL: her bolum qwen3:8b'ye GONDERILIP Ollama'nin
dondurdugu `prompt_eval_count` okunuyor. "4 karakter = 1 token" gibi bir
kestirim bu projede kabul edilemez -- Turkce ve `\\device\\harddiskvolume3`
gibi yollar o orani bozar.

OLCUM ARACININ KENDISI DE SINANIYOR (madde 3, dokuz kez arac hatasi
bulundu): taban cizgi ayrica olculuyor ve bolumlerin toplaminin tam
metnin sayimina yakinligi raporlaniyor. Sapma buyukse sayim yontemi
yanlistir, sonuc degil.

BEKLENTI (olcumden ONCE yazildi): timeline baskin bolum olacak ve TEK
BASINA butceyi asacak, cunku 51 girisin `evidence` alani sik sik ham log
kopyasi (bkz. app/correlation/timeline.py -- `_looks_like_raw_log` ayni
sorunu zaten belgeliyor). Cozum: saklanmis `evidence` yerine Gorev 25'in
cumle ureticisini kullanmak -- hem KISA hem daha bilgilendirici.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.batch.serialize import canonicalize_row
from app.correlation.dedup import confidence_threshold_sentence
from app.correlation.risk_score import THRESHOLD_SENTENCE, breakdown_sentences
from app.correlation.tactic_labels import tactic_label
from app.correlation.technique_narrative import technique_sentences
from app.llm.chat_assistant import CHAT_MODEL
from app.mapping.coverage import build_coverage_report
from app.mapping.event_labels import event_label, required_sources_sentence
from app.mapping.text_input import text_to_row
from app.ui.diagrams import format_timestamp

RESULT = Path("data/bulk_results/bulk_20260904_030101.json")
OUT = Path("evaluation/results/bulk_chat_context.json")

#: app/llm/ollama_client.py::DETERMINISTIC_OPTIONS ile AYNI olmali.
NUM_CTX = 6144

#: Butcenin baglam DISINDA kalmasi gereken kismi.
#: - sohbet gecmisi: 6 tur x ~120 token (soru + yanit)
#: - modelin uretecegi yanit: num_predict tavani
RESERVE_HISTORY = 720
RESERVE_ANSWER = 700

OLLAMA = "http://localhost:11434/api/chat"


def token_count(text: str) -> int:
    """Metnin GERCEK token sayisi (qwen3:8b tokenizer'i).

    Ollama prompt_eval_count'u sistem + kullanici + sablon damgalarini
    birlikte sayar; sabit ek yuk _baseline() ile olculup dusuluyor."""
    payload = {
        "model": CHAT_MODEL,
        "messages": [{"role": "system", "content": text}, {"role": "user", "content": "x"}],
        "stream": False,
        "think": False,
        "keep_alive": "30m",
        "options": {"temperature": 0, "seed": 42, "num_ctx": 40960, "num_predict": 1},
    }
    response = requests.post(OLLAMA, json=payload, timeout=180)
    response.raise_for_status()
    return response.json()["prompt_eval_count"]


_BASELINE: int | None = None


def net_tokens(text: str) -> int:
    global _BASELINE
    if _BASELINE is None:
        _BASELINE = token_count("")
    return token_count(text) - _BASELINE


# --------------------------------------------------------------------
# Aday baglam bolumleri -- kullanicinin onerdigi kapsam
# --------------------------------------------------------------------


def bolum_ozet(inc: dict, techniques: list, weak: list) -> str:
    return "\n".join([
        f"INCIDENT {inc['id']} — sunucu: {inc['hostname']}, kullanici: {inc['primary_user']}",
        f"{len(inc['row_indices'])} log kaydi, {len(techniques)} dogrulanmis teknik, "
        f"{len(weak)} zayif sinyal, {len(inc['attack_chain'])} taktik asamasi",
        f"Analist ozeti: {inc['attack_summary']}",
    ])


def bolum_teknikler(techniques: list, weak: list, sentences: dict) -> str:
    lines = ["DOGRULANMIS TEKNIKLER (kanit duzeyi yeterli):"]
    for t in techniques:
        lines.append(
            f"- {t['attack_id']} {t['name']} | taktikler: "
            f"{', '.join(tactic_label(x, with_english=False) for x in t['tactics'])} "
            f"| guven: {t.get('confidence_level')} | {t['occurrence_count']} kayit "
            f"| satirlar: {t['source_row_indices']}"
        )
        if sentences.get(t["attack_id"]):
            lines.append(f"  Ne oldu: {sentences[t['attack_id']]}")
    lines.append("ZAYIF SINYALLER (skora ve zincire GIRMEDI):")
    for t in weak:
        lines.append(
            f"- {t['attack_id']} {t['name']} | guven: {t.get('confidence_level')} "
            f"| {t['occurrence_count']} kayit | satirlar: {t['source_row_indices']}"
        )
    return "\n".join(lines)


def bolum_timeline_ham(inc: dict) -> str:
    """Kullanicinin onerdigi hali: saklanmis `evidence` metni."""
    lines = ["ZAMAN CIZELGESI:"]
    for e in inc["timeline"]:
        lines.append(
            f"- satir {e['row_index']} | {e['timestamp']} | EventID={e['event_id']} | {e['evidence']}"
        )
    return "\n".join(lines)


def bolum_timeline_cumleli(inc: dict, parsed: dict) -> str:
    """Alternatif: Gorev 25'in alan tabanli cumlesi + olay adi."""
    from app.correlation.technique_narrative import technique_sentence

    lines = ["ZAMAN CIZELGESI:"]
    for e in inc["timeline"]:
        sahte = {
            "attack_id": e.get("attack_id"),
            "source_row_indices": [e["row_index"]],
            "first_seen_timestamp": e["timestamp"],
        }
        cumle = technique_sentence(sahte, parsed)
        if not cumle:
            cumle = f"{format_timestamp(None)} {event_label(e['event_id'])}"
        etiket = f" [{e['attack_id']}]" if e.get("attack_id") else ""
        lines.append(f"- satir {e['row_index']} | {cumle}{etiket}")
    return "\n".join(lines)


def bolum_risk(inc: dict, techniques: list) -> str:
    lines = [f"RISK SKORU: {inc['risk']['score']}/100 ({inc['risk']['severity']})"]
    for ad, gerekce, katki in breakdown_sentences(inc["risk"], technique_count=len(techniques)):
        lines.append(f"- {ad}: {gerekce} -> {katki}")
    lines.append(THRESHOLD_SENTENCE)
    lines.append("Kanit duzeyi esigi: " + confidence_threshold_sentence().replace("**", ""))
    return "\n".join(lines)


def bolum_kapsam(items: list) -> str:
    rows = [canonicalize_row(it["source_row"]) for it in items]
    report = build_coverage_report(rows)
    lines = [
        "TESPIT KAPSAMI (veri setindeki olay ID'leri: "
        + ", ".join(event_label(e) for e in report.dataset_event_ids) + ")",
        "Degerlendirilemeyen taktikler:",
    ]
    for t in report.unassessable:
        lines.append(
            f"- {t.tactic_name or t.tactic}: eksik "
            f"{', '.join(event_label(e) for e in t.missing_event_ids)}. "
            f"{required_sources_sentence(t.missing_event_ids)}"
        )
    lines.append("Degerlendirilebilen taktikler: " + ", ".join(
        (t.tactic_name or t.tactic) for t in report.assessable))
    return "\n".join(lines)


def bolum_ioc(inc: dict) -> str:
    ioc = inc["ioc_summary"]
    return "IOC OZETI: " + (
        ", ".join(f"{i['type']}:{i['value']}" for i in ioc["ioc_list"]) or "-"
    )


def main() -> int:
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    inc = result["incidents"][0]
    techniques = inc.get("techniques") or inc["deduped_techniques"]
    weak = inc.get("weak_techniques") or []
    parsed = {
        it["index"]: text_to_row(it["raw_log"]) for it in result["items"] if it.get("raw_log")
    }
    sentences = technique_sentences(list(techniques) + list(weak), parsed)

    bolumler = {
        "1 incident ozeti": bolum_ozet(inc, techniques, weak),
        "2 teknik listesi (3 guclu + 22 zayif)": bolum_teknikler(techniques, weak, sentences),
        "3a timeline — SAKLANMIS evidence": bolum_timeline_ham(inc),
        "3b timeline — Gorev 25 cumlesi": bolum_timeline_cumleli(inc, parsed),
        "4 risk breakdown": bolum_risk(inc, techniques),
        "5 kapsam tablosu": bolum_kapsam(result["items"]),
        "6 IOC ozeti": bolum_ioc(inc),
    }

    print(f"Model: {CHAT_MODEL} · num_ctx={NUM_CTX} (ollama_client.DETERMINISTIC_OPTIONS)")
    print(f"Girdi: {RESULT.name} — {len(result['items'])} satir, incident {inc['id']}\n")
    print(f"{'BOLUM':<40} {'KARAKTER':>9} {'TOKEN':>8}  {'kar/tok':>7}")
    print("-" * 70)

    olculen: dict[str, dict] = {}
    for ad, metin in bolumler.items():
        tokens = net_tokens(metin)
        olculen[ad] = {"karakter": len(metin), "token": tokens}
        print(f"{ad:<40} {len(metin):>9,} {tokens:>8,}  {len(metin)/max(tokens,1):>7.2f}")

    # --- ARACIN KENDI SINAMASI: bolumlerin toplami tam metne yakin mi?
    tam = "\n\n".join(
        m for ad, m in bolumler.items() if not ad.startswith("3b")
    )
    tam_token = net_tokens(tam)
    toplam = sum(v["token"] for ad, v in olculen.items() if not ad.startswith("3b"))
    sapma = abs(tam_token - toplam) / max(tam_token, 1) * 100
    print("-" * 70)
    print(f"{'bolumlerin toplami (3a ile)':<40} {'':>9} {toplam:>8,}")
    print(f"{'tek parca olculen tam metin':<40} {len(tam):>9,} {tam_token:>8,}")
    print(f"ARAC SINAMASI: sapma %{sapma:.1f} "
          f"({'kabul' if sapma < 5 else 'YONTEM SUPHELI'})\n")

    butce = NUM_CTX - RESERVE_HISTORY - RESERVE_ANSWER
    print(f"BUTCE: {NUM_CTX} (num_ctx) − {RESERVE_HISTORY} (gecmis) "
          f"− {RESERVE_ANSWER} (yanit) = {butce} token baglam icin\n")

    for etiket, timeline_key in (("A) saklanmis evidence", "3a"), ("B) Gorev 25 cumlesi", "3b")):
        secili = sum(
            v["token"] for ad, v in olculen.items()
            if not ad.startswith("3") or ad.startswith(timeline_key)
        )
        durum = "SIGIYOR" if secili <= butce else f"TASIYOR (+{secili - butce})"
        print(f"{etiket:<26} toplam {secili:>6,} token / {butce} → {durum}")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({
        "model": CHAT_MODEL,
        "num_ctx": NUM_CTX,
        "butce": butce,
        "bolumler": olculen,
        "tam_metin_token": tam_token,
        "arac_sapmasi_yuzde": round(sapma, 2),
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nYazildi: {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
