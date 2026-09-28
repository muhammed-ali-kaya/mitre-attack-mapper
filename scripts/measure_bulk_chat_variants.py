"""Gorev 26 olcumu, ikinci gecis — NEYI KESMELI?

Birinci gecis (measure_bulk_chat_context.py) onerilen baglamin 7.169
token oldugunu, butcenin ise 4.724 oldugunu olctu: %52 tasma.

Bu betik daraltma SECENEKLERINI olcer. Amac "sigdirmak" degil, hangi
bolumun ne kadara mal oldugunu gorup NEYIN EKRANDA ZATEN DURDUGUNU
baglamdan cikarmak. Kullanicinin kendi ilkesi: "satir bazli detay ancak
sorulunca cekilsin".

Token sayimi yine gercek (`prompt_eval_count`), tahmin degil.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.batch.serialize import canonicalize_row
from app.correlation.tactic_labels import tactic_label
from app.correlation.technique_narrative import technique_sentence, technique_sentences
from app.mapping.coverage import build_coverage_report
from app.mapping.event_labels import event_label, required_sources_sentence
from app.mapping.text_input import text_to_row

from scripts.measure_bulk_chat_context import (  # noqa: E402
    NUM_CTX,
    RESERVE_ANSWER,
    RESERVE_HISTORY,
    RESULT,
    bolum_ioc,
    bolum_ozet,
    bolum_risk,
    net_tokens,
)


def timeline_yalniz_teknikli(inc: dict, parsed: dict) -> str:
    """Teknik uretmis satirlar. Teknik uretmeyen satir sohbette bir
    soruya cevap olmuyor -- ama SAYISI onemli, o yuzden yaziliyor."""
    lines = ["ZAMAN CIZELGESI (teknik ureten satirlar):"]
    atlanan = 0
    for e in inc["timeline"]:
        if not e.get("attack_id"):
            atlanan += 1
            continue
        sahte = {"source_row_indices": [e["row_index"]], "first_seen_timestamp": e["timestamp"]}
        cumle = technique_sentence(sahte, parsed) or event_label(e["event_id"])
        lines.append(f"- satir {e['row_index']} | {cumle} [{e['attack_id']}]")
    lines.append(f"(+{atlanan} satir teknik uretmedi; sorulursa satir bazli detay cekilebilir)")
    return "\n".join(lines)


def timeline_gruplu(inc: dict, parsed: dict) -> str:
    """AYNI cumleyi ureten satirlari tek satirda topla.

    Gorev 25'in bulgusu: bes ayri teknik ayni kaydi gerekce gosteriyor,
    ve 5156/5158 kayitlari birbirinin tekrari. Tekrari baglamda 51 kez
    yazmak token yakmaktan baska bir sey yapmiyor."""
    gruplar: dict[str, list[int]] = {}
    saatler: dict[str, list[str]] = {}
    for e in inc["timeline"]:
        sahte = {"source_row_indices": [e["row_index"]], "first_seen_timestamp": e["timestamp"]}
        cumle = technique_sentence(sahte, parsed) or event_label(e["event_id"]) or "-"
        # Saati cikar ki ayni olay farkli saatlerde tek grupta toplansin.
        govde = cumle.split(" · ", 1)[-1]
        gruplar.setdefault(govde, []).append(e["row_index"])
        saat = cumle.split(" · ", 1)[0] if " · " in cumle else "-"
        saatler.setdefault(govde, []).append(saat)

    lines = ["ZAMAN CIZELGESI (ayni olay tek satirda toplandi):"]
    for govde, satirlar in gruplar.items():
        s = sorted(x for x in saatler[govde] if x != "-")
        aralik = f"{s[0]}-{s[-1]}" if len(s) > 1 and s[0] != s[-1] else (s[0] if s else "-")
        lines.append(f"- {aralik} | {govde} | {len(satirlar)} kayit, satirlar: {satirlar}")
    return "\n".join(lines)


def kapsam_ciplak(items: list) -> str:
    """Olay adlari ve log kaynagi cumlesi EKRANDA duruyor; baglamda
    taktik + eksik ID yeterli."""
    rows = [canonicalize_row(it["source_row"]) for it in items]
    report = build_coverage_report(rows)
    lines = [
        "TESPIT KAPSAMI — veri setindeki olay ID'leri: "
        + ", ".join(report.dataset_event_ids),
        "Degerlendirilemeyen taktikler (eksik olay ID'leriyle):",
    ]
    for t in report.unassessable:
        lines.append(f"- {t.tactic_name or t.tactic}: {', '.join(t.missing_event_ids)}")
    lines.append("Degerlendirilebilen: " + ", ".join(
        (t.tactic_name or t.tactic) for t in report.assessable))
    return "\n".join(lines)


def kapsam_sadece_taktik(items: list) -> str:
    rows = [canonicalize_row(it["source_row"]) for it in items]
    report = build_coverage_report(rows)
    return (
        "TESPIT KAPSAMI — degerlendirilemeyen taktikler: "
        + ", ".join((t.tactic_name or t.tactic) for t in report.unassessable)
        + ". Degerlendirilebilen: "
        + ", ".join((t.tactic_name or t.tactic) for t in report.assessable)
        + ". (Eksik olay ID'leri sorulursa verilir.)"
    )


def teknikler_tam(techniques: list, weak: list, sentences: dict) -> str:
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


def teknikler_zayif_kompakt(techniques: list, weak: list, sentences: dict) -> str:
    """Zayif sinyallerin HEPSI ekranda tabloda. Baglamda ID + ad yeterli;
    'neden zayif' sorusunun cevabi esik cumlesidir, liste degil."""
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
    lines.append(
        f"ZAYIF SINYALLER ({len(weak)} adet, skora ve zincire GIRMEDI): "
        + ", ".join(f"{t['attack_id']} ({t['occurrence_count']} kayit)" for t in weak)
    )
    return "\n".join(lines)


def main() -> int:
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    inc = result["incidents"][0]
    techniques = inc.get("techniques") or inc["deduped_techniques"]
    weak = inc.get("weak_techniques") or []
    parsed = {it["index"]: text_to_row(it["raw_log"]) for it in result["items"] if it.get("raw_log")}
    sentences = technique_sentences(list(techniques) + list(weak), parsed)

    teknikli = sum(1 for e in inc["timeline"] if e.get("attack_id"))
    print(f"51 timeline girisinin {teknikli}'i bir teknige bagli, "
          f"{51 - teknikli}'i hicbir teknik uretmemis.\n")

    secenekler = {
        "TIMELINE": {
            "a) 51 satir, saklanmis evidence": None,  # birinci gecisten: 3141
            "b) 51 satir, Gorev 25 cumlesi": None,    # birinci gecisten: 3119
            "c) yalniz teknik ureten satirlar": timeline_yalniz_teknikli(inc, parsed),
            "d) ayni olay tek satirda (gruplu)": timeline_gruplu(inc, parsed),
        },
        "KAPSAM": {
            "a) tam (ad + log kaynagi cumlesi)": None,  # birinci gecisten: 1594
            "b) taktik + eksik ID (ciplak)": kapsam_ciplak(result["items"]),
            "c) yalniz taktik adlari": kapsam_sadece_taktik(result["items"]),
        },
        "TEKNIKLER": {
            "a) tam (zayiflar satir listeli)": teknikler_tam(techniques, weak, sentences),
            "b) zayiflar kompakt": teknikler_zayif_kompakt(techniques, weak, sentences),
        },
    }

    onceki = {
        "a) 51 satir, saklanmis evidence": 3141,
        "b) 51 satir, Gorev 25 cumlesi": 3119,
        "a) tam (ad + log kaynagi cumlesi)": 1594,
    }

    olculen: dict[str, dict[str, int]] = {}
    for grup, varyantlar in secenekler.items():
        print(f"{grup}")
        olculen[grup] = {}
        for ad, metin in varyantlar.items():
            tokens = onceki[ad] if metin is None else net_tokens(metin)
            olculen[grup][ad] = tokens
            print(f"   {ad:<38} {tokens:>6,} token")
        print()

    sabit = net_tokens(bolum_ozet(inc, techniques, weak))
    risk = net_tokens(bolum_risk(inc, techniques))
    ioc = net_tokens(bolum_ioc(inc))
    print(f"SABIT: ozet {sabit} + risk {risk} + IOC {ioc} = {sabit + risk + ioc}\n")

    butce = NUM_CTX - RESERVE_HISTORY - RESERVE_ANSWER
    print(f"BUTCE: {butce} token\n")

    paketler = {
        "P0 kullanicinin onerisi (hicbir sey kesilmemis)":
            ("a) 51 satir, saklanmis evidence", "a) tam (ad + log kaynagi cumlesi)",
             "a) tam (zayiflar satir listeli)", True),
        "P1 timeline gruplu, kapsam ciplak":
            ("d) ayni olay tek satirda (gruplu)", "b) taktik + eksik ID (ciplak)",
             "a) tam (zayiflar satir listeli)", True),
        "P2 + zayiflar kompakt, IOC disarida":
            ("d) ayni olay tek satirda (gruplu)", "b) taktik + eksik ID (ciplak)",
             "b) zayiflar kompakt", False),
        "P3 en dar: teknikli satirlar, yalniz taktik adlari":
            ("c) yalniz teknik ureten satirlar", "c) yalniz taktik adlari",
             "b) zayiflar kompakt", False),
    }

    for ad, (tl, kap, tek, ioc_var) in paketler.items():
        toplam = (
            sabit + risk + (ioc if ioc_var else 0)
            + olculen["TIMELINE"][tl] + olculen["KAPSAM"][kap] + olculen["TEKNIKLER"][tek]
        )
        pay = toplam / butce * 100
        durum = f"SIGIYOR (%{pay:.0f} dolu)" if toplam <= butce else f"TASIYOR (+{toplam - butce})"
        print(f"{ad:<52} {toplam:>6,} → {durum}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
