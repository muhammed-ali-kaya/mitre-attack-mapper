"""Teshis probu: 4 kayit logunu hattan gecirip HER KATMANIN ciktisini raporlar.

NE ICIN: bir degisiklikten sonra "duzeldi mi" sorusunu tek komutla cevaplamak.
Ciktisi bir taban cizgisi dosyasina yazilir ve sonraki kosularla
karsilastirilir; boylece bir katmani duzeltirken baskasini bozmak sessiz
kalmaz.

BU BIR BASARI OLCUMU DEGILDIR. Dort log, hattin hangi katmaninin kirik
oldugunu gosteren bir TEŞHIS PROBUDUR -- gecmeleri hedef degil alt sinirdir.
Genelleme icin ayri ve daha buyuk bir olcum seti gerekir (bkz. Gorev 13);
bu betigin sayilarina bakarak model/prompt ayari yapmak, dort ornege asiri
uyum demektir.

RAPORLANAN KATMANLAR
    parser      : cikarilan alan sayisi ve alan adlari (anahtar cakismasi,
                  deger kirpilmasi burada gorunur)
    retrieval   : aday teknikler, ham ve normalize skorlar
    LLM         : sectigi teknikler ve kendi bildirdigi guven
    kompozit    : her bilesenin degeri + None olup olmadigi
    kanit kapisi: elenen davranislar ve bunlarin parser ciktisinda
                  KARSILIGI OLUP OLMADIGI (kapi zarar veriyor mu olcusu)
    ajanlar     : kararlar, elemeler
    dongu       : kac tur, ne disland

KULLANIM
    python scripts/run_probe_diagnostics.py                 # calistir + yaz
    python scripts/run_probe_diagnostics.py --compare       # onceki ile kiyasla
    python scripts/run_probe_diagnostics.py --out other.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import traceback
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.normalization.input_parser import normalize_input
from app.retrieval.improved_pipeline import LLM_MODEL, run_improved_query

OLLAMA_HOST = "http://localhost:11434"


def unload_model(model: str = LLM_MODEL) -> None:
    """Modeli VRAM'den bosaltir (keep_alive=0).

    Ollama AYRI BIR SUNUCUDUR: yeni bir Python sureci baslatmak modeli
    sogutmaz, sunucu onu keep_alive suresince yuklu tutar. Bu yuzden
    "arka arkaya kosarak soguk baslangici test etmek" mumkun degil --
    ikinci kosudan itibaren model zaten sicaktir."""
    import requests

    requests.post(
        f"{OLLAMA_HOST}/api/generate",
        json={"model": model, "prompt": "", "keep_alive": 0},
        timeout=30,
    )


def warmup(model: str = LLM_MODEL) -> None:
    """Olculmeyen bir isinma cagrisi -- sonucu KULLANILMAZ.

    Neden gerekli: sapma her zaman ILK kosuda goruluyorsa bu rastgele
    gurultu degil, SIRAYA BAGLI SISTEMATIK YANLILIKTIR. Sabit sirali bir
    olcum setinde hep ayni senaryo basta durur ve o senaryonun olcumu her
    seferinde bozuk cikar. Isinma cagrisi bu yanliligi olcumun disina atar."""
    import requests

    requests.post(
        f"{OLLAMA_HOST}/api/generate",
        json={"model": model, "prompt": "warmup", "stream": False,
              "options": {"num_predict": 1}},
        timeout=300,
    )

FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "registry_object_access_logs.json"
DEFAULT_OUT = PROJECT_ROOT / "evaluation" / "results" / "probe_diagnostics.json"
# Duzeltmelerden ONCEKI hal. Betik buraya ASLA yazmaz -- uzerine yazilabilen
# bir referans noktasi referans degildir.
FROZEN_BASELINE = PROJECT_ROOT / "evaluation" / "results" / "baseline_pre_fix.json"


_SHORT_VALUE_LEN = 3
_PROSE_OVERLAP_THRESHOLD = 0.5


def _gate_damage(filtered: list[str], facts: dict[str, str], raw: str) -> list[dict]:
    """Elenen her davranis icin: girdide GERCEKTEN karsiligi var miydi?

    Bu sayi > 0 ise kanit kapisi zarar veriyor demektir -- girdide var olan
    bir gozlemi silmis. Olculmus ornek: T3'te kapi 'New Value: 1' maddesini
    eledi; logda 'New Value=1' vardi ve bu, Defender'in kapatildiginin TEK
    kanitiydi. Fark yalnizca iki nokta ile esittir isaretiydi.

    IKI AYRI BICIM, IKI AYRI OLCUT -- ilk yazimda tek olcut vardi ve
    metrigi guvenilmez kiliyordu:

    1. "Alan: Deger" bicimi -> alan adi ve deger AYRI dogrulanir.
       Yalnizca degere bakmak yaniltici: "New Value: 1" icin deger "1"dir
       ve ham logda 0x2b1c, 0x1e40 gibi onlarca yerde gecer, yani her
       zaman eslesir. Bu yuzden deger _SHORT_VALUE_LEN'den kisaysa alan
       adinin da parser ciktisinda bulunmasi SART kosulur.

    2. Duz cumle (LLM Turkce yazdiginda) -> iki nokta yoktur, tum cumleyi
       tek token saymak her zaman "eslesmedi" verir. Oysa kapinin en cok
       zarar verdigi yer tam burasidir: Turkce islev kelimeleri Ingilizce
       logda gecmez. Bu yuzden cumledeki 3+ karakterli tokenlarin ne
       kadarinin fact DEGERLERINDE gectigi oranlanir."""
    raw_lower = raw.lower()
    fact_values = {
        str(v).strip().lower().rstrip(",") for v in facts.values() if str(v).strip()
    }
    fact_keys = {str(k).strip().lower() for k in facts}
    fact_blob = " ".join(fact_values)

    damage: list[dict] = []
    for item in filtered:
        entry: dict = {"filtered_item": item}

        if ":" in item:
            field, _, value = item.partition(":")
            field = field.strip().lower()
            value = value.strip().lower()
            # Alan adi cok kelimeli olabilir ("Object Value Name"); parser
            # anahtarlari tek kelimeye inmis olabilecegi icin son kelimeye
            # de bakilir.
            field_tokens = {field, field.split()[-1] if field.split() else field}
            field_present = bool(field_tokens & fact_keys) or field in raw_lower
            value_present = bool(value) and (value in fact_values or value in raw_lower)

            if len(value) < _SHORT_VALUE_LEN:
                # Kisa deger tek basina kanit degil -- alan adi da gerekli.
                present = value_present and field_present
            else:
                present = value_present

            entry.update({
                "form": "field_value",
                "field": field,
                "value": value,
                "field_present": field_present,
                "value_present": value_present,
                "gate_was_wrong": present,
            })
        else:
            tokens = [t.strip(".,;()'\"") for t in item.lower().split()]
            tokens = [t for t in tokens if len(t) >= _SHORT_VALUE_LEN]
            hits = [t for t in tokens if t in fact_blob or t in raw_lower]
            ratio = len(hits) / len(tokens) if tokens else 0.0
            entry.update({
                "form": "prose",
                "token_count": len(tokens),
                "matched_tokens": hits,
                "overlap_ratio": round(ratio, 3),
                "gate_was_wrong": ratio >= _PROSE_OVERLAP_THRESHOLD,
            })

        damage.append(entry)
    return damage


def probe_one(log: dict) -> dict:
    raw = log["raw"]
    normalized = normalize_input(raw)
    facts = normalized.get("extracted_facts") or {}

    record: dict = {
        "id": log["id"],
        "baslik": log["baslik"],
        "expected_decision": log.get("expected_decision"),
        "expected_techniques": log.get("expected_techniques"),
        "parser": {
            "field_count": len(facts),
            "fields": facts,
            "event_id": normalized.get("event_id"),
            "process_name": normalized.get("process_name"),
            "platform": normalized.get("platform"),
        },
    }

    t0 = time.time()
    try:
        result = run_improved_query(raw, platform=None)
    except Exception as e:
        record["error"] = str(e)
        record["traceback"] = traceback.format_exc()
        return record
    record["seconds"] = round(time.time() - t0, 1)

    karar = result.get("decision") or {}
    record["decision"] = {
        # Gorev 5: 'verdict' anahtari LLM beyanindan geliyordu, kalkti.
        # Simdi uc sinif + GEREKCE ZINCIRI. Zincir kayda giriyor cunku
        # sinif dogru cikip gerekce yanlis olabilir.
        "verdict": karar.get("decision"),
        "reason": karar.get("reason"),
        "reason_chain": karar.get("reason_chain"),
        "paths": karar.get("paths"),
        "inputs": karar.get("inputs"),
        "suppression": karar.get("suppression"),
    }
    record["observed_behaviors"] = result.get("observed_behaviors")
    record["filtered_behaviors"] = result.get("filtered_observed_behaviors")
    record["gate_damage"] = _gate_damage(
        result.get("filtered_observed_behaviors") or [], facts, raw
    )

    # ZINCIRIN HER HALKASI. Bir teknigin ciktida olmamasi tek basina bir
    # teshis degil: retrieval getirmedi mi, LLM secmedi mi, ajan mi dusurdu?
    # Ucu de ayni sonucu verir, ucunun cozumu farklidir.
    # ILK turun havuzu yetkilidir. Son tur havuzu, ajanlarin curuttuklerini
    # dislayarak yeniden kuruluyor; ona bakmak birinci turda BULUNMUS bir
    # teknigi "retrieval bulamadi" diye raporlar (olculdu: T1/T1003.002
    # reranker'in 7. sirasindaydi, probe 'in_retrieval: False' dedi).
    candidates = result.get("retrieval_candidates_first_pass") or result.get("retrieval_candidates") or []
    final_candidates = result.get("retrieval_candidates") or []
    before_agents = [m.get("attack_id") for m in (result.get("mappings_before_agents") or [])]
    final_ids = [m.get("attack_id") for m in (result.get("mappings") or [])]
    record["pipeline_stages"] = {
        "retrieval_candidates": candidates,
        "retrieval_candidate_ids": [c["attack_id"] for c in candidates],
        "retrieval_candidate_ids_final_pass": [c["attack_id"] for c in final_candidates],
        "llm_selected": before_agents,
        "after_agents": final_ids,
        "dropped_by_llm": [c["attack_id"] for c in candidates if c["attack_id"] not in before_agents],
        "dropped_by_agents": [a for a in before_agents if a not in final_ids],
        # HAVUZ DISI SECIM -- Gorev 2A'nin kabul olcusu.
        #
        # LLM aday havuzuyla sinirli degil; havuzda olmayan bir teknigi
        # parametrik hafizasindan secebiliyor (bkz. validator.py, GROUNDING
        # UYARISI). Bu bir kacak degil, bilincli bir karar -- ama olculmesi
        # gerekiyor: retrieval guclendikce bu oranin DUSMESI beklenir.
        # Dusmuyorsa 2A ise yaramamis demektir.
        #
        # T1'de olculen hal: dogru cevap (T1003.002) havuzda YOKTU, LLM onu
        # kendi bilgisinden secti ve dogruydu. Yani su an LLM, retrieval'in
        # zayifligini telafi ediyor.
        "out_of_pool": [
            a for a in before_agents
            if a not in {c["attack_id"] for c in candidates}
        ],
    }

    expected = log.get("expected_techniques") or []
    record["expected_technique_trace"] = {
        tid: {
            "in_retrieval": tid in record["pipeline_stages"]["retrieval_candidate_ids"],
            "in_llm_selection": tid in before_agents,
            "in_final": tid in final_ids,
        }
        for tid in expected
    }

    # Taktik dogrulugu: v19.1'de taktikler yeniden adlandirildi ve ayrildi,
    # bu yuzden isim/ID esleşmesi ayrica raporlanir.
    expected_tactics = set(log.get("expected_tactics") or [])
    produced_tactics = {t for m in (result.get("mappings") or []) for t in (m.get("tactics") or [])}
    record["tactics"] = {
        "expected": sorted(expected_tactics),
        "expected_ids": log.get("expected_tactic_ids") or [],
        "produced": sorted(produced_tactics),
        "matched": sorted(expected_tactics & produced_tactics),
        "missing": sorted(expected_tactics - produced_tactics),
    }

    record["mappings"] = [
        {
            "attack_id": m.get("attack_id"),
            "llm_reported": m.get("llm_reported_confidence"),
            "label": m.get("confidence_level"),
            "composite": round(m.get("confidence_score") or 0.0, 4),
            "components": m.get("confidence_components"),
            "retrieval_absolute": m.get("retrieval_support_score"),
            "retrieval_relative": m.get("retrieval_rank_score"),
            "tactics": m.get("tactics"),
        }
        for m in (result.get("mappings") or [])
    ]
    # DENETIM IZI, sayi degil. Onceki kayitlar yalnizca "kac karar" tutuyordu
    # ve bu iki cok farkli durumu ayirt edilemez kiliyordu: (a) ajan o kosuda
    # HIC calismadi (teknik bulgu kumesine girmemisti) ve (b) ajan calisti ama
    # FARKLI karar verdi. Iki kosu karsilastirilirken tam olarak bu ayrim
    # gerekiyordu ve kayitta yoktu -- "elenen X" bilgisi, X'i KIMIN neden
    # eledigini soylemiyor.
    # improved_pipeline zaten duz sozluk olarak seri hale getiriyor
    # (agent_id / attack_id / verdict / reason). Alan adlarini TAHMIN ETME:
    # ilk yazimda "technique_id" varsayildi ve izin tamami None cikti.
    kararlar = result.get("agent_decisions") or []
    record["agents"] = {
        "decisions": len(kararlar),
        "rejected": [m.get("attack_id") for m in (result.get("agent_rejected_mappings") or [])],
        "trace": list(kararlar),
    }
    record["loop"] = {
        "passes": result.get("loop_passes"),
        "trace": result.get("loop_trace"),
    }
    return record


def print_report(records: list[dict]) -> None:
    total_gate_damage = 0
    for r in records:
        print("=" * 78)
        print(f"### {r['id']} -- {r['baslik']}")
        if "error" in r:
            print(f"  HATA: {r['error']}")
            continue
        p = r["parser"]
        print(f"  parser    : {p['field_count']} alan | event_id={p['event_id']} "
              f"process={p['process_name']} platform={p['platform']}")
        print(f"              alanlar: {sorted(p['fields'])}")
        print(f"  karar     : {r['decision']['verdict']}  (beklenen: {r['expected_decision']})")
        print(f"  teknikler : {[m['attack_id'] for m in r['mappings']]}  "
              f"(beklenen: {r['expected_techniques']})")
        for m in r["mappings"]:
            comp = {k: ("None" if v is None else round(v, 3))
                    for k, v in (m["components"] or {}).items()}
            print(f"    [{m['attack_id']}] llm={m['llm_reported']} kompozit={m['composite']} "
                  f"-> {m['label']} | retr abs={m['retrieval_absolute']} rel={m['retrieval_relative']}")
            print(f"        {comp}")
        wrong = [d for d in r["gate_damage"] if d["gate_was_wrong"]]
        total_gate_damage += len(wrong)
        kept = len(r.get("observed_behaviors") or [])
        dropped = len(r["filtered_behaviors"] or [])
        # IKI SUTUN: "hasar 0" tek basina belirsiz -- hic elenmedi mi, yoksa
        # elendi de hepsi dogru sebeple mi? Ikisi cok farkli seyler.
        print(f"  kapi      : gecen {kept} / elenen {dropped} / bunlardan YANLIS {len(wrong)}")
        for d in wrong:
            print(f"        YANLIS ELEME: {d['filtered_item']!r}")
        st = r.get("pipeline_stages") or {}
        oop = st.get("out_of_pool") or []
        beklenen_oop = [t for t in (r.get("expected_techniques") or []) if t in oop]
        print(f"  retrieval : {len(st.get('retrieval_candidate_ids') or [])} aday | "
              f"havuz disi secim {len(oop)} {oop}"
              + (f"  <== BEKLENEN CEVAP HAVUZ DISINDAN: {beklenen_oop}" if beklenen_oop else ""))
        print(f"  ajanlar   : {r['agents']['decisions']} karar, elenen {r['agents']['rejected']}")
        for d in r["agents"].get("trace") or []:
            tid = d.get("attack_id") or "?"
            karar = str(d.get("verdict") or "?")
            isaret = " <<<" if tid in (r.get("expected_techniques") or []) else ""
            print(f"      {karar:<10s} {tid:<12s} {d.get('agent_id')}{isaret}")
            if karar.lower() in ("reject", "downgrade"):
                print(f"                   gerekce: {(d.get('reason') or '')[:130]}")
        print(f"  dongu     : {r['loop']['passes']} tur")

    print("\n" + "=" * 78)
    print(f"KAPI HASARI TOPLAMI: {total_gate_damage}  (0 olmali)")
    print("Not: bu dort log bir TEŞHIS PROBUDUR, basari olcumu degildir.")


def compare(previous: list[dict], current: list[dict]) -> bool:
    """Onceki kosuyla farki yazar ve GERILEME olup olmadigini dondurur.

    Gerileme sayilan uc durum -- ucu de "bir katmani duzeltirken baskasini
    bozmak" kalibina girer:
      - kapi hasari artti (kapi girdide var olan bir gozlemi silmeye basladi)
      - beklenen bir teknik listeden dustu
      - parser daha az alan cikariyor"""
    prev_by_id = {r["id"]: r for r in previous}
    regressed = False

    print("\n" + "=" * 78)
    print("ONCEKI KOSUYA GORE DEGISIM")
    for cur in current:
        old = prev_by_id.get(cur["id"])
        if not old or "error" in cur or "error" in old:
            continue
        changes: list[str] = []

        if old["parser"]["field_count"] != cur["parser"]["field_count"]:
            worse = cur["parser"]["field_count"] < old["parser"]["field_count"]
            regressed = regressed or worse
            changes.append(
                f"{'GERILEME ' if worse else ''}parser alan "
                f"{old['parser']['field_count']} -> {cur['parser']['field_count']}"
            )
        if old["parser"]["event_id"] != cur["parser"]["event_id"]:
            changes.append(f"event_id {old['parser']['event_id']} -> {cur['parser']['event_id']}")
        if old["decision"]["verdict"] != cur["decision"]["verdict"]:
            changes.append(f"karar {old['decision']['verdict']} -> {cur['decision']['verdict']}")

        old_ids = [m["attack_id"] for m in old["mappings"]]
        cur_ids = [m["attack_id"] for m in cur["mappings"]]
        if old_ids != cur_ids:
            changes.append(f"teknikler {old_ids} -> {cur_ids}")
        expected = cur.get("expected_techniques") or []
        lost = [t for t in expected if t in old_ids and t not in cur_ids]
        if lost:
            regressed = True
            changes.append(f"GERILEME beklenen teknik dustu: {lost}")

        old_dropped = len(old.get("filtered_behaviors") or [])
        cur_dropped = len(cur.get("filtered_behaviors") or [])
        if old_dropped != cur_dropped:
            changes.append(f"kapi elemesi {old_dropped} -> {cur_dropped}")

        old_dmg = sum(1 for d in old.get("gate_damage", []) if d["gate_was_wrong"])
        cur_dmg = sum(1 for d in cur.get("gate_damage", []) if d["gate_was_wrong"])
        if old_dmg != cur_dmg:
            worse = cur_dmg > old_dmg
            regressed = regressed or worse
            changes.append(f"{'GERILEME ' if worse else ''}kapi HASARI {old_dmg} -> {cur_dmg}")

        print(f"  {cur['id']}: " + ("; ".join(changes) if changes else "degisiklik yok"))

    return regressed


def report_variance(runs: list[list[dict]]) -> bool:
    """Ayni girdi N kez kosuldugunda cikti sabit mi?

    OLCULDU (2026-08-16) -- cevap: ORNEKLEM DEGIL, GIZLI GIRDI.
        Ollama'ya zaten temperature=0 ve sabit seed gidiyor. Alti kosuluk
        iki kol: model soguk 6/6 ayni cevap A, model sicak 6/6 ayni cevap B.
        Her kol kendi icinde kararli, kollar birbirinden farkli. Yani hat
        deterministik; kayitsiz bir girdi (model yukleme durumu) vardi.

        Bu yuzden bu rapor "sicaklik/seed sabitle" demez. Ayni kosuda
        varyans gorulurse once ISINMA yapilip yapilmadigina bakilir
        (bkz. app/evaluation/run_hygiene.py); isinma varken hala
        oynuyorsa YENI bir gizli girdi aranir."""
    print("\n" + "=" * 78)
    print(f"DETERMINIZM ({len(runs)} kosu)")
    unstable = False
    for i, first in enumerate(runs[0]):
        variants = [run[i] for run in runs if "error" not in run[i]]
        if len(variants) < 2:
            continue
        ids = {tuple(m["attack_id"] for m in v.get("mappings", [])) for v in variants}
        labels = {tuple(m["label"] for m in v.get("mappings", [])) for v in variants}
        scores = {tuple(m["composite"] for m in v.get("mappings", [])) for v in variants}
        verdicts = {v.get("decision", {}).get("verdict") for v in variants}

        # VARYANSIN KAYNAGINI AYIRAN OLCU. Ollama'ya zaten temperature=0 ve
        # sabit seed gidiyor, yani ayni prompt ayni cikti vermeli. Cikti yine
        # de degisiyorsa PROMPT degisiyor demektir -- ve prompt'un degisken
        # kismi retrieval'dan gelen baglamdir. Aday listesi/sirasi sabitken
        # cikti degisiyorsa sorun modeldedir; aday listesi de degisiyorsa
        # sorun retrieval'in beraberlik bozmasindadir (skorlar birbirine cok
        # yakin oldugunda siralama kararsiz kalir).
        stages = [v.get("pipeline_stages") or {} for v in variants]
        cand_sets = {frozenset(s.get("retrieval_candidate_ids") or []) for s in stages}
        cand_orders = {tuple(s.get("retrieval_candidate_ids") or []) for s in stages}
        llm_sel = {tuple(s.get("llm_selected") or []) for s in stages}
        passes = {v.get("loop", {}).get("passes") for v in variants}

        flags = []
        if len(cand_sets) > 1:
            flags.append(f"ADAY KUMESI {len(cand_sets)} farkli varyant (retrieval kararsiz)")
        elif len(cand_orders) > 1:
            flags.append(f"aday SIRASI {len(cand_orders)} farkli varyant (beraberlik bozma)")
        if len(llm_sel) > 1:
            flags.append(f"LLM secimi {len(llm_sel)} farkli varyant")
        if len(passes) > 1:
            flags.append(f"dongu tur sayisi {sorted(passes)}")
        if len(ids) > 1:
            flags.append(f"teknik listesi {len(ids)} varyant: {sorted(ids)}")
        if len(labels) > 1:
            flags.append(f"etiketler {len(labels)} varyant: {sorted(labels)}")
        if len(scores) > 1:
            flags.append(f"kompozit {len(scores)} varyant: {sorted(scores)}")
        if len(verdicts) > 1:
            flags.append(f"karar {len(verdicts)} varyant: {sorted(v for v in verdicts if v)}")

        unstable = unstable or bool(flags)
        if flags:
            print(f"  {first['id']}:")
            for flag in flags:
                print(f"      {flag}")
            # Hangi kosuda ne ciktigi -- varyansi tek bir kosuya baglamak icin.
            for run_no, v in enumerate(variants, start=1):
                print(f"      kosu {run_no}: "
                      f"{[(m['attack_id'], m['label']) for m in v.get('mappings', [])]} "
                      f"karar={v.get('decision', {}).get('verdict')}")
        else:
            print(f"  {first['id']}: SABIT")

    if unstable:
        print("  -> VARYANS VAR. Once isinma yapildi mi kontrol edin: model")
        print("     yukleme durumu ciktiyi degistiriyor (soguk/sicak kollari")
        print("     6/6 kararli ama BIRBIRINDEN farkli). Isinma varken hala")
        print("     oynuyorsa YENI bir gizli girdi arayin -- seed/sicaklik")
        print("     zaten sabit, orada aramayin.")
    else:
        print("  -> Cikti sabit: etiket farklari girdi/kod kaynakli.")
    return unstable


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--compare", action="store_true",
                        help="onceki kosunun ciktisiyla karsilastir")
    parser.add_argument("--baseline", type=Path, default=FROZEN_BASELINE,
                        help="karsilastirilacak dondurulmus taban cizgisi")
    parser.add_argument("--repeat", type=int, default=1,
                        help="ayni girdileri N kez kos ve varyansi raporla")
    parser.add_argument("--cold", action="store_true",
                        help="her kosudan ONCE modeli VRAM'den bosalt. Soguk "
                             "baslangic hipotezini test etmenin TEK yolu: ayni "
                             "surecte arka arkaya kosmak modeli sicak birakir.")
    parser.add_argument("--no-warmup", action="store_true",
                        help="olcum oncesi isinma cagrisini atla (varsayilan: yap)")
    parser.add_argument("--only", action="append", metavar="ID",
                        help="yalnizca bu log(lar)i kos (orn. --only T1). "
                             "Determinizm olcumu icin: tek zengin logu cok kez "
                             "kosmak, dort logu az kez kosmaktan daha guclu "
                             "sinyal verir ve cok daha ucuzdur.")
    args = parser.parse_args()

    # Dondurulmus taban cizgisi UZERINE YAZILAMAZ. Bir referans noktasi,
    # yanlislikla ezilebiliyorsa referans degildir.
    if args.out.resolve() == FROZEN_BASELINE.resolve():
        print(f"HATA: {FROZEN_BASELINE.name} dondurulmus taban cizgisidir, "
              "uzerine yazilamaz. Baska bir --out ver.", file=sys.stderr)
        return 2

    logs = json.loads(FIXTURE.read_text(encoding="utf-8"))["logs"]
    if args.only:
        wanted = {x.upper() for x in args.only}
        logs = [l for l in logs if l["id"].upper() in wanted]
        if not logs:
            print(f"HATA: {sorted(wanted)} fixture'da yok.", file=sys.stderr)
            return 2

    runs: list[list[dict]] = []
    for pass_no in range(max(1, args.repeat)):
        if args.repeat > 1:
            print(f"\n########## KOSU {pass_no + 1}/{args.repeat} ##########")

        if args.cold:
            # SOGUK kol: her kosu modeli yeniden yukletsin.
            print("  (model VRAM'den bosaltiliyor)", flush=True)
            unload_model()
        elif not args.no_warmup:
            # SICAK kol: ilk cagrinin artefakti olcume girmesin.
            if pass_no == 0:
                print("  (isinma cagrisi -- olcume girmez)", flush=True)
                warmup()

        runs.append([probe_one(log) for log in logs])

    records = runs[-1]
    print_report(records)

    unstable = report_variance(runs) if len(runs) > 1 else False

    regressed = False
    baseline_file = args.baseline if args.baseline.exists() else (
        args.out if args.out.exists() else None
    )
    if args.compare and baseline_file:
        previous = json.loads(baseline_file.read_text(encoding="utf-8"))["records"]
        print(f"\n(karsilastirma kaynagi: {baseline_file.name})")
        if len(runs) == 1:
            # OLCULDU (2026-08-17): bu hatta tek kosu ayirt edici degil.
            # Sicak kolda bile guven etiketi oynuyor (T1012 low/low/medium) ve
            # LLM secimi kosular arasinda degisebiliyor -- karar sayisi 6'ya da
            # 7'ye de cikiyor. Tek kosuluk iki kaydi karsilastirip "degisti"
            # demek, gurultuyu bulgu sanmaya davettir; bu oturumda tam olarak
            # bir kez oldu ve yanlis bir nedensellik iddiasina goturdu.
            print(
                "\n  !! UYARI: TEK KOSU ile karsilastiriyorsunuz.\n"
                "     Bu hatta gurultu OLCULDU: sicak kolda guven etiketi\n"
                "     oynayabiliyor, LLM secimi degisince ajan karar sayisi da\n"
                "     degisiyor. Buradaki farklarin hangisi gercek, hangisi\n"
                "     gurultu AYIRT EDILEMEZ.\n"
                "     Karar vermeden once: --repeat 3 ile kosun."
            )
        regressed = compare(previous, records)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    payload: dict = {"records": records}
    if len(runs) > 1:
        # TUM kosular saklanir. Yalnizca sonuncuyu yazmak, varyans tespitini
        # bellekte birakip "hangi kosu farkliydi" sorusunu cevapsiz birakiyordu:
        # rapor "2 farkli varyant" diyor ama varyantlarin ne oldugu diske hic
        # yazilmiyordu.
        payload["runs"] = runs
    args.out.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"\nYazildi -> {args.out}" + (f" ({len(runs)} kosu saklandi)" if len(runs) > 1 else ""))

    # Cikis kodu bir PASS/FAIL kapisi degil: "bir sey kotulesti" sinyali.
    # Otomasyonun bunu okuyabilmesi icin insan raporundan ayri tutuluyor.
    if regressed:
        print("\nGERILEME TESPIT EDILDI (cikis kodu 1)")
        return 1
    if unstable:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
