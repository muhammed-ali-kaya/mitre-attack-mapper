"""Gorev 14'un UCTAN UCA (LLM + indeks) dogrulamasi.

NEDEN AYRI BETIK: `measure_task14_closure.py` uc kapanis kriterini
DETERMINISTIK katmanlarda olcer (LLM/indeks gerekmez). Gorev 14'un beklenti
belgesi E5'te acik yaziyor:

    "Cok olayli bir girdinin UCTAN UCA (LLM + indeks) davranisi. Indeks
     damgasiz oldugu icin bu oturumda kosturulamadi; birlestirme yarisi
     tests/test_multi_event_pipeline.py'de tek-olay analizi SAHTELENEREK
     olculdu."

Yani bugune kadar bolme yarisi gercek, birlestirme yarisi sahteydi. Bu betik
ikisini de gercek hatta kosturur.

KRITERLER KOSMADAN ONCE YAZILDI (2026-08-30). Ciktiya bakip esik ayarlamak
bu projede acikca yasak.

    E2E-1  BOLME        Cok olayli girdi gercek hatta >=2 olaya bolunur ve
                        `events` uzunlugu `split.event_count` ile birebir
                        esit.

    E2E-2  BASTIRMA     V-BASTIRMA'nin birlesik karari SUFFICIENT_BENIGN
           (SERT)       DEGIL.
                        Neden sert kriter "BENIGN degil", "== SUSPICIOUS"
                        degil: kapatilan acik BASTIRMAYDI -- zararsiz bir
                        olay ekleyerek alarmi susturmak. BENIGN'e dusmek
                        acigin ta kendisidir. SUSPICIOUS'a ULASMAK ise
                        ayrica LLM'in teknik secmesine baglidir (Yol A'nin
                        girdisi "teknik + dogrulanmis kanit"), ve o BASKA
                        bir katmandir. T2 bulgusu geregi karar sinifi
                        isabeti ile teknik isabeti AYRI raporlanir; ikisini
                        tek kritere baglamak hangi katmanin bozuldugunu
                        kaybettirir. Ikisi de raporlanir, kapanis yalnizca
                        BENIGN olmamaya baglidir.

    E2E-3  SEVIYE       Bastirilan event varsa bastirma EVENT seviyesinde
                        kalir: alarm karari bastirilan event'ten GELMEZ
                        (`belirleyen_event` != bastirilan index).

    E2E-4  ATIF         Birlesik `mappings`'teki HER kayit
                        `source_event_index` tasir. Atifsiz tek bir kayit
                        kriteri dusurur -- "dogru cevap, gosterilemeyen
                        sebep" bu projede iki kez olcum kirletti.

    E2E-5  DEGISMEZLIK  Tek olayli gercek senaryo `split.event_count == 1`
                        uretir ve eski cikti anahtarlari (`mappings`,
                        `decision`, `evidence_summary`) yerinde durur.
                        Gecmis olcumlerin karsilastirilabilirligi buna bagli.

GOZLEM (kriter DEGIL -- Gorev 13'e girdi olarak raporlanir):
    G1  Birlesik karar SUSPICIOUS'a ulasti mi, ulasmadiysa hangi yol eksik.
    G2  Duzyazi olay ("wiki goruntuledi") teknik uretti mi. Uretiyorsa bu bir
        BULGUDUR, kriter ihlali degil: ayri katman.
    G3  Sure olay sayisiyla nasil olcekleniyor -- Gorev 13'un sure butcesi.

    .venv/Scripts/python.exe scripts/measure_task14_end_to_end.py

Cikis kodu: SERT kriterlerden biri saglanmiyorsa 1.
LLM ve indeks GEREKIR. ONPLANDA kosturulur (uzun olcumler arka planda iki kez
oldu, sebebi bulunamadi -- bkz. HANDOFF olcum hijyeni).
"""
from __future__ import annotations

import json
import pathlib
import sys
import time

KOK = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KOK))

from app.retrieval.improved_pipeline import run_improved_query  # noqa: E402
from app.validation.decision import (  # noqa: E402
    SUFFICIENT_BENIGN,
    SUFFICIENT_SUSPICIOUS,
)

FIXTURE = KOK / "tests" / "fixtures" / "merge_vulnerability_logs.json"
SENARYOLAR = KOK / "evaluation" / "test_scenarios.json"
CIKTI = KOK / "evaluation" / "results" / "task14_end_to_end.json"

VAKA = {v["id"]: v for v in json.loads(FIXTURE.read_text(encoding="utf-8"))["vakalar"]}


def _birlesik_girdi(vaka_id: str) -> str:
    return "\n".join(o["raw"] for o in VAKA[vaka_id]["olaylar"])


def _yaz(mesaj: str) -> None:
    print(mesaj, flush=True)


# Windows konsolu cp1252: Turkce karakter yazilinca UnicodeEncodeError ile
# olcum yarida duser. Olculdu (2026-08-30) -- betigin kendisi ayarlar ki
# cagiranin ortam degiskeni ayarlamis olmasina bagli kalmasin.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def _kosa(ad: str, girdi: str) -> dict:
    _yaz(f"\n[{ad}] kosuyor... ({len(girdi)} karakter)")
    t0 = time.time()
    sonuc = run_improved_query(girdi)
    sure = time.time() - t0
    bolme = sonuc.get("split") or {}
    karar = sonuc.get("decision") or {}
    _yaz(
        f"[{ad}] bitti  {sure:.0f}s · bolme={bolme.get('rule')} "
        f"olay={len(sonuc.get('events') or [])} · karar={karar.get('decision')}"
    )
    return {"ad": ad, "girdi": girdi, "sure": sure, "sonuc": sonuc}


def main() -> int:
    _yaz("=" * 72)
    _yaz("GOREV 14 -- UCTAN UCA DOGRULAMA (LLM + indeks devrede)")
    _yaz("=" * 72)

    kosular = [
        _kosa("V-BASTIRMA", _birlesik_girdi("V-BASTIRMA")),
        _kosa("V-CAPRAZ", _birlesik_girdi("V-CAPRAZ")),
    ]

    # Tek olayli kontrol: gercek senaryo setinden ILK senaryo. Index SABIT --
    # secim sonuca bakilarak yapilmasin diye.
    ham = json.loads(SENARYOLAR.read_text(encoding="utf-8"))
    senaryo_listesi = ham if isinstance(ham, list) else ham.get("scenarios", [])
    tekil = senaryo_listesi[0]
    tekil_girdi = tekil.get("input") or tekil.get("text") or tekil.get("raw_input")
    kosular.append(_kosa(f"TEKIL[{tekil.get('test_id')}]", tekil_girdi))

    _yaz("\n" + "=" * 72)
    _yaz("KRITERLER")
    _yaz("=" * 72)

    sonuclar_ozet = []
    basarisiz = []

    for kosu in kosular:
        ad, s = kosu["ad"], kosu["sonuc"]
        bolme = s.get("split") or {}
        karar = s.get("decision") or {}
        events = s.get("events") or []
        mappings = s.get("mappings") or []
        cok_olayli = ad.startswith("V-")

        # --- E2E-1 BOLME ---
        if cok_olayli:
            # `event_count` -- `events` DEGIL. Ilk yazimda `bolme.get("events",
            # len(events))` okunuyordu; anahtar yok oldugu icin varsayilan
            # len(events)'e dusuyor ve kriter len(events)==len(events) yani
            # TOTOLOJI olarak geciyordu. Olculdu (2026-08-30): kriter gercekte
            # de geciyor (event_count 2/2/1), ama gecmesi ancak dogru anahtar
            # okununca BIR SEY SOYLUYOR.
            beklenen = bolme.get("event_count")
            e1 = beklenen is not None and beklenen >= 2 and len(events) == beklenen
            _yaz(
                f"E2E-1 [{ad}] BOLME: split.event_count={beklenen} "
                f"events={len(events)} kural={bolme.get('rule')} "
                f"-> {'GECTI' if e1 else 'KALDI'}"
            )
            if not e1:
                basarisiz.append(f"E2E-1/{ad}")

        # --- E2E-2 BASTIRMA (yalniz V-BASTIRMA) ---
        if ad == "V-BASTIRMA":
            e2 = karar.get("decision") != SUFFICIENT_BENIGN
            _yaz(
                f"E2E-2 [{ad}] BASTIRMA: karar={karar.get('decision')} "
                f"(BENIGN olmamali) -> {'GECTI' if e2 else 'KALDI'}"
            )
            if not e2:
                basarisiz.append(f"E2E-2/{ad}")
            _yaz(
                "  G1 gozlem: SUSPICIOUS'a ulasti mi -> "
                f"{'EVET' if karar.get('decision') == SUFFICIENT_SUSPICIOUS else 'HAYIR'} "
                f"| yollar={karar.get('paths')} girdiler={karar.get('inputs')}"
            )

        # --- E2E-3 SEVIYE ---
        if cok_olayli:
            event_kararlari = karar.get("event_kararlari") or []
            bastirilan = [e["index"] for e in event_kararlari if e.get("suppression")]
            belirleyen = karar.get("belirleyen_event")
            e3 = belirleyen not in bastirilan
            _yaz(
                f"E2E-3 [{ad}] SEVIYE: bastirilan={bastirilan} "
                f"belirleyen_event={belirleyen} -> {'GECTI' if e3 else 'KALDI'}"
            )
            if not e3:
                basarisiz.append(f"E2E-3/{ad}")
            for e in event_kararlari:
                _yaz(f"    event #{e['index']}: {e['decision']} · {(e.get('reason') or '')[:90]}")

        # --- E2E-4 ATIF ---
        if cok_olayli:
            atifsiz = [m.get("attack_id") for m in mappings if "source_event_index" not in m]
            e4 = not atifsiz
            _yaz(
                f"E2E-4 [{ad}] ATIF: {len(mappings)} mapping, atifsiz={atifsiz} "
                f"-> {'GECTI' if e4 else 'KALDI'}"
            )
            if not e4:
                basarisiz.append(f"E2E-4/{ad}")
            for m in mappings:
                _yaz(
                    f"    {m.get('attack_id')} <- event "
                    f"{m.get('source_event_indices')} · guven={m.get('confidence_level')}"
                )

        # --- E2E-5 DEGISMEZLIK (tekil) ---
        if not cok_olayli:
            anahtarlar = ("mappings", "decision", "evidence_summary")
            eksik = [a for a in anahtarlar if a not in s]
            e5 = bolme.get("event_count") == 1 and len(events) == 1 and not eksik
            _yaz(
                f"E2E-5 [{ad}] DEGISMEZLIK: split.event_count={bolme.get('event_count')} "
                f"events={len(events)} eksik_anahtar={eksik} "
                f"-> {'GECTI' if e5 else 'KALDI'}"
            )
            if not e5:
                basarisiz.append(f"E2E-5/{ad}")

        sonuclar_ozet.append({
            "ad": ad,
            "sure_sn": round(kosu["sure"], 1),
            "split": bolme,
            "karar": karar.get("decision"),
            "belirleyen_event": karar.get("belirleyen_event"),
            "dagilim": karar.get("dagilim"),
            "event_kararlari": karar.get("event_kararlari"),
            "mappings": [
                {
                    "attack_id": m.get("attack_id"),
                    "source_event_indices": m.get("source_event_indices"),
                    "confidence_level": m.get("confidence_level"),
                }
                for m in mappings
            ],
            "reason_chain": karar.get("reason_chain"),
        })

    # --- G2 / G3 gozlemler ---
    _yaz("\n" + "=" * 72)
    _yaz("GOZLEMLER (kriter degil -- Gorev 13'e girdi)")
    _yaz("=" * 72)
    capraz = next((k for k in kosular if k["ad"] == "V-CAPRAZ"), None)
    if capraz:
        mappings = capraz["sonuc"].get("mappings") or []
        duzyazi = [
            m.get("attack_id") for m in mappings if m.get("source_event_indices") == [0]
        ]
        _yaz(
            "G2 duzyazi olaydan (event #0 'wiki goruntuledi') gelen teknikler: "
            f"{duzyazi or 'yok'}"
        )
    for kosu in kosular:
        olay = len(kosu["sonuc"].get("events") or [])
        _yaz(
            f"G3 sure: {kosu['ad']} {kosu['sure']:.0f}s / {olay} olay "
            f"= {kosu['sure'] / max(olay, 1):.0f}s per olay"
        )

    CIKTI.parent.mkdir(parents=True, exist_ok=True)
    CIKTI.write_text(
        json.dumps(
            {"kosular": sonuclar_ozet, "basarisiz": basarisiz},
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    _yaz(f"\nAyrinti yazildi: {CIKTI.relative_to(KOK)}")

    _yaz("\n" + "=" * 72)
    if basarisiz:
        _yaz(f"SONUC: {len(basarisiz)} SERT kriter KALDI -> {basarisiz}")
        return 1
    _yaz("SONUC: tum SERT kriterler GECTI (uctan uca, LLM + indeks devrede)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
