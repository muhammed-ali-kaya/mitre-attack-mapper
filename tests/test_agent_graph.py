"""Agentic dongunun testleri -- tamami AGSIZ ve LLM'siz.

Dugumler retrieval/LLM fonksiyonlarini kendi govdelerinde import ettigi icin
(dairesel bagimlilik nedeniyle) monkeypatch app.retrieval.improved_pipeline
uzerinde yapiliyor; graf gercek LangGraph grafi olarak kosuyor.

Testlerin asil derdi dongunun KARARI: ne zaman ikinci tura cikiliyor, ne
zaman cikilmiyor, ve dongu sonlaniyor mu."""

from __future__ import annotations

import pytest

from app.agents import graph as graph_module
from app.agents.base import AgentDecision, Verdict
from app.agents.graph import MAX_PASSES, run_analysis_graph, should_refine
from app.agents.verification import VerificationReport

NORMALIZED = {
    "platform": "Windows",
    "extracted_facts": {"EventID": "4688", "NewProcessName": "schtasks.exe"},
}


def _mapping(attack_id: str, confidence: str = "high") -> dict:
    return {"attack_id": attack_id, "name": attack_id, "confidence_level": confidence}


def _report(accepted: list[dict], rejected: list[str] | None = None) -> VerificationReport:
    rejected_pairs = [
        (
            _mapping(aid),
            AgentDecision(
                agent_id="evidence-gate",
                technique_id=aid,
                verdict=Verdict.REJECT,
                reason="kanit yok",
            ),
        )
        for aid in (rejected or [])
    ]
    return VerificationReport(accepted=accepted, rejected=rejected_pairs, decisions=[])


# ----------------------------------------------------------- dallanma karari

def test_no_refine_when_a_solid_finding_survived_untouched():
    """Ajanlar hicbir sey elemedi ve saglam bulgu var -> ikinci tur zaman kaybi."""
    state = {"pass_index": 0, "pass_verification": _report([_mapping("T1053.005", "high")])}
    assert should_refine(state) == "done"


def test_refine_when_nothing_survived_verification():
    """Elimizde sonuc yok; baska aday aramamak icin sebep yok."""
    state = {"pass_index": 0, "pass_verification": _report([])}
    assert should_refine(state) == "refine"


def test_refine_when_agents_rejected_something():
    """Aday havuzu kirliydi: eleme, retrieval'in yanlis adayi one cikardigina
    dair somut bir sinyal."""
    state = {
        "pass_index": 0,
        "pass_verification": _report([_mapping("T1053.005")], rejected=["T1686.003"]),
    }
    assert should_refine(state) == "refine"


def test_hepsi_zayif_TEK_BASINA_ikinci_tura_CIKARMAZ():
    """GOREV 22'DE DEGISTI -- politika degisimi, zayiflatma degil.

    Eskiden ucuncu bir tetikleyici vardi: "gecenlerin HEPSI dusuk guvenli".
    Kaldirildi cunku guven seviyesini AJAN KATMANININ KENDISI dusuruyordu;
    dongu, sistemin kendi urettigi bir kosula tepki veriyordu. Bir geri
    besleme dongusunun tetigi, dongunun kendi ciktisi olamaz.

    Olculdu (126 kayit, 2026-09-02): donguyu kosan 105 kaydin 46'si
    (%43) YALNIZCA bu tetikleyiciyle kosuyordu; tur basina 52 sn.

    Kalan iki tetikleyicinin hala calistigi asagida ayrica siniyor --
    bu test tek basina "dongu olmuyor" demez, "ZAYIFLIK dongu tetigi
    DEGIL" der."""
    state = {
        "pass_index": 0,
        "pass_verification": _report([_mapping("T1053.005", "low"), _mapping("T1059.001", "insufficient")]),
    }
    assert should_refine(state) == "done"


def test_zayif_olsa_da_ELEME_varsa_ikinci_tura_CIKILIR():
    """Kaldirilan tetikleyici digerlerini goturmedi.

    Bu test olmadan yukaridaki degisiklik "dongu tamamen olduruldu" diye
    okunabilirdi."""
    rapor = _report([_mapping("T1053.005", "low")], rejected=["T1059.001"])
    assert should_refine({"pass_index": 0, "pass_verification": rapor}) == "refine"


def test_pass_limit_is_checked_before_any_other_trigger():
    """Ust sinir en basta: dongunun sonlanmasi model yargisina degil koda bagli."""
    state = {"pass_index": MAX_PASSES, "pass_verification": _report([])}
    assert should_refine(state) == "done"


# ----------------------------------------------------------- uctan uca dongu

class _FakePipeline:
    """retrieve/select fonksiyonlarinin yerine gecer, cagrilari sayar."""

    def __init__(self, per_pass_mappings: list[list[dict]]):
        self.per_pass_mappings = per_pass_mappings
        self.retrieve_calls: list[set[str]] = []
        self.select_calls = 0

    def retrieve_and_rerank(self, user_input, enriched_query, platform=None, exclude_attack_ids=None):
        self.retrieve_calls.append(set(exclude_attack_ids or []))
        return [], {}, {"retrieval_seconds": 1.0, "reranking_seconds": 0.5}

    def select_and_validate(self, user_input, normalized, reranked, retrieval_support):
        mappings = self.per_pass_mappings[min(self.select_calls, len(self.per_pass_mappings) - 1)]
        self.select_calls += 1
        # Gorev 5: assessment donusu kalkti -- karar artik ayri bir dugumde.
        return {"mappings": [dict(m) for m in mappings]}, {"llm_seconds": 2.0}


@pytest.fixture
def patched(monkeypatch):
    def _install(per_pass_mappings, verify_results):
        fake = _FakePipeline(per_pass_mappings)
        import app.retrieval.improved_pipeline as pipeline

        monkeypatch.setattr(pipeline, "retrieve_and_rerank", fake.retrieve_and_rerank)
        monkeypatch.setattr(pipeline, "select_and_validate", fake.select_and_validate)

        calls = {"n": 0}

        def fake_verify(mappings, rows, **kwargs):
            result = verify_results[min(calls["n"], len(verify_results) - 1)]
            calls["n"] += 1
            return result

        monkeypatch.setattr(graph_module, "verify_mappings", fake_verify)
        # Graf modul duzeyinde onbelleklenıyor; yamalar arasinda temiz baslasin.
        monkeypatch.setattr(graph_module, "_compiled_graph", None)
        return fake

    return _install


def _run():
    return run_analysis_graph(
        user_input="schtasks /create /tn evil",
        normalized=NORMALIZED,
        enriched_query="schtasks scheduled task",
        platform="Windows",
    )


def test_single_pass_when_first_result_is_clean(patched):
    fake = patched(
        per_pass_mappings=[[_mapping("T1053.005", "high")]],
        verify_results=[_report([_mapping("T1053.005", "high")])],
    )
    state = _run()

    assert fake.select_calls == 1, "temiz sonucta ikinci tura cikilmamali"
    assert state["pass_index"] == 0
    assert state["loop_trace"] == []


def test_second_pass_excludes_the_disproven_technique(patched):
    """Dongunun retrieval'a dokunan tek mekanizmasi: curutulen teknigi aday
    havuzundan dusurmek."""
    fake = patched(
        per_pass_mappings=[[_mapping("T1686.003")], [_mapping("T1059.001")]],
        verify_results=[
            _report([], rejected=["T1686.003"]),
            _report([_mapping("T1059.001", "high")]),
        ],
    )
    state = _run()

    assert fake.select_calls == 2
    assert fake.retrieve_calls[0] == set(), "ilk turda dislama olmamali"
    assert fake.retrieve_calls[1] == {"T1686.003"}, "ikinci tur curutuleni dislamali"
    assert state["pass_index"] == 1


def test_loop_trace_records_why_it_looped(patched):
    """'Sistem iki kez aradi' yetmez -- neden aradigi raporda yazmali."""
    patched(
        per_pass_mappings=[[_mapping("T1686.003")], [_mapping("T1059.001")]],
        verify_results=[
            _report([_mapping("T1053.005")], rejected=["T1686.003"]),
            _report([_mapping("T1059.001", "high")]),
        ],
    )
    state = _run()

    assert len(state["loop_trace"]) == 1
    entry = state["loop_trace"][0]
    assert entry["pass"] == 1
    assert entry["excluded_attack_ids"] == ["T1686.003"]
    assert "T1686.003" in entry["reason"]
    assert entry["agent_reasons"] == ["evidence-gate: kanit yok"]


def test_loop_terminates_even_when_every_pass_fails(patched):
    """En kotu durum: hicbir tur sonuc uretmiyor. Graf yine de duruyor."""
    fake = patched(
        per_pass_mappings=[[]],
        verify_results=[_report([])],
    )
    state = _run()

    assert fake.select_calls == MAX_PASSES + 1
    assert state["pass_index"] == MAX_PASSES


def test_timings_accumulate_across_passes(patched):
    """Ikinci turun maliyeti raporda gorunmeli -- uzerine yazilmamali."""
    patched(
        per_pass_mappings=[[]],
        verify_results=[_report([])],
    )
    state = _run()

    # Iki tur x 1.0 sn retrieval
    assert state["timings"]["retrieval_seconds"] == pytest.approx(2.0)
    assert state["timings"]["llm_seconds"] == pytest.approx(4.0)


# ------------------------------------------------- dongu gerileme yapamaz

def test_second_pass_cannot_lose_first_pass_findings(patched):
    """DONGUNUN EN ONEMLI GUVENLIK OZELLIGI.

    Birinci tur iki dusuk guvenli bulgu uretiyor, ikinci tur HICBIR SEY
    uretmiyor. Birikimli olmasaydi 'iyilestirme' adina elimizde bos sonuc
    kalirdi -- yani dongu sistemi geriletirdi."""
    patched(
        per_pass_mappings=[
            [_mapping("T1571", "low"), _mapping("T1041", "low")],
            [],
        ],
        verify_results=[
            # GOREV 22: ikinci turu zorlayan sey artik "hepsi zayif" DEGIL
            # (o tetikleyici olcume dayanarak kaldirildi), ELEME. Testin
            # asil iddiasi degismedi -- ikinci tur birincinin sonucunu
            # silemez -- yalnizca donguyu baslatan gecerli tetikleyiciye
            # baglandi. Kapsam kaybi yok.
            _report([_mapping("T1571", "low"), _mapping("T1041", "low")],
                    rejected=["T1499"]),
            _report([]),
        ],
    )
    state = _run()

    assert state["pass_index"] == 1, "eleme varken ikinci tura cikilmali"
    surviving = [m["attack_id"] for m in state["validated"]["mappings"]]
    assert surviving == ["T1571", "T1041"], "ikinci tur birincinin sonucunu silmemeli"


def test_second_pass_findings_are_added_to_the_first(patched):
    """Ikinci turun kazanci: birincinin bulamadigi teknik ekleniyor."""
    patched(
        per_pass_mappings=[[_mapping("T1571", "low")], [_mapping("T1059.001", "high")]],
        verify_results=[
            # Donguyu ELEME baslatiyor (Gorev 22; bkz. yukaridaki not).
            _report([_mapping("T1571", "low")], rejected=["T1499"]),
            _report([_mapping("T1059.001", "high")]),
        ],
    )
    state = _run()

    assert [m["attack_id"] for m in state["validated"]["mappings"]] == ["T1571", "T1059.001"]


def test_duplicate_across_passes_keeps_the_first_pass_version(patched):
    """Ayni teknik iki turda da gecerse birinci turunki korunur: ikinci tur
    aday havuzunu dislanmis gormustu, daha az bilgiyle uretilen kopya
    digerinin yerine gecmemeli."""
    patched(
        per_pass_mappings=[[_mapping("T1571", "low")], [_mapping("T1571", "high")]],
        verify_results=[
            _report([_mapping("T1571", "low")]),
            _report([_mapping("T1571", "high")]),
        ],
    )
    state = _run()

    mappings = state["validated"]["mappings"]
    assert len(mappings) == 1, "ayni teknik iki kez listelenmemeli"
    assert mappings[0]["confidence_level"] == "low"


def test_first_pass_mappings_are_kept_as_the_ablation_reference(patched):
    """mappings_before_agents ILK turun listesi olmali: ajan katmaninin
    etkisini olcen karsilastirmanin referans noktasi dongu oncesidir."""
    patched(
        per_pass_mappings=[[_mapping("T1686.003")], [_mapping("T1059.001")]],
        verify_results=[
            _report([], rejected=["T1686.003"]),
            _report([_mapping("T1059.001", "high")]),
        ],
    )
    state = _run()

    assert [m["attack_id"] for m in state["mappings_before_agents"]] == ["T1686.003"]


# -- run_improved_query'nin DURUM SOZLESMESI -----------------------------------
#
# Neden ayri test: yukaridaki testler grafi kosturuyor ama ciktiyi sozluge
# ceviren katmani (run_improved_query'nin state[...] okumalarini) HIC
# calistirmiyor. Gorev 5'te `assessment` anahtari kaldirildi;
# run_improved_query'de ona erisen bir satir kaldi ve TUM TESTLER GECTI.
# Kusur ancak gercek bir kosuda (40 dakikalik prob) ortaya cikti ve o kosu
# veri uretmeden bitti.
#
# Bu test o bosluğu kapatir: LLM'siz, grafi yamali kosturur ve
# run_improved_query'nin okudugu her anahtarin durumda GERCEKTEN oldugunu
# dogrular.

def test_run_improved_query_state_anahtarlarini_okuyabiliyor(patched):
    """Durumda olmayan bir anahtara erisim KeyError'la patlar; test onu yakalar."""
    import app.retrieval.improved_pipeline as pipeline

    patched(
        per_pass_mappings=[[{"attack_id": "T1053.005", "confidence_level": "high"}]],
        verify_results=[VerificationReport(
            accepted=[{"attack_id": "T1053.005", "confidence_level": "high"}],
            rejected=[], decisions=[],
        )],
    )
    sonuc = pipeline.run_improved_query("schtasks /create /tn evil", platform=None)

    # Sozlesme: bu anahtarlar projenin her yerinde bekleniyor.
    for anahtar in ("input_summary", "decision", "mappings", "mappings_before_agents",
                    "mappings_after_first_pass", "observed_behaviors"):
        assert anahtar in sonuc, f"cikti sozlugunde {anahtar!r} yok"

    # Karar dugumu gercekten kostu mu?
    assert sonuc["decision"].get("decision") in (
        "INSUFFICIENT_DATA", "SUFFICIENT_BENIGN", "SUFFICIENT_SUSPICIOUS")
    assert sonuc["decision"].get("reason_chain"), "gerekce zinciri bos"
