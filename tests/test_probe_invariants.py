"""Olcum aracinin degismezleri.

NEDEN VAR: bu oturumda IKI kez, arac dogru gorunen ama YANLIS KAYNAKTAN
okunan bir sayi uretti.

  1. _gate_damage token cikarimi: "New Value: 1" -> token "1", ham logdaki
     0x2b1c icinde gecti, dogru vakayi YANLIS SEBEPLE yakaladi. Bir sonraki
     vakada sessizce kaciracakti.
  2. in_retrieval: probe, dongunun IKINCI turundaki aday havuzunu okuyordu.
     Ikinci tur ajanlarin curuttuklerini havuzdan duser, dolayisiyla birinci
     turda 7. sirada BULUNMUS bir teknik "retrieval bulamadi" diye
     raporlandi -- ve bu yanlis girdi uzerine bir gorev kapsami revize edildi.

Ikisi de ayni aileden. Duzeltmek yetmez: ayni hata ucuncu kez baska bir
alanda cikar. Bu dosya, aracin okudugu KAYNAGIN dogru oldugunu sabitler."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from run_probe_diagnostics import probe_one  # noqa: E402


class _FakePipeline:
    """run_improved_query'nin dondurdugu sozlugu taklit eder.

    Kritik nokta: birinci tur havuzunda olan bir teknik, IKINCI tur
    havuzundan dusurulmus olsa bile in_retrieval'de gorunmeli."""

    def __init__(self, first_pass_ids, final_pass_ids, selected, final):
        self.first = first_pass_ids
        self.final_pool = final_pass_ids
        self.selected = selected
        self.final = final

    def __call__(self, raw, platform=None):
        def pool(ids):
            return [{"attack_id": i, "absolute": 0.1, "relative": 1.0} for i in ids]

        return {
            "retrieval_candidates_first_pass": pool(self.first),
            "retrieval_candidates": pool(self.final_pool),
            "mappings_before_agents": [{"attack_id": i} for i in self.selected],
            "mappings": [{"attack_id": i, "confidence_level": "low"} for i in self.final],
            "decision": {"decision": "INSUFFICIENT_DATA", "reason": "r", "reason_chain": []},
            "observed_behaviors": [],
            "filtered_observed_behaviors": [],
            "agent_decisions": [],
            "agent_rejected_mappings": [],
            "loop_passes": 1,
            "loop_trace": [],
            "timings": {},
        }


LOG = {
    "id": "TX",
    "baslik": "degismez testi",
    "raw": "{Event ID=4656, Object Name=\\REGISTRY\\MACHINE\\SAM}",
    "expected_techniques": ["T1003.002"],
}


def _probe_with(monkeypatch, fake):
    import run_probe_diagnostics as probe

    monkeypatch.setattr(probe, "run_improved_query", fake)
    return probe_one(LOG)


def test_a_technique_found_in_the_first_pass_is_always_reported_as_retrieved(monkeypatch):
    """DEGISMEZ: birinci turda bulunan teknik, ikinci turda havuzdan
    dusurulmus olsa bile in_retrieval TRUE gorunur.

    Olculmus vaka: T1003.002 birinci turda reranker'in 7. sirasindaydi,
    kanit kapisi onu eledi, ikinci tur havuzdan dusurdu ve arac
    'retrieval bulamadi' dedi. Retrieval BULMUSTU."""
    fake = _FakePipeline(
        first_pass_ids=["T1552.002", "T1003.002", "T1112"],
        final_pass_ids=["T1552.002", "T1112", "T1012"],   # T1003.002 dusurulmus
        selected=["T1003.002", "T1552.002"],
        final=["T1552.002"],
    )
    record = _probe_with(monkeypatch, fake)

    trace = record["expected_technique_trace"]["T1003.002"]
    assert trace["in_retrieval"] is True, (
        "birinci turda bulunan teknik 'retrieval bulamadi' diye raporlanamaz"
    )
    assert trace["in_llm_selection"] is True
    assert trace["in_final"] is False


def test_the_final_pass_pool_is_reported_separately_not_instead(monkeypatch):
    """Son tur havuzu KAYBOLMAZ -- ayri alanda durur. Ikisini karistirmak
    yerine ikisini de gostermek, hangi turun neyi dusurdugunu izlenebilir
    kilar."""
    fake = _FakePipeline(
        first_pass_ids=["A", "B", "C"],
        final_pass_ids=["A", "C"],
        selected=["A"],
        final=["A"],
    )
    stages = _probe_with(monkeypatch, fake)["pipeline_stages"]

    assert stages["retrieval_candidate_ids"] == ["A", "B", "C"]
    assert stages["retrieval_candidate_ids_final_pass"] == ["A", "C"]


def test_out_of_pool_is_measured_against_the_first_pass(monkeypatch):
    """Havuz disi secim orani 2A'nin kabul olcusu. Son tura gore olcmek,
    ikinci turda dusurulen her teknigi yapay olarak 'havuz disi' gosterir
    ve olcuyu sisirir."""
    fake = _FakePipeline(
        first_pass_ids=["A", "B"],
        final_pass_ids=["A"],
        selected=["A", "B"],       # ikisi de birinci tur havuzunda vardi
        final=["A"],
    )
    stages = _probe_with(monkeypatch, fake)["pipeline_stages"]

    assert stages["out_of_pool"] == [], (
        "birinci tur havuzunda olan teknik havuz disi sayilamaz"
    )


def test_a_genuinely_unretrieved_technique_is_still_flagged(monkeypatch):
    """Koruma, gercek basarisizligi gizlememeli."""
    fake = _FakePipeline(
        first_pass_ids=["T1059.001", "T1546.013"],
        final_pass_ids=["T1059.001"],
        selected=["T1059.001", "T9999"],
        final=["T1059.001"],
    )
    stages = _probe_with(monkeypatch, fake)["pipeline_stages"]

    assert "T9999" in stages["out_of_pool"]
