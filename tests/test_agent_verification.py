"""Dogrulama katmani: LLM ciktisinin kanit kapisindan ve ajanlardan gecisi.

TESTLER AG'A CIKMAZ. verify_mappings'in VARSAYILAN ajani artik dil modeli
kullanan genel ajandir (bkz. verification.default_agents), bu yuzden her
cagriya ajan listesi ACIKCA veriliyor:

    agents=[]                   -> yalnizca kanit kapisi olculur
    agents=DETERMINISTIC_AGENTS -> uzman ajan davranisi olculur
    agents=[_fake_general(...)] -> genel ajan yonlendirmesi olculur

Varsayilani kullanan bir test yazmak, test paketini Ollama'nin ayakta
olmasina bagimli kilar -- 4 saniyelik paket 110 saniyeye cikmisti."""

from __future__ import annotations

import json

from app.agents.base import Verdict
from app.agents.deterministic import DETERMINISTIC_AGENTS
from app.mapping.text_input import text_to_row
from app.agents.general import DetectionEvidenceAgent
from app.agents.verification import (
    EVIDENCE_GATE_ID,
    default_agents,
    evidence_gate_decisions,
    mapping_to_finding,
    verify_mappings,
)
from tests.generated_data import requires_attack_data


def _mapping(attack_id, name="X", confidence="high", tactics=("Execution",)):
    return {
        "attack_id": attack_id,
        "name": name,
        "confidence_level": confidence,
        "tactics": list(tactics),
        "evidence": [],
    }


def _fake_general(evidence="supports", reason="test gerekcesi", knowledge=None):
    """Sahte modelli genel ajan -- yonlendirmeyi ag olmadan test etmek icin."""
    return DetectionEvidenceAgent(
        knowledge=knowledge if knowledge is not None else {
            "T1059.001": {"name": "PowerShell", "detection": "Script block logging (4104)."},
            "T1218.012": {"name": "Verclsid", "detection": "Monitor verclsid.exe execution."},
            "T1003.001": {"name": "LSASS Memory", "detection": "Monitor handle access to lsass.exe."},
        },
        llm_fn=lambda system, user: json.dumps({"reason": reason, "evidence": evidence}),
    )


FIREWALL_ROW = {
    "EventID": "5156",
    "Message": "The Windows Filtering Platform has permitted a connection.",
}
# SATIRLAR URETIM YOLUNDAN GECIRILIR, elle kurulmaz.
#
# NEDEN (olculdu 2026-08-18): bu satirlar {"EventID", "Message"} diye elle
# yaziliyordu ve URETIMIN URETTIGI SEY DEGILDI. Gercek bir 4656 logu
# text_to_row'dan gecince object.name, access.mask, event.id de tasiyor;
# elle kurulan satirda yalnizca Message vardi.
#
# Bu fark, kural kosullari Message'dan yapisal alanlara tasininca ortaya
# cikti: testler kirildi ama URUN degil, FIXTURE gercekci degildi. Ayni
# desenin ucuncu tekrari (bkz. HANDOFF calisma yontemi 7): test yalnizca
# kendi kurdugu dunyaya bakiyordu.
SCRIPTBLOCK_ROW = text_to_row(
    'EventID=4104 Message="Creating Scriptblock text (1 of 1): IEX (New-Object Net.WebClient)"'
)


# ------------------------------------------------------------------ kopru

def test_mapping_is_converted_into_a_finding():
    finding = mapping_to_finding(
        _mapping("T1059.001", "PowerShell", "medium", ("Execution",)), [0, 1]
    )
    assert finding.technique_id == "T1059.001"
    assert finding.confidence == "medium"
    assert finding.evidence_row_ids == [0, 1]


# ------------------------------------------------------------------ kanit kapisi

def test_gate_rejects_technique_whose_conditions_are_not_met():
    """Projenin en pahali halusinasyonu: 5156 'permitted' -> T1686.003.

    Girdi bir olay kaydi (EventID var) ama beklenen ID'lerden degil --
    yani kosul SINANDI ve saglanmadi. Eleme burada dogru.

    IDDIA DEGISTI (2026-08-18): eskiden mesajda "4948" arantiyordu, yani
    "beklenen ID'ler sunlardi" listesi. Yeni mesaj daha KESIN: 5156 bu
    teknik icin YASAKLI listede. Ikisi ayni sey degil -- "yanlis ID"
    demek ile "bu ID acikca kanit DEGIL diye beyan edilmis" demek farkli
    seylerdir, ve ikincisi bu halusinasyonu yakalayan mekanizmanin ta
    kendisi. Trafik denetim kayitlari (5156/5158) guvenlik duvari
    YAPILANDIRMASININ degistigine kanit olamaz."""
    decisions = evidence_gate_decisions([_mapping("T1686.003")], [FIREWALL_ROW])
    assert len(decisions) == 1
    assert decisions[0].verdict is Verdict.REJECT
    assert decisions[0].agent_id == EVIDENCE_GATE_ID
    assert "5156" in decisions[0].reason
    assert "YASAKLI" in decisions[0].reason


def test_gate_abstains_when_the_input_has_no_event_data_at_all():
    """REGRESYON -- ablasyonun ilk senaryosunda olculdu.

    Girdi duz metinse (EventID yok), olay ID'si sart kosan bir kural
    YAPISAL OLARAK saglanamaz. Bunu 'kanit yok' sayip elemek, dogru
    teknigi siliyordu: single-001'de skor 0.70 -> 0.00.

    Dogru okuma: bu girdi teknigi ne kanitlar ne curutur -> cekimser."""
    prose_row = {"Message": "Kullanıcı makro içeren bir Word ekini açtı."}
    decisions = evidence_gate_decisions([_mapping("T1686.003")], [prose_row])

    assert len(decisions) == 1
    assert decisions[0].verdict is Verdict.ABSTAIN
    assert "veri yokluğu" in decisions[0].reason


def test_gate_confirms_technique_whose_conditions_are_met():
    decisions = evidence_gate_decisions([_mapping("T1059.001")], [SCRIPTBLOCK_ROW])
    assert decisions[0].verdict is Verdict.CONFIRM


def test_gate_stays_silent_for_techniques_without_a_rule():
    """Katalogda kurali olmayan teknik hakkinda fikir beyan edilmez.

    Aksi halde YAML'da olmayan her teknigi elemek, sistemin buyuk kismini
    sessizce kapatmak olurdu."""
    assert evidence_gate_decisions([_mapping("T1218.012")], [FIREWALL_ROW]) == []


# ------------------------------------------------------------------ varsayilan yapilandirma

@requires_attack_data
def test_default_agent_list_combines_specialists_with_one_general_agent():
    """Mimari beyani: katman iki farkli seyi birden satin alir.

    Uzman ajanlar KESINLIK (az teknik, deterministik, bedava), genel ajan
    KAPSAM (her teknik, olcutu ATT&CK detection metni). Biri digerinin
    yerine gecmez; varsayilan yolda ikisi de bulunmali."""
    agents = default_agents()

    general = [a for a in agents if a.technique_id is None]
    specialists = {a.technique_id for a in agents if a.technique_id is not None}

    assert len(general) == 1, "kapsami saglayan genel ajan tam olarak bir tane olmali"
    # T1686.003 kutupsallik kontrolu bu projenin en pahali hatasini yakaliyor;
    # varsayilan yoldan dusmesi sessiz bir gerileme olurdu.
    assert {"T1053.005", "T1003.001", "T1686.003"} <= specialists


# ------------------------------------------------------------------ genel ajan yonlendirmesi

def test_general_agent_reviews_every_finding_regardless_of_technique():
    mappings = [_mapping("T1059.001"), _mapping("T1218.012"), _mapping("T1003.001")]
    report = verify_mappings(mappings, [SCRIPTBLOCK_ROW], agents=[_fake_general()])

    reviewed = {
        d.technique_id for d in report.decisions if d.agent_id == "detection-evidence"
    }
    assert reviewed == {"T1059.001", "T1218.012", "T1003.001"}


def test_general_agent_can_lower_confidence_but_not_delete():
    mappings = [_mapping("T1218.012", confidence="high")]
    report = verify_mappings(
        mappings, [SCRIPTBLOCK_ROW], agents=[_fake_general(evidence="absent")]
    )

    assert [m["attack_id"] for m in report.accepted] == ["T1218.012"]
    assert report.accepted[0]["confidence_level"] == "low"
    assert report.rejected == []


def test_general_agent_abstains_when_the_technique_has_no_detection_text():
    """Olcut yoksa ajan fikir beyan etmez -- ve neden edemedigini soyler.

    v19.1 ve v19.2'de detection metni olmayan teknik kumesi ile revoked/deprecated
    kumesi birebir ayni (161/161), yani bu durum korpus sizintisina isaret
    eder."""
    mappings = [_mapping("T1218.012", confidence="high")]
    report = verify_mappings(
        mappings, [SCRIPTBLOCK_ROW],
        agents=[_fake_general(knowledge={"T1218.012": {"name": "Verclsid"}})],
    )

    assert report.accepted[0]["confidence_level"] == "high"
    note = " ".join(report.accepted[0]["verification_notes"])
    assert "revoked/deprecated" in note


# ------------------------------------------------------------------ uctan uca (kapi)

def test_hallucinated_technique_is_removed_with_a_reason():
    report = verify_mappings([_mapping("T1686.003")], [FIREWALL_ROW], agents=[])

    assert report.accepted == []
    assert report.rejected_ids == ["T1686.003"]
    assert "sağlanmıyor" in report.rejected[0][1].reason


def test_supported_technique_survives_with_verification_notes():
    report = verify_mappings([_mapping("T1059.001")], [SCRIPTBLOCK_ROW], agents=[])

    assert [m["attack_id"] for m in report.accepted] == ["T1059.001"]
    assert report.accepted[0]["verification_notes"]


def test_technique_without_rule_passes_through_untouched():
    report = verify_mappings(
        [_mapping("T1218.012", confidence="low")], [FIREWALL_ROW], agents=[]
    )
    assert [m["attack_id"] for m in report.accepted] == ["T1218.012"]
    assert report.accepted[0]["confidence_level"] == "low"


def test_verification_never_adds_a_technique():
    """Sozlesme: dogrulama katmani teknik EKLEYEMEZ."""
    mappings = [_mapping("T1686.003"), _mapping("T1059.001"), _mapping("T1218.012")]
    report = verify_mappings(mappings, [FIREWALL_ROW], agents=[_fake_general()])

    before = {m["attack_id"] for m in mappings}
    after = {m["attack_id"] for m in report.accepted}
    assert after <= before


def test_specialist_agent_still_works_when_explicitly_enabled():
    """Uzman ajanlar varsayilan yolda degil ama kaldirilmadi: cagiran taraf
    acikca ekledigi zaman aynen calisirlar."""
    # Uretim yolundan: gercek bir 4656 logu object.name ve access.mask
    # uretir. Elle {"EventID","Message"} kurmak, urunun hic gormedigi bir
    # satir uzerinde test yapmaktir.
    row = text_to_row("EventID=4656 ObjectName=lsass.exe AccessMask=0x40")
    report = verify_mappings(
        [_mapping("T1003.001", confidence="high")], [row], agents=DETERMINISTIC_AGENTS
    )

    assert [m["attack_id"] for m in report.accepted] == ["T1003.001"]
    assert report.accepted[0]["confidence_level"] == "medium"


def test_every_rejection_carries_a_reason():
    mappings = [_mapping("T1686.003"), _mapping("T1003.001")]
    report = verify_mappings(mappings, [FIREWALL_ROW], agents=[])
    assert all(decision.reason.strip() for _, decision in report.rejected)


def test_empty_input_is_handled():
    report = verify_mappings([], [FIREWALL_ROW], agents=[])
    assert report.accepted == []
    assert report.rejected == []


# ------------------------------------------- kapi mesaji: HANGI kosul dustu

def test_rejection_message_names_the_condition_that_failed():
    """Eski mesaj yalnizca beklenen olay ID'lerini yaziyordu ve olay ID
    ESLESSE BILE ayni cumleyi kuruyordu:

        "kanit kosullari saglanmiyor (beklenen olay ID'leri: 1, 4656, ...)"

    Logda 4656 VARDI ve listede de VARDI. Analist olay ID'sine bakip
    "ama esleşiyor" diyor, gercek sebebi goremiyordu. Bu, T1003.002
    vakasinda yanlis katmanin suclanmasina yol acti -- ben de Gorev 8'in
    kapsamini bu mesaja bakip yanlis ajana gore yazdim."""
    row = text_to_row(r"EventID=4656 ObjectName=\REGISTRY\MACHINE\SOFTWARE\Foo AccessMask=0x1")
    d = evidence_gate_decisions([_mapping("T1003.002")], [row])[0]

    assert d.verdict is Verdict.REJECT
    assert "olay ID eşleşti (4656)" in d.reason, "olay ID'nin ESLESTIGI soylenmeli"
    assert "object.name" in d.reason, "dusen kosulun ALANI soylenmeli"


def test_rejection_message_says_whether_normalisation_was_tried():
    """Lehce normalizasyonu SESSIZCE calismazsa kimse fark etmez ve ayni
    hata ayiklama korlugu baska bir alanda tekrar eder. Mesaj denenen
    BICIMLERI yazmali."""
    row = text_to_row(r"EventID=4656 ObjectName=\REGISTRY\MACHINE\SOFTWARE\Foo AccessMask=0x1")
    d = evidence_gate_decisions([_mapping("T1003.002")], [row])[0]

    assert "denenen biçimler" in d.reason
    assert "REGISTRY" in d.reason, "ham bicim yazilmali"
    assert "HKLM" in d.reason, "normalize edilmis bicim de yazilmali"


def test_rejection_message_distinguishes_a_missing_field_from_a_failed_match():
    """'Alan yok' ile 'alan var ama eslesmedi' farkli teshislerdir ve
    farkli yerlere baktirirlar."""
    row = text_to_row("EventID=4656 AccessMask=0x1")
    d = evidence_gate_decisions([_mapping("T1003.002")], [row])[0]
    assert "girdide YOK" in d.reason


def test_rejection_message_reports_a_mismatched_event_id_as_such():
    row = text_to_row("EventID=5156 Message=connection permitted")
    d = evidence_gate_decisions([_mapping("T1003.002")], [row])[0]
    assert "olay ID eşleşmedi" in d.reason
    assert "5156" in d.reason
