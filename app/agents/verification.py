"""Doğrulama hattı: LLM'in seçtiği teknikleri kanıt kapısından ve kontrol
ajanlarından geçirir (şartname Bölüm 27).

MIMARIDEKI YERI
    girdi -> hybrid retrieval -> adaylar -> reranking -> LLM SECER
                                                            |
                                                            v
                                                  [BU MODUL: dogrulama]
                                                            |
                                                            v
                                                          cikti

LLM'in yerini ALMAZ. LLM hala teknigi seciyor -- sartnamenin istedigi RAG
hatti aynen calisiyor. Bu katman yalnizca "sectigin seyin kaniti var mi?"
diye soruyor ve cevap hayirsa eliyor.

NEDEN GEREKLI (olculmus): gercek bir kosuda LLM, guvenlik duvarinin
CALISTIGINI gosteren 5156 "permitted a connection" kayitlarindan T1686.003
"Windows Host Firewall" (Impair Defenses) uretti -- hem de 14 kez. Ayni veri
setinde guvenlik duvari degisikligi olayi (4946-4954, 5025) hic yoktu. Bu
katman o cikti icin "YAML'da bu teknigin kanit kosulu tanimli ve saglanmiyor"
diyip eliyor.

IKI ASAMA
    1. Kanit kapisi  -- teknik icin YAML'da kural VARSA, kosullari saglaniyor
                        mu? Kural yoksa fikir beyan etmez (susar).
    2. Kontrol ajani -- teknige ozel yargi (bkz. app/agents/deterministic.py).

Ikisi de app/agents/base.py'deki AgentDecision sozlesmesine uyar: eleyebilir,
dusurebilir; EKLEYEMEZ, YUKSELTEMEZ."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.agents.base import AgentDecision, ControlAgent, Verdict
from app.agents.deterministic import DETERMINISTIC_AGENTS
from app.agents.general import DetectionEvidenceAgent, load_attack_knowledge
from app.agents.runner import apply_decisions
from app.mapping.rule_engine import Finding, Rule, load_rules

EVIDENCE_GATE_ID = "evidence-gate"

#: Bir eslestirmenin GELDIGI satirin indeksi. Gorev 14'un on kosulu:
#: "kanit, teknigin geldigi satirda aranir" cumlesi ancak her eslestirme
#: kaynak satirini tasiyorsa kurulabilir.
SOURCE_ROW_KEY = "source_row_id"


class UnattributedMappingError(ValueError):
    """Cok satirli girdide kaynak satiri belirsiz bir eslestirme.

    NEDEN SESSIZ VARSAYIM YOK: eski kod `row_ids = list(range(len(rows)))`
    diyordu, yani her bulgu HER satiri kendi kaniti sayiyordu. Bu bir
    kolaylik degil, ACIGIN kendisiydi -- kanit baska satirda bulunuyor ve
    teknik onaylaniyordu (V-CAPRAZ), ya da alakasiz bir satirin olay ID'si
    'sinanamadi'yi 'curutuldu'ya ceviriyordu (V-ELEME).

    Uretim yolunda bu hata olusamaz: girdi once olaylara BOLUNUR ve her olay
    kendi tek satirlik cagrisini alir (app/normalization/formats.split_events
    + app/retrieval/improved_pipeline). Bu istisna, o sozlesmenin sessizce
    bozulmasini engelleyen bekcidir."""


def _kanit_satir_ids(mapping: dict[str, Any], rows: list[dict[str, Any]]) -> list[int]:
    """Bir eslestirmenin kanit olarak sayabilecegi satir(lar).

    Tek satirlik girdide cevap zaten tektir. Cok satirlida ATIF ZORUNLUDUR:
    tahmin etmek, acigin dogdugu yerdir."""
    ham = mapping.get(SOURCE_ROW_KEY)
    if ham is None:
        if len(rows) <= 1:
            return list(range(len(rows)))
        raise UnattributedMappingError(
            f"{mapping.get('attack_id')}: {len(rows)} satirlik girdide "
            f"'{SOURCE_ROW_KEY}' yok. Kanit, teknigin GELDIGI satirda aranir; "
            "kaynak satir bilinmeden bu soru cevaplanamaz."
        )
    index = int(ham)
    if not 0 <= index < len(rows):
        raise UnattributedMappingError(
            f"{mapping.get('attack_id')}: {SOURCE_ROW_KEY}={index} satir "
            f"araliginda degil (0..{len(rows) - 1})."
        )
    return [index]


def default_agents() -> list[ControlAgent]:
    """Varsayilan ajan listesi: UZMAN ajanlar + TEK bir GENEL ajan.

    IKISI BIRDEN, cunku farkli seyleri satin aliyorlar:

      UZMAN ajanlar (deterministic.py) KESINLIK satin alir. Yalnizca 3
          teknige dokunurlar ama o uclunde LLM'den kesin olarak iyidirler:
          bedava, deterministik, her kosuda ayni. T1686.003 kutupsallik
          kontrolu bu projenin en pahali hatasini yakalayan kontrol --
          onu bir dil modelinin yargisina birakmak gerileme olurdu.

      GENEL ajan (general.py) KAPSAM satin alir. Her bulguda calisir ve
          olcutunu teknigin kendi ATT&CK detection metninden aldigi icin
          kapsami elle yazilan ajan sayisiyla degil ATT&CK verisiyle
          olceklenir (697 teknikte resmi detection metni var).

    Cakisma riski yok: apply_decisions ayni teknik icin gelen kararlardan
    EN SERT olani uygular (reject > downgrade > confirm/abstain). Yani
    uzman ajan bir bulguyu elerken genel ajan 'destekliyor' derse eleme
    gecerli kalir -- somut gerekceli karar, genel yargiyi yener.

    Sira KASITLI: uzman ajanlar once, cunku deterministik ve bedavalar."""
    return [*DETERMINISTIC_AGENTS, DetectionEvidenceAgent(knowledge=load_attack_knowledge())]


@dataclass
class VerificationReport:
    """Dogrulama sonucu.

    accepted / rejected AYRI tutuluyor: elenen bir teknik kaybolmuyor,
    gerekcesiyle raporda duruyor. "Sistem bunu eledi ama neden bilmiyoruz"
    bir olay raporunda savunulamaz."""
    accepted: list[dict[str, Any]] = field(default_factory=list)
    rejected: list[tuple[dict[str, Any], AgentDecision]] = field(default_factory=list)
    decisions: list[AgentDecision] = field(default_factory=list)

    @property
    def rejected_ids(self) -> list[str]:
        return [m.get("attack_id") for m, _ in self.rejected]

    def decisions_for(self, attack_id: str) -> list[AgentDecision]:
        return [d for d in self.decisions if d.technique_id == attack_id]


def mapping_to_finding(mapping: dict[str, Any], evidence_row_ids: list[int]) -> Finding:
    """LLM'in urettigi 'mapping' sozlugunu ajan katmaninin anladigi Finding'e cevirir.

    Neden ceviriyoruz: ajanlar ve kanit kapisi zaten kural motoru bulgulari
    icin yazildi. Ayni katmani LLM ciktisi icin BIR KEZ DAHA yazmak yerine
    girdiyi uyarliyoruz -- boylece iki uretici (kural motoru ve LLM) tek bir
    dogrulama katmanini paylasiyor. Bir kontrol iyilestirildiginde ikisi de
    faydalaniyor."""
    return Finding(
        technique_id=mapping.get("attack_id") or "",
        tactic=(mapping.get("tactics") or [None])[0] or "",
        confidence=(mapping.get("confidence_level") or "low").lower(),
        evidence_row_ids=list(evidence_row_ids),
        name=mapping.get("name"),
    )


def _rules_by_technique(rules: list[Rule]) -> dict[str, list[Rule]]:
    grouped: dict[str, list[Rule]] = {}
    for rule in rules:
        grouped.setdefault(rule.technique_id, []).append(rule)
    return grouped


def evidence_gate_decisions(
    mappings: list[dict[str, Any]],
    rows: list[dict[str, Any]],
    rules: list[Rule] | None = None,
) -> list[AgentDecision]:
    """Kanit kapisi: LLM'in sectigi teknigin YAML'daki kosullari saglaniyor mu?

    UC DURUM VAR ve ucu de farkli davranir:

    1. Teknik icin YAML'da kural YOK
       -> SUSAR (karar uretmez). Katalog su an 858 teknigin ~40'ini kapsiyor;
          kapsanmayan her teknigi elemek, sistemin %95'ini sessizce kapatmak
          olurdu.

    2. Kural VAR ve kosullar SAGLANIYOR
       -> onaylar. LLM'in secimi bagimsiz bir kanitla teyit edilmis olur.

    3. Kural VAR ama kosullar SAGLANMIYOR
       -> ELER. Bu en degerli durum: teknigin nasil kanitlanacagini biliyoruz
          ve bu girdide o kanit yok. LLM'in benzerlikten uydurdugu tam olarak
          buraya dusuyor."""
    if rules is None:
        rules = load_rules()
    grouped = _rules_by_technique(rules)

    decisions: list[AgentDecision] = []

    for mapping in mappings:
        attack_id = mapping.get("attack_id")
        technique_rules = grouped.get(attack_id)
        if not technique_rules:
            continue  # 1. durum: fikir beyan etmiyoruz

        # KANIT, TEKNIGIN GELDIGI SATIRDA ARANIR (Gorev 14 §3).
        #
        # Eskiden `evidence` TUM satirlardi ve kosul
        # `any(rule.row_matches(row) for rule in kurallar for row in satirlar)`
        # yani CAPRAZ CARPIMdi: teknik satir 3'ten gelse bile kanit satir
        # 1'de bulunursa onaylaniyordu. Ayni capraz carpim `input_has_event_id`
        # kontrolunde de vardi ve alakasiz bir satirin olay ID'si, olay ID'si
        # OLMAYAN bir satirin 'sinanamadi'sini 'curutuldu'ya ceviriyordu.
        # Ikisi ayni kokten: satirlar arasi ANY semantigi.
        evidence = [rows[i] for i in _kanit_satir_ids(mapping, rows)]

        satisfied = any(
            rule.row_matches(row) for rule in technique_rules for row in evidence
        )
        if satisfied:
            decisions.append(AgentDecision(
                agent_id=EVIDENCE_GATE_ID,
                technique_id=attack_id,
                verdict=Verdict.CONFIRM,
                reason="Tekniğin YAML'daki kanıt koşulları girdide sağlanıyor.",
            ))
            continue

        expected = sorted({
            eid for rule in technique_rules for eid in rule.required_event_ids
        })

        # OLCULMUS DUZELTME -- "kosul saglanmadi" ile "kosul denenemedi" ayrimi.
        #
        # Kural olay ID'si istiyor ama girdide HIC olay ID'si yoksa (duz metin
        # senaryolari), o kosul saglanamaz -- ama saglanamamasi teknigi
        # curutmez. Ablasyonun ilk senaryosu tam bunu gosterdi: girdi
        # "makro iceren Word ekini acti" cumlesiydi, LLM T1566.001'i DOGRU
        # secmisti, kapi "kosul saglanmiyor" deyip eledi ve senaryo skoru
        # 0.70'ten 0.00'a dustu.
        #
        # Dogru okuma: bu girdi o teknigi ne kanitlar ne curutur -> CEKIMSER.
        # Eleme yalnizca girdi o kosulu SINAYABILECEK yapidayken anlamlidir:
        # olay ID'si var ama beklenenlerden degilse, orada gercekten kanit yok.
        input_has_event_id = any(str(row.get("EventID") or "").strip() for row in evidence)
        if expected and not input_has_event_id:
            decisions.append(AgentDecision(
                agent_id=EVIDENCE_GATE_ID,
                technique_id=attack_id,
                verdict=Verdict.ABSTAIN,
                reason=(
                    "Girdi olay kaydı içermediği için bu tekniğin kanıt koşulu "
                    f"sınanamadı (beklenen olay ID'leri: {', '.join(expected)}) — "
                    "kanıtın yokluğu değil, veri yokluğu."
                ),
            ))
            continue

        # HANGI kosulun dustugunu soyle -- ve normalizasyon denendi mi.
        #
        # Eski mesaj yalnizca beklenen olay ID'lerini yaziyordu ve olay ID
        # ESLESSE BILE ayni cumleyi kuruyordu:
        #   "kanit kosullari saglanmiyor (beklenen olay ID'leri: 1, 4656, ...)"
        # Logda 4656 VARDI ve listede de VARDI. Analist olay ID'sine bakip
        # "ama eslesiyor" diyor, gercek sebebi (field_condition) goremiyordu.
        # Bu, T1003.002 vakasinda yanlis katmanin suclanmasina yol acti.
        #
        # Denenen BICIMLER de yaziliyor: lehce normalizasyonu sessizce
        # calismazsa kimse fark etmez ve ayni korluk baska alanda tekrarlar.
        teshisler = []
        for rule in technique_rules:
            for row in evidence:
                teshis = rule.diagnose_failure(row)
                if teshis not in teshisler:
                    teshisler.append(teshis)
        ayrinti = " | ".join(teshisler[:3]) if teshisler else ""

        decisions.append(AgentDecision(
            agent_id=EVIDENCE_GATE_ID,
            technique_id=attack_id,
            verdict=Verdict.REJECT,
            reason=(
                "Bu teknik için tanımlı kanıt koşulları girdide sağlanmıyor"
                + (f" — {ayrinti}" if ayrinti else "")
                + "."
            ),
        ))

    return decisions


def verify_mappings(
    mappings: list[dict[str, Any]],
    rows: list[dict[str, Any]],
    *,
    agents: list[ControlAgent] | None = None,
    rules: list[Rule] | None = None,
) -> VerificationReport:
    """LLM eslestirmelerini kanit kapisi + kontrol ajanlarindan gecirir.

    rows: LLM'in analiz ettigi ham satir(lar). Tekli analizde tek elemanli
    liste (bkz. app/mapping/text_input.py::text_to_row)."""
    if agents is None:
        agents = default_agents()

    # ATIF (Gorev 14 §3): her bulgu YALNIZCA kendi kaynak satirini kanit
    # sayar. Eskiden `row_ids = list(range(len(rows)))` idi -- her bulgu her
    # satiri kendi kaniti sayiyordu ve ajanlar da (app/agents/base.evidence_rows)
    # o listeden okudugu icin kusur kapiyla sinirli degildi.
    findings = [mapping_to_finding(m, _kanit_satir_ids(m, rows)) for m in mappings]
    by_id = {f.technique_id: m for f, m in zip(findings, mappings)}

    decisions = evidence_gate_decisions(mappings, rows, rules)

    # Yonlendirme run_agents ile ayni: genel ajanlar her bulguya, uzman
    # ajanlar yalnizca kendi teknigine.
    general: list[ControlAgent] = [a for a in agents if a.technique_id is None]
    agents_by_technique: dict[str, list[ControlAgent]] = {}
    for agent in agents:
        if agent.technique_id is not None:
            agents_by_technique.setdefault(agent.technique_id, []).append(agent)
    for finding in findings:
        for agent in [*general, *agents_by_technique.get(finding.technique_id, [])]:
            decisions.append(agent.review(finding, rows))

    result = apply_decisions(findings, decisions)

    # Kararlari LLM mapping'lerine geri yansit: guven seviyesi dusurulduyse
    # kullaniciya gosterilen sozlukte de dusmus gorunmeli.
    accepted: list[dict[str, Any]] = []
    for finding in result.findings:
        mapping = dict(by_id[finding.technique_id])
        mapping["confidence_level"] = finding.confidence
        mapping["verification_notes"] = [
            f"{d.agent_id}: {d.reason}"
            for d in decisions
            if d.technique_id == finding.technique_id
        ]
        accepted.append(mapping)

    rejected = [(by_id[f.technique_id], d) for f, d in result.rejected]

    return VerificationReport(accepted=accepted, rejected=rejected, decisions=decisions)
