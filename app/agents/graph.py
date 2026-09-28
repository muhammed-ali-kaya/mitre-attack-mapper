"""Analiz akisinin LangGraph ile yurutulmesi + hedefli yeniden retrieval dongusu.

AKIS
    retrieve --> select --> verify --> decide --> END
                    ^           |
                    |           v
                    +-------- refine                  (en fazla 1 kez)

DUGUMLERIN GOREVI AYRI (senin istedigin "her ajanin farkli gorevi olacak"
maddesi burada, akis seviyesinde de geceriyor):

    retrieve  ADAY uretir, karar vermez (sartname Bolum 18: "retrieval
              asamasi dogrudan tek bir teknik karari vermemelidir").
    select    Dil modeli adaylardan SECER. Teknik secimi hala burada.
    verify    Kanit kapisi + kontrol ajanlari DENETLER. Eleyebilir, guven
              dusurebilir; teknik EKLEYEMEZ (app/agents/base.py).
    refine    Denetimin sonucunu YENI BIR ARAMAYA cevirir. Dongunun beyni.
    decide    "Bu is dusmanca mi" KARARI. Dongunun DISINDA ve verify'dan
              SONRA: karar girdilerinden biri "dogrulanmis kanit sayisi" ve
              o sayi ancak kanit kapisi calistiktan sonra vardir. Karar
              eskiden select icinde veriliyordu -- yani girdisi matematiksel
              olarak var olmadan (Gorev 5).

LANGGRAPH NE YAPIYOR, NE YAPMIYOR -- bu ayrim onemli
    YAPIYOR : dugumleri sirayla kosturmak, kosullu dallanma, durum tasima,
              ve akisin kendisini gorsellestirilebilir bir graf yapmak.
    YAPMIYOR: sozlesmeyi zorlamak. "Ajan teknik ekleyemez, guven
              yukseltemez" garantisi hala app/agents/runner.py::apply_decisions
              icinde, kodla zorlaniyor. Bir framework'un dugum sirasini
              yonetmesi ile bir invariant'i garanti etmesi ayri seylerdir;
              ikincisini disariya devretmedik. LangGraph'i sokup yerine duz
              bir while dongusu koysak guvenlik ozellikleri aynen kalir.

DONGU NEDEN TEK TUR
    Yerel modelde her tur ~20-40 sn. 60 senaryoluk degerlendirme iki turda
    zaten iki katina cikiyor. Ustelik olculen fayda ikinci turda toplaniyor:
    ucuncu tur, ikinci turun eledigi adaylarin arkasindakileri getiriyor ve
    oradan asagisi gurultu. Ust sinir MAX_PASSES ile tek yerden degistirilebilir.
"""

from __future__ import annotations

import copy
import time
from typing import Any, TypedDict

from langgraph.graph import END, StateGraph

from app.agents.verification import VerificationReport, verify_mappings
from app.mapping.text_input import text_to_row

# Kac EK tur atilabilir. 1 = ilk gecis + en fazla bir yeniden deneme.
MAX_PASSES = 1

# Ikinci turu tetikleyen guven esigi: kabul edilen her teknik bu seviyedeyse
# hat "emin degil" demektir ve baska aday aramaya deger.
_WEAK_LEVELS = {"low", "insufficient"}


class AnalysisState(TypedDict, total=False):
    """Dugumler arasinda tasinan durum.

    LangGraph her dugumun DONDURDUGU sozlugu bu duruma birlestirir; dugumler
    durumu yerinde degistirmez. Bu, hangi dugumun neyi yazdigini okunur
    kiliyor -- akisi sunumda anlatirken de tek tek gosterilebiliyor."""
    # girdi (degismez)
    user_input: str
    normalized: dict[str, Any]
    enriched_query: str
    platform: str | None

    # tur kontrolu
    pass_index: int
    query: str
    excluded_attack_ids: list[str]
    loop_trace: list[dict[str, Any]]

    # dugum ciktilari
    reranked: list[dict[str, Any]]
    # {attack_id: {"absolute": ham reranker skoru, "relative": sorgu ici
    # min-max}} -- bkz. improved_pipeline.normalize_support.
    retrieval_support: dict[str, dict[str, float]]
    # Ilk turun aday havuzu -- ikinci tur retrieval_support'u ezdigi icin
    # ayri tutulur. "Retrieval bunu buldu mu" sorusu BUNA sorulur.
    first_pass_retrieval_support: dict[str, dict[str, float]]
    validated: dict[str, Any]
    # Karar katmaninin ciktisi (Gorev 5). Eski 'assessment' anahtari
    # kaldirildi: LLM beyanina dayaniyordu ve yedek birakmak iki
    # gerceklik demekti.
    decision: dict[str, Any]
    # pass_verification: YALNIZCA icinde bulunulan turun sonucu. Dallanma
    # karari buna bakar -- "bu turda bir sey elendi mi?" sorusunun cevabi
    # birikmis listede kaybolmamali.
    pass_verification: VerificationReport
    # verification: TUM turlarin BIRLESIMI. Rapora giden budur.
    verification: VerificationReport
    mappings_before_agents: list[dict[str, Any]]
    # Ilk turun ajan SONRASI listesi -- "ajanlar var, dongu yok" kolu.
    mappings_after_first_pass: list[dict[str, Any]]
    timings: dict[str, float]


def _merge_timings(state: AnalysisState, new: dict[str, float]) -> dict[str, float]:
    """Sureleri TOPLAR, uzerine yazmaz: iki tur donuldugunde 'retrieval_seconds'
    iki retrieval'in toplamidir. Aksi halde ikinci turun maliyeti raporda
    gorunmez olurdu."""
    merged = dict(state.get("timings") or {})
    for key, value in new.items():
        merged[key] = merged.get(key, 0.0) + value
    return merged


# --------------------------------------------------------------- dugumler

def retrieve_node(state: AnalysisState) -> dict[str, Any]:
    """ADAY uretir. Ikinci turda, ajanlarin curuttugu teknikler aday
    havuzundan dusuk gelir (excluded_attack_ids).

    OLCULEN ETKI (Gorev 10 icin kaydedildi, 2026-08-16)
        Niyet, retrieve_and_rerank'te yazili: "cezalandirmak degil,
        reranker'in top_n'ini bosaltmak". Niyet bu olabilir; ETKI su:

            birinci turda reddedilen bir teknik BIR DAHA GERI GELEMEZ.
            Yanlis bir reddetme KALICI hale gelir.

        T1'de olculdu. Zincir: retrieval T1003.002'yi buldu (semantic 2.,
        RRF 3., reranker 7.) -> LLM sectI -> kanit kapisi BOZUK BIR REGEX
        yuzunden eledi -> ikinci tur onu havuzdan dusurdu -> dogru cevap
        sistemden tumden cikti.

        "Turlar birikimlidir" garantisi bunu KAPSAMAZ: o garanti kabul
        edilmis BULGULAR icindir (_merge_reports), aday havuzu ayri bir
        mekanizmadir. Celiski yok ama garanti, adindan anlasilandan dar.

        Gorev 10'un onerilen yonu: CURUTME ile ELEME ayrilsin. Ajan/kapi
        bir teknigi dusurdugunde havuzdan cikarilmasin, ISARETLENSIN;
        ikinci tur onu yeniden degerlendirebilsin. Aksi halde tek bir bozuk
        desen dogru cevabi sistemden kalici olarak silebiliyor."""
    from app.retrieval.improved_pipeline import retrieve_and_rerank

    reranked, support, timings = retrieve_and_rerank(
        user_input=state["user_input"],
        enriched_query=state["query"],
        platform=state.get("platform"),
        exclude_attack_ids=set(state.get("excluded_attack_ids") or []),
    )
    updates: dict[str, Any] = {
        "reranked": reranked,
        "retrieval_support": support,
        "timings": _merge_timings(state, timings),
    }
    if state.get("pass_index", 0) == 0:
        # ILK turun aday havuzu AYRICA saklanir.
        #
        # Ikinci tur retrieval_support'u UZERINE YAZAR ve ajanlarin
        # curuttugu teknikleri havuzdan duser. Yalnizca son durumu olcen bir
        # arac, birinci turda BULUNMUS bir teknigi "retrieval bulamadi" diye
        # raporlar -- olculdu: T1'de T1003.002 reranker'in 7. sirasindaydi
        # ama probe onu 'in_retrieval: False' gosterdi, cunku ikinci turda
        # dislanmisti. Yanlis teshis, yanlis cozume goturur.
        updates["first_pass_retrieval_support"] = support
    return updates


def select_node(state: AnalysisState) -> dict[str, Any]:
    """Dil modeli adaylardan teknigi SECER; ardindan dogrulayici ve guven
    hesabi calisir."""
    from app.retrieval.improved_pipeline import select_and_validate

    validated, timings = select_and_validate(
        user_input=state["user_input"],
        normalized=state["normalized"],
        reranked=state["reranked"],
        retrieval_support=state["retrieval_support"],
    )
    return {
        "validated": validated,
        "timings": _merge_timings(state, timings),
    }


def verify_node(state: AnalysisState) -> dict[str, Any]:
    """Kanit kapisi + kontrol ajanlari (sartname Bolum 27).

    TURLAR BIRIKIMLIDIR -- bu, dongunun en onemli guvenlik ozelligi.
    Ikinci tur birincinin uzerine YAZMAZ, uzerine EKLER. Gerekcesi: aksi
    halde dongu geriletebilirdi. Birinci tur iki dusuk guvenli bulgu
    uretip ikinci tur hicbir sey uretmeseydi, "iyilestirme" adina elimizde
    kalan sonuc bos olurdu. Simdi ikinci turun en kotu etkisi 'hicbir sey
    eklemedi'dir.

    Birlestirme neden guvenli: birlesime giren her eslestirme, AYNI girdi
    icin kanit kapisindan ve ajanlardan BAGIMSIZ olarak gecmis durumda.
    Ikinci tur yalnizca aday havuzunu genisletiyor; karari yine dogrulama
    katmani veriyor. Birinci turda ELENEN teknikler ikinci turun aday
    havuzundan zaten disland igi icin (refine_node) arka kapidan geri
    giremezler.

    mappings_before_agents burada saklaniyor: ajanlar yalnizca eleyip guven
    dusurebildigi icin "katman kapali" hali bu listeden ibarettir -- ablasyon
    icin senaryolari iki kez kosmak gerekmiyor (scripts/run_agent_ablation.py).
    Iki tur donuldugunde ILK turun listesi korunur; karsilastirmanin anlamli
    olmasi icin referans noktasi dongu oncesi olmali."""
    t0 = time.time()
    validated = state["validated"]
    before = copy.deepcopy(validated["mappings"])

    pass_report = verify_mappings(
        validated["mappings"], [text_to_row(state["user_input"])]
    )

    previous = state.get("verification")
    merged = _merge_reports(previous, pass_report)

    validated = {**validated, "mappings": merged.accepted}
    timings = _merge_timings(state, {"agent_verification_seconds": time.time() - t0})

    updates: dict[str, Any] = {
        "validated": validated,
        "pass_verification": pass_report,
        "verification": merged,
        # Ilk turun "ajan oncesi" listesi referanstir; sonraki turlar ezmez.
        "mappings_before_agents": state.get("mappings_before_agents") or before,
        "timings": timings,
    }

    if previous is None:
        # ILK turun ajan SONRASI listesi. Ablasyonun ucuncu kolu icin gerekli:
        # "ajanlar var ama dongu yok" hali tam olarak budur. Boylece uc kol
        # (ajansiz / ajanli / ajan+dongu) TEK kosudan cikiyor -- senaryolari
        # uc kez kosturmadigimiz icin kollar arasindaki fark modelin orneklem
        # gurultusunden etkilenmiyor. Bkz. scripts/run_agent_loop_ablation.py.
        updates["mappings_after_first_pass"] = copy.deepcopy(pass_report.accepted)

    return updates


def _merge_reports(
    previous: VerificationReport | None, current: VerificationReport
) -> VerificationReport:
    """Iki turun dogrulama raporunu birlestirir.

    Ayni teknik iki turda da gecerse ILK turunki korunur: birinci tur aday
    havuzunu filtresiz gormustu, ikincisi disllamali gordu -- daha az bilgiyle
    uretilen kopya, daha cogunun yerine gecmemeli."""
    if previous is None:
        return current

    seen = {m.get("attack_id") for m in previous.accepted}
    accepted = [*previous.accepted, *(
        m for m in current.accepted if m.get("attack_id") not in seen
    )]

    return VerificationReport(
        accepted=accepted,
        rejected=[*previous.rejected, *current.rejected],
        decisions=[*previous.decisions, *current.decisions],
    )


def refine_node(state: AnalysisState) -> dict[str, Any]:
    """Denetim sonucunu yeni bir aramaya cevirir -- dongunun beyni.

    IKI SEY YAPAR:
      1. Ajanlarin ELEDIGI teknikleri disla. Bunlar "belki yanlistir" degil,
         "kaniti bu girdide YOK" diye isaretlenmis tekniklerdir. Aday
         havuzunda kalmalari ikinci turu birincinin kopyasi yapardi.
      2. Sorguyu somut artefactlara dogru cek. Ilk tur ham metnin anlatimina
         (prose) gore eslesti; ikinci turda olay ID'si, surec adi, komut
         satiri gibi SOMUT alanlar one aliniyor. Gerekce: elenen bulgularin
         cogu "benzer anlatim, farkli artefact" hatasiydi.

    Dikkat: burada LLM YOK. Sorgu genisletme tamamen kod tarafli ve
    deterministik -- dongunun kendisi bir dil modeli yargisina baglanmis
    olsaydi, hattaki en oynak parcayi akis kontrolune tasimis olurduk."""
    verification: VerificationReport = state["pass_verification"]

    rejected_ids = [
        m.get("attack_id") for m, _ in verification.rejected if m.get("attack_id")
    ]
    excluded = sorted(set(state.get("excluded_attack_ids") or []) | set(rejected_ids))

    normalized = state["normalized"]
    facts = normalized.get("extracted_facts") or {}
    artifacts = [
        f"{key}={value}"
        for key, value in facts.items()
        if str(value or "").strip()
    ]

    query = state["enriched_query"]
    if artifacts:
        query = (
            f"{query}\n"
            "Somut artefactlar: " + " | ".join(artifacts)
        )

    trace = list(state.get("loop_trace") or [])
    trace.append({
        "pass": state["pass_index"] + 1,
        "reason": _refine_reason(state),
        "excluded_attack_ids": rejected_ids,
        "agent_reasons": [
            f"{d.agent_id}: {d.reason}" for _, d in verification.rejected
        ],
    })

    return {
        "pass_index": state["pass_index"] + 1,
        "query": query,
        "excluded_attack_ids": excluded,
        "loop_trace": trace,
    }


# --------------------------------------------------------------- dallanma

def _refine_reason(state: AnalysisState) -> str:
    """Dongunun NEDEN dondugunu tek cumleyle soyler. Rapora giriyor:
    'sistem iki kez aradi' demek yetmez, neden aradigi da yazmali."""
    verification: VerificationReport = state["pass_verification"]

    if not verification.accepted:
        return "Birinci turda doğrulamayı geçen teknik kalmadı."
    if verification.rejected:
        ids = ", ".join(m.get("attack_id", "?") for m, _ in verification.rejected)
        return f"Ajan katmanı {ids} tekniğini eledi; yerine başka aday arandı."
    return "Kabul edilen tekniklerin tamamı düşük güvenli."


def decide_node(state: AnalysisState) -> dict[str, Any]:
    """KARAR -- dongu durulduktan SONRA, bir kez (Gorev 5).

    KONUMU BILINCLI. Karar eskiden select_node'da veriliyordu, yani AJAN
    KATMANINDAN ONCE: "dogrulanmis kanit sayisi" girdisi o noktada
    matematiksel olarak var olamazdi, cunku kanit kapisi henuz
    calismamisti. Karar LLM'in beyanina bu yuzden de mahkumdu.

    Simdi verify'dan sonra ve dongunun disinda: birikmis dogrulama raporu
    hazir, ikinci tur da bitmis durumda. Karar bir kez veriliyor, cunku iki
    kez verilen bir karar iki gerceklik demektir."""
    from app.validation.decision import decide

    karar = decide(
        normalized=state["normalized"],
        mappings=(state.get("validated") or {}).get("mappings") or [],
        verification=state.get("verification"),
    )

    # Alarm URETMEYEN her karar eslestirmeleri "bilgi amacli" isaretler.
    # metrics.py bu isarete bakiyor (informational_only -> alarm sayilmaz);
    # kural artik tek yerden geliyor: karar sinifi.
    validated = state.get("validated") or {}
    for mapping in validated.get("mappings") or []:
        if karar.alerts:
            mapping.pop("informational_only", None)
        else:
            mapping["informational_only"] = True

    return {"validated": validated, "decision": karar.to_dict()}


def should_refine(state: AnalysisState) -> str:
    """Ikinci tura cikilsin mi?

    IKI TETIKLEYICI VAR ve ikisi de ajan katmaninin SOMUT bir eylemine
    dayanir:
      1. Hicbir teknik dogrulamayi gecemedi -> elimizde sonuc yok
      2. Ajanlar en az bir teknigi eledi    -> aday havuzu kirliydi

    UCUNCU BIR TETIKLEYICI VARDI VE OLCUME DAYANARAK KALDIRILDI (Gorev 22):
    "gecenlerin HEPSI dusuk guvenli".

    Neden yanlisti: guven seviyesini zaten AJAN KATMANININ KENDISI
    dusuruyordu. Yani dongu, sistemin kendi urettigi bir kosula tepki
    veriyordu -- disaridan gelen bir "emin olamadim" sinyali degil, IC
    GURULTU. Bir geri besleme dongusunun tetigi, dongunun kendi ciktisi
    olamaz.

    OLCUM (126 kayit: S 60 + G 51 + H 15, kayitli kosulardan; 2026-09-02):
        dongu kosan kayit          105/126  (%83)
        tetikleyici 1 veya 2        59
        YALNIZCA tetikleyici 3      46      (dongulerin %43'u)
        tur basina ek sure          52 sn   (medyan 50 -> 102)
        46 x 52 sn                  ~40 dk

    Ilk olcum (2026-08-16, 60 senaryo) tetiklenme oranini %63.8 bulmustu;
    bugun %83. Yani kaldirilma gerekcesi ZAYIFLAMADI, GUCLENDI.

    KAZANC TARAFI BUGUN YENIDEN OLCULMEDI: eski ablasyon dongunun
    hierarchical_score katkisini +0.0018 bulmustu ve o sayi 2026-08-16
    kodundan geliyor. Bugunku kazanci olcmek 126 kaydin LLM ile yeniden
    kosulmasini gerektirirdi. Yani bu degisiklik OLCULMUS MALIYETE ve
    ESKI OLCULMUS (~0) KAZANCA dayaniyor -- kayit acik.

    Ust sinir kontrolu ONCE: dongunun sonlandigi kodla garanti, model
    yargisiyla degil.

    Karar BU TURUN raporuna bakar, birikmis olana degil: ikinci turda
    "birinci turda bir sey elenmisti" diye yeniden donmek, dongunun kendi
    gecmisine takilmasi olurdu."""
    if state["pass_index"] >= MAX_PASSES:
        return "done"

    verification: VerificationReport = state["pass_verification"]

    if not verification.accepted:
        return "refine"
    if verification.rejected:
        return "refine"
    return "done"


# --------------------------------------------------------------- graf

def build_analysis_graph() -> Any:
    """Grafi kurar ve derler.

    Kenarlar okundugunda akis aynen goruluyor -- sunumda anlatilacak sey de
    bu: retrieval karar vermiyor, LLM seciyor, ajanlar denetliyor, denetim
    sonucu retrieval'a GERI besleniyor."""
    graph = StateGraph(AnalysisState)

    graph.add_node("retrieve", retrieve_node)
    graph.add_node("select", select_node)
    graph.add_node("verify", verify_node)
    graph.add_node("refine", refine_node)
    graph.add_node("decide", decide_node)

    graph.set_entry_point("retrieve")
    graph.add_edge("retrieve", "select")
    graph.add_edge("select", "verify")
    graph.add_conditional_edges(
        "verify", should_refine, {"refine": "refine", "done": "decide"}
    )
    # Karar dongunun DISINDA: her tur sonunda degil, dongu durulunca bir kez.
    graph.add_edge("decide", END)
    # Donguyu kapatan kenar: refine yeni sorguyu yazar, retrieval bastan koser.
    graph.add_edge("refine", "retrieve")

    return graph.compile()


_compiled_graph: Any | None = None


def _get_graph() -> Any:
    """Graf bir kez derlenir; her analizde yeniden derlemek gereksiz."""
    global _compiled_graph
    if _compiled_graph is None:
        _compiled_graph = build_analysis_graph()
    return _compiled_graph


def run_analysis_graph(
    user_input: str,
    normalized: dict[str, Any],
    enriched_query: str,
    platform: str | None = None,
) -> AnalysisState:
    """Grafi kosturur ve son durumu dondurur.

    recursion_limit: LangGraph'in kendi guvenlik agi. MAX_PASSES zaten
    should_refine icinde kontrol ediliyor; bu ikinci kemer, bir hata
    durumunda grafin sonsuza kadar donmesini engelliyor. Tur basina 4
    dugum ziyareti + pay."""
    initial: AnalysisState = {
        "user_input": user_input,
        "normalized": normalized,
        "enriched_query": enriched_query,
        "platform": platform,
        "pass_index": 0,
        "query": enriched_query,
        "excluded_attack_ids": [],
        "loop_trace": [],
        "timings": {},
    }
    return _get_graph().invoke(
        initial, config={"recursion_limit": 4 * (MAX_PASSES + 1) + 4}
    )
