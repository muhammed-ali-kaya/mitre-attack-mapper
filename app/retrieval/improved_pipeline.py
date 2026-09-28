"""Gelistirilmis RAG pipeline (dokuman bolum 17.2): hybrid retrieval (semantic +
BM25), platform/revoked/deprecated metadata filtreleme, reranking, context token
butcesi ve LLM ciktisi uzerinde dogrulama katmani.

Baseline (app/retrieval/baseline_pipeline.py) kasitli olarak degistirilmedi --
ikisi ayni test setiyle calistirilip karsilastirilacak (bolum 33).
"""

from __future__ import annotations

import json
import time
from typing import Any

from app.ingestion.embedding_client import embed_texts
from app.ingestion.attack_version import attack_version
from app.llm.ollama_client import chat, usage_since, usage_snapshot
from app.llm.prompts import SYSTEM_PROMPT, build_context, build_user_prompt
from app.llm.schemas import MAPPING_RESPONSE_SCHEMA
from app.normalization.input_parser import build_layered_query, normalize_input
from app.agents.verification import verify_mappings
from app.mapping.text_input import text_to_row
from app.reporting.qradar_rule import build_qradar_rule_draft
from app.retrieval.keyword_index import KeywordIndex
from app.retrieval.reranker import Reranker
from app.retrieval.vector_store import VectorStore
from app.validation.benign_signals import detect_benign_signals
from app.validation.confidence import compute_confidence
from app.validation.evidence_requirements import build_evidence_summary
from app.validation.validator import AttackKnowledgeBase, validate_response

EMBEDDING_MODEL = "bge-m3"
LLM_MODEL = "qwen3:8b"
COLLECTION_NAME = "attack_content_type_bge_m3"
ATTACK_VERSION = attack_version()  # data/metadata'dan; sabit degil

SEMANTIC_CANDIDATES = 20
KEYWORD_CANDIDATES = 20
RERANK_TOP_N = 10
CONTEXT_MAX_CHUNKS = 8

# Aday havuzunda teknik basina en fazla kac chunk (None = sinirsiz).
#
# OLCULDU (2026-08-16, uc kol x dort probe logu, bkz. cap_per_technique):
#     T0/T1/T2 : sinirsiz, 2 ve 3 kollari BIREBIR AYNI -- havuzlari zaten
#                cesitliydi (20/16/20 benzersiz), sinirin dagitacagi sey yok
#     T3       : reranker top-10'undaki benzersiz teknik 4 -> 8 (sinir=2),
#                4 -> 7 (sinir=3); "Defender" baglama sinirsizda GIRMIYOR,
#                sinirli kollarda GIRIYOR
#     regresyon: T1003.002 uc kolda da reranker 7. sirasinda -- bozulmadi
#
# Yani sinir hicbir yerde zarar vermedi, bir yerde belirgin fayda sagladi.
# None birakmak, bilinen tek patolojik davranisi (tek teknigin havuzu
# doldurmasi) VARSAYILAN tutmak olurdu.
#
# Ikinci gerekce olcum hijyeni: sonraki adim (artefakt cikarimi) T1685'i
# top-20'ye tasimayi hedefliyor. Cesitlilik cokusu acikken olcersek T1685
# havuza girse bile top-10'da ezilebilir ve "artefakt ise yaramadi" gibi
# YANLIS bir sonuca varilir.
#
# 2 mi 3 mu: dort logda 2 az farkla onde (8 vs 7 benzersiz) ve olculen bir
# maliyeti yok. 60 senaryoluk sette dogrulanacak; yanlissa bu tek satir
# geri alinir.
#
# BILINEN SINIRI: sinir listeyi KISALTIR, yerine yeni aday CEKMEZ. T3'te
# havuz 20 -> 14. Reranker yine 10 aliyor (kalan 14 >= 10), o yuzden bu
# asamada kayip yok; ama gercek telafi SEMANTIC_CANDIDATES'i buyutup sonra
# sinirlamak olurdu. Ayri bir karar, henuz verilmedi.
MAX_CHUNKS_PER_TECHNIQUE: int | None = 2

_keyword_index: KeywordIndex | None = None
_reranker: Reranker | None = None
_kb: AttackKnowledgeBase | None = None


def _get_keyword_index() -> KeywordIndex:
    global _keyword_index
    if _keyword_index is None:
        _keyword_index = KeywordIndex.load()
    return _keyword_index


def _get_reranker() -> Reranker:
    global _reranker
    if _reranker is None:
        _reranker = Reranker()
    return _reranker


def _get_kb() -> AttackKnowledgeBase:
    global _kb
    if _kb is None:
        _kb = AttackKnowledgeBase()
    return _kb


_integrity_checked = False


def _check_index_integrity() -> None:
    """Indeks, uretildigi chunk setiyle uyusuyor mu -- SORGU YOLUNDA kontrol.

    Yazilip okunmayan damga, olmayan damgadir. Bu yuzden dogrulama yalnizca
    insa betiginde degil, hattin kendisinde yapiliyor: bozuk bir indeks
    uzerine alinan her olcum, dogru gorunen ama yanlis kaynaktan gelen bir
    sayidir.

    Surec basina BIR KEZ: chunk dosyasi ~8 MB, her sorguda hash'lemek anlamsiz
    maliyet olurdu. Indeks surec calisirken degisirse zaten yeniden baslatma
    gerekir."""
    global _integrity_checked
    if _integrity_checked:
        return

    import json as _json
    import pathlib as _pathlib

    from app.retrieval.index_integrity import verify

    chunks_file = (
        _pathlib.Path(__file__).resolve().parents[2]
        / "data" / "processed" / "chunks_content_type.json"
    )
    chunks = _json.loads(chunks_file.read_text(encoding="utf-8"))
    verify(chunks, COLLECTION_NAME, VectorStore(COLLECTION_NAME).count())
    _integrity_checked = True


def _chroma_results_to_chunks(results: dict[str, Any]) -> list[dict[str, Any]]:
    chunks = []
    for cid, text, meta, dist in zip(
        results["ids"][0], results["documents"][0], results["metadatas"][0], results["distances"][0]
    ):
        chunks.append({
            "chunk_id": cid, "attack_id": meta["attack_id"], "content_type": meta["content_type"],
            "text": text, "metadata": meta, "semantic_distance": dist,
        })
    return chunks


def cap_per_technique(
    candidates: list[dict[str, Any]], limit: int | None
) -> list[dict[str, Any]]:
    """Teknik basina en fazla `limit` chunk birakir; sirayi KORUR.

    NEDEN VAR (olculdu 2026-08-16): T3'te LLM'e giden 10 chunk'in 7'si
    T1059.001'in prosedur ornekleriydi ve havuzda toplam 4 BENZERSIZ teknik
    vardi. Baglamda "Defender", "disable", "security tool" hic gecmiyordu --
    yani model dogru cevabi (T1685) SECEMEZDI, cunku onu tarif eden hicbir
    metin gonderilmemisti. Bu sartlarda modelin T1059.001 demesi bir hata
    degil; elindeki tek sey oydu.

    Sinir REranker'a girmeden uygulanir: havuzda cesitlilik korunur, reranker
    yine serbest siralar. Reranker'in son 10'unda uygulansaydi "dogru teknik
    havuza girsin" ile "en iyi chunk'lar siralansin" hedefleri cakisirdi.

    limit=None sinirsiz (eski davranis)."""
    if not limit:
        return candidates

    seen: dict[str, int] = {}
    kept: list[dict[str, Any]] = []
    for chunk in candidates:
        attack_id = chunk["attack_id"]
        if seen.get(attack_id, 0) >= limit:
            continue
        seen[attack_id] = seen.get(attack_id, 0) + 1
        kept.append(chunk)
    return kept


def hybrid_retrieve(
    user_input: str,
    store: VectorStore,
    keyword_index: KeywordIndex,
    platform: str | None = None,
    exclude_revoked_deprecated: bool = True,
    max_chunks_per_technique: int | None = MAX_CHUNKS_PER_TECHNIQUE,
) -> list[dict[str, Any]]:
    """Semantic + BM25 sonuclarini chunk_id bazinda birlestirir (reciprocal rank fusion)."""
    query_embedding = embed_texts(EMBEDDING_MODEL, [user_input])[0]

    where = None
    if exclude_revoked_deprecated:
        where = {"$and": [{"revoked": {"$eq": False}}, {"deprecated": {"$eq": False}}]}

    semantic_results = store.query(query_embedding, n_results=SEMANTIC_CANDIDATES, where=where)
    semantic_chunks = {c["chunk_id"]: c for c in _chroma_results_to_chunks(semantic_results)}

    keyword_hits = keyword_index.search(user_input, n_results=KEYWORD_CANDIDATES)

    RRF_K = 60
    fused_scores: dict[str, float] = {}
    for rank, chunk_id in enumerate(semantic_chunks.keys(), start=1):
        fused_scores[chunk_id] = fused_scores.get(chunk_id, 0.0) + 1.0 / (RRF_K + rank)
    for rank, (chunk_id, _score) in enumerate(keyword_hits, start=1):
        if exclude_revoked_deprecated and chunk_id not in semantic_chunks:
            continue
        fused_scores[chunk_id] = fused_scores.get(chunk_id, 0.0) + 1.0 / (RRF_K + rank)

    # Ikincil anahtar KARARLILIK icin: RRF skorlari sik sik esitlenir
    # (iki aday ayni siralarda gelirse 1/(k+r) toplamlari birebir ayni olur).
    # Esitlikte Python'un sirali sort'u girdi sirasini korur, ama girdi sirasi
    # dict ekleme sirasindan gelir ve o da semantic/BM25 sonuclarinin
    # birlesme sirasina baglidir. chunk_id'ye gore ikincil siralama, ayni
    # girdinin her kosuda ayni aday sirasini uretmesini garantiler.
    ranked_ids = sorted(fused_scores.keys(), key=lambda cid: (-fused_scores[cid], cid))

    all_chunks = dict(semantic_chunks)
    candidates = [all_chunks[cid] for cid in ranked_ids if cid in all_chunks]

    if platform:
        filtered = [c for c in candidates if not c["metadata"].get("platforms") or platform in c["metadata"]["platforms"]]
        if filtered:
            candidates = filtered

    # Sinir platform filtresinden SONRA: filtre aday dusurebilir, once
    # uygulanirsa kontenjan bosa harcanmis olur.
    return cap_per_technique(candidates, max_chunks_per_technique)


def build_bounded_context(chunks: list[dict[str, Any]], max_chunks: int = CONTEXT_MAX_CHUNKS) -> str:
    seen_attack_ids: set[str] = set()
    selected = []
    for c in chunks:
        if len(selected) >= max_chunks:
            break
        selected.append(c)
        seen_attack_ids.add(c["attack_id"])
    return build_context(selected)


def retrieve_and_rerank(
    user_input: str,
    enriched_query: str,
    platform: str | None = None,
    exclude_attack_ids: set[str] | None = None,
    max_chunks_per_technique: int | None = None,
) -> tuple[list[dict[str, Any]], dict[str, float], dict[str, float]]:
    """Hybrid retrieval + reranking. Graph'in `retrieve` dugumu bunu cagirir.

    exclude_attack_ids: ajan katmaninin KANITSIZ oldugunu gosterdigi teknikler.
    Ikinci turda bunlar aday listesinden dusuruluyor -- amac cezalandirmak
    degil, reranker'in top_n'ini bosaltmak: disproven adaylar cikinca yerlerine
    ilk turda esik altinda kalmis teknikler yukseliyor. Dongunun retrieval'a
    dokunan tek mekanizmasi budur."""
    timings: dict[str, float] = {}
    _check_index_integrity()
    store = VectorStore(COLLECTION_NAME)
    keyword_index = _get_keyword_index()

    t0 = time.time()
    candidates = hybrid_retrieve(
        enriched_query, store, keyword_index, platform=platform,
        max_chunks_per_technique=(
            max_chunks_per_technique
            if max_chunks_per_technique is not None
            else MAX_CHUNKS_PER_TECHNIQUE
        ),
    )
    timings["retrieval_seconds"] = time.time() - t0

    if exclude_attack_ids:
        candidates = [c for c in candidates if c["attack_id"] not in exclude_attack_ids]

    t0 = time.time()
    reranker = _get_reranker()
    reranked = reranker.rerank(user_input, candidates, top_n=RERANK_TOP_N)
    timings["reranking_seconds"] = time.time() - t0

    retrieval_support: dict[str, float] = {}
    for c in reranked:
        aid = c["attack_id"]
        retrieval_support[aid] = max(retrieval_support.get(aid, -1e9), c.get("rerank_score", 0.0))

    return reranked, normalize_support(retrieval_support), timings


def _candidate_list(support: dict[str, dict[str, float]]) -> list[dict[str, Any]]:
    """Aday havuzunu rapor edilebilir bir listeye cevirir (en iyiden koture)."""
    return [
        {
            "attack_id": aid,
            "absolute": scores.get("absolute"),
            "relative": scores.get("relative"),
        }
        for aid, scores in sorted(
            support.items(), key=lambda kv: -(kv[1].get("relative") or 0.0)
        )
    ]


def normalize_support(retrieval_support: dict[str, float]) -> dict[str, dict[str, float]]:
    """Reranker skorlarini SORGU ICINDE min-max normalize eder.

    IKI AYRI SAYI donuyor, cunku iki ayri soruya cevap veriyorlar:

      absolute : reranker'in ham ciktisi. Cross-encoder bunu ZATEN sigmoid'den
                 gecirmis durumda (gozlenen aralik (0, 0.24], hepsi pozitif;
                 ham logit olsaydi alakasiz adaylarda negatif gorurduk).
                 Sorgular arasi KARSILASTIRILAMAZ: bir sorguda 0.24 en iyi
                 aday olabilirken digerinde 0.05 en iyi adaydir. Mutlak bir
                 esik icin kullanilabilir, siralama icin degil.

      relative : ayni sorgunun adaylari arasinda min-max. Siralamaya bilgi
                 katan tek olcu budur.

    NEDEN DEGISTI: guven skoru absolute degeri bir kez DAHA sigmoid'den
    geciriyordu. sigmoid(0.0015)=0.5004, sigmoid(0.236)=0.559 -- yani en
    yuksek agirlikli bileseni (0.30) pratikte 0.5 sabitine eziyordu.
    Olculen dort logda retrieval_similarity 0.500-0.559 arasinda kaldi ve
    siralamaya hicbir sey katmadi.

    Tek aday varsa relative=1.0: "bu adaylar arasinda en iyisi" ifadesi tek
    elemanli kumede dogrudur. Mutlak kalitesini absolute soyler."""
    if not retrieval_support:
        return {}

    values = list(retrieval_support.values())
    lo, hi = min(values), max(values)
    span = hi - lo

    return {
        aid: {
            "absolute": score,
            # span==0: butun adaylar ayni skoru aldi, aralarinda ayrim yok.
            "relative": 1.0 if span <= 0 else (score - lo) / span,
        }
        for aid, score in retrieval_support.items()
    }


def select_and_validate(
    user_input: str,
    normalized: dict[str, Any],
    reranked: list[dict[str, Any]],
    retrieval_support: dict[str, float],
) -> tuple[dict[str, Any], dict[str, float]]:
    """LLM teknigi SECER, ardindan dogrulayici (ID/isim/revoked/grounding)
    ve guven hesabi calisir. Graph'in `select` dugumu bunu cagirir.

    Not: teknik secimi hala burada, yani dil modelinde. Ajan katmani bunun
    yerine gecmez, arkasina gecer (sartname Bolum 27)."""
    timings: dict[str, float] = {}

    context = build_bounded_context(reranked, max_chunks=CONTEXT_MAX_CHUNKS)
    user_prompt = build_user_prompt(user_input, context)

    t0 = time.time()
    response = chat(LLM_MODEL, SYSTEM_PROMPT, user_prompt, json_schema=MAPPING_RESPONSE_SCHEMA)
    timings["llm_seconds"] = time.time() - t0
    llm_output = json.loads(response["message"]["content"])

    t0 = time.time()
    kb = _get_kb()
    grounded_ids = set(retrieval_support.keys())
    validated = validate_response(
        llm_output, kb, grounded_attack_ids=grounded_ids, raw_input=user_input
    )
    for mapping in validated["mappings"]:
        support = retrieval_support.get(mapping["attack_id"]) or {}
        # absolute: mutlak sinyal (karar katmani icin). relative: sorgu ici
        # siralama olcusu (guven skoru icin). Bkz. normalize_support.
        mapping["retrieval_support_score"] = support.get("absolute")
        mapping["retrieval_rank_score"] = support.get("relative")
        mapping["qradar_rule_draft"] = build_qradar_rule_draft(mapping, normalized)
        technique = kb.by_id.get(mapping["attack_id"])
        confidence = compute_confidence(mapping, technique, normalized, user_input)
        mapping["llm_reported_confidence"] = mapping["confidence_level"]
        mapping["confidence_level"] = confidence["level"]
        mapping["confidence_score"] = confidence["score"]
        mapping["confidence_components"] = confidence["components"]

    timings["validation_seconds"] = time.time() - t0

    # KARAR BURADA VERILMIYOR (Gorev 5). Eskiden assess_activity burada
    # cagriliyordu -- yani AJAN KATMANINDAN ONCE, "dogrulanmis kanit
    # sayisi" girdisinin var olmasi imkansizken. Karar artik grafin
    # `decide` dugumunde, dogrulama bittikten sonra.
    return validated, timings


def _analyze_event(user_input: str, platform: str | None = None) -> dict[str, Any]:
    """TEK BIR OLAYIN analizi. Akis LangGraph tarafindan yurutuluyor
    (bkz. app/agents/graph.py); bu fonksiyon girdi hazirlar, grafi kosturur
    ve ciktiyi projenin her yerinde beklenen sozluk formatina cevirir.

    Cikti anahtarlari BILEREK degismedi: toplu mod, arayuz ve degerlendirme
    betikleri bu sozlesmeye bagli. Dongu yalnizca YENI anahtar ekler.

    BOLME BURADA YAPILMAZ (Gorev 14): girdiyi olaylara bolen ve event
    kararlarini birlestiren yol `run_improved_query`. Bu fonksiyon her zaman
    TEK olay gorur -- toplu modun her CSV satiri icin gordugu seyin aynisi."""
    # Ic ice import: graph modulu bu modulun dugum fonksiyonlarini kullaniyor,
    # yani tepe seviyede import etmek dairesel bagimlilik olurdu.
    from app.agents.graph import run_analysis_graph

    t_start = time.time()
    usage_start = usage_snapshot()

    normalized = normalize_input(user_input)
    effective_platform = platform or normalized.get("platform")
    # KATMANLI SORGU, KOSULSUZ (2A(b), olculdu 2026-08-17). Esik YOK, dal YOK.
    # Gerekce ve olcum: docs/beklenti_2a_b_esik.md + HANDOFF "2A(b)".
    enriched_query = build_layered_query(user_input, normalized, include_raw=True)

    state = run_analysis_graph(
        user_input=user_input,
        normalized=normalized,
        enriched_query=enriched_query,
        platform=effective_platform,
    )

    validated = state["validated"]
    reranked = state["reranked"]
    verification = state["verification"]
    mappings_before_agents = state["mappings_before_agents"]
    timings = dict(state["timings"])

    timings["total_seconds"] = time.time() - t_start

    return {
        "input_summary": {
            "raw_input": user_input,
            "platform_filter": platform,
            "detected_platform": normalized.get("platform"),
            "detected_tools": normalized.get("detected_tools"),
            "is_remote": normalized.get("is_remote"),
            "observed_actions_heuristic": normalized.get("observed_actions"),
        },
        "decision": state.get("decision") or {},
        # YALNIZCA GOSTERIM. Karar girdisi DEGIL (Gorev 5 bolum 5.3):
        # ham metin taramasi taklit edilebilir -- T3'e aktor olmayan bir
        # alana "trustedinstaller.exe" dizesi konunca sinyal mesru diyordu,
        # process.name hala powershell.exe idi. Analiste gosterilir, karari
        # etkilemez.
        "benign_signals_display": detect_benign_signals(user_input).signals,
        "observed_behaviors": validated.get("observed_behaviors", []),
        "filtered_observed_behaviors": validated.get("filtered_observed_behaviors", []),
        "mappings": validated.get("mappings", []),
        "mappings_before_agents": mappings_before_agents,
        # Ablasyonun uc kolu (bkz. scripts/run_agent_loop_ablation.py):
        #   mappings_before_agents     -> ajansiz
        #   mappings_after_first_pass  -> ajanli, dongusuz
        #   mappings                   -> ajanli + dongulu (nihai)
        "mappings_after_first_pass": state.get("mappings_after_first_pass", []),
        "rejected_mappings": validated.get("rejected_mappings", []),
        # Ajan katmaninin eledikleri AYRI tutuluyor: dogrulama katmaninin
        # (ID/isim/revoked) eledikleriyle karistirilmamali -- ikisi farkli
        # sorulara cevap veriyor.
        "agent_rejected_mappings": [
            {**mapping, "agent_id": decision.agent_id, "agent_reason": decision.reason}
            for mapping, decision in verification.rejected
        ],
        "agent_decisions": [
            {
                "agent_id": d.agent_id,
                "attack_id": d.technique_id,
                "verdict": d.verdict.value,
                "reason": d.reason,
            }
            for d in verification.decisions
        ],
        "alternative_candidates": validated.get("alternative_candidates", []),
        "additional_data_needed": validated.get("additional_data_needed", []),
        "evidence_summary": build_evidence_summary(
            normalized.get("extracted_facts") or {},
            validated.get("mappings", []),
            validated.get("rejected_mappings", []),
        ),
        "attack_version": ATTACK_VERSION,
        "retrieved_chunk_ids": [c["chunk_id"] for c in reranked],
        # LLM'e GIDEN aday havuzu -- secim yapilmadan onceki hali.
        #
        # Bu alan olmadan "teknik X ciktida yok" gozlemi tesihs edilemiyor:
        # retrieval mi getirmedi, LLM mi secmedi, kapi mi eledi, ajan mi
        # dusurdu -- dordu de ayni sonucu veriyor ama dordunun cozumu farkli.
        # mappings_before_agents ile birlikte zincirin her halkasi izlenebilir:
        #   retrieval_candidates -> mappings_before_agents -> mappings
        "retrieval_candidates": _candidate_list(state["retrieval_support"]),
        # ILK turun havuzu. "Retrieval bu teknigi buldu mu" sorusu BUNA
        # sorulur: ikinci tur havuzu ezer ve ajanlarin curuttuklerini duser,
        # yani son duruma bakan bir olcum birinci turda BULUNMUS bir teknigi
        # "hic gelmedi" diye raporlar.
        "retrieval_candidates_first_pass": _candidate_list(
            state.get("first_pass_retrieval_support") or state["retrieval_support"]
        ),
        # Dongu denetim izi: kac tur donuldu, neden donuldu, ikinci turda
        # hangi teknikler aday listesinden dusuruldu. Bos liste = dongu hic
        # tetiklenmedi (tek gecis yeterli olmus).
        "loop_passes": state["pass_index"],
        "loop_trace": state["loop_trace"],
        "timings": timings,
        "token_usage": usage_since(usage_start),
        "system": "improved",
    }


# --------------------------------------------------------------------------
# Girdi bolme + alarm seviyesi karar (Gorev 14)
# --------------------------------------------------------------------------
#
# TEK YOL, IKI GIRDI BICIMI. Toplu mod zaten dogru yapiyordu: her CSV satiri
# kendi `run_improved_query` cagrisini aliyor, yani asagi akista `rows` tek
# elemanli ve satirlar arasi capraz carpim kendiliginden cokuyor. Kusur
# YALNIZCA tekli girdiye cok olay yapistirildiginda dogar.
#
# Bu yuzden burada YENI bir dogrulama mimarisi yok; tekli girdi olaylara
# bolunup toplu modun kullandigi AYNI fonksiyondan (`_analyze_event`)
# geciriliyor. Iki ayri kod yolu yazmak bu oturumda uc kez isirdi
# (space_kv, to_legacy_facts, text_to_row): duzeltme bir yola iniyor, obur
# yol eski davranisi sakliyor ve testler yesil kaliyor.
#
# TEKLI GIRDI DE AYNI YOLDAN GECER: bolme tek elemanli liste dondurur ve
# birlestirici tek event'te hicbir sey eklemez. "Bolundu mu" diye dallanan
# bir if YOK -- olsaydi tek olayli girdi olculmemis bir yola dusebilirdi.

_SAYISAL_TOPLANAN = ("timings", "token_usage")


def _birlestir_sozluk_listeleri(sozlukler: list[dict[str, Any]]) -> dict[str, Any]:
    """Sayisal alanlari TOPLAR (sure, token). Alarm 3 event'e bolunduyse
    harcanan sure ucunun toplamidir; birini raporlamak yaniltir."""
    toplam: dict[str, Any] = {}
    for s in sozlukler:
        for k, v in (s or {}).items():
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                toplam[k] = toplam.get(k, 0) + v
            else:
                toplam.setdefault(k, v)
    return toplam


def _etiketli(kayitlar: list[dict[str, Any]] | None, index: int) -> list[dict[str, Any]]:
    """Her kaydi geldigi event ile isaretler.

    Atifin gorunur yarisi: alarm seviyesinde "bu teknik nereden geldi"
    sorusunun cevabi ciktida durmali. Gorunmez yarisi kanit kapisindaki
    `source_row_id` (app/agents/verification.py).

    Metin kayitlari (gozlemlenen davranislar, dongu izi) sozluk degil, o
    yuzden onlarda etiket metnin onune yazilir."""
    return [
        {**k, "source_event_index": index} if isinstance(k, dict) else f"event #{index}: {k}"
        for k in (kayitlar or [])
    ]


def _mappings_birlestir(sonuclar: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Event'lerin eslestirmelerini teknik basina TEKLESTIRIR.

    Ayni teknik iki event'te de secildiyse tek satir kalir ve hangi
    event'lerden geldigi `source_event_indices`'te durur. Gerekce olculmus:
    `mappings` listesi her yerde TEKNIK LISTESI olarak okunuyor (metrics
    precision/recall, UI tablosu, QRadar taslagi); ayni ID'yi iki kez
    koymak bir tekniği iki bulgu gibi saydirirdi."""
    birlesik: list[dict[str, Any]] = []
    index_of: dict[str, int] = {}
    for i, sonuc in enumerate(sonuclar):
        for mapping in sonuc.get("mappings") or []:
            attack_id = mapping.get("attack_id")
            if attack_id in index_of:
                mevcut = birlesik[index_of[attack_id]]
                mevcut["source_event_indices"] = sorted(
                    set(mevcut.get("source_event_indices") or []) | {i}
                )
                continue
            index_of[attack_id] = len(birlesik)
            birlesik.append({
                **mapping,
                "source_event_index": i,
                "source_event_indices": [i],
            })
    return birlesik


def _evidence_summary_birlestir(sonuclar: list[dict[str, Any]]) -> dict[str, list[str]]:
    birlesik: dict[str, list[str]] = {}
    for sonuc in sonuclar:
        for anahtar, deger in (sonuc.get("evidence_summary") or {}).items():
            hedef = birlesik.setdefault(anahtar, [])
            for oge in deger or []:
                if oge not in hedef:
                    hedef.append(oge)
    return birlesik


def _alarm_karari(sonuclar: list[dict[str, Any]], bolme: Any) -> dict[str, Any]:
    """Event kararlarini §1 ile birlestirir -- EN SERT KAZANIR.

    Birlestirici karar katmanindadir (`combine_event_decisions`), burada
    degil: karar mantiginin ikinci bir kopyasini hat katmanina yazmak iki
    gerceklik demektir."""
    from app.validation.decision import Decision, combine_event_decisions

    ham = [sonuc.get("decision") for sonuc in sonuclar]
    if not all(ham):
        # HEPSI YA DA HICBIRI. Eksik bir event karari, kalanlari bir index
        # kaydirir ve `belirleyen_event` YANLIS event'i gosterir -- dogru
        # sinif, yanlis atif. Bu projede tam olarak bu desen defalarca
        # olcum kirletti; sessizce yarim birlestirmektense hic birlestirme.
        return {}
    kararlar = [Decision(**d) for d in ham]
    return combine_event_decisions(kararlar, split=bolme.to_dict()).to_dict()


def run_improved_query(user_input: str, platform: str | None = None) -> dict[str, Any]:
    """Gelistirilmis hattin GIRIS NOKTASI: girdiyi olaylara boler, her olayi
    tek-olay yolundan gecirir, event kararlarini alarm karariyla birlestirir.

    Cikti sozlesmesi korunur -- `decision` anahtari hala bir karar sozlugudur
    (alarm karari onun ustkumesidir), `mappings` hala teknik listesidir.
    YENI anahtarlar: `split`, `events`.

    Tek olayli girdide davranis DEGISMEZ: bolme tek elemanli liste doner,
    birlestirici zincire hicbir sey eklemez ve sonuc tek event'in sonucudur.
    Olculdu (2026-08-19): 60 senaryonun 60'i, dort probe logunun dordu ve 51
    gercek QRadar satirinin 51'i tek olay uretiyor -- yani gecmis olcumler
    karsilastirilabilir kaliyor."""
    from app.normalization.formats import split_events

    bolme = split_events(user_input)
    sonuclar = [_analyze_event(olay, platform=platform) for olay in bolme.events]

    if len(sonuclar) == 1:
        # TEK OLAY: sonucun kendisi doner. Alarm karari tek event'in
        # kararinin ustkumesidir (ayni sinif, ayni zincir) -- ek alanlar
        # tekli girdide de tasiniyor ki tuketiciler tek bicim gorsun.
        tek = dict(sonuclar[0])
        tek["decision"] = _alarm_karari(sonuclar, bolme) or tek.get("decision") or {}
        tek["split"] = bolme.to_dict()
        tek["events"] = [{"index": 0, "raw": bolme.events[0]}]
        return tek

    birlesik: dict[str, Any] = {
        "input_summary": {
            "raw_input": user_input,
            "platform_filter": platform,
            "detected_platform": (sonuclar[0].get("input_summary") or {}).get(
                "detected_platform"
            ),
            "detected_tools": sorted({
                arac
                for s in sonuclar
                for arac in (s.get("input_summary") or {}).get("detected_tools") or []
            }),
            "is_remote": any(
                (s.get("input_summary") or {}).get("is_remote") for s in sonuclar
            ),
            "observed_actions_heuristic": [
                f"event #{i}: {eylem}"
                for i, s in enumerate(sonuclar)
                for eylem in (s.get("input_summary") or {}).get(
                    "observed_actions_heuristic"
                ) or []
            ],
        },
        "decision": _alarm_karari(sonuclar, bolme),
        "split": bolme.to_dict(),
        "events": [
            {
                "index": i,
                "raw": bolme.events[i],
                "decision": s.get("decision") or {},
                "mappings": [m.get("attack_id") for m in s.get("mappings") or []],
            }
            for i, s in enumerate(sonuclar)
        ],
        "benign_signals_display": [
            f"event #{i}: {sinyal}"
            for i, s in enumerate(sonuclar)
            for sinyal in s.get("benign_signals_display") or []
        ],
        "mappings": _mappings_birlestir(sonuclar),
        "evidence_summary": _evidence_summary_birlestir(sonuclar),
        "attack_version": ATTACK_VERSION,
        "loop_passes": max(s.get("loop_passes") or 0 for s in sonuclar),
        "timings": _birlestir_sozluk_listeleri([s.get("timings") for s in sonuclar]),
        "token_usage": _birlestir_sozluk_listeleri(
            [s.get("token_usage") for s in sonuclar]
        ),
        "system": "improved",
    }

    # Kalan listeler: her kayit GELDIGI event ile isaretlenerek birlestirilir.
    for anahtar in (
        "observed_behaviors",
        "filtered_observed_behaviors",
        "mappings_before_agents",
        "mappings_after_first_pass",
        "rejected_mappings",
        "agent_rejected_mappings",
        "agent_decisions",
        "alternative_candidates",
        "retrieval_candidates",
        "retrieval_candidates_first_pass",
        "loop_trace",
    ):
        birlesik[anahtar] = [
            kayit
            for i, s in enumerate(sonuclar)
            for kayit in _etiketli(s.get(anahtar), i)
        ]

    birlesik["additional_data_needed"] = [
        oge for s in sonuclar for oge in s.get("additional_data_needed") or []
    ]
    birlesik["retrieved_chunk_ids"] = [
        cid for s in sonuclar for cid in s.get("retrieved_chunk_ids") or []
    ]
    return birlesik
