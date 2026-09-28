"""Baseline RAG pipeline (dokuman bolum 17.1): yalnizca semantic search + LLM.

Hybrid retrieval, reranking, metadata filtreleme, log parsing/davranis cikarimi
ve dogrulama katmani burada YOK -- bunlar bilerek "Gelistirilmis Sistem"e
(Milestone 5) birakildi, boylece iki sistem olculebilir sekilde karsilastirilabilir
(dokuman bolum 33).
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
from app.retrieval.vector_store import VectorStore

EMBEDDING_MODEL = "bge-m3"
LLM_MODEL = "qwen3:8b"
COLLECTION_NAME = "attack_content_type_bge_m3"
ATTACK_VERSION = attack_version()  # data/metadata'dan; sabit degil


def _chroma_results_to_chunks(results: dict[str, Any]) -> list[dict[str, Any]]:
    chunks = []
    for cid, text, meta, dist in zip(
        results["ids"][0], results["documents"][0], results["metadatas"][0], results["distances"][0]
    ):
        chunks.append({
            "chunk_id": cid,
            "attack_id": meta["attack_id"],
            "content_type": meta["content_type"],
            "text": text,
            "metadata": meta,
            "distance": dist,
        })
    return chunks


def run_baseline_query(user_input: str, top_k: int = 10) -> dict[str, Any]:
    timings: dict[str, float] = {}
    t_start = time.time()
    usage_start = usage_snapshot()

    t0 = time.time()
    query_embedding = embed_texts(EMBEDDING_MODEL, [user_input])[0]
    timings["embedding_seconds"] = time.time() - t0

    t0 = time.time()
    store = VectorStore(COLLECTION_NAME)
    results = store.query(query_embedding, n_results=top_k)
    retrieved_chunks = _chroma_results_to_chunks(results)
    timings["retrieval_seconds"] = time.time() - t0

    context = build_context(retrieved_chunks)
    user_prompt = build_user_prompt(user_input, context)

    t0 = time.time()
    response = chat(LLM_MODEL, SYSTEM_PROMPT, user_prompt, json_schema=MAPPING_RESPONSE_SCHEMA)
    timings["llm_seconds"] = time.time() - t0

    llm_output = json.loads(response["message"]["content"])
    timings["total_seconds"] = time.time() - t_start

    return {
        "input_summary": {"raw_input": user_input},
        "observed_behaviors": llm_output.get("observed_behaviors", []),
        "mappings": llm_output.get("mappings", []),
        "alternative_candidates": llm_output.get("alternative_candidates", []),
        "additional_data_needed": llm_output.get("additional_data_needed", []),
        "attack_version": ATTACK_VERSION,
        "retrieved_chunk_ids": [c["chunk_id"] for c in retrieved_chunks],
        "timings": timings,
        "token_usage": usage_since(usage_start),
        "system": "baseline",
    }
