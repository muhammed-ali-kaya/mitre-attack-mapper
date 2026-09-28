"""Iki embedding modelini (qwen3-embedding, bge-m3) kucuk, elle etiketlenmis bir
sorgu setiyle karsilastirir. Bu, resmi 60 test senaryosunun (Milestone 6) yerine
gecmez -- sadece embedding modeli secimini erken ve olculebilir bir sekilde
yapabilmek icin dokuman bolum 4'teki ornek senaryolardan turetilmis kucuk bir
"seed" settir.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.ingestion.embedding_client import embed_texts

PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
EVAL_SEED_FILE = PROJECT_ROOT / "evaluation" / "embedding_comparison_seed.json"

MODELS = ["qwen3-embedding", "bge-m3"]
DESCRIPTION_TYPES = {"technique_description", "subtechnique_description"}


def cosine_sim_matrix(query_vecs: np.ndarray, corpus_vecs: np.ndarray) -> np.ndarray:
    q = query_vecs / np.linalg.norm(query_vecs, axis=1, keepdims=True)
    c = corpus_vecs / np.linalg.norm(corpus_vecs, axis=1, keepdims=True)
    return q @ c.T


def evaluate_model(model: str, corpus_texts: list[str], corpus_ids: list[str], seed: list[dict]) -> dict:
    print(f"[{model}] Teknik aciklamalari embed ediliyor ({len(corpus_texts)} chunk)...")
    t0 = time.time()
    corpus_vecs = np.array(embed_texts(model, corpus_texts))
    corpus_time = time.time() - t0

    queries = [item["query"] for item in seed]
    t0 = time.time()
    query_vecs = np.array(embed_texts(model, queries))
    query_time = time.time() - t0

    sims = cosine_sim_matrix(query_vecs, corpus_vecs)

    recall_at_5 = 0
    recall_at_10 = 0
    reciprocal_ranks = []
    per_query_results = []

    for i, item in enumerate(seed):
        order = np.argsort(-sims[i])
        ranked_ids = [corpus_ids[j] for j in order]
        expected = item["expected_attack_id"]
        rank = ranked_ids.index(expected) + 1 if expected in ranked_ids else None

        if rank is not None and rank <= 5:
            recall_at_5 += 1
        if rank is not None and rank <= 10:
            recall_at_10 += 1
        reciprocal_ranks.append(1.0 / rank if rank else 0.0)

        per_query_results.append({
            "query": item["query"],
            "expected": expected,
            "rank": rank,
            "top3": ranked_ids[:3],
        })

    n = len(seed)
    return {
        "model": model,
        "recall_at_5": recall_at_5 / n,
        "recall_at_10": recall_at_10 / n,
        "mrr": sum(reciprocal_ranks) / n,
        "corpus_embed_seconds": corpus_time,
        "corpus_embed_per_chunk_ms": (corpus_time / len(corpus_texts)) * 1000,
        "query_embed_seconds": query_time,
        "embedding_dim": corpus_vecs.shape[1],
        "per_query": per_query_results,
    }


def main() -> None:
    chunks = json.loads((PROCESSED_DIR / "chunks_content_type.json").read_text(encoding="utf-8"))
    description_chunks = [c for c in chunks if c["content_type"] in DESCRIPTION_TYPES and not c["metadata"]["revoked"]]
    corpus_texts = [c["text"] for c in description_chunks]
    corpus_ids = [c["attack_id"] for c in description_chunks]

    seed = json.loads(EVAL_SEED_FILE.read_text(encoding="utf-8"))

    results = []
    for model in MODELS:
        result = evaluate_model(model, corpus_texts, corpus_ids, seed)
        results.append(result)
        print(f"\n=== {model} ===")
        print(f"Recall@5:  {result['recall_at_5']:.2f}")
        print(f"Recall@10: {result['recall_at_10']:.2f}")
        print(f"MRR:       {result['mrr']:.3f}")
        print(f"Embedding boyutu: {result['embedding_dim']}")
        print(f"Corpus embed suresi: {result['corpus_embed_seconds']:.1f}s ({result['corpus_embed_per_chunk_ms']:.1f} ms/chunk)")
        print()
        for pq in result["per_query"]:
            mark = "OK" if pq["rank"] and pq["rank"] <= 5 else "MISS"
            print(f"  [{mark}] rank={pq['rank']}  beklenen={pq['expected']}  top3={pq['top3']}  soru={pq['query'][:60]}")
        print()

    out_file = PROJECT_ROOT / "evaluation" / "results" / "embedding_model_comparison.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Sonuclar kaydedildi: {out_file}")


if __name__ == "__main__":
    main()
