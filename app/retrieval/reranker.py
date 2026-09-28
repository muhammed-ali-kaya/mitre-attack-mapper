"""Cross-encoder reranker (dokuman bolum 19). bge-m3 ile ayni aileden olan
BAAI/bge-reranker-base kullanilir; sentence-transformers uzerinden local olarak
calisir (HuggingFace'ten bir kere indirilir, sonrasinda internet gerekmez).

Donanim notu: reranker bilerek CPU'da calistiriliyor. 8GB VRAM'lik kartimizda
Ollama zaten qwen3:8b (~5.6GB) + bge-m3 (~0.7GB) = ~6.2GB tutuyor; reranker'i da
GPU'ya koymak karti doldurup Ollama'nin modelleri surekli VRAM'den atip yeniden
yuklemesine (thrashing) yol aciyordu -- bu da LLM cagrilarinin 300s timeout'a
takilmasina sebep oldu (evaluation kosumunda gozlemlendi). Kucuk bir cross-encoder
(278M) icin CPU makul bir hizda calisiyor; Ollama'nin VRAM'i tam kalmasi daha
kritik oldugu icin bu tercih edildi."""

from __future__ import annotations

from typing import Any

RERANKER_MODEL = "BAAI/bge-reranker-base"


class Reranker:
    def __init__(self, model_name: str = RERANKER_MODEL, device: str = "cpu"):
        from sentence_transformers import CrossEncoder

        self.model = CrossEncoder(model_name, device=device)

    def rerank(self, query: str, chunks: list[dict[str, Any]], top_n: int = 10) -> list[dict[str, Any]]:
        if not chunks:
            return []
        pairs = [(query, c["text"]) for c in chunks]
        scores = self.model.predict(pairs)
        for chunk, score in zip(chunks, scores):
            chunk["rerank_score"] = float(score)
        ranked = sorted(chunks, key=lambda c: -c["rerank_score"])
        return ranked[:top_n]
