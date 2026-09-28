"""Ollama local embedding API'sine ince bir istemci katmani."""

from __future__ import annotations

import requests

OLLAMA_HOST = "http://localhost:11434"


def embed_texts(model: str, texts: list[str], batch_size: int = 16) -> list[list[float]]:
    """Verilen metinleri Ollama /api/embed uzerinden vektorlere cevirir. Ollama tek
    istekte bir liste kabul ediyor; yine de asiri buyuk isteklerden kacinmak icin
    kucuk gruplar halinde gonderiyoruz."""
    embeddings: list[list[float]] = []
    for i in range(0, len(texts), batch_size):
        batch = texts[i:i + batch_size]
        response = requests.post(
            f"{OLLAMA_HOST}/api/embed",
            json={"model": model, "input": batch},
            timeout=300,
        )
        response.raise_for_status()
        embeddings.extend(response.json()["embeddings"])
    return embeddings
