"""BM25 tabanli keyword index. Semantic search'un kacirdigi tam eslesmeleri
(schtasks.exe, T1059.001, LSASS gibi) yakalamak icin kullanilir (dokuman bolum 17.3).
"""

from __future__ import annotations

import pickle
import re
from pathlib import Path
from typing import Any

from rank_bm25 import BM25Okapi

DEFAULT_INDEX_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "indexes" / "bm25_index.pkl"

TOKEN_PATTERN = re.compile(r"[a-zA-Z0-9_./:\\-]+")


def tokenize(text: str) -> list[str]:
    return [t.lower() for t in TOKEN_PATTERN.findall(text)]


class KeywordIndex:
    def __init__(self, chunk_ids: list[str], bm25: BM25Okapi):
        self.chunk_ids = chunk_ids
        self.bm25 = bm25

    @classmethod
    def build(cls, chunks: list[dict[str, Any]]) -> "KeywordIndex":
        chunk_ids = [c["chunk_id"] for c in chunks]
        tokenized_corpus = [tokenize(c["text"]) for c in chunks]
        bm25 = BM25Okapi(tokenized_corpus)
        return cls(chunk_ids, bm25)

    def save(self, path: Path = DEFAULT_INDEX_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump({"chunk_ids": self.chunk_ids, "bm25": self.bm25}, f)

    @classmethod
    def load(cls, path: Path = DEFAULT_INDEX_PATH) -> "KeywordIndex":
        with open(path, "rb") as f:
            data = pickle.load(f)
        return cls(data["chunk_ids"], data["bm25"])

    def search(self, query: str, n_results: int = 10) -> list[tuple[str, float]]:
        scores = self.bm25.get_scores(tokenize(query))
        ranked = sorted(zip(self.chunk_ids, scores), key=lambda x: -x[1])
        return ranked[:n_results]
