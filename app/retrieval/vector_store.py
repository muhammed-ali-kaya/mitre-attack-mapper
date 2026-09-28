"""ChromaDB uzerinde persistent bir vector store katmani.

ChromaDB metadata degerleri yalnizca str/int/float/bool olabilir; None, list ve
dict degerleri desteklenmez. Bu yuzden chunk metadata'sini Chroma'ya yazmadan
once sadelestiriyoruz (liste -> virgullu string, dict -> json string, None -> atla).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import chromadb

DEFAULT_INDEX_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "indexes" / "chroma"


def sanitize_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    for key, value in metadata.items():
        if value is None:
            continue
        if isinstance(value, list):
            clean[key] = ", ".join(str(v) for v in value)
        elif isinstance(value, dict):
            clean[key] = json.dumps(value, ensure_ascii=False)
        else:
            clean[key] = value
    return clean


class VectorStore:
    def __init__(self, collection_name: str, persist_dir: Path = DEFAULT_INDEX_DIR):
        persist_dir.mkdir(parents=True, exist_ok=True)
        self.client = chromadb.PersistentClient(path=str(persist_dir))
        self.collection = self.client.get_or_create_collection(
            name=collection_name,
            metadata={"hnsw:space": "cosine"},
        )

    def add_chunks(self, chunks: list[dict[str, Any]], embeddings: list[list[float]], batch_size: int = 200) -> None:
        for i in range(0, len(chunks), batch_size):
            batch = chunks[i:i + batch_size]
            batch_embeddings = embeddings[i:i + batch_size]
            self.collection.add(
                ids=[c["chunk_id"] for c in batch],
                embeddings=batch_embeddings,
                documents=[c["text"] for c in batch],
                metadatas=[sanitize_metadata({"attack_id": c["attack_id"], "content_type": c["content_type"], **c["metadata"]}) for c in batch],
            )

    def query(self, query_embedding: list[float], n_results: int = 10, where: dict | None = None) -> dict:
        return self.collection.query(
            query_embeddings=[query_embedding],
            n_results=n_results,
            where=where,
        )

    def count(self) -> int:
        return self.collection.count()

    def reset(self) -> None:
        """Koleksiyonu bosaltir (varsa siler, yeniden olusturur).

        Insa oncesi gerekli: eski hali koleksiyonu temizlemeden uzerine
        yaziyordu ve yarida kalan bir insa, bir kismi yeni bir kismi eski
        gommeli KARISIK bir indeks birakiyordu -- chunk sayisi dogru
        kaldigi icin fark edilmeden."""
        name = self.collection.name
        try:
            self.client.delete_collection(name)
        except Exception:
            pass  # yoktu; olusturmak yeterli
        self.collection = self.client.get_or_create_collection(
            name=name, metadata={"hnsw:space": "cosine"}
        )

    def promote_to(self, target_name: str) -> None:
        """Bu (gecici) koleksiyonun icerigini hedef koleksiyona TAKAS eder.

        Chroma'da atomik rename yok, bu yuzden: hedefi sil, yeniden olustur,
        kayitlari toptan kopyala. Kopyalama basarisiz olursa gecici
        koleksiyon yerinde durur ve insa tekrarlanabilir.

        Kritik nokta: buraya YALNIZCA insa tamamlandigi DOGRULANDIKTAN sonra
        gelinir. Yarida kesilen insa canli koleksiyona hic dokunmaz."""
        data = self.collection.get(include=["embeddings", "documents", "metadatas"])
        ids = data["ids"]
        if not ids:
            raise RuntimeError("Gecici koleksiyon bos -- takas edilmeyecek.")

        try:
            self.client.delete_collection(target_name)
        except Exception:
            pass
        target = self.client.get_or_create_collection(
            name=target_name, metadata={"hnsw:space": "cosine"}
        )

        batch = 500
        for i in range(0, len(ids), batch):
            target.add(
                ids=ids[i:i + batch],
                embeddings=data["embeddings"][i:i + batch],
                documents=data["documents"][i:i + batch],
                metadatas=data["metadatas"][i:i + batch],
            )

        # Gecici koleksiyon artik gereksiz.
        try:
            self.client.delete_collection(self.collection.name)
        except Exception:
            pass
