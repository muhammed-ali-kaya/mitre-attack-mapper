"""Indeks butunluk damgasi -- yarida kalan insanin SESSIZ kalmasini engeller.

OLCULEN HATA (2026-08-16)
    build_index.py koleksiyonu temizlemiyordu; batch batch uzerine yaziyordu.
    Ollama zaman asimiyla dusen bir insa, bir kismi YENI bir kismi ESKI
    gommeli KARISIK bir indeks birakti. Chunk sayisi 3122'de kaldigi icin
    hicbir sey yanlis gorunmedi -- sayim, koleksiyonun tutarli oldugunu
    SANDIRAN bir olcuydu.

    Bu, oturumda tekrar eden "sessizce yanlis calisan katman" ailesinin en
    tehlikelisi: tespit edilebilir izi yok. Yedek olmasaydi bozuk indeks
    uzerine olcmeye devam edilecekti.

IKI PARCALI COZUM -- biri digeri olmadan ise yaramaz
    1. ATOMIK INSA: gecici koleksiyona yaz, tamamlandigini dogrula, sonra
       takas et. Yarida kesilen insa hicbir seyi degistirmemeli.
    2. HER SORGUDA KONTROL: damga yazilip okunmuyorsa, olmayan damgadir.
       Uyusmazlikta hat ACIK HATA verir; sessizce devam etmez.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

STAMP_FILE = (
    Path(__file__).resolve().parents[2] / "data" / "indexes" / "index_stamp.json"
)


class IndexIntegrityError(RuntimeError):
    """Indeks, uretildigi chunk setiyle uyusmuyor.

    Sessizce devam etmek yerine acik hata: bozuk bir indeks uzerine alinan
    her olcum, dogru gorunen ama yanlis kaynaktan gelen bir sayidir."""


@dataclass(frozen=True)
class IndexStamp:
    chunk_count: int
    chunk_text_hash: str
    collection: str
    embedding_model: str
    built_at: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, indent=2)


def chunk_text_hash(chunks: list[dict[str, Any]]) -> str:
    """Chunk KUMESININ icerik parmak izi.

    chunk_id + metin birlikte hash'lenir: yalnizca sayiya bakmak, ayni
    sayida ama farkli icerikli bir koleksiyonu tutarli gosterir -- olculen
    hata tam olarak buydu."""
    payload = "".join(
        c["chunk_id"] + c["text"] for c in sorted(chunks, key=lambda x: x["chunk_id"])
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def write_stamp(
    chunks: list[dict[str, Any]],
    collection: str,
    embedding_model: str,
    path: Path = STAMP_FILE,
) -> IndexStamp:
    """Damgayi insa BITTIKTEN sonra yazar.

    Sirasi kritik: once damga yazilirsa, yarida kalan bir insa gecerli
    gorunen bir damga birakir."""
    stamp = IndexStamp(
        chunk_count=len(chunks),
        chunk_text_hash=chunk_text_hash(chunks),
        collection=collection,
        embedding_model=embedding_model,
        built_at=datetime.now(timezone.utc).isoformat(),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(stamp.to_json(), encoding="utf-8")
    return stamp


def read_stamp(path: Path = STAMP_FILE) -> IndexStamp | None:
    if not path.exists():
        return None
    try:
        return IndexStamp(**json.loads(path.read_text(encoding="utf-8")))
    except Exception:
        return None


def verify(
    chunks: list[dict[str, Any]],
    collection: str,
    actual_count: int,
    path: Path = STAMP_FILE,
) -> None:
    """Sorgu oncesi kontrol. Uyusmazlikta ACIK HATA atar.

    Yazilip okunmayan damga, olmayan damgadir -- bu yuzden kontrol
    retrieval yolunda cagriliyor, yalnizca insa betiginde degil."""
    stamp = read_stamp(path)
    if stamp is None:
        raise IndexIntegrityError(
            "Indeks butunluk damgasi yok. Indeks, hangi chunk setinden "
            "uretildigi bilinmeden kullanilamaz -- scripts/build_index.py "
            "ile yeniden insa edin."
        )

    expected = chunk_text_hash(chunks)
    if stamp.chunk_text_hash != expected:
        raise IndexIntegrityError(
            f"Indeks, mevcut chunk setiyle UYUSMUYOR.\n"
            f"  damgadaki hash : {stamp.chunk_text_hash[:16]}\n"
            f"  mevcut chunk'lar: {expected[:16]}\n"
            "chunks_content_type.json degistiyse indeks yeniden insa edilmeli."
        )
    if stamp.chunk_count != actual_count:
        raise IndexIntegrityError(
            f"Koleksiyondaki kayit sayisi damgayla uyusmuyor: "
            f"{actual_count} != {stamp.chunk_count}. Yarida kalmis bir insa "
            "olabilir."
        )
    if stamp.collection != collection:
        raise IndexIntegrityError(
            f"Damga baska bir koleksiyon icin: {stamp.collection} != {collection}"
        )
