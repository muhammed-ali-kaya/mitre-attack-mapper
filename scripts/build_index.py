"""Content-type chunk'larini bge-m3 ile embed edip ChromaDB'ye yazar, ayni
zamanda BM25 keyword index'ini kurar. Hybrid retrieval'in (semantic + keyword)
veri katmanini olusturan script budur.

INSA ATOMIKTIR -- olculmus bir hatanin sonucu
    Eski hali koleksiyonu temizlemeden batch batch uzerine yaziyordu. Ollama
    zaman asimiyla dusen bir insa, bir kismi YENI bir kismi ESKI gommeli
    KARISIK bir indeks birakti; chunk sayisi dogru kaldigi icin hicbir sey
    yanlis gormedi. Yedek olmasaydi bozuk indeks uzerine olcmeye devam
    edilecekti.

    Simdi: GECICI koleksiyona yazilir, tamamlandigi dogrulanir, sonra takas
    edilir. Yarida kesilen bir insa CANLI koleksiyona dokunmaz.

MODEL ROLLERI AYRIDIR -- 8 GB VRAM kisiti
    Bu makinede analiz ve indeks insasi ESZAMANLI YAPILAMAZ. qwen3:8b ~5.9GB
    tutuyor ve app/llm/ollama_client.py keep_alive=30m gonderiyor (cikti
    tutarliligi icin, olculmus gerekce orada). bge-m3'e yer kalmayinca Ollama
    surekli tahliye/yukleme yapiyor ve gomme istekleri 300sn zaman asimina
    giriyor -- ilk insa denemesi tam boyle dustu.

    Bu yuzden insa, basinda LLM'i VRAM'den bosaltir. Analiz tarafi kendi
    isinmasini zaten yapiyor (app/ui/streamlit_app.py).
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.evaluation.run_hygiene import unload_model
from app.ingestion.embedding_client import embed_texts
from app.retrieval.index_integrity import write_stamp
from app.retrieval.keyword_index import KeywordIndex
from app.retrieval.vector_store import VectorStore

PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
EMBEDDING_MODEL = "bge-m3"
COLLECTION_NAME = "attack_content_type_bge_m3"
STAGING_COLLECTION = f"{COLLECTION_NAME}__staging"
EMBED_BATCH_SIZE = 16


def main() -> None:
    chunks = json.loads((PROCESSED_DIR / "chunks_content_type.json").read_text(encoding="utf-8"))
    print(f"Toplam chunk: {len(chunks)}")

    # LLM'i bosalt: gomme isinin VRAM'e ihtiyaci var (bkz. modul basligi).
    if unload_model():
        print("LLM VRAM'den bosaltildi (insa modu).")
    else:
        print("UYARI: LLM bosaltilamadi -- gomme istekleri zaman asimina girebilir.")

    keyword_index = KeywordIndex.build(chunks)

    # --- gecici koleksiyona yaz -------------------------------------------
    staging = VectorStore(STAGING_COLLECTION)
    staging.reset()

    texts = [c["text"] for c in chunks]
    t0 = time.time()
    done = 0
    for i in range(0, len(texts), EMBED_BATCH_SIZE):
        batch_chunks = chunks[i:i + EMBED_BATCH_SIZE]
        batch_texts = texts[i:i + EMBED_BATCH_SIZE]
        batch_embeddings = embed_texts(EMBEDDING_MODEL, batch_texts, batch_size=EMBED_BATCH_SIZE)
        staging.add_chunks(batch_chunks, batch_embeddings)
        done += len(batch_chunks)
        elapsed = time.time() - t0
        rate = done / elapsed if elapsed > 0 else 0
        eta = (len(texts) - done) / rate if rate > 0 else 0
        print(f"  {done}/{len(texts)}  ({elapsed:.0f}s gecti, tahmini kalan {eta:.0f}s)", flush=True)

    # --- tamamlandigini DOGRULA, sonra takas et ---------------------------
    staged = staging.count()
    if staged != len(chunks):
        raise RuntimeError(
            f"Insa tamamlanmadi: gecici koleksiyonda {staged} kayit var, "
            f"{len(chunks)} bekleniyordu. CANLI koleksiyona DOKUNULMADI."
        )

    staging.promote_to(COLLECTION_NAME)
    print(f"Gecici koleksiyon canliya alindi: {COLLECTION_NAME}")

    # Damga ve BM25 indeksi EN SON yazilir. Once yazilirsa, yarida kalan bir
    # insa gecerli gorunen bir damga birakir.
    keyword_index.save()
    stamp = write_stamp(chunks, COLLECTION_NAME, EMBEDDING_MODEL)
    print("BM25 keyword index kaydedildi.")
    print(f"Butunluk damgasi: {stamp.chunk_count} chunk, hash {stamp.chunk_text_hash[:16]}")

    store = VectorStore(COLLECTION_NAME)
    print(f"Tamamlandi. ChromaDB koleksiyonundaki toplam kayit: {store.count()}")


if __name__ == "__main__":
    main()
