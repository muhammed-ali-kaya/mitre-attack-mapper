"""Parse edilmis ATT&CK verisinden iki chunking stratejisi uretir: naive (baseline)
ve content_type (gelistirilmis). Sonuclari data/processed/chunks_*.json'a yazar."""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.ingestion.chunking import (
    chunk_mitigation,
    chunk_technique_content_type,
    chunk_technique_naive,
    estimate_tokens,
)

PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"


def report_stats(name: str, chunks: list[dict]) -> None:
    token_counts = sorted(estimate_tokens(c["text"]) for c in chunks)
    n = len(token_counts)
    from collections import Counter
    by_type = Counter(c["content_type"] for c in chunks)
    print(f"--- {name} ---")
    print(f"Toplam chunk: {n}")
    for t, c in by_type.most_common():
        print(f"  {t}: {c}")
    if n:
        print(f"Token: min={token_counts[0]} p50={token_counts[n//2]} p90={token_counts[int(n*0.9)]} max={token_counts[-1]}")
    print()


def main() -> None:
    techniques = json.loads((PROCESSED_DIR / "techniques.json").read_text(encoding="utf-8"))
    mitigations = json.loads((PROCESSED_DIR / "mitigations.json").read_text(encoding="utf-8"))

    naive_chunks = [chunk_technique_naive(t) for t in techniques]

    content_type_chunks: list[dict] = []
    for t in techniques:
        content_type_chunks.extend(chunk_technique_content_type(t))
    for m in mitigations:
        content_type_chunks.append(chunk_mitigation(m))

    (PROCESSED_DIR / "chunks_baseline.json").write_text(
        json.dumps(naive_chunks, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (PROCESSED_DIR / "chunks_content_type.json").write_text(
        json.dumps(content_type_chunks, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    report_stats("Strateji A: naive (baseline)", naive_chunks)
    report_stats("Strateji B: content_type (gelistirilmis)", content_type_chunks)


if __name__ == "__main__":
    main()
