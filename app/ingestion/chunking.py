"""ATT&CK verisini RAG icin chunk'lara boler.

Iki farkli strateji uretilir (dokuman bolum 13, "en az iki farkli strateji
karsilastirilmali" gereksinimi icin):

  - naive: teknik basina tek buyuk chunk (baseline karsilastirma icin)
  - content_type: icerik turune gore bolunmus chunk'lar (technique_description,
    procedure_example, detection_guidance, mitigation ...)

Her chunk metninin basinda ATT&CK kimligi ve adi tekrarlanir, boylece chunk
tek basina retrieval'e girdiginde hangi teknige ait oldugu embedding'in
kendisinden de anlasilabilir (bolum 13, kural 1).
"""

from __future__ import annotations

from typing import Any

MIN_CHUNK_TOKENS = 250
TARGET_CHUNK_TOKENS = 600
MAX_CHUNK_TOKENS = 700


def estimate_tokens(text: str) -> int:
    """Kaba bir token tahmini (kelime sayisi * 1.3). Tam bir tokenizer degil,
    yalnizca chunk boyutunu 250-700 token araligina yaklastirmak icin kullanilir."""
    return max(1, round(len(text.split()) * 1.3))


def _technique_header(technique: dict[str, Any]) -> str:
    tactics = ", ".join(technique["tactics"]) if technique["tactics"] else "-"
    platforms = ", ".join(technique["platforms"]) if technique["platforms"] else "-"
    return (
        f"[{technique['attack_id']}] {technique['name']} "
        f"({technique['object_type']})\n"
        f"Taktikler: {tactics}\n"
        f"Platformlar: {platforms}"
    )


def _make_chunk(
    chunk_id: str,
    attack_id: str,
    content_type: str,
    text: str,
    technique: dict[str, Any],
) -> dict[str, Any]:
    return {
        "chunk_id": chunk_id,
        "attack_id": attack_id,
        "content_type": content_type,
        "text": text,
        "metadata": {
            "attack_version": technique["attack_version"],
            "name": technique["name"],
            "object_type": technique["object_type"],
            "is_subtechnique": technique["is_subtechnique"],
            "parent_technique_id": technique["parent_technique_id"],
            "tactics": technique["tactics"],
            "platforms": technique["platforms"],
            "deprecated": technique["deprecated"],
            "revoked": technique["revoked"],
            "revoked_by": technique.get("revoked_by"),
            "source_url": technique["source_url"],
        },
    }


def chunk_technique_description(technique: dict[str, Any]) -> dict[str, Any]:
    content_type = "subtechnique_description" if technique["is_subtechnique"] else "technique_description"
    text = f"{_technique_header(technique)}\n\n{technique['description']}"
    chunk_id = f"{technique['attack_id']}::{content_type}::0"
    return _make_chunk(chunk_id, technique["attack_id"], content_type, text, technique)


# --------------------------------------------------------------------------
# 2C PLANI -- beklentiler ONCEDEN yazildi (olcum gelince yorum kaymasin diye)
#
# OLCULEN DURUM (2026-08-16)
#   procedure_example korpusun en uzun ve en kalabalik turu: ort. 3107 kr,
#   n=1299. T1685'in "Defender" gecen metinleri burada (~4300 kr x8).
#   BM25 uzunluk normalizasyonu bunlari eziyor.
#
# BEKLENTI -- chunk bolme TEK BASINA yetmeyecek
#   T1685 su an T3 sorgusunda semantic 117. sirada (zenginlestirme kapali
#   olcumu). Bolme onu bir miktar yukari cekmeli ama TOP-20'YE SOKMAYACAK.
#   Gerekce olculdu: kisa sorgular AYNI uzun chunk'lari zaten buluyor
#       BM25 "Defender"                -> T1685.002 geliyor
#       BM25 "disable or modify tools" -> T1685.001 geliyor
#       BM25 T3'un 709 kr ham logu     -> 300 hit icinde HIC YOK
#   Yani darbogaz uzunluk cezasi degil, SORGU SEYRELTMESI. Asil sicrama
#   sorgu tarafindan (cozulmus semantigin sorguya beslenmesi) gelecek.
#
#   Bu not, olcum gelince "bolme ise yaramadi, geri alalim" yanlisina
#   dusmemek icin ONCEDEN yazildi. Kucuk kazanc da kazanctir.
#
# BOLMENIN OLCULMESI GEREKEN IKI YAN ETKISI
#   a) ADAY CESITLILIGI: ayni teknigin birden cok chunk'i ust siralari
#      doldurabilir; top-20, 20 farkli teknik yerine 5 teknigin 4'er
#      chunk'i olabilir. Dort testin sorunu zaten "dogru teknik havuza
#      girmiyor"du -- bu onu KOTULESTIREBILIR. Olculecek: top-20'deki
#      BENZERSIZ teknik sayisi, bolme oncesi ve sonrasi.
#   b) RRF SKOR BANDI kayar (daha cok chunk, daha cok siralama pozisyonu).
#      Tie-break kararliligi sagliyor ama dagilim degisir; band oncesi/
#      sonrasi raporlanacak.
#
# CHUNK ID UYARISI
#   Asagidaki idx = len(chunks) bir SIRA NUMARASIDIR, icerik hash'i degil.
#   ID'ler procedure_examples listesinin sirasina bagli; o sira yeniden
#   insada degisirse hem ID'ler hem chunk metinleri kayar ve GECMIS TUM
#   OLCUMLER karsilastirilamaz hale gelir. Bolme yapilirken ID uretimini
#   icerik hash'ine cevirmek dusunulmeli.
# --------------------------------------------------------------------------


def chunk_procedure_examples(technique: dict[str, Any]) -> list[dict[str, Any]]:
    examples = technique["procedure_examples"]
    if not examples:
        return []

    header = _technique_header(technique)
    chunks: list[dict[str, Any]] = []
    bucket_lines: list[str] = []
    bucket_tokens = estimate_tokens(header)

    def flush():
        if not bucket_lines:
            return
        body = "\n".join(bucket_lines)
        text = f"{header}\nProsedur Ornekleri:\n{body}"
        idx = len(chunks)
        chunks.append(_make_chunk(
            f"{technique['attack_id']}::procedure_example::{idx}",
            technique["attack_id"], "procedure_example", text, technique,
        ))

    for ex in examples:
        line = f"- {ex['actor']} ({ex['actor_type']}): {ex['description']}"
        line_tokens = estimate_tokens(line)
        if bucket_lines and bucket_tokens + line_tokens > TARGET_CHUNK_TOKENS:
            flush()
            bucket_lines = []
            bucket_tokens = estimate_tokens(header)
        bucket_lines.append(line)
        bucket_tokens += line_tokens

    flush()
    return chunks


def chunk_detection_guidance(technique: dict[str, Any]) -> dict[str, Any] | None:
    if not technique.get("detection"):
        return None
    header = _technique_header(technique)
    components = ", ".join(technique["data_components"]) if technique["data_components"] else "-"
    text = f"{header}\n\nTespit Rehberi:\n{technique['detection']}\n\nIlgili Veri Bilesenleri: {components}"
    chunk_id = f"{technique['attack_id']}::detection_guidance::0"
    return _make_chunk(chunk_id, technique["attack_id"], "detection_guidance", text, technique)


def chunk_technique_content_type(technique: dict[str, Any]) -> list[dict[str, Any]]:
    chunks = [chunk_technique_description(technique)]
    chunks.extend(chunk_procedure_examples(technique))
    detection_chunk = chunk_detection_guidance(technique)
    if detection_chunk:
        chunks.append(detection_chunk)
    return chunks


def chunk_mitigation(mitigation: dict[str, Any]) -> dict[str, Any]:
    techniques = ", ".join(mitigation["mitigated_techniques"]) if mitigation["mitigated_techniques"] else "-"
    text = (
        f"[{mitigation['attack_id']}] {mitigation['name']} (mitigation)\n\n"
        f"{mitigation['description']}\n\n"
        f"Ilgili Teknikler: {techniques}"
    )
    return {
        "chunk_id": f"{mitigation['attack_id']}::mitigation::0",
        "attack_id": mitigation["attack_id"],
        "content_type": "mitigation",
        "text": text,
        "metadata": {
            "attack_version": mitigation["attack_version"],
            "name": mitigation["name"],
            "object_type": "mitigation",
            "deprecated": mitigation["deprecated"],
            "revoked": mitigation["revoked"],
            "mitigated_techniques": mitigation["mitigated_techniques"],
            "source_url": mitigation["source_url"],
        },
    }


def chunk_technique_naive(technique: dict[str, Any]) -> dict[str, Any]:
    """Baseline strateji: teknik basina tek buyuk chunk (karsilastirma icin)."""
    header = _technique_header(technique)
    parts = [header, "", technique["description"]]

    if technique["mitigations"]:
        mit_names = ", ".join(m["name"] for m in technique["mitigations"])
        parts.append(f"\nMitigations: {mit_names}")

    if technique["procedure_examples"]:
        top_examples = technique["procedure_examples"][:3]
        example_lines = [f"- {e['actor']}: {e['description']}" for e in top_examples]
        parts.append("\nProsedur Ornekleri:\n" + "\n".join(example_lines))

    if technique.get("detection"):
        parts.append(f"\nTespit: {technique['detection']}")

    text = "\n".join(parts)
    chunk_id = f"{technique['attack_id']}::naive::0"
    return _make_chunk(chunk_id, technique["attack_id"], "naive_full", text, technique)
