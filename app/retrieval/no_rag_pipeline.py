"""RAG'siz dogrudan siniflandirma (dokuman bolum 9.1, secenek 3: 'Ayni model,
dogrudan siniflandirma ve RAG destekli siniflandirma seklinde karsilastirilmali').

Ayni LLM'e (qwen3:8b) hicbir ATT&CK kaynak metni/context vermeden, sadece
kendi on-egitim bilgisiyle teknik tahmini yaptiriyoruz. Amac: RAG'in (retrieval +
dogrulama) gercekten katma deger sagladigini olculebilir sekilde gostermek.
"""

from __future__ import annotations

import json
import time
from typing import Any

from app.ingestion.attack_version import attack_version
from app.llm.ollama_client import chat, usage_since, usage_snapshot
from app.llm.schemas import MAPPING_RESPONSE_SCHEMA
from app.validation.validator import AttackKnowledgeBase, validate_response

LLM_MODEL = "qwen3:8b"
ATTACK_VERSION = attack_version()  # data/metadata'dan; sabit degil

NO_RAG_SYSTEM_PROMPT = """Sen bir MITRE ATT&CK eslestirme asistanisin.

Sana herhangi bir ATT&CK kaynak metni verilmeyecek -- yalnizca kendi bilgine
dayanarak en uygun ATT&CK teknik/alt teknik kimligini ve adini tahmin et.

Mumkun oldugunca dogru ve guncel ATT&CK kimligi ve ismi kullanmaya calis.
Emin olmadigin durumlarda dusuk guven ver.

Cikti kesinlikle istenen JSON semasina uymalidir. source_url alanina
attack.mitre.org altinda tahmini bir URL yazabilirsin."""

_kb: AttackKnowledgeBase | None = None


def _get_kb() -> AttackKnowledgeBase:
    global _kb
    if _kb is None:
        _kb = AttackKnowledgeBase()
    return _kb


def run_no_rag_query(user_input: str) -> dict[str, Any]:
    t_start = time.time()
    usage_start = usage_snapshot()
    user_prompt = f"KULLANICI GIRDISI:\n{user_input}"

    response = chat(LLM_MODEL, NO_RAG_SYSTEM_PROMPT, user_prompt, json_schema=MAPPING_RESPONSE_SCHEMA)
    llm_output = json.loads(response["message"]["content"])

    validated = validate_response(llm_output, _get_kb(), grounded_attack_ids=None)

    return {
        "input_summary": {"raw_input": user_input},
        "observed_behaviors": validated.get("observed_behaviors", []),
        "mappings": validated.get("mappings", []),
        "rejected_mappings": validated.get("rejected_mappings", []),
        "alternative_candidates": validated.get("alternative_candidates", []),
        "additional_data_needed": validated.get("additional_data_needed", []),
        "attack_version": ATTACK_VERSION,
        "retrieved_chunk_ids": [],
        "timings": {"total_seconds": time.time() - t_start},
        "token_usage": usage_since(usage_start),
        "system": "no_rag",
    }
