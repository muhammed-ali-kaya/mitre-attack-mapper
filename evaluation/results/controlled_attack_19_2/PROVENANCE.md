# Provenance: controlled 60-scenario benchmark, ATT&CK Enterprise 19.2

These four files are the complete, verified result of the controlled 19.2 run used by the ATT&CK
19.1 → 19.2 migration study ([`docs/attack-19.2-migration.md`](../../../docs/attack-19.2-migration.md)).
They are byte-identical copies of the installed result files of that run.

| File | SHA-256 |
|---|---|
| `comparison_summary.json` | `91c8e250e94c70341de79f938ee546f3bc9e5da99937f759555ecd3e85484017` |
| `eval_baseline.jsonl` (60 rows) | `c4cc112d695660b8553a2d246a9de7803fb46bb1a29afd23bcd2047d58956de3` |
| `eval_improved.jsonl` (60 rows) | `87619a3fe148da05a457e145c40a2b4b75ef85db9bd1b764aa6827d2f867e271` |
| `eval_raw_outputs.jsonl` (60 rows) | `9ec262a8032a43cf1ad6c6a6aa9a41ee801da412d6104429a3fe10f231689b88` |

`comparison_summary.json` was produced by the unchanged `scripts/summarize_evaluation.py`; its
`meta.sources` hashes match the two metric files beside it, and `meta.missing_test_ids` is empty.

## Run conditions

- **Date:** 2026-09-27.
- **Dataset:** ATT&CK Enterprise 19.2 (`enterprise-attack-19.2.json`, sha256 `dc1639caa5501d72…`,
  26,086 objects). Processed data and indexes were built from it: 858 techniques, 3,139
  content-type chunks, index stamp `98745fa4…`.
- **Code:** this repository at commit `0493e00` (the commit before the migration).
  `app/`, `config/`, `rules/`, `scripts/` and `evaluation/test_scenarios.json` were identical
  after line-ending normalisation. The migration afterwards changed only version labels,
  messages and comments; scoring, retrieval, prompts and configuration are unchanged.
- **Models and generation:**
  - `qwen3:8b` (digest `500a1f067a9f`), `bge-m3` (`790764642607`), `BAAI/bge-reranker-base` on CPU
  - temperature 0, seed 42, top_p 1, `num_ctx` 6144, `keep_alive` 30m
- **Procedure:**
  - 20 batches of 3 scenarios, in `test_scenarios.json` order. Each batch ran in a fresh
    process, after both Ollama models were unloaded (cold start) and at least 8,192 MB of RAM
    was free.
  - A 900 MB free-RAM guard was active; no batch was stopped by it.
  - Batching was needed because a single 60-scenario process exceeded the RAM of the 16 GB
    machine used.
- **Verification:**
  - Every non-error row (117 of 120) was re-scored from `eval_raw_outputs.jsonl` with the
    unchanged `evaluate_one`, and every one matched.
  - All three files contain exactly the 60 scenario IDs in order.

## Known properties of this result

- **Version label.** Output records say `"attack_version": "19.1"`. At the time of the run the
  label was a hard-coded constant in `app/retrieval/*_pipeline.py`. The knowledge base and index
  used were 19.2. The migration replaced the constant with the value from
  `data/metadata/attack_source_metadata.json`.
- **Error rows.** The 3 improved-pipeline error rows (`subtech-001`, `multi-002`,
  `crosslang-002`) are the same `AgentContractViolation`
  (`t1003.001-lsass-access: T1003.001 low -> medium`). They are recorded as they happened and
  were not retried.
- **Latency outlier.** One improved row (`subtech-007`) took 943.7 s, of which 926.1 s was agent
  verification. It dominates the improved mean latency; the median is 43.97 s.
- **No repeat run.** Run-to-run variance was not measured.

## Recomputing

From the repository root, with the data pipeline built:

```
python -c "from pathlib import Path; from scripts.summarize_evaluation import check_summary_is_current as c; d=Path('evaluation/results/controlled_attack_19_2'); print(c(d/'comparison_summary.json',[d/'eval_baseline.jsonl',d/'eval_improved.jsonl']))"
```

To re-score a row, call `scripts.run_evaluation.evaluate_one(system, raw[system + "_raw"],
scenario, kb_by_id)`. `kb_by_id` is built from `data/processed/techniques.json`; the row's raw
output comes from `eval_raw_outputs.jsonl` and its scenario from `evaluation/test_scenarios.json`.
