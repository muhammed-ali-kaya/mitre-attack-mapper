# ATT&CK Enterprise 19.1 → 19.2 migration

This note records what changed when the repository moved from ATT&CK Enterprise 19.1 to 19.2,
what the controlled benchmark measured, and which files deliberately keep a 19.1 label.

## What changed in the data

All counts are measured on the two STIX bundles and on the processed data built from them.

| Item | 19.1 | 19.2 |
|---|---|---|
| STIX objects | 25,843 | 26,086 (+243) |
| `uses` relationships | 18,220 | 18,457 (+237) |
| Procedure examples (`uses` → technique) | 16,903 | 17,136 (+233) |
| Intrusion sets / malware | 189 / 729 | 191 / 733 |
| Techniques (IDs) | 858 | 858, with no ID added or removed |
| Revoked / deprecated / live | 149 / 12 / 697 | 149 / 12 / 697, with no status changes |
| Technique names, platforms, tactics, descriptions, detection text | — | unchanged |
| Detection strategies / analytics / data components | 699 / 1,758 / 109 | unchanged |
| Content-type chunks | 3,122 | 3,139 (+19, −2, all procedure examples) |

Changes to the retrieval corpus:
- 1,196 chunk texts changed: 1,173 procedure examples and 23 mitigation chunks.
- The mitigation chunks changed only in the order of the techniques they list.
- The BM25 and Chroma indexes are rebuilt from the new chunks.

## What the controlled benchmark measured

The same 60 scenarios were run under the same procedure against both versions: batches of 3,
each batch cold-started, with byte-identical code, scorer, prompts, retrieval parameters and
models. The 19.2 result files are in
[`evaluation/results/controlled_attack_19_2/`](../evaluation/results/controlled_attack_19_2/).
The 19.1 result files are not in this repository; the 19.1 `comparison_summary.json` has
sha256 `3b4c7cd0b677a9c1a6aac6c1c48d7d166c17b6bacd1b7cbae9c39511d3d9de4b`.

| Metric | Baseline 19.1 | Baseline 19.2 | Improved 19.1 | Improved 19.2 |
|---|---:|---:|---:|---:|
| Mean hierarchical score | 0.6633 | 0.6600 | 0.6810 | 0.6719 |
| Top-1 exact accuracy | 0.6167 | 0.6167 | 0.6552 | 0.6491 |
| Partial-or-better rate | 0.6667 | 0.6667 | 0.6724 | 0.6667 |
| Recall@5 | 0.7931 | 0.8103 | 0.7321 | 0.7455 |
| Recall@10 | 0.8103 | 0.8103 | 0.8393 | 0.8000 |
| Hallucination rate | 0.0 | 0.0 | 0.0 | 0.0 |
| Correct abstention (9) | 0.8889 | 1.0000 | 1.0000 | 1.0000 |
| Runtime errors | 0 | 0 | 2 | 3 |

**Observed:**
- Scores changed in 4 baseline scenarios and 2 improved scenarios.
  - Baseline: `single-002` 1.0 → 0.1, `rawlog-003` 0.1 → 1.0, and `multi-009` and `rawlog-002`
    0.1 → 0.0.
  - Improved: `ambig-001` 0.7 → 0.5, and `subtech-001` 1.0 → error.
- The prediction lists changed in 20 of 60 scenarios for each system.
- The retrieval top-10 technique set changed in 38 of 60 baseline scenarios and in 45 of 57
  improved scenarios.
- All error rows in both versions are the same `AgentContractViolation`.
- Revoked or deprecated IDs predicted by the baseline dropped from 14 to 8. The improved system
  predicted none in either version. Revocation data itself did not change between the versions.

**Not established:**
- There is no repeat run of either version, so run-to-run variance is unknown. No individual
  score change is attributed to the dataset version.
- 7 positions ran under different process conditions (freshly started process or not) in the
  two runs, because the batch layouts differed at the start of the set.
- No ranking of the two versions is made.

## Files that keep a 19.1 label on purpose

**Evaluation sets.** Their labels record the bundle they were authored and verified against.
- Files: `evaluation/heldout_set.json`, `evaluation/s_arm_set.json`,
  `scripts/build_{s_arm_set,h_arm_heldout,g_arm_labels}.py`, and `docs/beklenti_13_heldout_set.md`.
- These keep "v19.1" so that provenance stays exact.
- They were re-verified against 19.2 during the migration. All 84 distinct technique IDs they,
  `test_scenarios.json`, the parser-contract test and `rules/attack_mappings.yaml` reference have
  the same name, revoked/deprecated status, `revoked_by` target, tactics and platforms in 19.1 and
  19.2. The one ID absent from both versions is the invented `T9999` used as a hallucination test.

**Test fixtures.** The headers of `tests/fixtures/{access_class_source_logs,baseline_suppression_logs,merge_vulnerability_logs,registry_object_access_logs}.json`
say which version the fixture was authored and measured against, so they keep "19.1".

**Historical results.** `evaluation/results/*` at the top level are outputs of earlier runs on
19.1, so their labels are correct as written. [`evaluation.md`](evaluation.md) marks them as historical.

## Code changes of the migration

- `DEFAULT_ATTACK_VERSION` is `19.2`, and `.env.example` points to the 19.2 bundle.
- The `attack_version` field of pipeline output was a hard-coded `"19.1"`. It is now read from
  `data/metadata/attack_source_metadata.json` (`app/ingestion/attack_version.py`). The same value
  drives the UI caption, the validator's "unknown ID" message and the translation builder.
- Comments and messages that stated a 19.1 fact now say it also holds in 19.2, where that was
  verified on the 19.2 data:
  - 697 live techniques
  - the 161 techniques without detection text are exactly the revoked and deprecated ones
  - the Stealth and Defense Impairment tactics
  - the T1562* revocations
- No scoring, retrieval, prompt, model or configuration change.
