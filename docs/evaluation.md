# Evaluation

> **Source:** moved from `README.md` on 2026-09-28 when the README was shortened.
> The text, tables and numbers are unchanged; only relative link paths were
> adjusted for the new location. The README now shows a five-metric summary and
> links here.

The project ships a 60-scenario benchmark (`evaluation/test_scenarios.json`)
covering ten categories: single clear technique (10), sub-technique required (10),
multiple techniques (10), raw log (10), ambiguous input (5), negative examples (5),
platform conflict (3), prompt injection (3), deprecated/revoked (2), and
Turkish/English cross-language (2).

Scoring is hierarchical: exact sub-technique 1.0, acceptable alternative 0.7,
correct parent technique 0.5, right tactic but wrong technique 0.1, unrelated 0.0
(`app/evaluation/metrics.py`). Hallucination rate is the fraction of returned
ATT&CK IDs absent from the local knowledge base.

## Current benchmark: controlled run on ATT&CK Enterprise 19.2

Source: [`evaluation/results/controlled_attack_19_2/`](../evaluation/results/controlled_attack_19_2/)
— `comparison_summary.json` (sha256 `91c8e250…`) and the three JSONL files it was
generated from (60/60 scenarios, no missing test IDs; the summary's recorded
source hashes match the files beside it). Provenance and run conditions:
[`PROVENANCE.md`](../evaluation/results/controlled_attack_19_2/PROVENANCE.md).

Run on 2026-09-27 against ATT&CK Enterprise 19.2 with this repository's code,
scorer, prompts and retrieval parameters unchanged, `qwen3:8b` / `bge-m3` /
`BAAI/bge-reranker-base`, temperature 0, seed 42. Scenarios ran in batches of
three, each batch in a fresh process with the models unloaded first (cold start),
because a single 60-scenario process exceeded the RAM of the 16 GB test machine.
Every stored score was re-derived from the raw outputs with the unchanged scorer.

| Metric | Baseline | Improved |
|---|---:|---:|
| Mean hierarchical score | 0.660 | 0.672 |
| Top-1 exact accuracy | 61.7% | 64.9% |
| Partial-or-better rate | 66.7% | 66.7% |
| Recall@5 | 0.810 | 0.745 |
| Recall@10 | 0.810 | 0.800 |
| Hallucinated ATT&CK IDs | 0.000 | 0.000 |
| Correct abstention (9 applicable) | 100% | 100% |
| Runtime errors | 0 | 3 |
| Latency per scenario, mean / median | 20.0 s / 19.7 s | 63.1 s / 44.0 s |

Read factually: the improved pipeline has the higher mean score and top-1
accuracy, the same partial-or-better rate, and **lower** Recall@5 and Recall@10.
Its three runtime errors (`subtech-001`, `multi-002`, `crosslang-002`) are one
mechanism — the agent contract check raising `AgentContractViolation` when a
validation agent tries to raise a confidence level — and are excluded from its
averages. Its mean latency is dominated by one scenario (`subtech-007`, 943.7 s);
the median is 44.0 s. Neither arm returned a hallucinated ID.

Both arms abstained correctly on all nine applicable scenarios, yet **negative
examples still score 0.00 in both arms**: the abstention metric checks that no
high/medium-confidence alerting technique is returned, while the hierarchical
score of a negative example requires an empty answer. They measure different
things.

| Category (n) | Baseline | Improved |
|---|---:|---:|
| Single clear technique (10) | 0.69 | 1.00 |
| Sub-technique required (10) | 0.91 | 1.00 |
| Multiple techniques (10) | 0.67 | 0.70 |
| Raw log (10) | 0.68 | 0.63 |
| Ambiguous input (5) | 0.40 | 0.30 |
| Negative examples (5) | 0.00 | 0.00 |
| Platform conflict (3) | 1.00 | 1.00 |
| Prompt injection (3) | 0.37 | 0.03 |
| Deprecated / revoked (2) | 1.00 | 0.55 |
| TR/EN cross-language (2) | 1.00 | 1.00 |

In a category of n scenarios one scenario is 1/n of the mean, so in the
two-to-five-scenario categories a single scenario moves it by up to 0.2–0.5; the
prompt-injection and deprecated/revoked gaps rest on three and two scenarios.

## ATT&CK 19.1 → 19.2 migration study

The same 60 scenarios were run under the same procedure against both dataset
versions, with byte-identical code. Only the dataset differed: 19.2 adds 233
procedure-example relationships, 2 intrusion sets and 4 malware; the technique
catalogue itself (858 IDs, names, tactics, platforms, descriptions, detection
text, revoked/deprecated status) is unchanged.

| Mean hierarchical score | ATT&CK 19.1 | ATT&CK 19.2 |
|---|---:|---:|
| Baseline | 0.663 | 0.660 |
| Improved | 0.681 | 0.672 |

Scores changed in 4 baseline and 2 improved scenarios; retrieval top-10 sets
changed in most scenarios. There is no repeat run of either version, so these
differences cannot be separated from run-to-run variance, and no ranking of the
two versions is made. Details: [`attack-19.2-migration.md`](attack-19.2-migration.md).
The 19.1 result files of that study are not part of this repository; the 19.1
summary's sha256 is recorded in the migration note.

## Historical benchmark (2026-08-12, ATT&CK 19.1)

The table the README showed before the migration — baseline 0.688 / improved
0.708 mean score, correct abstention 33.3% / 0.0% — came from
`evaluation/results/comparison_summary.json`, generated 2026-08-12 with the code of
that time. It is kept as a historical record, **not** as a current result, and it
is **not reproducible from this repository**: the summary records 60-row source
files (sha256 `d72903b6…` / `678b4eee…`), whereas the `eval_baseline.jsonl` /
`eval_improved.jsonl` committed next to it are a later partial run of 16 rows with
different hashes. `docs/baseline_vs_improved_report.md` describes an even earlier
run, also historical.

## No-RAG control arm (historical, ATT&CK 19.1)

`evaluation/results/eval_no_rag.jsonl` — the same LLM answering from pre-training
alone, 60 scenarios: mean hierarchical score **0.352**, hallucination rate
**0.000**, correct abstention 4/9 (**44.4%**), mean latency 16.0 s.

This arm is a *directional* control, not a like-for-like row in the table above:
it comes from an early run (2026-08-03, ATT&CK 19.1, earlier code) that was not
repeated for 19.2, and the file does not record recall or top-1 fields. What it
supports is the narrower claim that retrieval grounding roughly doubles the
hierarchical score relative to the ungrounded model.

## Validation-layer ablation (historical, ATT&CK 19.1)

Source: [`evaluation/results/agent_loop_ablation_summary.json`](../evaluation/results/agent_loop_ablation_summary.json)
(58 scenarios, 2 errors; run 2026-08-16 on ATT&CK 19.1 with the code of that time,
not repeated for 19.2).

| Arm | Mean hierarchical score | Avg. high-confidence techniques |
|---|---:|---:|
| No validation agents | **0.717** | 1.45 |
| + validation agents | 0.674 | **0.45** |
| + agents + retrieval loop | 0.676 | **0.45** |

The validation layer **lowers** the hierarchical score by 0.043. Four scenarios
got worse and none got better: in each case an agent rejected a technique that was
in fact correct (for example `rawlog-008`, where both predicted techniques were
rejected and the answer became empty). In exchange it cuts high-confidence claims
by roughly two thirds.

That is a genuine trade-off, not a win: the layer buys fewer confident wrong
answers at the cost of some confident right ones. The retrieval loop recovers
almost nothing on aggregate (+0.002) while triggering on 63.8% of scenarios.

## Reproducibility

The current benchmark is self-contained: `controlled_attack_19_2/comparison_summary.json`
records the sha256 of the JSONL files beside it, and `eval_raw_outputs.jsonl`
holds the raw pipeline output of every row, so each stored score can be
recomputed with `scripts.run_evaluation.evaluate_one` without an LLM. Its output
records carry `"attack_version": "19.1"`: at the time of the run that label was a
hard-coded constant; the knowledge base and index actually used were 19.2. The
label is now read from `data/metadata/attack_source_metadata.json`.

The top-level files in `evaluation/results/` are historical (see above) and are
not mutually consistent.

Related measurement documents live in [`docs/`](./) — including held-out set
results, rule-quality measurement, and several hypotheses that were measured and
**disproved**.

## Performance & limitations

Measured on a single 8 GB VRAM machine, one `EventID=4688` line, improved pipeline:

| | Measured |
|---|---|
| Context window (`num_ctx`) | 6144 tokens |
| Token usage, full single-log analysis | 12,898 (11,153 input + 1,745 output) |
| LLM calls per analysis | 6 |
| Wall-clock latency | 166–185 s |
| Benchmark latency per scenario (controlled 19.2 run), mean / median | 20.0 / 19.7 s baseline, 63.1 / 44.0 s improved |
| Bulk chat context after packing | 4,558 tokens (from 7,169) |

Running the same input twice produced an **identical token count** and a different
wall-clock time, so token cost is deterministic while latency is not; latency
alone is not a useful optimisation signal here.

Known constraints:

- **The reranker runs on CPU on purpose.** On an 8 GB card `qwen3:8b` + `bge-m3`
  already occupy ~6.2 GB; putting the cross-encoder on the GPU evicts Ollama's
  models repeatedly and causes timeouts. With 16 GB+ it can be moved with
  `Reranker(device="cuda")`.
- **`num_ctx` is not raised** for the same reason — it is shared with the analysis
  path.
- **Token cost has not been optimised yet.** Measurements point at obvious
  targets: in one measured log line 53% of tokens were *field names* rather than
  discriminating content.
- **Negative examples are unsolved.** They score 0.00 in both arms of the
  controlled 19.2 run, even though both arms pass the abstention check on all nine
  applicable scenarios (the two metrics measure different things; see
  [Current benchmark](#current-benchmark-controlled-run-on-attck-enterprise-192)).
- **One agent-contract error path remains.** Three improved-pipeline scenarios in
  the controlled run end in `AgentContractViolation` (a validation agent trying to
  raise a confidence level); they are recorded as errors, not retried.
- **Small local models do not follow fine-grained formatting instructions
  reliably.** `qwen3:8b` repeatedly paraphrased instead of quoting the input
  verbatim in the `evidence` field; rather than hiding this, the validation layer
  checks word-level overlap with the input and shows an explicit evidence warning
  when it fails.
