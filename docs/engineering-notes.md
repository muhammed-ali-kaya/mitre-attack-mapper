# Engineering Notes

A condensed record of the architecture decisions, experiments and measurements
behind this project — including the ones that went against the hypothesis.

Two notes on scope. First, this document deliberately keeps results that were
*not* favourable; a measurement whose criterion is loosened after the number
disappoints is no longer a measurement. Second, the detailed expectation and
result write-ups this summarises live under `docs/` (`beklenti_*.md` = the
expectation, written before the code; `olcum_*.md` = the measurement;
`sonuc_*.md` = the outcome) and are in Turkish.

Commit hashes from the original development history are not cited here: this
repository was published with a fresh history, so those references cannot be
resolved from it, and inventing substitutes would be worse than omitting them.

---

## Method

These are the working rules the project converged on. Each one is here because
it was paid for at least once.

**1. The expectation is written and committed before the code.** The parser
contract was written first and the parser had to satisfy it. An expectation
written afterwards is a polite way of looking at the output and saying "yes,
that is what it should do".

**2. Every claim is measured against raw data.** The pattern *right answer,
wrong reason* appeared five separate times — a rule returning the correct
result through a broken regex; XPASS results that were vacuously true; a count
that matched only because of a trailing comma; a damage metric that caught the
right case via the wrong token; a value read from the wrong loop iteration.

**3. The measurement tooling is tested too.** Seven separate defects were found
in the measurement tools themselves, including a probe reading the wrong loop
round, a fingerprint treating a `1e-06` difference as nondeterminism, and a
scorer that silently iterated over the *keys* of a dict input instead of its
records — producing a plausible-looking number for a set that had never been
scored. Had that number been accepted because it looked reasonable, the
conclusion would have been invented rather than measured.

**4. If a mechanism has a suppressor written for it, that mechanism fires too
often.** A helper existed purely to suppress one false trigger of the query
enrichment table. When the table was removed the suppressor died with it — the
problem had been known all along, just not named. Adding an exception to a fix
is evidence that the mechanism, not the fix, is wrong.

**5. Fixtures are a lower bound, not a target.** Four logs are a diagnostic
probe. Generalisation needs a separate set of at least 60 logs, written without
running the pipeline once.

**6. A fix belongs in the mechanism layer, not the example layer.** Lookup
tables live in `config/*.yaml` as data; the code is the engine that reads them.
Growing a table must not require changing code.

**7. When fixing something, ask how many other paths do the same job.** Tests
staying green does not show that a fix reached every path — only that it
reached the tested one. This pattern appeared four times. In one instance 918
tests passed both before and after the fix, and the gap only became visible in
a measurement that placed the two paths side by side. The most expensive
instance: a command-line path-extraction fix was correct, had a test, and
genuinely worked in single-event mode, while the bulk path kept its own copy of
the bug for another twelve days because serialisation doubled a backslash that
parsing never undid. The resulting contract test is a path × field matrix
rather than another per-path fix.

**8. A fix elsewhere can invalidate an assumption encoded as a priority
order.** While one parser was buggy, a "the older extraction wins" choice was
correct. The parser was fixed; the choice was not updated, so the corrected
value kept being overwritten by the broken one. The thing to search for is not
old code but code resting on the assumption that the old code was right.

**9. Test count is not a quality measure; what the tests look at is.**

**10. A known regression is not silently accepted.** It is recorded with a root
cause and a closing criterion.

**11. A warning that fires on every input is not a warning, it is noise** — and
noise teaches people not to read warnings.

**12. Before planning a measurement, ask whether the layer being measured is
working right now.** Otherwise the measurement does not describe the layer, it
describes the defect — and produces a correct sentence with the wrong cause.

**13. If a transformation was added, check that its inverse was added too.**

---

## Findings

### Query enrichment was invalidating its own measurement

A ten-key lookup table in the input parser appended technique *names* to the
query when a keyword appeared in the raw log. For one scenario the expected
technique was `T1105 Ingress Tool Transfer` and the query literally ended with
`ingress tool transfer`. The retrieval arm had not found the technique; it had
been told the answer.

The signature was bulk entry rather than ranking: that arm's first 300 results
contained 24 separate chunks of the same technique, the comparison arm zero.
Semantic proximity does not admit a technique in a block like that — name
matching does.

The table was also fixture-shaped. It fired on 20 of 60 scenarios; three of its
ten keys never fired at all, and the remaining seven were exactly the tools
present in the test set. Tools that a real corpus would contain — `msiexec`,
`mshta`, `esentutl`, `curl`, `wget` — were absent. An earlier decision to keep
the table had been based on a 6-improvement / 6-regression measurement, but
that exam had been written against the table's own scenarios.

The corrected measurement split the set in two, with both expectations written
in advance:

| Split | Expected | Measured |
|---|---|---|
| 40 scenarios where the table never fires | no difference | identical — the queries were byte-for-byte the same, 32/40 found, mean rank 14.6 either way |
| 20 scenarios where it fires | the loss is the advantage the table was handing over | mean rank 2.63 → 12.95 |

Removing one scenario from that second split collapsed the effect entirely:
without it the mean was 1.44 either way and the rank sum was identical (26,
n=18). The whole 60-scenario difference came from a single scenario where the
table pasted the technique's name into the query.

**Decision: the table was removed.** Not for performance — its net contribution
across 60 scenarios was one scenario, and what it did there was cheat. Coverage
was unchanged at 51/60.

The guard is a mechanism, not an example: a test parses the enrichment suffix
for all 60 scenarios and asserts that no emitted term is the name of a live
technique (672 names checked). Asserting "certutil is absent" would not have
stopped the same table being rewritten with different tools. The limit is
written down: exact-name matching catches 10 of the old table's 17 terms and
will not catch paraphrases, because any similarity threshold would have been
arbitrary.

### Layered query: the conditional threshold was not added

Four retrieval query constructions were compared over 60 scenarios, with the
decision rule fixed before the measurement:

| Arm | Found | In top-20 | Median rank | Mean rank |
|---|---:|---:|---:|---:|
| A (baseline query) | 51/60 | 46 | 1.0 | 14.0 |
| D (layered, raw log dropped) | 51/60 | 49 | 1.0 | 8.4 |
| **D + raw log (selected)** | 51/60 | **49** | **1.0** | **7.9** |
| Conditional threshold | 51/60 | 48 | 2.0 | 8.8 |

The conditional variant was slightly *worse*, and the reason was structural
rather than incidental: the first layer is empty in 45 of 60 scenarios, and in
all 45 the query falls through to the raw text anyway. There is no case where
only the second layer remains. Adding two code paths, two test paths and a
tunable threshold to reproduce the fall-through was not justified — every
tunable is a door to overfitting.

The real question turned out to be whether to discard the raw log in the 15
scenarios where the first layer *is* populated. Keeping it was better in five
scenarios and worse in two, with the primary measure tied at 13/15; the
tie-break rule selected the arm that discards no information. The gain comes
from *adding* a layer, not from replacing the raw log.

One prediction in that expectation was partly wrong and is recorded as such: a
scenario assumed to be on the empty-layer side was on the populated side, and
was in fact the layered query's largest single loss.

### The validation layer is a measured trade-off, not a win

Ablating the per-technique validation agents over 58 scenarios lowered the mean
hierarchical score from 0.717 to 0.674, with four scenarios worse and none
better, while cutting the average number of high-confidence techniques from
1.45 to 0.45. The retrieval loop on top recovered +0.002 in aggregate while
triggering on 63.8% of scenarios. The full numbers are in
[`evaluation.md`](evaluation.md#validation-layer-ablation-historical-attck-191).

The layer buys fewer confident wrong answers at the cost of some confident
right ones. It is kept because unsupported high-confidence mappings are the
failure mode this project exists to prevent, but it is not presented as an
accuracy improvement, because it is not one.

### "The metric improved" does not mean "the mechanism is fixed"

One technique, one log, three points in time:

| State | Technique present? | Why |
|---|---|---|
| Before the parser work | yes | the event ID was missing, so the gate said *cannot be evaluated → abstain*. Right answer, wrong reason. |
| After the parser work | no | the gate could now evaluate, and the pattern it used was wrong. Wrong answer, right mechanism. |
| After the rule-condition work | yes | the condition reads a structured field and registry dialects are normalised. Right answer, right reason. |

Only the third state means anything, and the first and third are **identical in
the output**. What made the difference visible was having written the root
cause and the closing criterion down in advance. The middle state was the one
most likely to be read as "the fix broke something" — the parser work did not
create that error, it exposed it. Without the record, a correct fix would have
been reverted.

### Validation against the official bundle catches what memory does not

Writing expected answers by hand and checking them against the ATT&CK bundle
caught invalid technique IDs five separate times. In one labelling pass four
IDs from the same family were all revoked in the current version and redirected
elsewhere (`T1070.001`, `T1562.001`, `T1562.002`, `T1562.004`). Had the set
been written from memory, all four would have survived and the evaluation would
have been scored against techniques that no longer exist. The bundle contains
149 such redirections.

### Open: field selection depends on the event, not the technique

The rule field map stores a single target field per technique, and the same
evidence string lives in a different field depending on event type — a registry
path appears under the object name for one event ID and under the command line
for another. This was hit three times during a migration. It is recorded rather
than solved; the problem grows with the table.

### Fixed for process names (K1b): rules assumed the log source they were written against

Of 19 conditions that match on a name field, 11 required a full path. The
assumption was source-dependent, not event-dependent: the same event, the same
technique and the same event ID were missed silently if they arrived from a
source that writes a bare file name. Nothing errored and nothing warned — the
output became "no technique found", which reads like a correct sentence.

K1b changed those 11 conditions to accept either form. The new pattern is a
strict superset of the old one, so no full-path match was lost, and a name that
only ends like the target (`notcmd.exe`) or appears only in the command line
still does not match. The case that exposed the problem — an Office parent with a
bare-named shell child — now fires `T1204.002`.

**Still source-dependent:** conditions that read the English message text (the
rule field map marks them `S`) fail silently on localised Windows logs. K1 did
not touch them.

### Rule catalogue: measured first, then partly corrected (K1)

A static scan of all 49 rules found 12 with no discriminating condition, one
attributing another technique's indicator to itself, and several (rule, event)
pairs that are event-incompatible. The measurement was published deliberately
without a fix, so that the fix could later be judged against a number that
existed beforehand.

K1 then corrected part of it, in five separately measured steps, each predicted
in writing before the change (`docs/beklenti_K1_kural_kalitesi.md`, Turkish):

- **Rule IDs.** Checking the catalogue against the ATT&CK 19.2 bundle found three
  rules under revoked IDs, which could never match, and a firewall rule filed
  under `T1685.005` — in 19.2 that ID is *Clear Windows Event Logs*. A correctly
  chosen log-clearing technique was being tested against the firewall rule and
  removed. The earlier measurement had classified this as a missing event family;
  the cause was the wrong ID. Every rule now names a live technique, and a test
  checks IDs and names against the bundle.
- **Borrowed indicator.** `T1140` no longer claims `certutil -urlcache`, which is
  download evidence for `T1105`.
- **Equivalent events.** Rules that listed only the Windows event now also accept
  the Sysmon equivalent (and vice versa) where the fields line up; one requested
  equivalence was rejected because the events describe different behaviour.

Replaying the evidence gate over 186 stored records changed 13 decisions, all of
them predicted; the catalogue grew from 49 to 51 rules. These are gate decisions,
not a benchmark score — the controlled 19.2 benchmark predates K1 and was not
re-run.

**Still open:** the 12 rules without a discriminating condition (a single failed
logon counted as brute force needs count and time-window semantics the engine
does not have), and 4 (rule, event) pairs whose condition reads a field the event
does not carry.

---

## Disproved hypotheses

Kept so they are not retried.

| Hypothesis | Why it was wrong |
|---|---|
| "The composite confidence cannot reach the threshold" | the decision function never read the composite at all; it was reading the model's own verdict |
| "Revoked techniques are being favoured during retrieval" | metadata filtering runs at query time; every odd candidate was a live technique |
| "Most composite components are `None`" | only one component was, and one that had been suspected is never `None` |
| "Retrieval failed to find the right technique" | it found it (reranked 7th); the probe was reading the second loop round's pool |
| "Nondeterminism exists, the seed must be fixed" | the seed was already fixed; the variation came from model load state — a hidden input, not sampling |
| "Drop detection guidance from candidate generation" | it is the shortest chunk containing the discriminating term for the technique in question; dropping it would make that technique less visible |
| "The layered query is worse than the baseline over 60 scenarios" | that measurement was taken with truncated data caused by a parser bug; with clean data the layered query is better |
| "A containment-based dedup helps process-based techniques" | with clean data it fires once in 60 scenarios and makes the ranking *worse* there; repeated process names are useful weight, not noise |
| "A long command line is drowning the query in one scenario" | length does not explain it — two scenarios of comparable length behaved correctly; the cause was the enrichment table above |

---

## Why this project exists

> Moved from the README's *Engineering Notes* section on 2026-09-28; text
> unchanged apart from link paths.

This was built as a learning and research project: the goal was to construct every
layer of a local LLM + RAG pipeline — hybrid retrieval, reranking, metadata
filtering, output validation, rule engine, decision layer — rather than wrap an
existing AI API, and to find out where each layer breaks.

That shows up in the repository as measurement documents sitting next to the code.
Expectations were written **before** the code that would satisfy them, results were
measured separately, and disproved hypotheses were kept with their reasoning rather
than deleted (`docs/beklenti_*.md`, `docs/olcum_*.md`, `docs/sonuc_*.md`).
Measurements that came out unfavourable are kept too — the validation-layer
ablation in [`evaluation.md`](evaluation.md) is one of them — because loosening a
criterion once the number disappoints discards the measurement.

---

## Project status

> Moved from the README's *Project Status* section on 2026-09-28 and updated for
> the K1 rule-catalogue work the same day: the test count (was "1418 passed, 11
> skipped, 0 failed", then 1,429) and the two rule-catalogue gaps.

Working and measured:

- Baseline, improved and no-RAG pipelines all run and have been compared on the
  60-scenario benchmark.
- Validation layer, composite confidence, agent rejection and the agentic loop are
  implemented and ablated.
- Bulk mode with incident correlation, attack chain, timeline, IOC summary, risk
  score, Markdown report and draft QRadar rule is implemented.
- Rule catalogue: every rule filed under a live ATT&CK 19.2 technique, process-name
  conditions accept full paths and bare file names, Sysmon/Windows equivalent events
  added (K1).
- Test suite: 1,501 tests; 11 skipped in a public clone (the 11 are bound to an
  undistributed QRadar export), with the ATT&CK 19.2 data pipeline built.

Known gaps, stated as gaps:

- Negative-example handling is weak: negative examples score 0.00 in both arms
  (see [`evaluation.md`](evaluation.md)).
- The validation layer currently costs accuracy in aggregate while reducing
  overconfidence; the rejection rules that caused the four regressions have not
  been fixed yet.
- Rule catalogue, still open after K1: 12 of 51 rules carry no discriminating
  condition (they need count/time-window support), and 4 (rule, event) pairs read a
  field the event does not carry (`docs/beklenti_K1_kural_kalitesi.md`).
- Conditions on English message text still fail silently on localised Windows logs;
  K1 made only the process-name conditions source-format independent.
- The interface is Streamlit only; there is no API layer.

## Future work

> Moved from the README's *Future Work* section on 2026-09-28; one item narrowed
> after K1 made the process-name conditions source-format independent.

- Token and context optimisation, starting with canonical short field names
  (53% of tokens in one measured log line were field names) and applying the
  bulk-chat packing approach to the analysis prompt
- Reducing unnecessary LLM calls by widening the cases where the rule layer
  decides without invoking an agent
- Fixing the validation rejections that caused measured regressions, then
  re-running the ablation as the acceptance test
- Improving abstention and negative-example handling
- Making the remaining rule conditions source-format independent (process-name
  conditions were done in K1; message-text conditions remain)
- Count and time-window semantics in the rule engine, so the 12 rules without a
  discriminating condition can be corrected
- Broader evaluation coverage, including variance across repeated runs
- A thin API layer over the existing pipeline functions
- Richer evidence extraction, so `evidence_coverage` stops scoring 0 on inputs
  that clearly contain the evidence

None of the above is implemented.

---

## Related documents

- `docs/architecture.md` — pipeline diagrams, design principles, worked example
- `docs/evaluation.md` — benchmark method, full results, historical runs, performance
- `docs/setup-and-usage.md` — installation, CLI usage, project structure, privacy
- `docs/baseline_vs_improved_report.md` — an earlier comparison run, kept as a
  historical record (its numbers differ from the current summary; see the note
  at the top of that file)
- `docs/hybrid_agent_findings.md` — measured findings from the agent layer
- `docs/olcum_23_k1_kural_kalitesi.md` — the rule catalogue quality measurement
  (with a dated correction of the `T1685.005` diagnosis)
- `docs/beklenti_K1_kural_kalitesi.md` — the K1 correction: expectation, per-step
  predictions and measured results
- `docs/beklenti_*.md` / `docs/sonuc_*.md` — per-task expectations and outcomes
