# Setup and usage

> **Source:** moved from `README.md` on 2026-09-28 when the README was shortened
> (sections *Installation*, *Usage*, *Project Structure*, *Privacy & Data
> Handling*). Text unchanged; only relative link paths were adjusted. The README
> keeps a Quick Start and links here.

## Installation

Requires a running [Ollama](https://ollama.com/) instance. The repository declares
no minimum Python version; development and the measurements in
[`evaluation.md`](evaluation.md) were done on Python 3.14.

```
ollama pull qwen3:8b
ollama pull bge-m3

python -m venv .venv

# Windows
.venv\Scripts\activate
# Linux / macOS
source .venv/bin/activate

pip install -r requirements.txt

copy .env.example .env          # Linux / macOS: cp .env.example .env
```

Edit `.env` if Ollama is not on `localhost:11434`.

**GPU note.** `pip install torch` from PyPI installs a CPU-only build. The
`--extra-index-url https://download.pytorch.org/whl/cu126` line in
`requirements.txt` resolves the CUDA build automatically; for a different CUDA
driver, find a compatible index with
`pip index versions torch --index-url https://download.pytorch.org/whl/cuXXX`.

**Data pipeline** (in order; `build_index.py` takes roughly 30 minutes and must
finish before any analysis can run):

```bash
python scripts/download_attack_data.py   # fetch STIX bundle, record version + hash
python scripts/parse_stix.py             # techniques / tactics / mitigations
python scripts/build_chunks.py           # baseline + content-type chunking
python scripts/build_index.py            # ChromaDB + BM25 indexes
```

## Usage

**Streamlit interface** — single and bulk modes:

```bash
streamlit run app/ui/streamlit_app.py
```

**Single query from the command line:**

```bash
python scripts/run_baseline_query.py "EventID=4688 ... schtasks /create ..."
```

**Bulk analysis from the command line.** Uses the same engine as the UI's bulk
tab but is not tied to a browser session — preferred for long multi-row runs,
where a dropped WebSocket connection can otherwise interrupt the analysis:

```bash
python scripts/run_bulk_analysis.py logs.csv --system improved --out result.json
```

**Full evaluation** (60 scenarios; baseline, improved and no-RAG arms):

```bash
python scripts/run_evaluation.py              # baseline + improved
python scripts/backfill_failed_evaluations.py # retry scenarios that timed out
python scripts/summarize_evaluation.py        # comparison summary table
python scripts/run_no_rag_evaluation.py       # direct-LLM control arm
```

**Ablations and diagnostics:**

```bash
python scripts/run_agent_ablation.py          # validation layer on/off
python scripts/run_agent_loop_ablation.py     # + retrieval loop arm
python scripts/run_probe_diagnostics.py --compare   # regression probe vs baseline
```

Several `scripts/measure_*.py` tools require evaluation corpora that are not
distributed with this repository and will not run here; the results they produced
are kept under `evaluation/results/` and `docs/`.

## Project structure

```
app/
  parsers/         STIX parsing (techniques, tactics, mitigations)
  ingestion/       chunking, embedding client
  normalization/   input parsing, format detection, event splitting, enrichment
  retrieval/       vector store, BM25 index, reranker, baseline/improved/no-RAG pipelines
  llm/             Ollama client, prompts, JSON schema, chat assistants
  validation/      ATT&CK validation, composite confidence, evidence requirements
  agents/          per-technique validation agents and the agent runner
  mapping/         rule engine, polarity, text input handling
  correlation/     incident grouping, dedup, attack chain, timeline, IOC, risk score
  batch/           QRadar adapter, orchestrator, background jobs, result store
  reporting/       incident report, draft QRadar rule
  enrichment/      optional VirusTotal IP reputation
  evaluation/      metrics and run hygiene
  ui/              Streamlit interface

config/            field schema, event semantics, access masks, criticality
data/              STIX bundle, processed data, indexes (generated, git-ignored)
evaluation/        test scenarios and measurement results
rules/             detection rule catalogue
scripts/           data pipeline, evaluation, ablation and measurement tools
docs/              architecture, expectations, measurements and result write-ups
tests/             test suite
```

The Streamlit UI calls `app/retrieval/*_pipeline.py` functions directly rather
than going through a REST layer. A thin FastAPI wrapper over those same functions
would be straightforward to add if a non-Streamlit client were needed.

## Privacy & data handling

- **LLM inference is local.** Analysis runs against an Ollama instance
  (`localhost:11434` by default); security event content is not sent to a hosted
  LLM API.
- **The ATT&CK knowledge base is local.** The STIX bundle is downloaded once
  during setup from the official MITRE repository, then parsed, chunked and
  indexed on disk. Query-time retrieval and validation read only local data.
- **One optional external lookup exists.** VirusTotal IP reputation
  (`app/enrichment/virustotal.py`) stays disabled unless `VIRUSTOTAL_API_KEY` is
  set in `.env`; when disabled the feature reports itself as off and the analysis
  flow is unaffected. If enabled, IP addresses are sent to VirusTotal.
- **Evaluation corpora built from real telemetry are not distributed** with this
  repository. Tests that depend on them skip rather than fail, and state the
  reason (`tests/private_data.py`).

These are statements about what the code does, not a security assurance.
