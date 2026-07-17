# LLM Security Triage Lab

This repository contains a small research workspace for evaluating whether LLMs can help triage Dynamic Application Security Testing (DAST) findings from OWASP ZAP. It combines vulnerable web applications, a ZAP scanner runner, LLM prompt strategies, ground-truth labels, and research notes.

## Repository Layout

- `llm-sec-lab/` - Runnable security triage lab.
  - `compose.yaml` - Docker Compose stack for OWASP Juice Shop, DVWA, and OWASP ZAP.
  - `zap_scanner.py` - Runs scoped DAST workflows: traditional discovery, AJAX discovery for Juice Shop, authenticated DVWA scanning, baseline or targeted active rules, coverage validation, and report generation.
  - `run_pipeline.py` - Runs scans or loads cached alerts, asks the configured NVIDIA-hosted open-weight model to classify each alert, and writes evaluation results.
  - `evaluator.py` - Matches LLM classifications to ground-truth labels and calculates precision, recall, F1, Cohen kappa, false negatives, and McNemar comparison.
  - `ground_truth.csv` - Expected vulnerability labels used by the evaluator.
  - `ground_truth_detection_validation.csv` - Review overlay that records whether catalogue challenges have been reproducibly validated as ZAP-detectable.
  - `requirements.txt` - Python dependencies for the lab runner.
- `knowledge/` - Research papers, notes, draft material, and a wiki for the LLM triage project.
- `.discovery/` and `.github/` - Workspace metadata, agent guidance, task state, and Copilot/Discovery configuration.

Generated files such as `.env`, `zap_alerts.json`, timestamped `results/` artifacts, virtual environments, bytecode caches, and Discovery runtime indexes are ignored by Git.

## Prerequisites

Install these on the machine that will run the lab:

- Git
- Docker Desktop on Windows/macOS, or Docker Engine plus Docker Compose on Linux
- Python 3.11 or newer
- An NVIDIA API key available as `NVIDIA_API_KEY`

The vulnerable apps are intentionally insecure. Run this stack locally for lab use only, and do not expose the mapped ports to an untrusted network.

## Clone The Repository

```bash
git clone <repo-url>
cd "<repo-folder>"
```

On Windows PowerShell, paths with spaces need quotes:

```powershell
cd "D:\WebDev\New folder"
```

## Set Up Python

From the repository root:

### Windows Git Bash

```bash
cd llm-sec-lab
python -m venv .venv
source .venv/Scripts/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### macOS / Linux

```bash
cd llm-sec-lab
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Configure The API Key

Create `llm-sec-lab/.env`:

```text
NVIDIA_API_KEY=your_api_key_here
```

The file is ignored by Git.

The default model is configured in `llm-sec-lab/run_pipeline.py`:

```python
MODEL = "meta/llama-3.1-8b-instruct"
```

Change that value if your NVIDIA endpoint uses a different model name.

## Start The Lab Services

From `llm-sec-lab/`:

```bash
docker compose up -d
```

Check that the containers are running:

```bash
docker compose ps
```

Local service URLs:

- Juice Shop: `http://localhost:3000`
- DVWA: `http://localhost:8081`
- ZAP API: `http://localhost:8090`

The scanner code runs from your host and reaches ZAP at `localhost:8090`. ZAP reaches the vulnerable apps by Docker service names such as `http://juice-shop:3000`.

## Run The Pipeline

From `llm-sec-lab/` with the Python environment activated:

```bash
python run_pipeline.py --scan --scan-profile baseline
```

This waits for ZAP, resets DVWA's local lab database, scans Juice Shop and DVWA, saves `zap_alerts.json`, runs all prompt strategies, and evaluates them against the explicit crosswalk rules. The DAST workflow uses traditional crawling plus the AJAX spider for Juice Shop, an authenticated DVWA user, uncapped active-scan duration and per-rule alert limits, and refuses to continue when required application routes were not discovered. Each run writes timestamped artifacts to `results/pipeline/`, `results/evaluation/`, `results/audit/`, `results/statistics/`, `results/summary/`, `results/unmapped/`, and `results/scan/`. The scan artifact records the effective configuration, discovered URLs, alert-family counts, raw findings, and a quality-oriented summary.

For targeted triage validation, use a separate profile:

```bash
python run_pipeline.py --scan --scan-profile targeted
```

Targeted runs use reproducible DVWA form/API seeds, raise attack strength for injection/XSS/path-traversal/redirect rules, and disable the noisy User Agent Fuzzer rule. Baseline and targeted artifacts must not be pooled; each profile retains its own paired strategy analysis.

To reuse existing in-scope ZAP alerts and only rerun LLM evaluation:

```bash
python run_pipeline.py
```

Cached alert files containing a retired target such as WebGoat are rejected. Run `python run_pipeline.py --scan` to create a fresh two-app alert set.

The current two-app crosswalk contains defensible negative rules only. A run therefore writes its inference, audit, unmapped-alert, and coverage-summary artifacts, then blocks metric and statistical output until a defensible Juice Shop or DVWA positive rule is added. Positive rules must correspond to a `validated` entry in `ground_truth_detection_validation.csv`; candidate and supporting-only entries are never treated as positives. Earlier three-app artifacts are historical and must not be compared directly with two-app runs.

The pipeline currently compares:

- `zero_shot` - Direct JSON-only vulnerability assessment.
- `few_shot` - JSON assessment guided by labelled examples.
- `cot` - Stepwise assessment followed by final JSON and a reasoning consistency check.

## Stop The Lab Services

From `llm-sec-lab/`:

```bash
docker compose down
```

If you want to remove downloaded container data and images, use Docker Desktop or Docker CLI cleanup commands deliberately.

## Troubleshooting

- `NVIDIA_API_KEY` missing: confirm `llm-sec-lab/.env` exists and that you run the Python command from `llm-sec-lab/`.
- Docker cannot pull images: confirm Docker is running and the machine has internet access.
- ZAP does not respond: run `docker compose ps` and inspect logs with `docker compose logs zap`.
- DVWA/Juice Shop unavailable from the browser: check the local port mappings in `compose.yaml`.
- Thorough scans can take a substantial amount of time: active scan rule duration, total duration, and per-rule alert counts are intentionally uncapped. The AJAX spider is capped at 20 minutes by default (`ZAP_AJAX_MAX_DURATION_MINS`) so a browser crawl cannot run indefinitely; tune this only when necessary.

## Typical Workflow

1. Start Docker services with `docker compose up -d`.
2. Run `python run_pipeline.py --scan` for a fresh scan and evaluation.
3. Inspect `zap_alerts.json` and the timestamped artifacts under `results/`.
4. Adjust prompt strategies or model settings in `run_pipeline.py`.
5. Rerun `python run_pipeline.py` to reuse cached alerts while testing prompt changes.
6. Shut down services with `docker compose down`.
