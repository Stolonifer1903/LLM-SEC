# LLM Security Triage Lab

This repository contains a small research workspace for evaluating whether LLMs can help triage Dynamic Application Security Testing (DAST) findings from OWASP ZAP. It combines vulnerable web applications, a ZAP scanner runner, LLM prompt strategies, ground-truth labels, and research notes.

## Repository Layout

- `llm-sec-lab/` - Runnable security triage lab.
  - `compose.yaml` - Docker Compose stack for OWASP Juice Shop, OWASP VulnerableApp, and OWASP ZAP.
  - `zap_scanner.py` - Runs scoped DAST workflows: traditional discovery, AJAX discovery for Juice Shop, baseline or targeted active rules, coverage validation, and report generation.
  - `run_pipeline.py` - CLI entry point for the automated post-triage research workflow.
  - `research_pipeline.py` - Scans, deduplicates, triages every alert, then applies deterministic rules after inference.
  - `evaluator.py` - Retained for catalogue and validation-overlay utilities; it is never consulted during triage.
  - `ground_truth.csv` - Expected vulnerability labels used by the evaluator.
  - `ground_truth_detection_validation.csv` - Review overlay that records whether catalogue challenges have been reproducibly validated as ZAP-detectable.
  - `requirements.txt` - Python dependencies for the lab runner.
- `knowledge/` - Research papers, notes, draft material, and a wiki for the LLM triage project.
- `.discovery/` and `.github/` - Workspace metadata, agent guidance, task state, and Copilot/Discovery configuration.

Generated files such as `.env`, immutable `results/` corpus/experiment artifacts, virtual environments, bytecode caches, and Discovery runtime indexes are ignored by Git.

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

The default model is configured in `llm-sec-lab/research_pipeline.py`:

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
- OWASP VulnerableApp: `http://localhost:9090/VulnerableApp`
- ZAP API: `http://localhost:8090`

The scanner code runs from your host and reaches ZAP at `localhost:8090`. ZAP reaches the vulnerable apps by Docker service names such as `http://juice-shop:3000`.

## Run the Automated Pipeline

From `llm-sec-lab/` with the Python environment activated, run the complete targeted assessment:

```bash
python run_pipeline.py --scan --scan-profile targeted
```

To assess only ZAP against the webapps before adding or updating ground truth, run:

```bash
python run_pipeline.py --scan-only --scan-profile targeted
```

This writes the raw alerts and `zap_scan_report.json` under `results/runs/<run_id>/` and makes no NIM/LLM calls. Console output reports ZAP readiness, each target, per-target alert counts, and the artifact directory.

Browser-driven discovery defaults to two concurrent AJAX Spider browsers. Set `ZAP_AJAX_BROWSERS` to a positive integer to tune that concurrency for the local machine. `ZAP_AJAX_MAX_DURATION_MINS` defaults to `0`, which leaves the AJAX crawl uncapped; set a positive duration only when a bounded crawl is required. The Docker stack intentionally remains on ZAP's stable image for reproducible research runs.

Each run writes an immutable directory under `results/runs/<run_id>/`. The scan and inference stages never read ground truth. The targeted profile retains the scanner's authenticated seeds and focused active rules.

The pipeline deduplicates exact prompt-equivalent alerts, triages every unique cluster, and re-expands predictions to raw alerts. It runs `zero_shot`, `few_shot`, and `cot` without explicit confidence elicitation. The bundled few-shot examples are generic, source-cited, and do not identify either study application.

Only after `pipeline_results.json` is written does the evaluator use `ground_truth_match_rules.csv`. A rule requires exact app, controlled alert-family name, ZAP-provided CWE, route constraint, and evidence constraint. It never uses the model prediction, rationale, predicted CWE, severity, or confidence to assign a label.

Alerts with no validated rule remain in `unmapped_alerts.json` and the match audit, but are not assumed safe. Candidate and supporting-only validation-overlay matches are retained as provisional audit evidence and excluded from primary metrics.

Each run produces the scan report, raw alerts, clusters, pipeline results, parse diagnostics, rule audit, unmapped-alert audit, evaluation summary, classification metrics, calibration bins, and statistical output in the same run directory. Juice Shop and OWASP VulnerableApp are evaluated separately.

If no validated positive rule matches, or parse quality is below the configured threshold, the run still completes and writes all audit artefacts with an explicit insufficient-evidence status. It does not manufacture invalid F1 or statistical results.

CVSS exploitability estimates are currently descriptive only. CVSS-MAE and anonymised-target experiments are deferred research extensions.

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
- VulnerableApp/Juice Shop unavailable from the browser: check the local port mappings in `compose.yaml`.
- Thorough scans can take a substantial amount of time: active scan rule duration, total duration, per-rule alert counts, and AJAX Spider duration are uncapped by default. Set `ZAP_AJAX_MAX_DURATION_MINS` to a positive value when a bounded browser crawl is required, and tune `ZAP_AJAX_BROWSERS` if two concurrent browsers are too heavy for the local machine.

## Typical Workflow

1. Start Docker services with `docker compose up -d`.
2. Run `python run_pipeline.py --scan --scan-profile targeted`.
3. Inspect the immutable artefacts under `results/runs/<run_id>/`.
4. Add only version-controlled validated rules when new defensible alert-to-challenge evidence is available; do not edit runtime outputs to assign labels.
5. Shut down services with `docker compose down`.
