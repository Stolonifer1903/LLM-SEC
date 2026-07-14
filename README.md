# LLM Security Triage Lab

This repository contains a small research workspace for evaluating whether LLMs can help triage Dynamic Application Security Testing (DAST) findings from OWASP ZAP. It combines vulnerable web applications, a ZAP scanner runner, LLM prompt strategies, ground-truth labels, and research notes.

## Repository Layout

- `llm-sec-lab/` - Runnable security triage lab.
  - `compose.yaml` - Docker Compose stack for OWASP Juice Shop, DVWA, WebGoat, and OWASP ZAP.
  - `zap_scanner.py` - Starts ZAP spider and active scans against each target, then saves normalized alerts.
  - `run_pipeline.py` - Runs scans or loads cached alerts, asks the configured NVIDIA-hosted open-weight model to classify each alert, and writes evaluation results.
  - `evaluator.py` - Matches LLM classifications to ground-truth labels and calculates precision, recall, F1, Cohen kappa, false negatives, and McNemar comparison.
  - `ground_truth.csv` - Expected vulnerability labels used by the evaluator.
  - `requirements.txt` - Python dependencies for the lab runner.
- `knowledge/` - Research papers, notes, draft material, and a wiki for the LLM triage project.
- `.discovery/` and `.github/` - Workspace metadata, agent guidance, task state, and Copilot/Discovery configuration.

Generated files such as `.env`, `zap_alerts.json`, `evaluation_results.csv`, virtual environments, bytecode caches, and Discovery runtime indexes are ignored by Git.

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

### Windows PowerShell

```powershell
cd llm-sec-lab
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If PowerShell blocks activation, run:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Then activate the environment again.

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
- WebGoat: `http://localhost:8080/WebGoat`
- ZAP API: `http://localhost:8090`

The scanner code runs from your host and reaches ZAP at `localhost:8090`. ZAP reaches the vulnerable apps by Docker service names such as `http://juice-shop:3000`.

## Run The Pipeline

From `llm-sec-lab/` with the Python environment activated:

```bash
python run_pipeline.py --scan
```

This waits for ZAP, scans Juice Shop, DVWA, and WebGoat, saves `zap_alerts.json`, runs all prompt strategies, evaluates them against `ground_truth.csv`, and writes `evaluation_results.csv`.

To reuse existing ZAP alerts and only rerun LLM evaluation:

```bash
python run_pipeline.py
```

The pipeline currently compares:

- `zero_shot` - Direct JSON-only vulnerability assessment.
- `few_shot` - JSON assessment guided by labelled examples.
- `chain_of_thought` - Stepwise assessment followed by final JSON and a reasoning consistency check.

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
- DVWA/WebGoat/Juice Shop unavailable from the browser: check the local port mappings in `compose.yaml`.
- Slow scans: active scan rules are capped in `zap_scanner.py`, but WebGoat and DVWA can still take time depending on CPU and Docker resources.

## Typical Workflow

1. Start Docker services with `docker compose up -d`.
2. Run `python run_pipeline.py --scan` for a fresh scan and evaluation.
3. Inspect `zap_alerts.json` and `evaluation_results.csv`.
4. Adjust prompt strategies or model settings in `run_pipeline.py`.
5. Rerun `python run_pipeline.py` to reuse cached alerts while testing prompt changes.
6. Shut down services with `docker compose down`.
