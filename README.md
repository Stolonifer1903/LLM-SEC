# LLM Security Triage Lab

This repository contains a reproducible research lab for evaluating whether LLMs can help triage Dynamic Application Security Testing (DAST) findings from OWASP ZAP. It combines vulnerable web applications, a ZAP scanner runner, three LLM prompt strategies, source-bound ground-truth rules, and deterministic post-hoc evaluation.

## Repository Layout

- `llm-sec-lab/` - Runnable security triage lab.
  - `compose.yaml` - Docker Compose stack for OWASP Juice Shop, OWASP VulnerableApp, and OWASP ZAP.
  - `run_pipeline.py` - CLI entry point for the automated post-triage research workflow.
  - `research_pipeline.py` - Scans, deduplicates, triages every alert, then applies deterministic rules after inference.
  - `zap_scanner.py` - Runs scoped discovery, request seeding, active scanning, coverage validation, and report generation.
  - `evaluator.py` - Retained for catalogue and validation-overlay utilities; it is never consulted during triage.
  - `environment_lock.py` - Captures and verifies immutable container, application, catalogue, and ZAP add-on metadata.
  - `reevaluate_results.py` - Re-evaluates completed saved assessments without rescanning or making LLM calls.
  - `verify_rule_provenance.py` - Replays a bounded allow-list of paired VulnerableApp payloads and controls.
  - `ground_truth*.csv` and `semantic_taxonomy.json` - Source-bound labels, validation evidence, match rules, and semantic scoring taxonomy.
  - `tests/` - Unit tests for the scanner, pipeline, provenance, and evaluation contracts.
  - `MODELS.md` - Model registry and experiment compatibility notes.
  - `requirements.txt` - Python dependencies for the lab runner.

Local secrets, generated `results/`, virtual environments, and bytecode caches are ignored by Git.

## Prerequisites

Install these on the machine that will run the lab:

- Git
- Docker Desktop on Windows/macOS, or Docker Engine plus Docker Compose on Linux
- Python 3.11 or newer
- An NVIDIA API key available as `NVIDIA_API_KEY`

The vulnerable apps are intentionally insecure. Run this stack locally for lab use only, and do not expose the mapped ports to an untrusted network.

## Clone The Repository

```bash
git clone https://github.com/Stolonifer1903/LLM-SEC.git
cd LLM-SEC
```

On Windows PowerShell, paths with spaces need quotes:

```powershell
cd "D:\path\to\LLM-SEC"
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

Copy the provided template to `llm-sec-lab/.env`:

```bash
cp .env.example .env
```

On PowerShell, use `Copy-Item .env.example .env`. Then set your API key:

```text
NVIDIA_API_KEY=your_api_key_here
```

The file is ignored by Git.

The default model is `meta/llama-3.1-8b-instruct`. Override it in `.env` when required:

```text
NIM_MODEL=meta/llama-3.1-8b-instruct
# Optional for another OpenAI-compatible NIM endpoint:
# NIM_BASE_URL=https://integrate.api.nvidia.com/v1
```

For a one-off run, pass `--model <model-id>` instead. Record model changes as separate experimental conditions; see `MODELS.md`.

## Start The Lab Services

The Compose file deliberately refuses floating image tags. From `llm-sec-lab/`,
start Docker Desktop and capture the environment before the first final run:

```bash
python -B run_pipeline.py --capture-environment-lock
```

This inspects existing containers and local images before pulling anything, resolves
only missing images, writes ignored `pinned-images.env`, starts the services by
immutable digest, and records `environment-lock.json`. It also stores the pinned
Juice Shop challenge catalogue and a non-destructive catalogue sync report. Subsequent
invocations reuse the captured lock and recreate `pinned-images.env`; they do not
silently advance versions. Compose commands must use
`docker compose --env-file pinned-images.env ...`.

Check that the containers are running:

```bash
docker compose --env-file pinned-images.env ps
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

The scan profiles are `baseline`, `targeted`, `benchmark`, and `final`. The
`benchmark` profile is the broad Pen Test policy. It is distinct from the
VulnerableApp-only official comparator action:

```bash
python -B run_pipeline.py --benchmark --scan-profile benchmark
```

The comparator action scans only VulnerableApp and submits the resulting alert set to
its official `/scanner/benchmark` endpoint.

### Final reproducible scan workflow

Configure a dedicated local Juice Shop test account in `.env`; neither value is
written to scan artifacts:

```text
JUICE_SHOP_AUTH_EMAIL=llm-sec-zap@example.test
JUICE_SHOP_AUTH_PASSWORD=use-a-local-random-password
```

Then use at most the planned three attempts:

```bash
# Attempts 1 and 2: matched focused unauthenticated/authenticated Juice Shop pilots
python -B run_pipeline.py --juice-auth-pilot --scan-profile final

# Attempt 3: final two-application scan; auto consumes the pilot decision
python -B run_pipeline.py --scan-only --scan-profile final --juice-auth auto

# Begin LLM triage only after triage_eligibility.json says true
python -B run_pipeline.py --reuse-from results/runs/<final_scan_run_id> --scan-profile final
```

The final profile uses one attempt per target with no automatic retry. Its broad and
focused active scans have no elapsed or per-rule deadline; a 45-minute watchdog stops
only a scan whose overall percentage and per-plugin `scanProgress` snapshot both stop
changing. A watchdog stop is incomplete and cannot be reused for triage. Crawler and
passive-drain bounds remain in force. Juice Shop uses traditional plus AJAX discovery
and skips Client Spider.

The authenticated pilot is selected only if it adds an authenticated-only alert that
matches a validated positive rule exactly. New routes, passive noise, candidate rules,
and unsupported challenge families do not pass the gate. Pilot alerts are stored for
audit but never enter final metrics.

This writes the raw alerts and `zap_scan_report.json` under `results/runs/<run_id>/` and makes no NIM/LLM calls. Console output reports ZAP readiness, each target, per-target alert counts, and the artifact directory.

To triage a completed targeted scan without contacting ZAP again, pass its run
directory:

```bash
python run_pipeline.py --reuse-from results/runs/<scan_run_id> --scan-profile targeted
```

Use the same profile recorded by the source scan. A final scan must be reused with
`--scan-profile final`; do not relabel one scan corpus as another profile.

During LLM triage, each completed `(prompt_strategy, cluster_id)` assessment is appended to one `triage_checkpoint.jsonl` file and progress metadata is atomically updated in `triage_checkpoint_state.json`. A transient API disconnect is retried with bounded exponential backoff. If the process still exits before triage finishes, resume the same result directory in place:

```bash
python run_pipeline.py --resume-from results/runs/<incomplete_triage_run_id>
```

Checkpoint state includes a triage-protocol fingerprint covering the prompts, response
schema, probability contract, repair instruction, strategy list, and few-shot examples. A checkpoint created
under an older or different protocol is rejected; start a new triage run from its saved
complete `raw_alerts.json` with `--reuse-from` instead of mixing assessment protocols.

Resume validates the saved run, model, strategies, and cluster set, ignores a partially written final checkpoint line, and requests only missing assessments. After `pipeline_results.json` and `parse_diagnostics.json` are safely written, the two temporary checkpoint files are removed. Runs created before checkpoint support cannot recover earlier completed LLM calls and must restart from their saved raw alerts.

Historical profiles keep their bounded behavior. Their balanced defaults are:

- Traditional spider: 10 minutes, depth 5, 100 children.
- AJAX Spider: 10 minutes, depth 5, one browser.
- Client Spider: 15 minutes, depth 5, 100 children, one browser.
- Passive-scan drain: 10 minutes.
- Broad active scan: 120 minutes total and 10 minutes per rule.
- Focused scans: 5 minutes per request and 30 minutes total per target.
- Hard target failures: one retry in a fresh ZAP session.

Override these with `ZAP_SPIDER_MAX_DURATION_MINS`, `ZAP_SPIDER_MAX_DEPTH`, `ZAP_SPIDER_MAX_CHILDREN`, `ZAP_AJAX_MAX_DURATION_MINS`, `ZAP_AJAX_MAX_CRAWL_DEPTH`, `ZAP_AJAX_BROWSERS`, `ZAP_CLIENT_MAX_DURATION_MINS`, `ZAP_CLIENT_MAX_CRAWL_DEPTH`, `ZAP_CLIENT_MAX_CHILDREN`, `ZAP_CLIENT_BROWSERS`, `ZAP_PASSIVE_SCAN_TIMEOUT_SECONDS`, `ZAP_ACTIVE_MAX_SCAN_DURATION_MINS`, `ZAP_ACTIVE_MAX_RULE_DURATION_MINS`, `ZAP_FOCUSED_SCAN_TIMEOUT_MINS`, `ZAP_FOCUSED_SCAN_GROUP_TIMEOUT_MINS`, and `ZAP_TARGET_RETRIES`. All duration/depth/child/browser limits must be positive; retries may be zero.

For the final profile, `ZAP_ACTIVE_STALL_MINS` controls the activity watchdog and
defaults to 45. Fixed active-scan duration variables are intentionally ignored and
the effective limits are recorded as zero.

Each application runs in a new ZAP session. A controlled stage timeout is stopped, recorded as a warning, and the target proceeds to later seeding and active/focused stages. A hard API failure is checkpointed and retried once. If the retry fails, the other application is still attempted and the command exits nonzero after preserving partial evidence.

Each run creates its immutable directory under `results/runs/<run_id>/` before scanning. `scan_status.json` records run, target, attempt, and stage outcomes. Every attempt is checkpointed under `targets/<app>/attempt_<n>/`. Completed two-app scans write aggregate `raw_alerts.json`; failed or interrupted scans write `partial_raw_alerts.json` instead and cannot be selected automatically by `--reuse-from`. The scan and inference stages never read ground truth. The targeted profile retains the scanner's seeded requests and focused active rules.

The pipeline deduplicates exact prompt-equivalent alerts, triages every unique cluster, and re-expands predictions to raw alerts. It runs `zero_shot`, `few_shot`, and `cot` under one explicit probability contract: `vulnerability_probability` is the probability that the supplied alert represents a real, exploitable vulnerability in the target, conditioned only on the supplied alert fields. It is not confidence in the explanation, predicted family, CWE, severity, or ZAP itself. The model does not emit a separate Boolean verdict; the pipeline derives `confirmed = vulnerability_probability >= 0.5`. The bundled few-shot examples are schema-complete, generic, source-cited, and do not identify either study application.

If an initial response fails strict JSON parsing, the single automated repair attempt
replays the same alert and prompt strategy, includes the malformed response and parse
error, and asks the model to preserve every recoverable assessment value. Repair never
receives ground truth. Each result records `initial_parsed_successfully`,
`repair_attempted`, `repaired`, and `assessment_origin`; an unsuccessful repair remains
unparsed with no probability or verdict and is excluded from metrics rather than being
treated as safe.

Only after `pipeline_results.json` is written does the evaluator use `ground_truth_match_rules.csv`. A rule requires exact app, controlled alert-family name, ZAP-provided CWE, route constraint, and evidence constraint. Positive rules additionally require a canonical family from `semantic_taxonomy.json` and one or more explicit compatible model CWEs. It never uses the model prediction, rationale, predicted CWE, severity, or probability to assign a ground-truth label.

Alerts with no validated rule remain in `unmapped_alerts.json` and the match audit, but are not assumed safe. Candidate and supporting-only validation-overlay matches are retained as provisional audit evidence and excluded from primary metrics.

Each run produces the scan report, raw alerts, clusters, pipeline results, parse diagnostics, rule audit, unmapped-alert audit, evaluation summary, classification metrics, calibration bins, and statistical output in the same run directory. `evaluation_protocol.json` records the `semantic-v2` scoring contract and a fingerprint over its policy, taxonomy, match rules, validation overlay, and label-universe policy. Juice Shop and OWASP VulnerableApp are evaluated separately.

The primary outcome is semantic exact match: `SAFE` or canonical
`vulnerability_family|CWE`. Exact taxonomy aliases are accepted; fuzzy and substring
matching are not. `evaluation_results.csv` and `statistical_results.csv` are semantic
primary, including exact-match accuracy, macro F1, validated-positive semantic recall,
per-label results, and paired tests over semantic correctness. The former Boolean
verdict analysis is retained explicitly in
`boolean_verdict_evaluation_results.csv` and
`boolean_verdict_statistical_results.csv`.

Semantic macro F1 uses one ordered label universe per application, constructed once
from the run's validated mapped ground truths and shared by every strategy and by the
operational and initial-only populations: `SAFE`, sorted canonical positive labels,
then `OTHER_POSITIVE`. Confirmed diagnoses outside the canonical positive universe map
to `OTHER_POSITIVE` only for classification reporting; their raw semantic labels and
error reasons remain in `triage_results.csv`. All labels are always included in the
macro average with `zero_division=0`. Consequently, when an application has only
`SAFE` and one canonical positive ground-truth label, even a perfect classifier has a
macro-F1 ceiling of `2/3` because `OTHER_POSITIVE` has zero ground-truth support. This
deliberate `semantic-v2` convention makes strategies comparable within an evaluation,
but its macro-F1 values must not be compared directly with `semantic-v1` artifacts.

Operational metrics use every final parsed assessment. The evaluator also writes
`initial_only_evaluation_results.csv`, `initial_only_statistical_results.csv`, and
`initial_only_calibration_results.csv`. This paired sensitivity population excludes a
cluster from all three strategies whenever any strategy required repair or failed its
initial parse, preventing repair-rate differences from being mistaken for a prompt
strategy effect. The same population also receives separate initial-only Boolean files;
calibration remains a third, independently named section.

Brier score, ECE, calibration bins, and signed calibration gap use only a
contract-versioned `vulnerability_probability`. Historical completed artifacts remain
readable for Boolean and provenance reporting, but their ambiguous `confidence` value
is retained only as `legacy_llm_confidence`; legacy confidence is never silently
reinterpreted as vulnerability probability, and calibration is reported as unavailable.
Family/CWE compatibility never enters Brier score, ECE, or calibration bins: those
continue to measure only validated binary vulnerability existence.

VulnerableApp rule provenance can be refreshed without scanning or route discovery:

```bash
python -B verify_rule_provenance.py \
  --run-dir results/runs/<eligible_run_id> \
  --environment-lock environment-lock.json
```

The helper refuses non-local targets and mismatched release/image metadata, then sends
only six fixed GET payload/control pairs for parameter `id`. It stores bounded response
evidence, hashes, oracle outcomes, the pinned image, environment-lock hash, and
commit-pinned official source references in a new timestamped artifact.

Rule matching treats an explicit alert `target_version` as an exact constraint. When a
frozen alert records the version as blank or `unknown`, the rule may bind only if its
non-empty image digest and environment-lock SHA-256 both match the alert exactly. An
explicit version conflict, missing immutable identifier, or identifier mismatch remains
unmapped. `ground_truth_match_audit.csv` records the resulting
`version_match_basis` (`exact`, `immutable_provenance`, or `conflict` where applicable),
and this policy is covered by the evaluation-protocol fingerprint.

If no validated positive rule matches, or parse quality is below the configured threshold, the run still completes and writes all audit artefacts with an explicit insufficient-evidence status. It does not manufacture invalid F1 or statistical results.

CVSS exploitability estimates are currently descriptive only. CVSS-MAE and anonymised-target experiments are deferred research extensions.

Completed saved assessments can be re-evaluated without ZAP or LLM inference while
leaving the source run unchanged:

```bash
python -B reevaluate_results.py \
  --source-run results/runs/<completed_run_id> \
  --output-dir results/evaluations/<completed_run_id>_semantic-v2
```

The destination must not already exist. `evaluation_derivation.json` records the source
run, source-artifact hashes, derived evaluation protocol, and the no-network execution
contract.

## Stop The Lab Services

From `llm-sec-lab/`:

```bash
docker compose --env-file pinned-images.env down
```

If you want to remove downloaded container data and images, use Docker Desktop or Docker CLI cleanup commands deliberately.

## Troubleshooting

- `NVIDIA_API_KEY` missing: confirm `llm-sec-lab/.env` exists and that you run the Python command from `llm-sec-lab/`.
- Docker cannot pull images: confirm Docker is running and the machine has internet access.
- ZAP does not respond: run `docker compose --env-file pinned-images.env ps` and inspect logs with `docker compose --env-file pinned-images.env logs zap`.
- VulnerableApp/Juice Shop unavailable from the browser: check the local port mappings in `compose.yaml`.
- A completed run with `completed_with_warnings` reached one or more stage limits but still finalized both targets. Inspect `scan_status.json` and `zap_scan_report.json` before interpreting coverage.
- A `partial_failed` or `interrupted` run is audit/recovery evidence only. It has no aggregate `raw_alerts.json` and is deliberately excluded from automatic reuse.
- If browser crawling is still heavy, reduce the Client/AJAX depth or child limits rather than increasing browser concurrency first.

## Typical Workflow

1. Capture/start the pinned services with `python -B run_pipeline.py --capture-environment-lock`.
2. Run `python run_pipeline.py --scan --scan-profile targeted` for historical-profile work, or use the final workflow above.
3. Inspect the immutable artefacts under `results/runs/<run_id>/`.
4. Add only version-controlled validated rules when new defensible alert-to-challenge evidence is available; do not edit runtime outputs to assign labels.
5. Shut down services with `docker compose --env-file pinned-images.env down`.

## Run the Tests

From `llm-sec-lab/` with the virtual environment activated:

```bash
python -B -m unittest discover -s tests -q
```
