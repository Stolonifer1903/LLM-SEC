# NVIDIA NIM Model Registry

This file tracks models used or considered for the LLM-assisted vulnerability-triage pipeline. Model IDs are the values accepted by the NVIDIA-hosted OpenAI-compatible endpoint at `https://integrate.api.nvidia.com/v1`.

Availability was last checked against the NVIDIA API Catalog on **2026-07-16**. Recheck the linked model page before starting a new experiment because hosted endpoint availability and deprecation dates can change.

## Status Values

- **Current**: configured in `run_pipeline.py`.
- **Candidate**: recommended for a controlled comparison.
- **Tested**: evaluated using the same alert set, prompts, temperature, and evaluator.
- **Retired**: no longer suitable or no longer available through the required endpoint.

## Current Model

| Status | NIM model ID | Provider | Scale | Context | Pipeline role | Compatibility notes | NVIDIA page |
|---|---|---:|---:|---:|---|---|---|
| Current | `meta/llama-3.1-8b-instruct` | Meta | 8B | 128K | Current two-app study model | Directly compatible with `ChatNVIDIA`; use strict JSON-schema output and `temperature=0` for controlled comparisons. | [Model page](https://build.nvidia.com/meta/llama-3_1-8b-instruct) |

## Suggested Models

| Priority | Status | NIM model ID | Provider | Scale | Context | Why include it | Pipeline compatibility | NVIDIA page |
|---:|---|---|---|---:|---:|---|---|---|
| 1 | Candidate | `nvidia/nvidia-nemotron-nano-9b-v2` | NVIDIA | 9B | 128K | Similar scale with reasoning capability. | Treat reasoning-on and reasoning-off as separate conditions; it must meet the parse-quality gate. | [Model page](https://build.nvidia.com/nvidia/nvidia-nemotron-nano-9b-v2) |
| 2 | Candidate | `meta/llama-3.3-70b-instruct` | Meta | 70B | 128K | High-capability same-family upper bound for measuring the effect of scale. | Retain `temperature=0` and require the same structured-output and parse-quality checks. | [Model page](https://build.nvidia.com/meta/llama-3_3-70b-instruct) |
| 3 | Candidate | `nvidia/llama-3.3-nemotron-super-49b-v1` | NVIDIA | 49B | 128K | Reasoning-optimized mid-to-large comparison. | Treat reasoning configuration as a separate experimental condition and require the parse-quality gate. | [Model page](https://build.nvidia.com/nvidia/llama-3_3-nemotron-super-49b-v1) |
| 4 | Candidate | `mistralai/mistral-small-4-119b-2603` | Mistral AI | 119B total / 6.5B active MoE | 262K | Cross-family comparison with native JSON output support. | Use non-reasoning/instant mode for comparability and require the parse-quality gate. | [Model page](https://build.nvidia.com/mistralai/mistral-small-4-119b-2603) |
| 5 | Unqualified | `qwen/qwen3.5-122b-a10b` | Qwen | 122B total / 10B active MoE | 262K | The 2026-07-17 trial had high malformed-output frequency and excessive latency. | Excluded from study runs until it passes strict JSON-schema output and the 98% post-repair parse-success gate. | [Model page](https://build.nvidia.com/qwen/qwen3.5-122b-a10b) |

## Models Not Recommended for New Runs

| NIM model ID | Reason |
|---|---|
| `mistralai/mixtral-8x7b-instruct-v0.1` | NVIDIA lists the hosted API for deprecation on 2026-07-27. |
| `qwen/qwen3-next-80b-a3b-instruct` | NVIDIA lists the hosted API for deprecation on 2026-07-27. |
| `qwen/qwen2.5-coder-32b-instruct` | The hosted NIM endpoint is deprecated. |

## Experiment Log

Add one row after each completed model run. Do not compare rows unless the ZAP alert set, prompt strategies, temperature, ground-truth rules, and evaluator version were held constant.

The active study scope is OWASP Juice Shop and OWASP VulnerableApp. Results from earlier multi-app runs are historical artifacts and are not comparable with new two-app runs.

| Experiment | Date | NIM model ID | Temperature | Alert count | Prompt strategies | Result file or notes |
|---|---|---|---:|---:|---|---|
| EXP-001 | 2026 | `meta/llama-3.2-3b-instruct` | 0 | 643 | `zero_shot`, `few_shot`, `cot` | Historical three-app baseline including WebGoat; not comparable with the two-app study. |
