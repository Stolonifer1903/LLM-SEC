# Research Log: ZAP Coverage Validation and Benchmarking

**Date:** 18 July 2026  
**Study components:** OWASP ZAP 2.17.0, OWASP VulnerableApp, OWASP Juice Shop, and the LLM-SEC DAST-to-LLM-triage pipeline.

## Purpose

This log records the investigation into whether the local OWASP ZAP configuration produces sufficiently complete and well-characterised findings for two separate research purposes:

1. scanner-quality validation against an application with a known DAST ground truth; and
2. later LLM triage and metric calculation from the alerts produced by the scanner.

The study uses **OWASP VulnerableApp** as the primary scanner benchmark because it publishes a machine-readable list of intentionally vulnerable endpoints and exposes an endpoint that scores submitted scanner findings. Juice Shop remains a realistic secondary application, but it does not provide an equivalent live comparator in this lab.

## Research questions

- Is ZAP operational in the Docker lab and capable of producing actionable DAST findings?
- How much of VulnerableApp's official intentional-vulnerability ground truth does the current ZAP configuration detect?
- Does increasing crawling depth, scan-rule breadth, and attack strength improve benchmark coverage?
- Are the resulting alerts suitable for LLM triage experiments and conventional performance metrics such as precision, recall, and F1?
- What request coverage is required before a benchmark score can be treated as meaningful?

## Environment and targets

The Docker lab contains the following services:

| Application | In-container scan URL | Role |
|---|---|---|
| OWASP VulnerableApp | `http://vulnerable-app:9090/VulnerableApp` | Primary DAST benchmark target |
| OWASP Juice Shop | `http://juice-shop:3000` | Secondary realistic target |
| OWASP ZAP | `http://localhost:8090` API | Scanner/controller |

The scanner must use Docker service names when asking the ZAP container to reach target applications. Host-local `localhost` is appropriate for the controller to query the published VulnerableApp benchmark endpoint at `http://localhost:9090/VulnerableApp/scanner/benchmark`.

## Ground truth and benchmark model

VulnerableApp's `/VulnerableApp/scanner` endpoint provides live DAST ground truth. Each record supplies an endpoint URL, whether it is intentionally `UNSECURE`, its HTTP method, and one or more vulnerability types. The official comparator accepts scanner findings containing URL plus CWE, WASC ID, and optionally HTTP method, then returns:

- `coverage`: detected expected findings divided by total expected findings;
- `totalExpected`, `detected`, and `missed`; and
- `unmatchedItems`: findings that do not align with its intentional-vulnerability catalogue.

The comparator treats a URL and **any one** of vulnerability type, CWE, or WASC ID as a match. This is useful for tool interoperability but means the benchmark must be interpreted carefully: a broad WASC mapping can sometimes receive credit without proving that ZAP independently demonstrated the precise intended exploit.

Unmatched findings are not automatically false positives. In particular, missing security headers, cookie hardening, TLS, and similar configuration observations can be valid findings while remaining outside VulnerableApp's intentional vulnerability set. Therefore the comparator primarily measures **ground-truth detection coverage**, not alert precision.

## Initial scanner state

The initial targeted run was:

```text
results/runs/run_20260718T133244Z/
```

It contained 159 alerts overall, including 100 VulnerableApp alert instances. The run used targeted high-strength rules, but its discovery and request history were limited: VulnerableApp had no explicit POST/form/XML request catalogue and only a root request was seeded.

The initial manual submission of its VulnerableApp alerts to the official comparator produced:

| Measure | Result |
|---|---:|
| Submitted VulnerableApp alert instances | 100 |
| Expected benchmark cases | 145 |
| Detected expected cases | 16 |
| Coverage | 11.03% |
| Missed expected cases | 129 |
| Unmatched submitted findings | 83 |

This showed that ZAP was working operationally: it crawled the target and raised findings. However, it also showed that alert volume was not equivalent to vulnerability coverage. The output was dominated by generic findings such as missing headers and error disclosure rather than the deliberately vulnerable routes needed by the benchmark.

## Maximum-coverage configuration changes

The scanner was then changed so that `benchmark` is the default profile. The profile uses ZAP's installed `Pen Test` scan policy and is intended for the authorised local lab only.

### Active scanning

- All installed non-noise active scan rules are enabled.
- Each enabled non-noise rule is set to **High** attack strength and **Low** alert threshold.
- The User Agent Fuzzer rule is disabled as benchmark noise.
- Active-scan duration, per-rule duration, and maximum alerts per rule are set to `0` (unlimited).
- Anti-CSRF handling, query-parameter addition, header scanning, and scan-rule ID headers are enabled.
- Request methods are recovered from ZAP's stored HTTP message for each alert and saved as `request_method`.

A live configuration validation confirmed 51 non-noise scanners enabled with High strength and Low threshold.

### Discovery

- Traditional spider maximum depth and maximum children are both set to `0` (unlimited).
- AJAX spider maximum crawl depth and duration are set to `0` (unlimited).
- The Client Spider is run for both applications with Firefox headless and strict scope checking.
- ZAP waits for the passive-scan queue to drain before active scanning.

The Client Spider is now ZAP's recommended crawler for modern applications. It complements the traditional spider by interacting with browser-rendered DOM content and JavaScript application behaviour.

### Pipeline workflow

- VulnerableApp is scanned first, followed by Juice Shop.
- `run_pipeline.py --benchmark` executes a VulnerableApp-only scan, skips LLM triage, submits the official benchmark payload, and saves both the submitted payload and comparator response.
- `run_pipeline.py --scan` runs the two-application scan followed by LLM triage/evaluation.
- Running `run_pipeline.py` without a scan flag reuses the newest saved `raw_alerts.json` for LLM triage; it does not contact ZAP.
- `--reuse-from <run-directory-or-raw_alerts.json>` supports explicit reproducible selection of a historical scan.

## Full-coverage benchmark run

The benchmark configuration was exercised in:

```text
results/runs/run_20260718T164250Z/
```

The run completed successfully in approximately 11 minutes. Traditional, AJAX, and Client Spider discovery all completed. The run discovered 192 URLs and produced 435 raw VulnerableApp alerts.

The official comparator result was:

| Measure | Result |
|---|---:|
| Raw ZAP alerts | 435 |
| Deduplicated findings submitted to comparator | 135 |
| Expected benchmark cases | 145 |
| Detected expected cases | 15 |
| Coverage | **10.34%** |
| Missed expected cases | 130 |
| Unmatched submitted findings | 93 |

The complete artifacts are:

- `results/runs/run_20260718T164250Z/raw_alerts.json`
- `results/runs/run_20260718T164250Z/zap_scan_report.json`
- `results/runs/run_20260718T164250Z/vulnerable_app_benchmark_request.json`
- `results/runs/run_20260718T164250Z/vulnerable_app_benchmark_response.json`

### Interpretation

The broader configuration increased raw alert volume substantially, from 100 to 435 VulnerableApp alert instances, but did **not** improve benchmark coverage. The strict, method-preserving score was 15/145 (10.34%), compared with the prior lenient manual result of 16/145 (11.03%).

The detected benchmark entries were concentrated in authentication and cryptographic-storage routes. Major intentionally vulnerable families remained missed, including SQL injection, reflected and persistent XSS, path traversal, SSRF, command injection, LDAP injection, unrestricted file upload, JWT weaknesses, and XXE.

The central conclusion is that expanding scanner rules and crawl depth alone does not create the request shapes needed by these vulnerabilities. ZAP can only actively test parameterized requests that exist in its history. A route reached solely by a GET page crawl often contains no query parameter, form submission, JSON body, XML body, multipart upload, session state, or authenticated context for an active rule to mutate.

## Request-coverage fix: VulnerableApp catalogue seeding

VulnerableApp exposes a second endpoint, `/VulnerableApp/allEndPointJson`, intended to help scanners. It supplies route family, level, HTTP method, template, request-parameter location, sample values where available, and vulnerability descriptions.

The scanner now uses this catalogue before the VulnerableApp active scan. It generates and sends safe baseline requests through ZAP's `core/action/sendRequest` API, adding them to ZAP history so active rules have method-correct attack surfaces:

| Seed category | Generated request |
|---|---|
| GET route | Adds a benign `zap_seed=1` query parameter |
| Ordinary POST route | Sends an `application/x-www-form-urlencoded` body containing benign `username`, `password`, `input`, `comment`, and `file` fields |
| XXE POST route | Sends an `application/xml` body with a benign XML document |

Live validation found 153 catalogue routes: 129 GET and 24 POST. A ZAP `sendRequest` seed was accepted successfully. The scan report now records `benchmark_route_seeds` with attempted, seeded, failed, and error values.

This is a controlled request-coverage improvement, not an exploitation payload generator. It ensures that ZAP's active scanner sees concrete parameter/body locations and can apply its own rule payloads. The next benchmark run is required to measure its effect on coverage.

## Juice Shop implications

The broader scan policy, unlimited discovery, and browser spiders apply to Juice Shop as well. However, the new 153-route seed catalogue is intentionally VulnerableApp-specific because it relies on that application's own scanner metadata endpoint.

Juice Shop currently has two stable read-only seeds:

- `/rest/products/search?q=apple`
- `/rest/products/1/reviews`

Equivalent Juice Shop improvement requires a separate, reviewed request catalogue containing relevant API routes, representative JSON bodies, authentication state, and parameterized requests. It should not reuse VulnerableApp assumptions.

## Consequences for LLM triage and evaluation

The scan artifacts are valid inputs for **LLM triage experiments**: the model can be asked to assess each ZAP alert independently, and reuse mode allows repeat prompt/model experiments without changing the scanner input.

They are not yet sufficient for defensible precision, recall, F1, calibration, or statistical comparisons of the LLM triage system. Those metrics require a reviewed alert-level ground-truth crosswalk containing both positives and negatives. At the time of this investigation:

- the local metric rules mainly cover a small set of Juice Shop negative cases;
- VulnerableApp positive matching rules have not been validated and expanded; and
- the scanner coverage benchmark is only about 10%, so missed scanner vulnerabilities cannot be treated as evidence that the LLM classified them correctly or incorrectly.

The pipeline correctly blocks classification metrics when it lacks enough validated positives, negatives, or parse-quality support. This safeguard should remain in place.

## Limitations and threats to validity

1. **Coverage is not precision.** VulnerableApp's comparator measures overlap with its intentional vulnerability catalogue. It does not adjudicate every unmatched hardening/configuration finding.
2. **Flexible axis matching.** URL plus either CWE, WASC, or type can match. A match should be audited before it becomes an alert-level positive label.
3. **No application authentication flow.** The current benchmark run does not establish a fully authenticated user/session workflow. Routes requiring account state may remain unreachable or untestable.
4. **Seed bodies are generic.** Catalogue seeding introduces safe parameters, but it does not yet model every form field, multipart boundary, application-specific workflow, anti-CSRF token, or state transition.
5. **Unbounded scans may be slow.** Unlimited depth and duration are appropriate for this authorised ad-hoc lab benchmark, but should be monitored to prevent loops or target instability.
6. **Post-seeding score pending.** The 10.34% benchmark result predates the new catalogue-seeding change. It is the baseline against which the next benchmark run should be compared.

## Recommended next steps

1. Run `python run_pipeline.py --benchmark` after catalogue seeding and compare the official response to the 10.34% baseline.
2. Analyse seeded POST/XML routes by alert family to identify which request formats produce new active-scan findings.
3. Add reviewed, application-specific seed specifications for forms and workflows where generic bodies are insufficient, beginning with SQL injection, XSS, XXE, file upload, and session/authentication routes.
4. Build a separate Juice Shop request catalogue from documented API and authentication flows.
5. Only after scanner coverage and alert-level labels improve, expand the validated ground-truth crosswalk and enable LLM precision/recall/F1 reporting.

## External documentation consulted

- [OWASP ZAP Scan Policies](https://www.zaproxy.org/docs/desktop/addons/scan-policies/)
- [OWASP ZAP Client Spider](https://www.zaproxy.org/docs/desktop/addons/client-side-integration/spider/)
- [OWASP ZAP Client Spider API](https://www.zaproxy.org/docs/desktop/addons/client-side-integration/spider-api/)
- [OWASP ZAP Spider options](https://www.zaproxy.org/docs/desktop/addons/spider/options/)
- [OWASP ZAP Requestor automation job](https://www.zaproxy.org/docs/desktop/addons/automation-framework/job-requestor/)
- [OWASP ZAP target-scanning limits](https://www.zaproxy.org/docs/getting-further/automation/target-scanning-issues/)
- [VulnerableApp benchmark framework](../VulnerableApp-master/VulnerableApp-master/benchmarks/README.md)

## Integration chronology and reproducibility record

### Replacement of DVWA

DVWA was removed as a pipeline target and replaced with OWASP VulnerableApp. The Docker Compose service is `vulnerable-app`, exposed on host port `9090`, with the in-network base URL `http://vulnerable-app:9090/VulnerableApp`. This matters because ZAP runs in Docker: target URLs supplied to ZAP must use Docker service discovery, not host `localhost`.

The replacement was applied across the scan target configuration, Compose dependencies, scanner labels, documentation, tests, and ground-truth data. Juice Shop was retained as a second target. The result is a two-application test bed with distinct purposes:

| Application | Research role | Ground-truth status |
|---|---|---|
| VulnerableApp | Controlled scanner-coverage benchmark | Official live DAST catalogue and comparator |
| Juice Shop | Broader realistic DAST target | Local, partially validated rules only |

### Pipeline execution modes

The pipeline now separates scanner assessment from model-based triage:

| Command mode | Scope | Intended use |
|---|---|---|
| `--scan-only` | ZAP scans both configured applications and writes scan artifacts; no NIM/LLM calls | Inspect scanner output before evaluating triage |
| `--scan` | ZAP scan followed by LLM triage/evaluation | Full experiment after scanner configuration is accepted |
| `--benchmark` | VulnerableApp-only ZAP scan followed by submission to its official comparator | Controlled scanner-coverage measurement |
| `--reuse-from <run>` | Reuse stored raw alerts without a new scan | Repeat triage/evaluation without changing scanner evidence |

This separation prevents scanner limitations from being obscured by downstream model behaviour and avoids unnecessary model calls during scanner tuning.

### Targeted-scan defect discovered and corrected

The first `--scan-only --scan-profile targeted` execution reached Juice Shop successfully but failed while starting VulnerableApp focused scans. ZAP returned HTTP 400 for the malformed path:

```text
http://vulnerable-app:9090/VulnerableApp/VulnerableApp/
```

The immediate cause was an application-context prefix in the VulnerableApp targeted request specification combined with the already context-qualified target base URL. The request definition was corrected to target `/`, allowing the scanner to compose exactly one `/VulnerableApp/` context path. This is a configuration defect, not a finding about the application or a ZAP detection failure. The successful follow-up run is retained as evidence at `results/runs/run_20260718T133244Z/`.

## Ground-truth import and data-governance record

### Source and unit of analysis

The local `ground_truth.csv` now imports VulnerableApp entries from the live `GET /VulnerableApp/scanner` DAST catalogue. The catalogue must be flattened carefully: a response record represents a route/method/variant, while its `vulnerabilityTypes` field can contain multiple intentional weakness types. The official comparator evaluates the flattened `(normalised URL, HTTP method, vulnerability type)` cases.

At the time of import, the source contained 145 response records: 129 marked `UNSECURE` and 16 marked `SECURE`. Flattening the 129 `UNSECURE` records produced **145 expected benchmark cases**, because 16 additional vulnerability-type associations occur on multi-type routes. The 16 `SECURE` records were intentionally excluded: they are not expected detections in VulnerableApp's own DAST comparator.

| Imported data set | Count | Treatment |
|---|---:|---|
| Existing Juice Shop CSV records | 92 | Retained; some are disabled by local evaluation rules |
| VulnerableApp `UNSECURE` route records | 129 | Source records, before type expansion |
| VulnerableApp expected benchmark cases | 145 | Imported as individual `vulnerable_app` CSV rows |
| VulnerableApp `SECURE` route records | 16 | Excluded from positive DAST ground truth |
| Total rows in local CSV after import | 237 | Includes both applications |
| Active rows returned by the local loader | 225 | 145 VulnerableApp plus 80 enabled Juice Shop rows |

An early import included only the first 129 flattened entries. Reconciliation against the official comparator exposed the discrepancy. The omitted 16 cases were then added: six persistent-XSS routes, eight reflected-XSS routes, and two XXE POST routes. Recording this correction is important: **129 is a route-record count; 145 is the applicable benchmark-case count.** Benchmark coverage denominators and future recall calculations must use 145 unless the upstream catalogue changes.

### Field provenance and interpretation

Each imported row uses a stable local provider key, captures the catalogue route and HTTP method in `benchmark_endpoint`, and records the source as `OWASP VulnerableApp /scanner endpoint`. The following provenance boundaries apply:

- CWE identifiers and names originate from the VulnerableApp vulnerability-type mapping and are marked `official_category_mapping`.
- OWASP Top 10 categories are local analyst mappings, explicitly marked `analyst_mapped`; they are useful for analysis but are not represented as first-party VulnerableApp claims.
- `expected_zap_alert_names` is deliberately `N/A` for VulnerableApp rows. The catalogue identifies intentionally vulnerable routes, not validated one-to-one ZAP alert signatures.
- Therefore, this CSV is valid for route/vulnerability coverage analysis, but it is not yet a complete alert-level truth set for precision, recall, F1, calibration, or statistical comparison of LLM decisions.

Before using any row as an LLM-evaluation positive, retain the raw ZAP evidence and validate the proposed correspondence among endpoint, method, ZAP alert family, parameter, and vulnerability type. Generic hardening alerts must not be relabelled as positives simply because they appear on an intentionally vulnerable route.

## Evidence inventory

| Evidence | Location | Research use |
|---|---|---|
| Local imported truth set | `ground_truth.csv` | Reproducible local catalogue snapshot and mapping metadata |
| Targeted scan artifacts | `results/runs/run_20260718T133244Z/` | Post-fix two-application scan output; 159 alerts total |
| Benchmark scan artifacts | `results/runs/run_20260718T164250Z/` | Official comparator submission and response |
| Comparator response | `results/runs/run_20260718T164250Z/vulnerable_app_benchmark_response.json` | 15/145 detection result and unmatched items |
| Scanner configuration | `zap_scanner.py` | Profile, discovery, seeding, and benchmark-payload logic |
| Pipeline orchestration | `research_pipeline.py` and `run_pipeline.py` | Command-mode behaviour and artifact lifecycle |
| Upstream benchmark description | `../VulnerableApp-master/VulnerableApp-master/benchmarks/README.md` | Comparator contract and source-ground-truth rationale |

## Claims suitable for a report

The available evidence supports the following carefully bounded claims:

1. ZAP can scan both local applications and produces stored, reviewable alerts.
2. VulnerableApp enables an external, machine-scored coverage measure with 145 expected intentional DAST cases in the observed catalogue snapshot.
3. The pre-seeding benchmark configuration detected 15 of 145 expected cases (10.34% coverage); the earlier manual targeted submission detected 16 of 145 (11.03%). These runs are configurations at different times, not a controlled head-to-head comparison.
4. The scanner's generic alert volume is substantially higher than its verified intentional-vulnerability coverage, demonstrating that alert count alone is not a valid measure of scanner effectiveness.
5. The pipeline now supports scanner-only execution and official benchmark scoring, allowing scanner evidence to be assessed independently of LLM triage.

The evidence does **not** yet support claims that the LLM has a measured precision, recall, F1, calibration quality, or statistically significant improvement. Those claims require a reviewed alert-level crosswalk, reproducible repeated runs, and a post-seeding benchmark result.

## Juice Shop discovery-hardening decision

The official [ZAP versus OWASP Juice Shop](https://www.zaproxy.org/docs/scans/juiceshop/) page and its linked automation plan were reviewed as a discovery reference. The reference uses the AJAX Spider with ten browsers and the nightly ZAP image, and its expected URL set includes application routes such as `/ftp/legal.md`, product reviews, administrative configuration, API collections, product search, and `whoami`.

This lab deliberately keeps the stable ZAP image for reproducibility and defaults to two AJAX browsers to limit local resource pressure. The browser count is configurable through `ZAP_AJAX_BROWSERS`; the AJAX duration remains unlimited when `ZAP_AJAX_MAX_DURATION_MINS=0`.

Juice Shop discovery and attack scope are now separated. Stable application routes, including `/ftp/legal.md`, remain in context and are seeded with read-only GET requests when necessary. Static assets, build dependencies, fonts, i18n resources, and Socket.IO traffic remain discoverable/passively observable but are excluded from active attack. Reports retain crawler-only URLs before seeding as well as final scan-ready URLs, applied exclusions, required paths, and route-seed outcomes. This makes coverage improvements auditable without treating raw alert volume as scanner effectiveness.
