# Supervisor Handover Guide

## 1. Purpose and Reproducibility Boundary

This repository contains the source code, retained input data, raw and reviewed
outputs, analysis programs, tests, documentation and version-control history for
the Group 11 open-source WAF investigation.

A reviewer can reproduce the following without access to the original lab:

- validate the repository structure and evidence checksums;
- run 43 offline unit and controlled-request tests;
- regenerate the primary Baseline/ModSecurity/Coraza analysis from retained raw
  `detailed.csv` files and compare it byte-for-byte with the tracked summaries;
- inspect and safely plan the maintained ModSecurity/NAXSI test corpus without
  transmitting requests; and
- trace all reported results to retained source data and Git history.

Repeating the live attacks requires an isolated DVWA/WAF/ZAP laboratory. The
original VMware virtual machines are not included. Private credentials and live
session cookies are deliberately excluded. The retained environment records are
evidence of the reported runs, not a deployable VM image.

## 2. Package Layout

| Path | Purpose |
|---|---|
| `README.md` | Project overview and primary navigation. |
| `framework/` | Primary automated experiment framework. |
| `output/` | Raw structured Baseline, ModSecurity and Coraza runs. |
| `analysis/` | Analysis code and authoritative generated summaries. |
| `evidence/` | Manual and controlled validation evidence. |
| `experiments/` | Later ModSecurity/NAXSI and R11/R12 controlled work. |
| `contributions/` | Contributor-specific analysis and preserved evidence. |
| `tests/` | Offline tests for the maintained experiment implementation. |
| `tools/controlled_validation/` | Offline encoding/request-construction tests. |
| `docs/` | Architecture, methodology, environment and historical notes. |
| `reports/final/` | Submission-ready project report. |
| `scripts/verify_handover.sh` | One-command offline verification. |
| `scripts/create_handover_zip.sh` | Repeatable supervisor-package builder. |

The datasets under `output/`, `experiments/modsecurity-naxsi/`, and
`experiments/r11-r12/` use different corpora and validation methods. Do not pool
their percentages into a single cross-WAF score.

## 3. Prerequisites

For offline verification:

- macOS or Linux;
- Python 3.11 or newer;
- approximately 1 GB of free space for a virtual environment and temporary
  regenerated analysis;
- internet access only while installing Python packages; and
- `shasum` or `sha256sum` for evidence-integrity checks.

Git and `zip` are additionally required to build the supervisor package.

## 4. Clean Setup

From the extracted handover directory:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-lock.txt
```

`requirements-lock.txt` records the exact versions used for the clean-room
handover verification. `requirements.txt` retains compatible version ranges for
future maintenance.

On Windows PowerShell, activate the environment with:

```powershell
.venv\Scripts\Activate.ps1
```

The verification and packaging scripts require a POSIX shell, so Windows users
should run them through Git Bash or WSL. The underlying Python commands can also
be run individually as shown below.

## 5. One-Command Offline Verification

Run from the repository root:

```bash
./scripts/verify_handover.sh
```

To select a particular interpreter:

```bash
PYTHON=.venv/bin/python ./scripts/verify_handover.sh
```

A successful run reports:

- repository structure: `PASS`;
- 27 maintained-framework tests: `OK`;
- 16 controlled-validation tests: `OK`;
- both evidence checksum manifests: `OK`;
- regenerated primary analysis matching all seven tracked generated files; and
- a ModSecurity/NAXSI `PLAN ONLY` run that sends no requests.

The test suites open only temporary loopback HTTP listeners. They do not contact
the WAF lab or transmit attack payloads to an external host.

### Manual equivalent

```bash
python scripts/validate_structure.py
python -m unittest discover -s tests -p 'test_*.py'
python -m unittest discover -s tools/controlled_validation -p 'test_*.py'
python scripts/list_experiment_coverage.py
shasum -a 256 -c experiments/modsecurity-naxsi/implementation/results/final/SHA256SUMS.txt
shasum -a 256 -c experiments/modsecurity-naxsi/reviewed-data/outputs/week06-approved-variant-hashes.txt
```

On Linux, replace `shasum -a 256` with `sha256sum` if necessary.

## 6. Reproducing the Primary Analysis

The primary automated dataset contains six completed runs: attack-only and mixed
traffic for Baseline, ModSecurity and Coraza. NAXSI belongs to a separate reviewed
experiment and is not silently added to this dataset.

To regenerate the primary analysis without overwriting tracked results:

```bash
temporary_output="$(mktemp -d)"
python analysis/metrics_analysis.py output/ \
  --out "$temporary_output/final_summary.csv"
```

The command generates these seven files in the temporary directory:

- `final_summary.csv`
- `final_attack_type_summary.csv`
- `final_benign_summary.csv`
- `final_waf_comparison.csv`
- `final_repetition_summary.csv`
- `report_summary.md`
- `key_findings.txt`

`scripts/verify_handover.sh` regenerates and compares all seven automatically.
Other files in `analysis/final/` are deeper retained outputs and are not produced
by this single analysis entry point.

## 7. Data Management and Traceability

Primary raw run folders follow this structure:

```text
output/<environment>/<phase>/<load_level>/run_<run_id>/
```

Each complete run contains `detailed.csv`, `summary.csv`, `run_summary.json`,
`metadata.json`, and `validation.txt`. Run coverage can be printed with:

```bash
python scripts/list_experiment_coverage.py
```

Authoritative navigation:

- `ANALYSIS_GUIDE.md` describes the primary dataset and completed runs.
- `RESULTS_INDEX.md` maps headline claims to source files.
- `analysis/final/README.md` describes generated analysis outputs.
- `evidence/manual_validation/README.md` describes curated SQLi/CSRF evidence.
- `experiments/README.md` separates the later controlled experiments.
- `contributions/README.md` identifies contributor-specific work.

The CSV paths under `contributions/roshan/evidence/` are historical branch
inventories. They intentionally record paths from the branches at the time of
review and are not a current-tree file list.

## 8. Safe Plan-Only Execution

The maintained ModSecurity/NAXSI runner plans by default. This command loads the
configuration and one test case, prints the corpus digest, and sends no requests:

```bash
python experiments/modsecurity-naxsi/implementation/zap_active_mixed_modsecurity.py \
  --config experiments/modsecurity-naxsi/implementation/config/test_config.json \
  --limit 1
```

Do not add `--execute` unless the isolated laboratory has been rebuilt and the
configuration has been reviewed.

## 9. Repeating Live Experiments

Live execution requires infrastructure outside this package:

1. An isolated Kali test machine with Python 3.11+ and OWASP ZAP.
2. A deliberately vulnerable DVWA target and its database.
3. Separately verified Baseline, ModSecurity/OWASP CRS, Coraza/OWASP CRS and, for
   the later experiment, NAXSI conditions.
4. Host-only routing between the test and target machines; NAT should be disabled
   during active scans.
5. Current DVWA credentials supplied through an untracked `.env` file.
6. Verification that only the intended WAF is enforcing for each condition.
7. Review of target URLs, versions, rule paths, thresholds and ZAP scope before
   any attack-capable command is enabled.

Start with:

- `docs/architecture.md`
- `docs/environment.md`
- `docs/methodology.md`
- `experiments/modsecurity-naxsi/implementation/docs/environment_inventory.md`
- `experiments/modsecurity-naxsi/implementation/docs/classification_rules.md`
- `experiments/modsecurity-naxsi/implementation/docs/obfuscation_methodology.md`
- `evidence/controlled_validation/environments/naxsi_deployment.md`

Copy `.env.example` to `.env`, replace every example value, and never commit the
result. The primary live commands are documented in `README.md`. The later
ModSecurity/NAXSI pipeline is documented in
`experiments/modsecurity-naxsi/implementation/README.md` and remains plan-only
unless `--execute` is explicitly supplied.

## 10. Testing, Quality Controls and Known Issues

Quality controls include deterministic corpus generation, fail-closed
configuration validation, explicit UNKNOWN classifications, redirect refusal,
session-renewal tests, response-size limits, WAF-log correlation and evidence
hashes. `VALIDATION.md` records the repository-level validation policy.

Known limitations:

- The original VMware images and complete live server/container definitions were
  not exported into this repository.
- Current live IP addresses, credentials and service state must be verified; the
  documented private addresses are examples or historical evidence.
- The primary structured output has Baseline, ModSecurity and Coraza runs but no
  NAXSI runs. NAXSI results are retained under a separate experiment.
- Some historical evidence is incomplete or contains UNKNOWN outcomes; these are
  deliberately not converted into TP, TN, FP or FN values.
- ZAP alerts are exploratory evidence and are not automatically treated as WAF
  detections.
- Performance timings include proxy, network and backend costs and are not a
  standalone WAF microbenchmark.

## 11. Future Work

- Export infrastructure-as-code or sanitized VM/container definitions for the
  complete laboratory.
- Repeat all WAF conditions against the same expanded, independently reviewed
  corpus and record multiple unchanged repetitions.
- Expand benign and OWASP-category coverage.
- Add controlled concurrent throughput and resource-usage measurements.
- Improve application-effect verification for allowed malicious-labelled cases.
- Preserve more request-correlated WAF and backend logs for rule-level proof.

## 12. Version-Control Recovery

The supervisor ZIP includes `repository-history.bundle`, a portable Git bundle
containing the available local and remote branch references at packaging time.
To inspect the history separately:

```bash
git bundle list-heads repository-history.bundle
git clone repository-history.bundle restored-waf-repository
cd restored-waf-repository
git bundle verify ../repository-history.bundle
git log --oneline --decorate --graph --all
```

`git bundle verify` requires an existing Git repository, which is why it is run
after cloning rather than directly in the extracted handover directory.

`PACKAGE_MANIFEST.txt` identifies the exact packaged commit. `SHA256SUMS.txt`
verifies every file in the extracted package except the checksum file itself. A
separate `.sha256` file verifies the ZIP before extraction.

## 13. Building the Supervisor ZIP

From a clean Git worktree:

```bash
./scripts/create_handover_zip.sh
```

The finished ZIP and its checksum are written to `dist/`. The builder exports
only committed files, so local `.env` files, caches, temporary results and other
ignored material cannot leak into the package.

## 14. Walkthrough Video

The clickable walkthrough URL will be included in the individual Blackboard
handover PDF when the recording is complete. It is intentionally not fabricated
or replaced with a placeholder URL in this technical package.
