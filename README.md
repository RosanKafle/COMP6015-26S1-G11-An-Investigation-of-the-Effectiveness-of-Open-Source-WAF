# WAF Evaluation Framework

COMP6015/COMP6016 Group 11 project repository

Automation repository for:

**An Investigation of the Effectiveness of Open-Source Web Application Firewalls**
## Supervisor Review

Use this README as the first review page.

Recommended review order:

1. `DEFENSE_GUIDE.md`
2. `reports/final/COMP6015_Group11_WAF_Final_Report_SubmissionReady.docx`
3. `analysis/final/report_summary.md`
4. `contributions/pabin/INTEGRATED_WAF_EVIDENCE_ANALYSIS.md`
5. `contributions/bishal/Final_Evidence/README.md`
6. `analysis/final/*.csv` and the linked raw evidence
7. `framework/`, `tools/`, and `scripts/` for reproducibility details

The repository contains multiple controlled experiments with different corpora and
validation methods. Keep their results separate; do not combine their percentages
into a single cross-WAF ranking.

## Project Map

The top level is organised by purpose. The original automated evaluation remains
in the primary folders below; later controlled experiments and individual work
are grouped separately so that similarly named results are not mistaken for one
combined dataset.

- `framework/` - executable Python framework source.
- `output/` - raw structured experiment runs.
- `analysis/final/` - generated final CSV and Markdown analysis outputs.
- `evidence/manual_validation/` - manual SQLi and CSRF validation evidence.
- `reports/final/` - submission-ready Word report.
- `experiments/` - later controlled evaluations, grouped by experiment.
- `contributions/` - contributor-specific analysis and preserved evidence.
- `docs/` - historical weekly evidence and cleaned evidence notes.
- `tools/manual_validation/` - manual validation helper scripts.
- `scripts/` - validation and coverage helper scripts.

## Start ZAP

```bash
zaproxy -daemon -host 127.0.0.1 -port 8080 -config api.disablekey=true
```

## Run Baseline Attack-Only

Disable ModSecurity first:

```bash
ssh sadaiba@192.168.209.130 "sudo a2dismod security2 && sudo systemctl restart apache2"
```

Run:

```bash
python3 -m framework.experiment_runner \
  --env baseline \
  --phase attack_only \
  --load-level none \
  --duration 120 \
  --output-root output \
  --use-zap-proxy \
  --assume-ready
```

## Run Baseline Mixed

```bash
python3 -m framework.experiment_runner \
  --env baseline \
  --phase mixed \
  --load-level medium \
  --duration 180 \
  --output-root output \
  --use-zap-proxy \
  --assume-ready
```

## Run ModSecurity Attack-Only

Enable ModSecurity first:

```bash
ssh sadaiba@192.168.209.130 "sudo a2enmod security2 && sudo systemctl restart apache2"
```

Run:

```bash
python3 -m framework.experiment_runner \
  --env modsec \
  --phase attack_only \
  --load-level none \
  --duration 120 \
  --output-root output \
  --use-zap-proxy \
  --assume-ready
```

## Run ModSecurity Mixed

```bash
python3 -m framework.experiment_runner \
  --env modsec \
  --phase mixed \
  --load-level medium \
  --duration 180 \
  --output-root output \
  --use-zap-proxy \
  --assume-ready
```

## Run Coraza Attack-Only

```bash
python3 -m framework.experiment_runner \
  --env coraza \
  --phase attack_only \
  --load-level none \
  --duration 120 \
  --output-root output \
  --use-zap-proxy \
  --assume-ready
```

## Run Coraza Mixed

```bash
python3 -m framework.experiment_runner \
  --env coraza \
  --phase mixed \
  --load-level medium \
  --duration 180 \
  --output-root output \
  --use-zap-proxy \
  --assume-ready
```

## Optional Remote State Check

Add:

```bash
--remote-host <LAB_HOST> --remote-user <LAB_USER> --check-remote-state
```

The runner prompts for the SSH password when `--remote-password` is omitted.

## Run Analysis

```bash
python3 analysis/metrics_analysis.py output/ --out analysis/final/final_summary.csv
```

This also generates:

```text
analysis/final/final_classification_matrix.csv
analysis/final/final_classification_summary.csv
```

To populate the classification matrix with ZAP-derived detected attack types,
add this flag to future experiment runs:

```bash
--enable-zap-alert-lookup
```

## Validate Repository

```bash
python3 scripts/validate_structure.py
python3 scripts/list_experiment_coverage.py
```


## COMP6016 Semester 2 integration

- [Reviewed ModSecurity/NAXSI evidence](contributions/bishal/Final_Evidence/README.md)
- [Current ModSecurity/NAXSI implementation](experiments/modsecurity-naxsi/implementation/README.md)
- [R11/R12 WAF evaluation](experiments/r11-r12/README.md)

Historical experiment results and Semester 2 controlled-testing
results must be interpreted separately.
