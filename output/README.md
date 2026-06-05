# Raw Experiment Output

This folder stores structured experiment evidence.

The expected layout is:

```text
output/<environment>/<phase>/<load_level>/run_<run_id>/
```

Each completed run folder should contain:

- `detailed.csv`
- `summary.csv`
- `run_summary.json`
- `metadata.json`
- `validation.txt`

## Completed Runs

Attack-only:

- `baseline/attack_only/none/run_20260519_063833/`
- `modsec/attack_only/none/run_20260519_064610/`
- `coraza/attack_only/none/run_20260519_074907/`

Mixed traffic:

- `baseline/mixed/medium/run_20260519_074733/`
- `modsec/mixed/medium/run_20260519_033300_rerun/`
- `coraza/mixed/medium/run_20260519_064803/`

Current completed environments are Baseline, ModSecurity, and Coraza. NAXSI structured outputs are not present unless partner results are added later.

Run `python3 scripts/list_experiment_coverage.py` from the repository root to print the current coverage table.
