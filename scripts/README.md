# Helper Scripts

- `validate_structure.py` checks the submission layout and run-folder completeness.
- `list_experiment_coverage.py` prints available and missing experiment datasets.
- `build_final_report.py` rebuilds the submission-ready Word report from current evidence CSVs.

Run the validation helpers from the repository root:

```bash
python3 scripts/validate_structure.py
python3 scripts/list_experiment_coverage.py
```

Rebuild the Word report after evidence changes with:

```bash
python3 scripts/build_final_report.py
```
