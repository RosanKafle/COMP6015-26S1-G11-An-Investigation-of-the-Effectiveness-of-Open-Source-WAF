# Helper Scripts

- `validate_structure.py` checks the submission layout and run-folder completeness.
- `list_experiment_coverage.py` prints available and missing experiment datasets.
- `build_final_report.py` rebuilds the submission-ready Word report from current evidence CSVs.
- `verify_handover.sh` runs the complete offline handover verification, including
  tests, checksums, regenerated-analysis comparison and a safe plan-only run.
- `create_handover_zip.sh` exports committed code/data, embeds a Git history
  bundle, creates file checksums and writes the supervisor ZIP under `dist/`.

Run the validation helpers from the repository root:

```bash
python3 scripts/validate_structure.py
python3 scripts/list_experiment_coverage.py
```

After installing `requirements.txt`, run the full handover check with:

```bash
./scripts/verify_handover.sh
```

Rebuild the Word report after evidence changes with:

```bash
python3 scripts/build_final_report.py
```
