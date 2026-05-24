# Analysis Folder

This folder contains the analysis code and generated report tables.

- `metrics_analysis.py` reads structured experiment runs from `output/`.
- `final/` contains the authoritative final CSV and Markdown outputs used in the report.
- `archive/` contains retained duplicate or superseded analysis material, including old root-level generated outputs.

Refresh final tables with:

```bash
python3 analysis/metrics_analysis.py output/ --out analysis/final/final_summary.csv
```
