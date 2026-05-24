# Migration Notes

Root framework Python files -> `framework/` | Organised executable framework code into package structure.
`analysis/final_summary.csv` -> `analysis/final/final_summary.csv` | Moved final analysis output into required final analysis folder.
`analysis/final_attack_type_summary.csv` -> `analysis/final/final_attack_type_summary.csv` | Moved final analysis output into required final analysis folder.
`analysis/final_benign_summary.csv` -> `analysis/final/final_benign_summary.csv` | Moved final analysis output into required final analysis folder.
`analysis/final_waf_comparison.csv` -> `analysis/final/final_waf_comparison.csv` | Moved final analysis output into required final analysis folder.
`analysis/report_summary.md` -> `analysis/archive/legacy_root_outputs/report_summary.md` | Archived duplicate root-level report summary because `analysis/final/report_summary.md` is authoritative.

No flat `output/*.csv`, `output/*.json`, or `output/*.txt` files were present during this migration.
