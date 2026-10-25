# Week 6 Reviewed Data

This directory retains only the reviewed Week 6 ModSecurity/NAXSI outputs and
results needed by the final evidence analysis.

- `outputs/` records the pre-approval variant corpus, inventories, semantic
  validation and retained-file hashes.
- `results/` records the source run identifiers and digests; its `processed/`
  directory is intentionally only a historical placeholder.
- `../Week_07/results/final/` contains the reviewed request-level comparison,
  metrics and analyses used by the final evidence package.
- `../Bishal/COMP6016_Group11_BishalGiri_Complete_Code_Data.zip` preserves the
  approved 1,084-row variant corpus at
  `Final_Submission_Complete/Project/Week_06/test_cases/variants/generated_variants.csv`.

`outputs/week06-approved-variant-hashes.txt` verifies the retained archive and
semantic-validation CSV. The approved archived member has SHA-256
`c9927f1c0929cfded027004f633b412d848bd1d311b5298eb2724df849ccf4b9`.

The superseded Week 6 source snapshot was removed during repository consolidation.
The maintained implementation and tests are in `Week_07/`.
