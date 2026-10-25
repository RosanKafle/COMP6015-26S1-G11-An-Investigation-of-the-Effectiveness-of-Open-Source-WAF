# Branch Evidence Inventories

The CSV files in this directory are historical branch inventories generated for
the individual evidence review. Their `path` values identify files that existed
on the listed `origin/*` branch when the inventory was created; they are not an
inventory of the cleaned `main` working tree.

- `repository_inventory.csv` records relevant files found across the reviewed branches.
- `evidence_candidates.csv` ranks those branch files for evidence review.
- `source_version_matrix.csv` compares Git blob versions of selected files across branches.

Paths to removed weekly snapshots and legacy working folders are therefore
intentional historical references. The files remain recoverable from the branch
named in each row and from Git history. Regenerate these CSVs only when an updated
branch-level survey is required, because their contents depend on the current
`origin/*` references.
