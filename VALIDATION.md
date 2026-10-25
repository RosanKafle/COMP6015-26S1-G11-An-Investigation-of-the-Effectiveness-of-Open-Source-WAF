# Repository Validation

Validated on 25 October 2026 (Australia/Perth) after branch integration and
repository consolidation.

- Repository structure validation passed.
- 27 inherited framework tests passed using synthetic fixtures and temporary
  loopback HTTP servers.
- 16 controlled-validation encoding and request-builder tests passed.
- The tests wrote no generated files into the repository.
- The main README contains no literal SSH password.
- Superseded weekly source snapshots and duplicate working folders were removed.
- `experiments/modsecurity-naxsi/implementation/` is the maintained Semester 2 implementation.
- `experiments/modsecurity-naxsi/reviewed-data/` retains only the reviewed data required by the final evidence analysis.

Validation commands:

```bash
python3 scripts/validate_structure.py
python3 -m unittest discover -s tests -p 'test_*.py'
python3 -m unittest discover -s tools/controlled_validation -p 'test_*.py'
shasum -a 256 -c experiments/modsecurity-naxsi/implementation/results/final/SHA256SUMS.txt
shasum -a 256 -c experiments/modsecurity-naxsi/reviewed-data/outputs/week06-approved-variant-hashes.txt
```

Software tests do not prove live WAF effectiveness. Experimental claims remain
grounded in the preserved baseline checks, reviewed classifications, correlated
logs and application-effect evidence described in `DEFENSE_GUIDE.md`.

The `contributions/roshan/evidence/` CSVs are historical branch inventories rather than a list
of current-tree paths. The retained Bishal ZIP includes expected private
laboratory addresses; a targeted publication scan found no retained private keys,
cloud/source-control tokens, authorization headers, ZAP API keys or PHP session IDs.
