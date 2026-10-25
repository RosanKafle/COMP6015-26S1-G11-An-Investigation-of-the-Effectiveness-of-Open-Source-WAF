#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPOSITORY_ROOT=$(dirname -- "$SCRIPT_DIR")
PYTHON_BIN=${PYTHON:-python3}
export PYTHONDONTWRITEBYTECODE=1

TEMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/waf-handover-verify.XXXXXX")
trap 'rm -rf "$TEMP_ROOT"' EXIT HUP INT TERM
export MPLCONFIGDIR="$TEMP_ROOT/matplotlib"
mkdir -p "$MPLCONFIGDIR"

cd "$REPOSITORY_ROOT"

"$PYTHON_BIN" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else "Python 3.11 or newer is required")'
"$PYTHON_BIN" -c 'import bs4, matplotlib, numpy, pandas, requests'

if command -v shasum >/dev/null 2>&1; then
    verify_manifest() {
        shasum -a 256 -c "$1"
    }
elif command -v sha256sum >/dev/null 2>&1; then
    verify_manifest() {
        sha256sum -c "$1"
    }
else
    echo "Missing checksum program: install shasum or sha256sum." >&2
    exit 1
fi

echo "[1/7] Validating repository structure"
"$PYTHON_BIN" scripts/validate_structure.py

echo "[2/7] Running maintained-framework tests"
"$PYTHON_BIN" -m unittest discover -s tests -p 'test_*.py'

echo "[3/7] Running controlled-validation tests"
"$PYTHON_BIN" -m unittest discover -s tools/controlled_validation -p 'test_*.py'

echo "[4/7] Verifying evidence checksums"
verify_manifest experiments/modsecurity-naxsi/implementation/results/final/SHA256SUMS.txt
verify_manifest experiments/modsecurity-naxsi/reviewed-data/outputs/week06-approved-variant-hashes.txt

echo "[5/7] Regenerating primary analysis in a temporary directory"
"$PYTHON_BIN" analysis/metrics_analysis.py output/ --out "$TEMP_ROOT/final_summary.csv"
for name in \
    final_summary.csv \
    final_attack_type_summary.csv \
    final_benign_summary.csv \
    final_waf_comparison.csv \
    final_repetition_summary.csv \
    report_summary.md \
    key_findings.txt
do
    cmp "$TEMP_ROOT/$name" "analysis/final/$name"
done
echo "Regenerated primary analysis matches the tracked outputs."

echo "[6/7] Printing retained experiment coverage"
"$PYTHON_BIN" scripts/list_experiment_coverage.py

echo "[7/7] Exercising the safe plan-only runner"
"$PYTHON_BIN" experiments/modsecurity-naxsi/implementation/zap_active_mixed_modsecurity.py \
    --config experiments/modsecurity-naxsi/implementation/config/test_config.json \
    --limit 1

echo "Handover verification: PASS"
