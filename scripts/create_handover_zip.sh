#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPOSITORY_ROOT=$(dirname -- "$SCRIPT_DIR")
OUTPUT_ROOT=${1:-"$REPOSITORY_ROOT/dist"}
PROJECT_NAME=COMP6015-COMP6016-Group11-WAF

cd "$REPOSITORY_ROOT"

if ! command -v git >/dev/null 2>&1 || ! command -v zip >/dev/null 2>&1; then
    echo "Both git and zip are required to build the handover package." >&2
    exit 1
fi

if command -v shasum >/dev/null 2>&1; then
    checksum_file() {
        shasum -a 256 "$1"
    }
elif command -v sha256sum >/dev/null 2>&1; then
    checksum_file() {
        sha256sum "$1"
    }
else
    echo "Missing checksum program: install shasum or sha256sum." >&2
    exit 1
fi

if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
    echo "Refusing to package an uncommitted worktree. Commit or remove changes first." >&2
    exit 1
fi

COMMIT=$(git rev-parse --short=12 HEAD)
BRANCH=$(git branch --show-current)
PACKAGE_NAME="$PROJECT_NAME-supervisor-handover-$COMMIT"
TEMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/waf-handover-package.XXXXXX")
PACKAGE_ROOT="$TEMP_ROOT/$PACKAGE_NAME"
ARCHIVE_PATH="$OUTPUT_ROOT/$PACKAGE_NAME.zip"

trap 'rm -rf "$TEMP_ROOT"' EXIT HUP INT TERM
mkdir -p "$PACKAGE_ROOT" "$OUTPUT_ROOT"

git archive --format=tar HEAD | tar -xf - -C "$PACKAGE_ROOT"
git bundle create "$PACKAGE_ROOT/repository-history.bundle" --all
git bundle verify "$PACKAGE_ROOT/repository-history.bundle" >/dev/null

{
    printf '%s\n' "Group 11 Open-Source WAF Supervisor Handover"
    printf '%s\n' "Packaged commit: $COMMIT"
    printf '%s\n' "Source branch: $BRANCH"
    printf '%s\n' "Entry guide: HANDOVER_GUIDE.md"
    printf '%s\n' "Offline verification: ./scripts/verify_handover.sh"
    printf '%s\n' "Git history: repository-history.bundle"
} > "$PACKAGE_ROOT/PACKAGE_MANIFEST.txt"

(
    cd "$PACKAGE_ROOT"
    find . -type f ! -name SHA256SUMS.txt | LC_ALL=C sort | while IFS= read -r file
    do
        checksum_file "$file"
    done > SHA256SUMS.txt
)

rm -f "$ARCHIVE_PATH" "$ARCHIVE_PATH.sha256"
(
    cd "$TEMP_ROOT"
    zip -qry "$ARCHIVE_PATH" "$PACKAGE_NAME"
)
checksum_file "$ARCHIVE_PATH" > "$ARCHIVE_PATH.sha256"

printf '%s\n' "Created: $ARCHIVE_PATH"
printf '%s\n' "Checksum: $ARCHIVE_PATH.sha256"
