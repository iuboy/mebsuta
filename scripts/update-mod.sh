#!/bin/bash

# update-mod.sh — update Go module dependencies across the workspace.
#
# Usage:
#   ./scripts/update-mod.sh                 # update all modules
#   ./scripts/update-mod.sh --minor         # minor version bumps only
#   ./scripts/update-mod.sh --patch         # patch version bumps only
#   ./scripts/update-mod.sh --dry-run       # preview only
#   ./scripts/update-mod.sh root            # update root module only
#   ./scripts/update-mod.sh syslog          # update specific module(s)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

ALL_MODULES=(
	"."
	"audit"
	"syslog"
	"database"
	"metrics"
)

# --- Args ---
DRY_RUN=false
UPDATE_TYPE="major"  # major allows all bumps
TARGETS=()

for arg in "$@"; do
	case "$arg" in
		--dry-run)  DRY_RUN=true ;;
		--major)    UPDATE_TYPE="major" ;;
		--minor)    UPDATE_TYPE="minor" ;;
		--patch)    UPDATE_TYPE="patch" ;;
		-*)         echo "unknown flag: $arg" >&2; exit 1 ;;
			root)       TARGETS+=(".") ;;
		*)          TARGETS+=("$arg") ;;
	esac
done

# Default: all modules
if [ ${#TARGETS[@]} -eq 0 ]; then
	TARGETS=("${ALL_MODULES[@]}")
fi

# Validate targets
for t in "${TARGETS[@]}"; do
	if [[ ! " ${ALL_MODULES[*]} " =~ " $t " ]]; then
		echo "error: unknown module '$t'. Available: ${ALL_MODULES[*]}" >&2
		exit 1
	fi
done

# Build go get flag
GET_FLAG="-u"
case "$UPDATE_TYPE" in
	patch) GET_FLAG="-u=patch" ;;
	minor) GET_FLAG="-u=minor" ;;
esac

echo "=== update-mod: $UPDATE_TYPE update for ${TARGETS[*]} ==="

has_changes=false

for mod in "${TARGETS[@]}"; do
	dir="$ROOT_DIR/$mod"
	gomod="$dir/go.mod"

	if [ ! -f "$gomod" ]; then
		echo "skip: $mod/go.mod not found"
		continue
	fi

	label="$mod"
	[ "$mod" = "." ] && label="root"

	echo ""
	echo "--- $label ---"

	if $DRY_RUN; then
		echo "[dry-run] would run in $dir/:"
		echo "  go get $GET_FLAG ./..."
		echo "  go mod tidy"
		continue
	fi

	echo "  updating dependencies..."

	# go get -u updates direct and indirect deps
	(cd "$dir" && go get $GET_FLAG ./... 2>&1 | sed 's/^/    /') || true

	# tidy removes unused entries and updates go.sum
	(cd "$dir" && go mod tidy 2>&1 | sed 's/^/    /') || true

	has_changes=true
done

# Sync workspace
if ! $DRY_RUN && $has_changes; then
	echo ""
	echo "--- workspace sync ---"
	(cd "$ROOT_DIR" && go work sync 2>&1 | sed 's/^/  /') || true
fi

echo ""
if $DRY_RUN; then
	echo "=== dry-run: no files were modified ==="
else
	echo "=== done ==="
fi
