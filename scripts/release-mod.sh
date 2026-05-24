#!/usr/bin/env bash
# release-mod.sh — prepare sub-module go.mod files for release.
#
# Removes local replace directives and sets real version numbers
# on intra-repo dependencies. Run before tagging on main.
#
# Usage:
#   ./scripts/release-mod.sh <version>          # e.g. v0.4.0
#   ./scripts/release-mod.sh --dry-run v0.4.0   # preview only

set -euo pipefail

ROOT_MODULE="github.com/iuboy/mebsuta"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

SUBMODULES=(
	"syslog"
	"database"
	"metrics"
)

# --- Args ---
DRY_RUN=false
VERSION=""

for arg in "$@"; do
	case "$arg" in
		--dry-run) DRY_RUN=true ;;
		v*) VERSION="$arg" ;;
		*)
			echo "unknown argument: $arg" >&2
			echo "usage: $0 [--dry-run] <version>" >&2
			exit 1
			;;
	esac
done

if [ -z "$VERSION" ]; then
	echo "usage: $0 [--dry-run] <version>" >&2
	exit 1
fi

if [[ ! "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+ ]]; then
	echo "error: version must match vX.Y.Z (got $VERSION)" >&2
	exit 1
fi

# Pattern: matches any intra-repo dependency line with a version
INTRA_REPO="github\.com/iuboy/mebsuta[^ ]* v[0-9]+\.[0-9]+\.[0-9]+"

echo "=== release-mod: preparing sub-modules for $VERSION ==="

has_changes=false

# Phase 1: tidy first (with replace blocks still in place)
if ! $DRY_RUN; then
	echo "--- phase 1: go mod tidy ---"
	for dir in "${SUBMODULES[@]}"; do
		gomod="$ROOT_DIR/$dir/go.mod"
		[ -f "$gomod" ] || continue
		echo "  $dir/"
		(cd "$ROOT_DIR/$dir" && go mod tidy 2>&1 | sed 's/^/    /') || true
	done
fi

# Phase 2: remove replace blocks + set versions
echo ""
echo "--- phase 2: rewrite go.mod files ---"

for dir in "${SUBMODULES[@]}"; do
	gomod="$ROOT_DIR/$dir/go.mod"

	if [ ! -f "$gomod" ]; then
		echo "skip: $dir/go.mod not found"
		continue
	fi

	has_replace=false
	has_intra=false
	grep -q "^replace " "$gomod" && has_replace=true || true
	grep -qE "$INTRA_REPO" "$gomod" && has_intra=true || true

	if ! $has_replace && ! $has_intra; then
		echo "  $dir/ — clean, no changes needed"
		continue
	fi

	if $DRY_RUN; then
		echo "  $dir/ would change:"
		$has_replace && echo "    - remove replace block"
		if $has_intra; then
			grep -E "$INTRA_REPO" "$gomod" | while IFS= read -r line; do
				cur="$(echo "$line" | sed -E 's|.* (v[0-9]+\.[0-9]+\.[0-9]+).*|\1|')"
				updated="$(echo "$line" | sed -E "s| v[0-9]+\.[0-9]+\.[0-9]+| $VERSION|")"
				echo "    - $(echo "$line" | sed 's/^[[:space:]]*//')"
				echo "      -> $(echo "$updated" | sed 's/^[[:space:]]*//')"
			done || true
		fi
		has_changes=true
		continue
	fi

	# Remove replace blocks (multi-line and single-line)
	awk '
	BEGIN { in_replace = 0 }
	/^replace[[:space:]]*\(/ { in_replace = 1; next }
	in_replace && /^\)/ { in_replace = 0; next }
	in_replace { next }
	/^replace[[:space:]][^(]*$/ { next }
	{ print }
	' "$gomod" > "$gomod.tmp"

	# Replace intra-repo dependency versions
	sed -E "s|(github\.com/iuboy/mebsuta[^ ]*) v[0-9]+\.[0-9]+\.[0-9]+.*|\1 $VERSION|g" \
		"$gomod.tmp" > "$gomod.final"

	mv "$gomod.final" "$gomod"
	rm -f "$gomod.tmp"

	echo "  $dir/ — updated"
	has_changes=true
done

echo ""
if $DRY_RUN; then
	echo "=== dry-run: no files were modified ==="
else
	echo "=== done ==="
fi
