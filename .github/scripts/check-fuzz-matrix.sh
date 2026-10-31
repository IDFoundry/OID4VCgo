#!/usr/bin/env bash
# Checks that .github/workflows/fuzz.yml's matrix lists exactly the fuzz
# targets the code defines: every `func FuzzXxx(f *testing.F)` in a
# _test.go file of any Go module in the repository (the root one,
# mobile/, examples/passport-vdc/, ...), as a module/pkg/name entry,
# and nothing else, each once, under an id of its own. A target missing
# from the matrix still runs its seed corpus under go test, but is
# never actually fuzzed, so the mismatch is easy to miss.
#
# A matrix entry is "- id: X" followed by "pkg:", "name:" and, outside
# the root module, "module:" (the module's directory); pkg is relative
# to the module: "." or "./dir".
#
# Usage: check-fuzz-matrix.sh [repo-root] [workflow-file]
set -euo pipefail

root=${1:-.}
workflow=${2:-$root/.github/workflows/fuzz.yml}

code=$(mktemp)
matrix=$(mktemp)
trap 'rm -f "$code" "$matrix"' EXIT

# The modules, as directories relative to root ("." for the root one),
# longest first so a file is matched to the innermost module holding it.
modules=$(cd "$root" && find . -name go.mod -not -path '*/testdata/*' -not -path '*/vendor/*' |
	sed -E 's#/go\.mod$##; s#^\./##; s#^\.$#.#' | awk '{ print length($0) " " $0 }' | sort -rn | cut -d' ' -f2-)

# Targets defined in code, as "<module> <pkg> <name>".
(cd "$root" && grep -rE --include='*_test.go' -o '^func Fuzz[A-Za-z0-9_]*\(f \*testing\.F\)' .) |
	sed -E 's#^\./(.*/)?[^/]+_test\.go:func (Fuzz[A-Za-z0-9_]*)\(.*#./\1 \2#' |
	while read -r dir name; do
		dir=${dir#./}
		dir=${dir%/}
		module=.
		for m in $modules; do
			if [[ "$m" == . ]] || [[ "$dir" == "$m" ]] || [[ "$dir" == "$m"/* ]]; then
				module=$m
				break
			fi
		done
		rel=$dir
		if [[ "$module" != . ]]; then
			rel=${dir#"$module"}
			rel=${rel#/}
		fi
		echo "$module ./${rel:-.} $name" | sed -E 's#\./\.( |$)#.\1#'
	done | sort -u >"$code"

# Targets in the matrix, as "<id> <module> <pkg> <name>".
entries=$(awk '
	function flush() { if (id != "") print id, (module == "" ? "." : module), pkg, name; id = module = pkg = name = "" }
	/^[[:space:]]*- id:[[:space:]]*/ { flush(); sub(/^[[:space:]]*- id:[[:space:]]*/, ""); id = $0; next }
	id != "" && /^[[:space:]]*module:[[:space:]]*/ { sub(/^[[:space:]]*module:[[:space:]]*/, ""); module = $0; next }
	id != "" && /^[[:space:]]*pkg:[[:space:]]*/ { sub(/^[[:space:]]*pkg:[[:space:]]*/, ""); pkg = $0; next }
	id != "" && /^[[:space:]]*name:[[:space:]]*Fuzz/ { sub(/^[[:space:]]*name:[[:space:]]*/, ""); name = $0; next }
	id != "" && !/^[[:space:]]*(#|$)/ && !/^[[:space:]]+(module|pkg|name):/ { flush() }
	END { flush() }
' "$workflow")
echo "$entries" | cut -d' ' -f2- | sort -u >"$matrix"

missing=$(comm -23 "$code" "$matrix")
extra=$(comm -13 "$code" "$matrix")
dupe_ids=$(echo "$entries" | cut -d' ' -f1 | sort | uniq -d)
dupe_targets=$(echo "$entries" | cut -d' ' -f2- | sort | uniq -d)
incomplete=$(echo "$entries" | awk 'NF != 4')

status=0
report() {
	echo "$1"
	local line
	while IFS= read -r line; do
		echo "  $line"
	done <<<"$2"
	status=1
}
[[ -z "$missing" ]] || report "Fuzz targets missing from $workflow's matrix (module pkg name):" "$missing"
[[ -z "$extra" ]] || report "Matrix entries in $workflow with no matching fuzz target (module pkg name):" "$extra"
# The id names the corpus cache and the failure artifact.
[[ -z "$dupe_ids" ]] || report "Matrix ids used more than once:" "$dupe_ids"
[[ -z "$dupe_targets" ]] || report "Fuzz targets listed more than once (module pkg name):" "$dupe_targets"
[[ -z "$incomplete" ]] || report "Matrix entries without a pkg or name (id module pkg name):" "$incomplete"
if [[ "$status" -eq 0 ]]; then
	echo "fuzz.yml's matrix matches all $(wc -l <"$code" | tr -d ' ') fuzz targets."
fi
exit "$status"
