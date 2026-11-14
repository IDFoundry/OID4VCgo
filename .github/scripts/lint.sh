#!/usr/bin/env bash
# Runs CI's gofmt and golangci-lint checks locally, as ci.yml runs them:
# under the Go version each module's go.mod names, with the golangci-lint
# version ci.yml pins. A newer local Go formats and type-checks against
# another standard library, so gofmt can disagree with CI, and a
# golangci-lint built for one Go release can fail to read another's
# ("export data version ... is greater than maximum supported").
#
# golangci-lint is built once, with that Go, into
# ${XDG_CACHE_HOME:-~/.cache}/oid4vcgo-lint. ci.yml names a minor version
# (v2.12), which golangci-lint-action resolves to its latest patch; so
# does this script, which needs the module proxy for that. Set
# GOLANGCI_LINT_VERSION (v2.12.2, say) to skip it.
#
# Usage: lint.sh [module-dir...]   (default: every module CI lints)
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"

modules=("$@")
if [[ ${#modules[@]} -eq 0 ]]; then
  modules=(. mobile sqlstore examples/passport-vdc)
fi

# go_version DIR: the version DIR's go.mod names in its go directive.
go_version() {
  local dir=$1
  awk '$1 == "go" { print $2; exit }' "$dir/go.mod"
}

# The golangci-lint version every ci.yml lint step pins: one, or stop.
pinned=$(grep -E '^\s+version: v[0-9]+\.[0-9]+' .github/workflows/ci.yml | awk '{ print $2 }' | sort -u)
if [[ $(wc -l <<< "$pinned") -ne 1 ]]; then
  echo "lint.sh: ci.yml pins more than one golangci-lint version: $pinned" >&2
  exit 2
fi

root_go=$(go_version .)
lint_version=${GOLANGCI_LINT_VERSION:-}
if [[ -z "$lint_version" ]]; then
  if [[ "$pinned" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    lint_version=$pinned
  else
    lint_version=$(GOTOOLCHAIN="go$root_go" go list -m -versions github.com/golangci/golangci-lint/v2 |
      tr ' ' '\n' | grep -E "^${pinned//./\\.}\.[0-9]+$" | sort -t. -k3 -n | tail -1)
  fi
fi
if [[ -z "$lint_version" ]]; then
  echo "lint.sh: no golangci-lint release matches $pinned" >&2
  exit 2
fi

fail=0
for dir in "${modules[@]}"; do
  gover=$(go_version "$dir")
  export GOTOOLCHAIN="go$gover"
  bin="${XDG_CACHE_HOME:-$HOME/.cache}/oid4vcgo-lint/golangci-lint-$lint_version-go$gover"
  if [[ ! -x "$bin" ]]; then
    echo "== building golangci-lint $lint_version with go$gover"
    tmp=$(mktemp -d)
    GOBIN="$tmp" go install "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$lint_version"
    mkdir -p "$(dirname "$bin")"
    mv "$tmp/golangci-lint" "$bin"
    rmdir "$tmp"
  fi

  args=()
  # CI's mobile job lints the mobiletest-tagged files too.
  if [[ "$dir" == mobile ]]; then args=(--build-tags mobiletest); fi

  echo "== $dir: golangci-lint $lint_version, go$gover"
  if ! (cd "$dir" && "$bin" run ${args[@]+"${args[@]}"} ./...); then fail=1; fi
done

# CI's conformance-issuer-production job lints cmd/conformance-issuer's
# and cmd/conformance-verifier's production setups, and the interop
# wallets' production stores (internal/prodwallet) and the database
# those setups open (internal/proddb), too: the
# conformance_production tag, in a workspace holding the root module
# and sqlstore.
if [[ $# -eq 0 ]]; then
  gover=$(go_version .)
  export GOTOOLCHAIN="go$gover"
  bin="${XDG_CACHE_HOME:-$HOME/.cache}/oid4vcgo-lint/golangci-lint-$lint_version-go$gover"
  work=$(mktemp -d)
  printf 'go %s\n\nuse (\n\t%s\n\t%s/sqlstore\n)\n' "$gover" "$root" "$root" >"$work/go.work"
  echo "== cmd/conformance-issuer, cmd/conformance-verifier, the interop wallets (conformance_production): golangci-lint $lint_version, go$gover"
  if ! GOWORK="$work/go.work" "$bin" run --build-tags conformance_production ./cmd/conformance-issuer/... ./cmd/conformance-verifier/... \
    ./internal/prodwallet/... ./internal/proddb/... ./interop/eudi/scripts/pidwallet/... ./interop/waltid/scripts/wallet/...; then fail=1; fi
  rm -rf "$work"
fi

# ci.yml runs gofmt once, from the root, over every module.
export GOTOOLCHAIN="go$root_go"
echo "== gofmt, go$root_go"
unformatted=$("$(go env GOROOT)/bin/gofmt" -l .)
if [[ -n "$unformatted" ]]; then
  echo "Not gofmt-formatted:"
  echo "$unformatted"
  fail=1
fi

exit "$fail"
