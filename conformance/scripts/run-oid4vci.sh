#!/usr/bin/env bash
# Runs every OID4VCI conformance configuration this repo has driver
# support for — the Issuer and Wallet roles, all 10 of the OIDF
# certification catalog's own oid4vci-1_0-*-haip-test-plan profiles
# (4 Issuer + 6 Wallet) — against one freshly-started OIDF conformance
# suite. The OID4VP half (Verifier, Wallet-VP) lives in the sibling
# run-oid4vp.sh instead: the two used to be one combined script/CI job
# (run-all.sh, still here for a single local "run everything" command)
# until the CI workflow split into two independent jobs
# (.github/workflows/oid4vci-conformance.yml, oid4vp-conformance.yml)
# so each half gets its own badge and so an OID4VP-only flake no
# longer marks the whole OID4VCI side red too — see lib.sh's own doc
# comment for the full rationale. Every actual driving/grading helper
# and the run_issuer/run_wallet functions themselves are shared,
# unchanged, from lib.sh.
#
# Prerequisites:
#   - The OIDF conformance suite itself running locally
#     (https://localhost:8443/ by default — export CONFORMANCE_SERVER
#     to override).
#   - Docker, for the conformance-issuer container (brought up
#     automatically, reconfigured+restarted in place per variant, by
#     conformance/issuer/scripts/run-fapi2sp-battery itself).
#
# Usage:
#   export CONFORMANCE_SERVER=https://localhost:8443/   # only if not the default
#   ./conformance/scripts/run-oid4vci.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=conformance/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

check_suite_reachable

run_issuer
run_wallet

print_oid4vci_matrix
print_combined_summary
finish
