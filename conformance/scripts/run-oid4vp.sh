#!/usr/bin/env bash
# Runs every OID4VP conformance configuration this repo has driver
# support for — the Verifier and Wallet-VP roles, all 6 of the OIDF
# certification catalog's own oid4vp-1final-*-haip-test-plan profiles
# this repo covers (2 Verifier + 4 Wallet, the other 2 Wallet profiles
# being dc_api.jwt — see conformance/wallet-vp/README.md's own "Scope"
# section) — against one freshly-started OIDF conformance suite. The
# OID4VCI half (Issuer, Wallet) lives in the sibling run-oid4vci.sh
# instead — see that script's own doc comment, and lib.sh's, for why
# the CI workflow split this way. Every actual driving/grading helper
# and the run_verifier/run_wallet_vp functions themselves are shared,
# unchanged, from lib.sh.
#
# Prerequisites:
#   - The OIDF conformance suite itself running locally
#     (https://localhost:8443/ by default — export CONFORMANCE_SERVER
#     to override).
#   - Docker, for the conformance-verifier and conformance-wallet-vp
#     containers (brought up automatically, reconfigured+restarted in
#     place per variant, by each role's own script).
#
# Usage:
#   export CONFORMANCE_SERVER=https://localhost:8443/   # only if not the default
#   ./conformance/scripts/run-oid4vp.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=conformance/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

check_suite_reachable

run_verifier
run_wallet_vp

print_oid4vp_matrix
print_combined_summary
finish
