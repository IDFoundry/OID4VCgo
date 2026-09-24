#!/usr/bin/env bash
# Runs every conformance configuration this repo has driver support
# for — one underlying OIDF conformance suite, exercised against all
# four roles (Issuer, Wallet, Verifier, Wallet-VP) — prints one
# combined summary at the end. Mirrors FAPIgo's own
# conformance/scripts/run-all.sh in spirit (one command, one summary,
# never stops early on a bad result, logs kept for post-mortem), but
# not mechanically: FAPIgo's own AS/RP legs are ~14 separately-built
# containers driven by the suite's own Python run-test-plan.py: this
# repo's four roles are each a single container reconfigured and
# restarted in place per variant (immediate/deferred, sd_jwt_vc/mdoc,
# HAIP/base plan — see each role's own conformance/*/scripts/README
# for why), driven by this repo's own all-Go tooling, no Python
# dependency at all. Everything here runs strictly sequentially, not
# per-role parallel, the same choice FAPIgo's own script already made
# for its ~14 legs despite having no technical blocker to parallelizing
# them — simplicity and log legibility over wall-clock time.
#
# This script itself is now a thin wrapper: every actual
# driving/grading helper, the four run_<role> functions, and the
# certification-profile-matrix printers live in lib.sh, shared with
# the two scripts CI actually runs — run-oid4vci.sh (Issuer+Wallet)
# and run-oid4vp.sh (Verifier+Wallet-VP), split into two independent
# CI jobs/workflows (each needs its own pass/fail badge, which GitHub
# only gives per-workflow, not per-job within one combined workflow —
# see lib.sh's own doc comment). This script still runs all four
# roles, unsplit, as the one-command full local reproduction — see
# each role's own conformance/*/scripts/README for why the exact set
# of modules each one runs is what it is.
#
# Prerequisites:
#   - The OIDF conformance suite itself running locally
#     (https://localhost:8443/ by default — export CONFORMANCE_SERVER
#     to override).
#   - Docker, for the conformance-issuer/-verifier/-wallet-vp
#     containers (brought up automatically, one at a time, by each
#     role's own script).
#   - No CONFORMANCE_SUITE_CHECKOUT, unlike FAPIgo's own run-all.sh —
#     every script here talks to the suite's own REST API directly
#     (internal/conformancesuite), never shells out to the suite's own
#     Python tooling.
#
# Usage:
#   export CONFORMANCE_SERVER=https://localhost:8443/   # only if not the default
#   ./conformance/scripts/run-all.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=conformance/scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

check_suite_reachable

run_issuer
run_wallet
run_verifier
run_wallet_vp

print_oid4vci_matrix
print_oid4vp_matrix
print_combined_summary
finish
