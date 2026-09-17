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
# What each role actually runs, and why each one is the exact set it
# is:
#
# Issuer (conformance/issuer/scripts/run-fapi2sp-battery, 3 runs
# against the one conformance-issuer container, reconfigured+restarted
# between each): the default HAIP battery (43 modules: the 21
# OID4VCI-specific ones plus the 39-module generic FAPI2SP battery plus
# Discovery plus 2 sanity checks), `-base-plan` (the suite's own base,
# non-HAIP plan — 38 modules, 2 of them expected self-SKIPPED per HAIP
# §4.5.1's own conditional-on-ecosystem-policy language and this
# binary's own deliberate unsupported-encryption-algorithm scope, see
# conformance/issuer/README.md), and `-credential-format mdoc` (2
# sanity-check modules under mso_mdoc format).
#
# Wallet (cmd/conformance-wallet, 6 runs — this binary is a one-shot
# CLI client, not a server, so no docker container/restart is involved
# at all): the default crossing (jwt-type proof, sd_jwt_vc,
# wallet_initiated — 22 module instances), `-proof-type attestation`
# (standalone Key Attestation proof, 22 instances), `-proof-type
# jwt-key-attestation` (Key Attestation nested in a jwt-type proof, 22
# instances), `-issuer-initiated` (the other Authorization Code Flow
# variant, 22 instances), `-base-plan` (the suite's own base plan, 5
# instances), and `-credential-format mdoc` (22 instances under
# mso_mdoc). Every one of these has run 100% clean (all instances
# FINISHED/PASSED) every time this repo's own README was updated after
# a live run — no known exceptions, unlike Issuer's battery.
#
# Verifier (conformance/verifier/scripts/run-sdjwt-modules and
# run-mdoc-module, 2 runs against the one conformance-verifier
# container): together, all 12 modules of
# oid4vp-1final-verifier-haip-test-plan. Both scripts already grade
# their own results and exit non-zero on anything unexpected (every
# module in this plan legitimately reaches REVIEW, never a plain
# PASSED — see conformance/verifier/README.md), so this script trusts
# their own exit code rather than re-parsing their logs.
#
# Wallet-VP (conformance/wallet-vp/scripts/run-modules, 1 run): 13 of
# 14 modules of oid4vp-1final-wallet-haip-test-plan (alternate-happy-flow
# is a known, documented gap — see that script's own doc comment). Also
# self-grading (positive modules PASSED, negative modules locally-
# rejected+REVIEW) and already exits non-zero on a mismatch, so this
# script trusts its own exit code too.
#
# Only Issuer's battery and Wallet's own 6 runs need this script's own
# result-parsing: neither cmd/conformance-wallet nor run-fapi2sp-battery
# treats an unexpected per-module result as a reason to exit non-zero
# (only infrastructure errors — a bad plan config, a container that
# never comes up — do that; see either binary's own main() for why:
# grading a whole battery's worth of modules was always meant to be
# read by a human, until this script). Both already print a parseable
# "=== summary ===" block (one "<module-name> <STATUS>=<RESULT> (module
# ..., url)" line per module) this script's own check_summary function
# reads.
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
CONFORMANCE_SERVER="${CONFORMANCE_SERVER:-https://localhost:8443/}"

WORKDIR="${WORKDIR:-$(mktemp -d)}"
mkdir -p "$WORKDIR"
RESULTS_FILE="$WORKDIR/results.txt"
touch "$RESULTS_FILE"
OVERALL_CLEAN=true
ALL_RUNS=()

log() { echo "[run-all] $*"; }

# record_result NAME LINE — appends "NAME|LINE" to $RESULTS_FILE. Not
# an associative array (declare -A needs bash 4+; the stock /bin/bash
# on macOS is 3.2, the same constraint FAPIgo's own run-all.sh
# documents) — results are looked up by grepping this file instead.
record_result() {
	local name="$1" line="$2"
	printf '%s|%s\n' "$name" "$line" >>"$RESULTS_FILE"
}

lookup_result() {
	local name="$1"
	grep -F "$name|" "$RESULTS_FILE" 2>/dev/null | tail -1 | cut -d'|' -f2- || true
}

# check_suite_reachable — polls rather than checking once, the same
# reasoning FAPIgo's own run-all.sh documents: a suite that was *just*
# started needs real time (30-90s) before Mongo + the Spring Boot app
# are actually healthy.
check_suite_reachable() {
	local i
	for i in $(seq 1 120); do
		if curl -sk --max-time 5 -f -o /dev/null "${CONFORMANCE_SERVER}api/runner/available"; then
			return 0
		fi
		sleep 1
	done
	echo "error: conformance suite not reachable at $CONFORMANCE_SERVER after 2 minutes — start it first" >&2
	exit 1
}

# check_summary LOG_FILE EXCEPTIONS — reads LOG_FILE's own
# "=== summary ===" block (one "<name> <STATUS>=<RESULT> (...)" line
# per module, or "<name> ERROR: ..."/"<name> ... NOT RUN ..."),
# comparing each module's own RESULT against "PASSED" by default, or
# the override named for it in EXCEPTIONS (newline-separated
# "name=RESULT" pairs). Prints every mismatch; returns 0 if there were
# none.
check_summary() {
	local log_file="$1" exceptions="$2"
	local clean=0
	local name result want
	while IFS='|' read -r name result; do
		[ -z "$name" ] && continue
		want="$(printf '%s\n' "$exceptions" | grep "^${name}=" | tail -1 | cut -d'=' -f2)"
		[ -z "$want" ] && want="PASSED"
		if [ "$result" != "$want" ]; then
			echo "  UNEXPECTED: $name = $result (want $want)"
			clean=1
		fi
	done < <(awk '
		/=== summary ===/ { insummary=1; next }
		insummary && NF {
			line = $0
			sub(/^[^ ]+ [^ ]+ /, "", line)  # strip the "YYYY/MM/DD HH:MM:SS " log.Printf timestamp
			if (match(line, /ERROR:/) || match(line, /NOT RUN/)) {
				name = substr(line, 1, RSTART - 1)
				gsub(/[ \t]+$/, "", name)
				print name "|FAILED"
			} else if (match(line, /[A-Za-z]+=[A-Z]+/)) {
				# Find the STATUS=RESULT token anywhere on the line —
				# not a fixed field position: conformance-issuer/
				# run-fapi2sp-battery prints bare "<name> STATUS=RESULT",
				# but cmd/conformance-wallet interleaves a
				# "[issuance-mode+encryption]" crossing token between
				# name and STATUS=RESULT ("<name> [crossing]
				# STATUS=RESULT") — a fixed-field-index parse silently
				# picked up "[crossing]" as the result instead (a real
				# bug this script hit on its own first live run: every
				# Wallet module was misreported as "UNEXPECTED: ... =
				# (want PASSED)", an empty result, not a real
				# regression). The "|"-delimited print (rather than a
				# plain space) is load-bearing too, not decorative: a
				# wallet module name legitimately contains an embedded
				# space ("<name> [<crossing>]"), and a plain `read -r
				# name result` (only two variables) dumps every field
				# past the first into result when split on whitespace —
				# silently prepending "[crossing] " to what should have
				# been a bare RESULT and breaking the comparison below,
				# a second real bug hit live in the same first run.
				name = substr(line, 1, RSTART - 1)
				gsub(/[ \t]+$/, "", name)
				token = substr(line, RSTART, RLENGTH)
				split(token, parts, "=")
				print name "|" parts[2]
			}
		}
	' "$log_file")
	return $clean
}

# run_go_checked NAME LOG_FILE EXCEPTIONS CMD... — runs CMD (a `go run`
# invocation), records OK/UNEXPECTED RESULTS based on check_summary
# (not the process's own exit code — see this file's own header
# comment for why neither Issuer's battery nor Wallet treats a bad
# per-module result as a reason to exit non-zero).
run_go_checked() {
	local name="$1" log_file="$2" exceptions="$3"
	shift 3
	ALL_RUNS+=("$name")
	log "$name: starting"
	(cd "$REPO_ROOT" && "$@") >"$log_file" 2>&1
	local mismatches
	mismatches="$(check_summary "$log_file" "$exceptions")"
	if [ -z "$mismatches" ]; then
		record_result "$name" "OK (see $log_file)"
		log "$name: OK"
	else
		OVERALL_CLEAN=false
		record_result "$name" "UNEXPECTED RESULTS (see $log_file)"
		log "$name: UNEXPECTED RESULTS"
		echo "$mismatches"
	fi
}

# run_go_self_graded NAME LOG_FILE CMD... — for the three scripts that
# already grade their own results and exit non-zero on a mismatch
# (both conformance/verifier scripts, conformance/wallet-vp's own) —
# trusts the process's own exit code rather than re-parsing its log.
run_go_self_graded() {
	local name="$1" log_file="$2"
	shift 2
	ALL_RUNS+=("$name")
	log "$name: starting"
	if (cd "$REPO_ROOT" && "$@") >"$log_file" 2>&1; then
		record_result "$name" "OK (see $log_file)"
		log "$name: OK"
	else
		OVERALL_CLEAN=false
		record_result "$name" "UNEXPECTED RESULTS (see $log_file)"
		log "$name: UNEXPECTED RESULTS"
	fi
}

run_issuer() {
	# 1 WARNING (attempt-reuse-authorization-code-after-one-second — a
	# suite-side timing WARNING this repo's own docs have consistently
	# reproduced, not a defect), 1 SKIPPED (refresh-token — HAIP's
	# pre-authorized_code grant doesn't issue refresh tokens), 1 REVIEW
	# (par-attempt-to-use-request_uri-for-different-client — a
	# screenshot-gated module, see conformance/issuer/README.md).
	local haip_exceptions='fapi2-security-profile-final-attempt-reuse-authorization-code-after-one-second=WARNING
fapi2-security-profile-final-refresh-token=SKIPPED
fapi2-security-profile-final-par-attempt-to-use-request_uri-for-different-client=REVIEW'
	run_go_checked "Issuer haip-battery" "$WORKDIR/issuer-haip.log" "$haip_exceptions" \
		go run ./conformance/issuer/scripts/run-fapi2sp-battery

	# 2 self-SKIPPED, both documented as deliberate Issuer-role scope
	# choices, not gaps — see conformance/issuer/README.md.
	local base_exceptions='oid4vci-1_0-issuer-fail-invalid-key-attestation-signature=SKIPPED
oid4vci-1_0-issuer-fail-unsupported-encryption-algorithm=SKIPPED'
	run_go_checked "Issuer base-plan" "$WORKDIR/issuer-base-plan.log" "$base_exceptions" \
		go run ./conformance/issuer/scripts/run-fapi2sp-battery -base-plan

	run_go_checked "Issuer mdoc" "$WORKDIR/issuer-mdoc.log" "" \
		go run ./conformance/issuer/scripts/run-fapi2sp-battery -credential-format mdoc
}

run_wallet() {
	# Every one of these 6 has always run 100% clean (all module
	# instances FINISHED/PASSED) — no known exceptions.
	run_go_checked "Wallet default (jwt, sd_jwt_vc)" "$WORKDIR/wallet-default.log" "" \
		go run ./cmd/conformance-wallet

	run_go_checked "Wallet attestation proof" "$WORKDIR/wallet-attestation.log" "" \
		go run ./cmd/conformance-wallet -proof-type attestation \
			-credential-configuration-id eu.europa.ec.eudi.pid.1.attestation -scope eudi.pid.1.attestation

	run_go_checked "Wallet jwt-key-attestation proof" "$WORKDIR/wallet-jwt-keyattest.log" "" \
		go run ./cmd/conformance-wallet -proof-type jwt-key-attestation \
			-credential-configuration-id eu.europa.ec.eudi.pid.1.jwt.keyattest -scope eudi.pid.1.jwt.keyattest

	run_go_checked "Wallet issuer-initiated" "$WORKDIR/wallet-issuer-initiated.log" "" \
		go run ./cmd/conformance-wallet -issuer-initiated

	run_go_checked "Wallet base-plan" "$WORKDIR/wallet-base-plan.log" "" \
		go run ./cmd/conformance-wallet -base-plan

	run_go_checked "Wallet mdoc" "$WORKDIR/wallet-mdoc.log" "" \
		go run ./cmd/conformance-wallet -credential-format mdoc \
			-credential-configuration-id eu.europa.ec.eudi.pid.mdoc.1 -scope eudi.pid.mdoc.1
}

run_verifier() {
	run_go_self_graded "Verifier sd_jwt_vc" "$WORKDIR/verifier-sdjwt.log" \
		go run ./conformance/verifier/scripts/run-sdjwt-modules

	run_go_self_graded "Verifier mdoc" "$WORKDIR/verifier-mdoc.log" \
		go run ./conformance/verifier/scripts/run-mdoc-module
}

run_wallet_vp() {
	run_go_self_graded "Wallet-VP" "$WORKDIR/wallet-vp.log" \
		go run ./conformance/wallet-vp/scripts/run-modules
}

check_suite_reachable

run_issuer
run_wallet
run_verifier
run_wallet_vp

echo
echo "=== combined summary ==="
for name in "${ALL_RUNS[@]}"; do
	result="$(lookup_result "$name")"
	printf '%-40s %s\n' "$name" "${result:-DID NOT RUN}"
done
echo
echo "full logs: $WORKDIR"

if [ "$OVERALL_CLEAN" = true ]; then
	echo
	echo "All ${#ALL_RUNS[@]} conformance runs completed with no unexpected results."
	exit 0
else
	echo
	echo "One or more conformance runs had unexpected results — see the log paths above."
	exit 1
fi
