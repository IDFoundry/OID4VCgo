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
# Issuer (conformance/issuer/scripts/run-fapi2sp-battery, 4 runs
# against the one conformance-issuer container, reconfigured+restarted
# between each): exactly the Issuer's own 2x2 certification profile
# matrix (sd_jwt_vc/mdoc x wallet_initiated/issuer_initiated) — the
# default HAIP battery (60 modules: the 21 OID4VCI-specific ones plus
# the 39-module generic FAPI2SP battery plus Discovery plus 2 sanity
# checks — see haipBattery's own doc comment for why 60, not the plan's
# full 61: fail-invalid-key-attestation-signature lives in
# keyAttestationBattery instead, not run here since it isn't one of the
# 10 catalog profiles), the same battery again under `-issuer-initiated`,
# `-credential-format mdoc` (2 sanity-check modules under mso_mdoc
# format, restricted per mdocBattery's own doc comment), and that same
# mdoc pair again under `-issuer-initiated`. Deliberately no -base-plan,
# -credential-encryption, or -credential-proof-type-hint runs — none of
# those are separate profiles in OIDF's own certification catalog, see
# run_issuer's own doc comment.
#
# Wallet (cmd/conformance-wallet, 6 runs — this binary is a one-shot
# CLI client, not a server, so no docker container/restart is involved
# at all): exactly the Wallet's own 2x3 certification profile matrix
# (sd_jwt_vc/mdoc x wallet_initiated/issuer_initiated-by_value/
# issuer_initiated-by_reference) — the default crossing (jwt-type
# proof, sd_jwt_vc, wallet_initiated — 22 module instances),
# `-issuer-initiated` crossed with both vci_credential_offer_variant
# values (by_value/by_reference, 22 instances each), and
# `-credential-format mdoc` crossed with wallet_initiated and both
# issuer_initiated offer variants (22 instances each). Every one of
# these has run 100% clean (all instances FINISHED/PASSED) every time
# this repo's own README was updated after a live run — no known
# exceptions, unlike Issuer's battery. Deliberately no -proof-type or
# -base-plan runs — see run_wallet's own doc comment.
#
# Every run above corresponds one-to-one with a row in the
# "certification profile matrix" this script prints at the end,
# mirroring how the OIDF certification catalog itself breaks OID4VCI
# into 10 distinct HAIP profiles (4 Issuer + 6 Wallet) rather than one
# monolithic pass/fail.
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
# Wallet-VP (conformance/wallet-vp/scripts/run-modules, 2 runs): all 14
# modules of oid4vp-1final-wallet-haip-test-plan's own direct_post.jwt +
# x509_hash + request_uri_signed module list, once under the default
# credential_format=sd_jwt_vc and again under -credential-format
# iso_mdl — see conformance/wallet-vp/README.md's own "credential_format:
# iso_mdl" section for why both crossings reach the exact same 14
# modules. Also self-grading (positive modules PASSED, negative modules
# locally-rejected+REVIEW) and already exits non-zero on a mismatch, so
# this script trusts its own exit code too.
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

log() {
	echo "[run-all] $*"
	return 0
}

# record_result NAME LINE — appends "NAME|LINE" to $RESULTS_FILE. Not
# an associative array (declare -A needs bash 4+; the stock /bin/bash
# on macOS is 3.2, the same constraint FAPIgo's own run-all.sh
# documents) — results are looked up by grepping this file instead.
record_result() {
	local name="$1" line="$2"
	printf '%s|%s\n' "$name" "$line" >>"$RESULTS_FILE"
	return 0
}

lookup_result() {
	local name="$1"
	grep -F "$name|" "$RESULTS_FILE" 2>/dev/null | tail -1 | cut -d'|' -f2- || true
	return 0
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
		[[ -z "$name" ]] && continue
		want="$(printf '%s\n' "$exceptions" | grep "^${name}=" | tail -1 | cut -d'=' -f2)"
		[[ -z "$want" ]] && want="PASSED"
		if [[ "$result" != "$want" ]]; then
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
# invocation). Per-module results are graded via check_summary, not
# the process's own exit code — see this file's own header comment for
# why neither Issuer's battery nor Wallet treats a bad per-module
# result as a reason to exit non-zero. But a *non-zero exit* is never
# one of those per-module results — per that same header comment, both
# binaries reserve it for a genuine infrastructure failure (a bad plan
# config, a container that never comes up) — so it's always an
# unconditional UNEXPECTED RESULTS, checked before check_summary even
# runs. Confirmed live as a real gap, not a hypothetical: every one of
# Issuer's four legs failed this way in the same run (the container
# never became ready) and all four were still recorded "OK", since a
# log with no module lines at all trivially has no *mismatches* against
# what check_summary expected either.
run_go_checked() {
	local name="$1" log_file="$2" exceptions="$3"
	shift 3
	ALL_RUNS+=("$name")
	log "$name: starting"
	local cmd_status=0
	(cd "$REPO_ROOT" && "$@") >"$log_file" 2>&1 || cmd_status=$?
	if [[ $cmd_status -ne 0 ]]; then
		OVERALL_CLEAN=false
		record_result "$name" "UNEXPECTED RESULTS (see $log_file)"
		log "$name: UNEXPECTED RESULTS (exit $cmd_status)"
		return 0
	fi
	local mismatches
	mismatches="$(check_summary "$log_file" "$exceptions")"
	if [[ -z "$mismatches" ]]; then
		record_result "$name" "OK (see $log_file)"
		log "$name: OK"
	else
		OVERALL_CLEAN=false
		record_result "$name" "UNEXPECTED RESULTS (see $log_file)"
		log "$name: UNEXPECTED RESULTS"
		echo "$mismatches"
	fi
	return 0
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
	return 0
}

run_issuer() {
	# Exactly the Issuer side's own 2x2 certification profile matrix
	# (sd_jwt_vc/mdoc x wallet_initiated/issuer_initiated) — the 4 of
	# the OIDF certification catalog's own 10 OID4VCI HAIP profiles this
	# role covers. Deliberately no -base-plan, -credential-encryption,
	# or -credential-proof-type-hint runs here: none of those are
	# separate certifiable profiles in the catalog, just this repo's own
	# extra proof-type/plan QA coverage — run manually via
	# run-fapi2sp-battery's own flags when needed, not as part of the
	# daily certification-profile report.
	#
	# 1 SKIPPED (refresh-token — HAIP's pre-authorized_code grant
	# doesn't issue refresh tokens), 1 REVIEW
	# (par-attempt-to-use-request_uri-for-different-client — a
	# screenshot-gated module, see conformance/issuer/README.md).
	# attempt-reuse-authorization-code-after-one-second used to be a
	# third exception (WARNING) until wiring.go's own shared
	# revocationStore fix — see conformance/issuer/README.md's own
	# "Update" note — so it's expected to PASS like everything else now.
	local haip_exceptions='fapi2-security-profile-final-refresh-token=SKIPPED
fapi2-security-profile-final-par-attempt-to-use-request_uri-for-different-client=REVIEW'
	run_go_checked "Issuer haip-battery" "$WORKDIR/issuer-haip.log" "$haip_exceptions" \
		go run ./conformance/issuer/scripts/run-fapi2sp-battery

	# Same 60-module battery, same two exceptions (both unrelated to
	# the authorization_code_flow_variant), just driven with the HAIP
	# plan's own issuer_initiated variant instead of the default
	# wallet_initiated one — this binary submits each module's own
	# Credential Offer itself before polling it, see
	# submitCredentialOffer's own doc comment.
	run_go_checked "Issuer issuer-initiated" "$WORKDIR/issuer-issuer-initiated.log" "$haip_exceptions" \
		go run ./conformance/issuer/scripts/run-fapi2sp-battery -issuer-initiated

	run_go_checked "Issuer mdoc" "$WORKDIR/issuer-mdoc.log" "" \
		go run ./conformance/issuer/scripts/run-fapi2sp-battery -credential-format mdoc

	# 0 exceptions: mdoc restricts the driven module set to the 2
	# sanity-check modules (mdocBattery) regardless of flow variant,
	# same restriction "Issuer mdoc" above has — this just drives that
	# same pair under issuer_initiated instead, completing the Issuer
	# side's own 2x2 matrix.
	run_go_checked "Issuer mdoc issuer-initiated" "$WORKDIR/issuer-mdoc-issuer-initiated.log" "" \
		go run ./conformance/issuer/scripts/run-fapi2sp-battery -credential-format mdoc -issuer-initiated
	return 0
}

run_wallet() {
	# Exactly the Wallet side's own 2x3 certification profile matrix
	# (sd_jwt_vc/mdoc x wallet_initiated/issuer_initiated-by_value/
	# issuer_initiated-by_reference) — the other 6 of the OIDF
	# certification catalog's own 10 OID4VCI HAIP profiles. Deliberately
	# no -proof-type or -base-plan runs here: proof type isn't a
	# separate certifiable profile in the catalog (it's an
	# implementation choice within whichever profile you're actually
	# being certified against), and the base plan is a different,
	# non-HAIP test plan altogether — both are this repo's own extra QA
	# coverage, run manually via cmd/conformance-wallet's own flags when
	# needed, not as part of the daily certification-profile report.
	#
	# Every one of these 6 has always run 100% clean (all module
	# instances FINISHED/PASSED) — no known exceptions.
	run_go_checked "Wallet default (jwt, sd_jwt_vc)" "$WORKDIR/wallet-default.log" "" \
		go run ./cmd/conformance-wallet

	run_go_checked "Wallet issuer-initiated" "$WORKDIR/wallet-issuer-initiated.log" "" \
		go run ./cmd/conformance-wallet -issuer-initiated

	# Same issuer_initiated flow variant, but vci_credential_offer_variant
	# =by_reference instead of the default by_value — the suite hands
	# this binary a credential_offer_uri instead of an inline JSON offer,
	# which wallet.Wallet.ResolveCredentialOffer already dereferences
	# unconditionally.
	run_go_checked "Wallet issuer-initiated (by_reference)" "$WORKDIR/wallet-issuer-initiated-by-reference.log" "" \
		go run ./cmd/conformance-wallet -issuer-initiated -credential-offer-variant by_reference

	run_go_checked "Wallet mdoc" "$WORKDIR/wallet-mdoc.log" "" \
		go run ./cmd/conformance-wallet -credential-format mdoc \
			-credential-configuration-id eu.europa.ec.eudi.pid.mdoc.1 -scope eudi.pid.mdoc.1

	# The mdoc row's own issuer_initiated x by_value/by_reference pair,
	# completing the Wallet side's own 2x3 matrix. Unlike "Wallet mdoc"
	# above, these two don't pass an explicit -credential-configuration-id/
	# -scope — confirmed live that the suite's own emulated Credential
	# Issuer accepts the default sd_jwt_vc-shaped IDs just as well under
	# vci_credential_format=mdoc, so the mismatch the flag's own doc
	# comment warns about isn't actually load-bearing for these two
	# module instances specifically (both FINISHED=PASSED as run).
	run_go_checked "Wallet mdoc issuer-initiated" "$WORKDIR/wallet-mdoc-issuer-initiated.log" "" \
		go run ./cmd/conformance-wallet -credential-format mdoc -issuer-initiated

	run_go_checked "Wallet mdoc issuer-initiated (by_reference)" "$WORKDIR/wallet-mdoc-issuer-initiated-by-reference.log" "" \
		go run ./cmd/conformance-wallet -credential-format mdoc -issuer-initiated -credential-offer-variant by_reference
	return 0
}

run_verifier() {
	run_go_self_graded "Verifier sd_jwt_vc" "$WORKDIR/verifier-sdjwt.log" \
		go run ./conformance/verifier/scripts/run-sdjwt-modules

	run_go_self_graded "Verifier mdoc" "$WORKDIR/verifier-mdoc.log" \
		go run ./conformance/verifier/scripts/run-mdoc-module
	return 0
}

run_wallet_vp() {
	# sd_jwt_vc + iso_mdl together are the OID4VP Wallet role's own 2 of
	# 4 catalog profiles this repo covers (the other 2, both dc_api.jwt,
	# are a deliberately separate, not-yet-attempted harness effort —
	# see conformance/wallet-vp/README.md's own "Scope" section).
	run_go_self_graded "Wallet-VP sd_jwt_vc" "$WORKDIR/wallet-vp-sdjwt.log" \
		go run ./conformance/wallet-vp/scripts/run-modules

	run_go_self_graded "Wallet-VP iso_mdl" "$WORKDIR/wallet-vp-mdoc.log" \
		go run ./conformance/wallet-vp/scripts/run-modules -credential-format iso_mdl
	return 0
}

check_suite_reachable

run_issuer
run_wallet
run_verifier
run_wallet_vp


# matrix_status NAME — a one-word PASS/FAIL/(DID NOT RUN) reduction of
# lookup_result's own "OK (see log)"/"UNEXPECTED RESULTS (see log)"
# strings, for the fixed-width certification profile matrix below (the
# full "(see log)" detail is already in the combined summary
# underneath, so the matrix stays scannable at a glance instead of
# wrapping).
matrix_status() {
	local name="$1" result
	result="$(lookup_result "$name")"
	case "$result" in
	OK*) echo "PASS" ;;
	UNEXPECTED*) echo "FAIL" ;;
	*) echo "DID NOT RUN" ;;
	esac
	return 0
}

# matrix_header/matrix_row FMT ... — print one certification profile
# matrix's own header/data row, FMT being one of the two column-width
# printf formats below. Split out (rather than inlining every printf,
# repeating "FORMAT"/"RESULT"/the format strings themselves row after
# row) purely to keep this section's own SonarCloud duplicated-literal
# count sane across two whole matrices' worth of rows — the underlying
# labels/values are still literal certification-relevant data, just
# named as shell variables once each so they're referenced, not
# repeated verbatim, in every row.
matrix_header() {
	local fmt="$1" col2label="$2"
	printf "$fmt" "$FORMAT_LABEL" "$col2label" "$RESULT_LABEL"
	return 0
}

matrix_row() {
	local fmt="$1" col1="$2" col2="$3" name="$4"
	printf "$fmt" "$col1" "$col2" "$(matrix_status "$name")"
	return 0
}

FORMAT_LABEL="FORMAT"
RESULT_LABEL="RESULT"
SD_JWT_VC="sd_jwt_vc"
DIRECT_POST_JWT="direct_post.jwt"
WALLET_INITIATED="wallet_initiated"
ROW_FMT_18='  %-10s %-18s %s\n'
ROW_FMT_30='  %-10s %-30s %s\n'

echo
echo "=== OID4VCI certification profile matrix ==="
echo "(mirrors the OIDF certification catalog's own per-profile breakdown:"
echo " 4 Issuer + 6 Wallet = 10 distinct oid4vci-1_0-*-haip-test-plan profiles)"
echo
echo "Issuer (oid4vci-1_0-issuer-haip-test-plan):"
matrix_header "$ROW_FMT_18" "FLOW"
matrix_row "$ROW_FMT_18" "$SD_JWT_VC" "$WALLET_INITIATED" "Issuer haip-battery"
matrix_row "$ROW_FMT_18" "$SD_JWT_VC" "issuer_initiated" "Issuer issuer-initiated"
matrix_row "$ROW_FMT_18" "mdoc" "$WALLET_INITIATED" "Issuer mdoc"
matrix_row "$ROW_FMT_18" "mdoc" "issuer_initiated" "Issuer mdoc issuer-initiated"
echo
echo "Wallet (oid4vci-1_0-wallet-haip-test-plan):"
matrix_header "$ROW_FMT_30" "OFFER DELIVERY"
matrix_row "$ROW_FMT_30" "$SD_JWT_VC" "$WALLET_INITIATED" "Wallet default (jwt, sd_jwt_vc)"
matrix_row "$ROW_FMT_30" "$SD_JWT_VC" "issuer_initiated (by_value)" "Wallet issuer-initiated"
matrix_row "$ROW_FMT_30" "$SD_JWT_VC" "issuer_initiated (by_reference)" "Wallet issuer-initiated (by_reference)"
matrix_row "$ROW_FMT_30" "mdoc" "$WALLET_INITIATED" "Wallet mdoc"
matrix_row "$ROW_FMT_30" "mdoc" "issuer_initiated (by_value)" "Wallet mdoc issuer-initiated"
matrix_row "$ROW_FMT_30" "mdoc" "issuer_initiated (by_reference)" "Wallet mdoc issuer-initiated (by_reference)"

echo
echo "=== OID4VP certification profile matrix ==="
echo "(mirrors the OIDF certification catalog's own per-profile breakdown:"
echo " 2 Verifier + 4 Wallet = 6 distinct oid4vp-1final-*-haip-test-plan profiles)"
echo
echo "Verifier (oid4vp-1final-verifier-haip-test-plan):"
matrix_header "$ROW_FMT_18" "RESPONSE MODE"
matrix_row "$ROW_FMT_18" "$SD_JWT_VC" "$DIRECT_POST_JWT" "Verifier sd_jwt_vc"
matrix_row "$ROW_FMT_18" "iso_mdl" "$DIRECT_POST_JWT" "Verifier mdoc"
echo
echo "Wallet (oid4vp-1final-wallet-haip-test-plan):"
matrix_header "$ROW_FMT_18" "RESPONSE MODE"
matrix_row "$ROW_FMT_18" "$SD_JWT_VC" "$DIRECT_POST_JWT" "Wallet-VP sd_jwt_vc"
matrix_row "$ROW_FMT_18" "iso_mdl" "$DIRECT_POST_JWT" "Wallet-VP iso_mdl"
printf "$ROW_FMT_18" "$SD_JWT_VC" "dc_api.jwt" "NOT IMPLEMENTED"
printf "$ROW_FMT_18" "iso_mdl" "dc_api.jwt" "NOT IMPLEMENTED"

echo
echo "=== combined summary ==="
for name in "${ALL_RUNS[@]}"; do
	result="$(lookup_result "$name")"
	printf '%-40s %s\n' "$name" "${result:-DID NOT RUN}"
done
echo
echo "full logs: $WORKDIR"

if [[ "$OVERALL_CLEAN" = true ]]; then
	echo
	echo "All ${#ALL_RUNS[@]} conformance runs completed with no unexpected results."
	exit 0
else
	echo
	echo "One or more conformance runs had unexpected results — see the log paths above."
	exit 1
fi
