# Shared by conformance/scripts/run-all.sh, run-oid4vci.sh and
# run-oid4vp.sh — every helper function, the four role-runner functions
# (run_issuer/run_wallet/run_verifier/run_wallet_vp), and the
# certification-profile-matrix printers, factored out once the CI
# workflow split into two independent jobs (.github/workflows/
# oid4vci-conformance.yml, oid4vp-conformance.yml — each needs its own
# badge, which GitHub only gives per-workflow, not per-job within one
# combined workflow) needed the OID4VCI (Issuer+Wallet) and OID4VP
# (Verifier+Wallet-VP) halves runnable independently while still
# sharing every bit of driving/grading logic with each other and with
# run-all.sh's own "run everything, one command" local-dev shape.
#
# Not meant to be run directly: a sourcing script must set REPO_ROOT
# (and may set CONFORMANCE_SERVER/WORKDIR) before sourcing this file —
# see any of the three top-level scripts for the exact pattern.

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
# comparing each module's own STATUS=RESULT against "FINISHED=PASSED"
# by default, or FINISHED and the result named for it in EXCEPTIONS
# (newline-separated "name=RESULT" pairs). A name is the summary's own,
# compared as a fixed string: run-fapi2sp-battery reports an
# OID4VCI-specific module as "<testName> [<vci_credential_encryption>]"
# (the HAIP plan lists some under both plain and encrypted), and
# cmd/conformance-wallet as "<testName> [<crossing>]". Prints every
# mismatch, and a summary with no module in it; returns 0 if there
# were none.
check_summary() {
	local log_file="$1" exceptions="$2"
	local clean=0 count=0
	local name result want
	while IFS='|' read -r name result; do
		[[ -z "$name" ]] && continue
		count=$((count + 1))
		want="$(printf '%s\n' "$exceptions" | awk -v n="$name=" 'index($0, n) == 1 { w = substr($0, length(n) + 1) } END { print w }')"
		[[ -z "$want" ]] && want="PASSED"
		# Every module must have run to completion: an INTERRUPTED
		# module's result is no verdict, whatever it says. A driver's
		# negative control ("crl control: ...") is graded by the driver
		# itself, which reports CONTROL=<verdict>.
		if [[ "$name" == "crl control: "* ]]; then
			if [[ "$result" != "CONTROL=$want" ]]; then
				echo "  UNEXPECTED: $name = $result (want CONTROL=$want)"
				clean=1
			fi
		elif [[ "$result" != "FINISHED=$want" ]]; then
			echo "  UNEXPECTED: $name = $result (want FINISHED=$want)"
			clean=1
		fi
	done < <(awk '
		/=== summary ===/ { insummary=1; next }
		insummary && NF {
			line = $0
			sub(/^[^ ]+ [^ ]+ /, "", line)  # strip the "YYYY/MM/DD HH:MM:SS " log.Printf timestamp
			if (match(line, /[ \t]CONTROL=[A-Z]+/)) {
				# A graded negative control (from the driver): its verdict
				# comes first, and the text after it may quote the
				# outcome the suite reported, "ERROR: ..." included.
				name = substr(line, 1, RSTART - 1)
				gsub(/[ \t]+$/, "", name)
				print name "|" substr(line, RSTART + 1, RLENGTH - 1)
			} else if (match(line, /ERROR:/) || match(line, /NOT RUN/)) {
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
				print name "|" substr(line, RSTART, RLENGTH)
			}
		}
	' "$log_file")
	if [[ $count -eq 0 ]]; then
		echo "  UNEXPECTED: no module results in $log_file's summary"
		clean=1
	fi
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
	# 1 SKIPPED (refresh-token — the suite skips it when the
	# authorization_code exchange returns no refresh token, and
	# fapigo/server issues one only for a grant whose scope includes
	# offline_access, which the suite never requests under the VCI
	# plans: it takes client.scope from the credential configuration's
	# scope, a single scope-token, and hides the field — see
	# conformance/issuer/README.md's "refresh-token"), 1 REVIEW
	# (par-attempt-to-use-request_uri-for-different-client — a
	# screenshot-gated module, see conformance/issuer/README.md).
	#
	# Every run's cmd/conformance-issuer requires DPoP nonces at PAR,
	# /token and the Credential Endpoint, and trusts key attestations
	# by their x5c chain (run-fapi2sp-battery's buildServerConfig).
	# attempt-reuse-authorization-code-after-one-second used to be a
	# third exception (WARNING) until wiring.go's own shared
	# revocationStore fix — see conformance/issuer/README.md's own
	# "Update" note — so it's expected to PASS like everything else now.
	# Every leg also drives run-fapi2sp-battery's two negative controls
	# of cmd/conformance-issuer's revocation check of the Wallet
	# Attestation signer: the plain happy-flow with an attester
	# certificate its CA's CRL revokes, and with one from a CA whose
	# distribution point serves only an expired CRL. The script grades
	# each itself: the suite must fail the module, and its log must
	# record the PAR error response naming that reason (CONTROL=REFUSED;
	# an ERROR line otherwise).
	local crl_exceptions='crl control: attester certificate revoked=REFUSED
crl control: attester CA without a current CRL=REFUSED'
	local haip_exceptions="fapi2-security-profile-final-refresh-token=SKIPPED
fapi2-security-profile-final-par-attempt-to-use-request_uri-for-different-client=REVIEW
$crl_exceptions"
	# run-fapi2sp-battery drives every entry of the plan's module list:
	# 63, its 61 modules with happy-flow and
	# fail-unknown-credential-configuration listed under
	# vci_credential_encryption=plain and again under encrypted. It
	# reports an OID4VCI-specific module as "<testName> [plain]" or
	# "<testName> [encrypted]", the names exceptions use.
	run_go_checked "Issuer haip-battery" "$WORKDIR/issuer-haip.log" "$haip_exceptions" \
		go run ./conformance/issuer/scripts/run-fapi2sp-battery -suite "$CONFORMANCE_SERVER"

	# Same 63 entries, same two exceptions (both unrelated to
	# the authorization_code_flow_variant), just driven with the HAIP
	# plan's own issuer_initiated variant instead of the default
	# wallet_initiated one — this binary submits each module's own
	# Credential Offer itself before polling it, see
	# submitCredentialOffer's own doc comment.
	run_go_checked "Issuer issuer-initiated" "$WORKDIR/issuer-issuer-initiated.log" "$haip_exceptions" \
		go run ./conformance/issuer/scripts/run-fapi2sp-battery -suite "$CONFORMANCE_SERVER" -issuer-initiated

	# mdoc and deferred issuance drive the plan's 21 OID4VCI-specific
	# modules (vciBattery: 23 entries, with the encrypted happy-flow and
	# fail-unknown-credential-configuration), not the FAPI2SP battery,
	# which never reaches credential issuance. Every module is expected
	# to pass, as in the sd_jwt_vc immediate runs
	# (conformance/issuer/README.md's "Runs"), except under deferral.
	local vci_exceptions="$crl_exceptions"
	run_go_checked "Issuer mdoc" "$WORKDIR/issuer-mdoc.log" "$vci_exceptions" \
		go run ./conformance/issuer/scripts/run-fapi2sp-battery -suite "$CONFORMANCE_SERVER" -credential-format mdoc

	run_go_checked "Issuer mdoc issuer-initiated" "$WORKDIR/issuer-mdoc-issuer-initiated.log" "$vci_exceptions" \
		go run ./conformance/issuer/scripts/run-fapi2sp-battery -suite "$CONFORMANCE_SERVER" -credential-format mdoc -issuer-initiated

	# Not certification profiles: deferred issuance (OID4VCI §9).
	# cmd/conformance-issuer defers every Credential Request, and each
	# module follows the 202 to the Deferred Credential Endpoint. The
	# encrypted happy-flow ends WARNING, the suite's: its compressed
	# request's Deferred Credential Request asks for no compression
	# (zip), yet VCICheckCredentialResponseCompression expects the
	# Deferred Credential Response compressed. run-fapi2sp-battery
	# fails the module if its log holds any other warning
	# (knownSuiteWarnings; conformance/issuer/README.md's "Runs").
	local deferred_exceptions="oid4vci-1_0-issuer-happy-flow [encrypted]=WARNING
$crl_exceptions"
	run_go_checked "Issuer deferred" "$WORKDIR/issuer-deferred.log" "$deferred_exceptions" \
		go run ./conformance/issuer/scripts/run-fapi2sp-battery -suite "$CONFORMANCE_SERVER" -deferred

	run_go_checked "Issuer mdoc deferred" "$WORKDIR/issuer-mdoc-deferred.log" "$deferred_exceptions" \
		go run ./conformance/issuer/scripts/run-fapi2sp-battery -suite "$CONFORMANCE_SERVER" -credential-format mdoc -deferred

	# Not a certification profile either: cmd/conformance-issuer's
	# production setup (Config.Production, built with the
	# conformance_production tag) — production assurance for the
	# Authorization Server and the Credential Issuer, sealed SQLite
	# stores, and jwt proofs that must carry a key attestation, with no
	# attestation proof type. It drives the plan's whole module list,
	# all 63 entries: haipBattery's 60 modules and
	# fail-invalid-key-attestation-signature, which
	# runs here with jwt proofs. Three modules expect REVIEW where
	# haip-battery expects PASSED: under production, an authorization
	# error before the user has authenticated (an unknown, reused or
	# expired request_uri; a request that didn't use PAR) is shown on
	# the Authorization Server's own page, not redirected
	# (SPECIFICATIONS.md's "Known strictness"), so the suite waits for a
	# screenshot of that page. Its log must still hold no FAILURE or
	# WARNING (run-fapi2sp-battery reads a REVIEW module's log).
	local production_exceptions="$haip_exceptions
fapi2-security-profile-final-ensure-unsigned-authorization-request-without-using-par-fails=REVIEW
fapi2-security-profile-final-par-attempt-reuse-request_uri=REVIEW
fapi2-security-profile-final-par-attempt-to-use-expired-request_uri=REVIEW"
	run_go_checked "Issuer production" "$WORKDIR/issuer-production.log" "$production_exceptions" \
		go run ./conformance/issuer/scripts/run-fapi2sp-battery -suite "$CONFORMANCE_SERVER" -production

	# The production setup under the other three certification-profile
	# axes: issuer_initiated drives the whole plan again, with the same
	# exceptions; mdoc and deferred issuance drive vciBattery, whose
	# modules end as at development (none of them ends on the
	# Authorization Server's own error page): all PASS, but for the
	# deferred run's encrypted happy-flow WARNING, the suite's.
	run_go_checked "Issuer production issuer-initiated" "$WORKDIR/issuer-production-issuer-initiated.log" "$production_exceptions" \
		go run ./conformance/issuer/scripts/run-fapi2sp-battery -suite "$CONFORMANCE_SERVER" -production -issuer-initiated

	run_go_checked "Issuer production mdoc" "$WORKDIR/issuer-production-mdoc.log" "$vci_exceptions" \
		go run ./conformance/issuer/scripts/run-fapi2sp-battery -suite "$CONFORMANCE_SERVER" -production -credential-format mdoc

	run_go_checked "Issuer production deferred" "$WORKDIR/issuer-production-deferred.log" "$deferred_exceptions" \
		go run ./conformance/issuer/scripts/run-fapi2sp-battery -suite "$CONFORMANCE_SERVER" -production -deferred
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
	# instances FINISHED/PASSED) — no known exceptions. In each, the
	# wallet reads its endpoints from the Credential Issuer's and the
	# Authorization Server's metadata, pins the suite's TLS
	# certificate, and verifies every credential it receives (its
	# signature, certificate chain, holder binding and status list
	# entry), failing the module when one doesn't verify.
	# The wallet_initiated sd_jwt_vc runs also drive cmd/conformance-wallet's
	# two negative controls of its revocation check of the SD-JWT VC
	# issuer's certificate (one its CA's CRL revokes, one from a CA
	# whose distribution point serves only an expired CRL): the wallet
	# must refuse the credential with certrevocation.ErrRevoked and
	# ErrNoCurrentCRL respectively, which it grades itself
	# (CONTROL=REFUSED; an ERROR line otherwise).
	local crl_exceptions='crl control: credential issuer certificate revoked=REFUSED
crl control: credential issuer CA without a current CRL=REFUSED'
	run_go_checked "Wallet default (jwt, sd_jwt_vc)" "$WORKDIR/wallet-default.log" "$crl_exceptions" \
		go run ./cmd/conformance-wallet -suite "$CONFORMANCE_SERVER"

	run_go_checked "Wallet issuer-initiated" "$WORKDIR/wallet-issuer-initiated.log" "" \
		go run ./cmd/conformance-wallet -suite "$CONFORMANCE_SERVER" -issuer-initiated

	# Same issuer_initiated flow variant, but vci_credential_offer_variant
	# =by_reference instead of the default by_value — the suite hands
	# this binary a credential_offer_uri instead of an inline JSON offer,
	# which wallet.Wallet.ResolveCredentialOffer already dereferences
	# unconditionally.
	run_go_checked "Wallet issuer-initiated (by_reference)" "$WORKDIR/wallet-issuer-initiated-by-reference.log" "" \
		go run ./cmd/conformance-wallet -suite "$CONFORMANCE_SERVER" -issuer-initiated -credential-offer-variant by_reference

	run_go_checked "Wallet mdoc" "$WORKDIR/wallet-mdoc.log" "" \
		go run ./cmd/conformance-wallet -suite "$CONFORMANCE_SERVER" -credential-format mdoc \
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
		go run ./cmd/conformance-wallet -suite "$CONFORMANCE_SERVER" -credential-format mdoc -issuer-initiated

	run_go_checked "Wallet mdoc issuer-initiated (by_reference)" "$WORKDIR/wallet-mdoc-issuer-initiated-by-reference.log" "" \
		go run ./cmd/conformance-wallet -suite "$CONFORMANCE_SERVER" -credential-format mdoc -issuer-initiated -credential-offer-variant by_reference

	# Not a certification profile: HAIP 1.0 §4.5.1's "Wallets MUST
	# support key attestations", each proof a jwt proof carrying a Key
	# Attestation in its key_attestation header (OID4VCI Appendix D.1),
	# against the suite's fixture that requires one.
	run_go_checked "Wallet key attestation (jwt-key-attestation)" "$WORKDIR/wallet-jwt-key-attestation.log" "$crl_exceptions" \
		go run ./cmd/conformance-wallet -suite "$CONFORMANCE_SERVER" -proof-type jwt-key-attestation \
			-credential-configuration-id eu.europa.ec.eudi.pid.1.jwt.keyattest -scope eudi.pid.1.jwt.keyattest
	return 0
}

run_verifier() {
	run_go_self_graded "Verifier sd_jwt_vc" "$WORKDIR/verifier-sdjwt.log" \
		go run ./conformance/verifier/scripts/run-sdjwt-modules -suite "$CONFORMANCE_SERVER"

	run_go_self_graded "Verifier mdoc" "$WORKDIR/verifier-mdoc.log" \
		go run ./conformance/verifier/scripts/run-mdoc-module -suite "$CONFORMANCE_SERVER"

	# Not certification profiles: the same plan served through
	# verifier.Transactions (cmd/conformance-verifier's transactions
	# engine) under production assurance, over a sealed SQLite store
	# (built with the conformance_production tag). Every module's
	# expected verdict is the legs' above, request-uri-method-post's
	# included: its requests ask for request_uri_method=post
	# (TransactionsConfig.RequestURIMethodPost; conformance/verifier/
	# README.md's "Transactions engine").
	run_go_self_graded "Verifier transactions sd_jwt_vc" "$WORKDIR/verifier-transactions-sdjwt.log" \
		go run ./conformance/verifier/scripts/run-sdjwt-modules -suite "$CONFORMANCE_SERVER" -transactions

	run_go_self_graded "Verifier transactions mdoc" "$WORKDIR/verifier-transactions-mdoc.log" \
		go run ./conformance/verifier/scripts/run-mdoc-module -suite "$CONFORMANCE_SERVER" -transactions
	return 0
}

run_wallet_vp() {
	# The OID4VP Wallet role's 4 catalog profiles: sd_jwt_vc and iso_mdl,
	# each over direct_post.jwt and over dc_api.jwt (the Digital
	# Credentials API, run-modules standing in for the browser — see
	# conformance/wallet-vp/README.md's "Scope" section).
	run_go_self_graded "Wallet-VP sd_jwt_vc" "$WORKDIR/wallet-vp-sdjwt.log" \
		go run ./conformance/wallet-vp/scripts/run-modules -suite "$CONFORMANCE_SERVER"

	run_go_self_graded "Wallet-VP iso_mdl" "$WORKDIR/wallet-vp-mdoc.log" \
		go run ./conformance/wallet-vp/scripts/run-modules -suite "$CONFORMANCE_SERVER" -credential-format iso_mdl

	run_go_self_graded "Wallet-VP sd_jwt_vc dc_api" "$WORKDIR/wallet-vp-sdjwt-dcapi.log" \
		go run ./conformance/wallet-vp/scripts/run-modules -suite "$CONFORMANCE_SERVER" -response-mode dc_api.jwt

	run_go_self_graded "Wallet-VP iso_mdl dc_api" "$WORKDIR/wallet-vp-mdoc-dcapi.log" \
		go run ./conformance/wallet-vp/scripts/run-modules -suite "$CONFORMANCE_SERVER" -response-mode dc_api.jwt -credential-format iso_mdl
	return 0
}

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

print_oid4vci_matrix() {
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
	return 0
}

print_oid4vp_matrix() {
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
	matrix_row "$ROW_FMT_18" "$SD_JWT_VC" "dc_api.jwt" "Wallet-VP sd_jwt_vc dc_api"
	matrix_row "$ROW_FMT_18" "iso_mdl" "dc_api.jwt" "Wallet-VP iso_mdl dc_api"
	return 0
}

print_combined_summary() {
	echo
	echo "=== combined summary ==="
	local name result
	for name in "${ALL_RUNS[@]}"; do
		result="$(lookup_result "$name")"
		printf '%-40s %s\n' "$name" "${result:-DID NOT RUN}"
	done
	echo
	echo "full logs: $WORKDIR"
	return 0
}

# finish — the one shared exit point every top-level script ends on:
# a final all-clear/not-clear line plus the actual exit code
# run-all.sh's own header comment (and each split script's own) relies
# on to report a real conformance failure as a real CI failure, not a
# green job with a buried "UNEXPECTED RESULTS" in the log.
finish() {
	if [[ "$OVERALL_CLEAN" = true ]]; then
		echo
		echo "All ${#ALL_RUNS[@]} conformance runs completed with no unexpected results."
		exit 0
	else
		echo
		echo "One or more conformance runs had unexpected results — see the log paths above."
		exit 1
	fi
}
