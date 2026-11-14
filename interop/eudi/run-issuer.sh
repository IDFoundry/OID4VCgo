#!/usr/bin/env bash
# The EUDI reference wallet library, eudi-lib-jvm-openid4vci-kt, obtains
# credentials from OID4VCgo's cmd/conformance-issuer: SD-JWT VC and
# mdoc PIDs, by the pre-authorized code and the authorization code
# flows, with every proof type, batches, encryption, signed metadata,
# deferral, notifications and DPoP nonces; EUDI's own SD-JWT VC verifier
# checks what's issued; then controls that must be refused. The issuer
# runs in five configurations in turn, its profiles, the last its
# production setup, every attestation from OID4VCgo's Wallet Provider
# (interop/walletprovider). See README.md.
#
#   interop/eudi/run-issuer.sh
#   PROFILES="base deferred" interop/eudi/run-issuer.sh
#
# Needs go, a JDK (17 or later), curl and jq; the driver's dependencies
# come from Maven Central, pinned and checksum-verified. Exits 0 only if
# every case passes and every control is refused.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="${OID4VCGO_SRC:-$(cd "$HERE/../.." && pwd)}"
PORT="${PORT:-18446}"
OFFERS_PORT="${OFFERS_PORT:-18447}"
# The production profile's Wallet Providers (a trusted one and one
# under a CA the issuer doesn't trust), their admin listeners and the
# wallet's agents for them: PORT+2 to PORT+7.
WP_PORT="${WP_PORT:-$((PORT + 2))}"
PROFILES="${PROFILES:-base key-attestation deferred dpop-nonces production}"
WORK="${WORK:-$(mktemp -d)}"
ISSUER="https://localhost:$PORT"

for p in "$PORT" "$OFFERS_PORT" $(seq "$WP_PORT" $((WP_PORT + 5))); do
  if (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then
    echo "port $p is in use; set PORT / OFFERS_PORT / WP_PORT" >&2
    exit 2
  fi
done

ISSUER_PID=""
stop_issuer() {
  if [[ -n "$ISSUER_PID" ]]; then
    kill "$ISSUER_PID" 2>/dev/null || true
    wait "$ISSUER_PID" 2>/dev/null || true
    ISSUER_PID=""
  fi
}
# The production profile's Wallet Providers and agents.
PROVIDER_PIDS=()
stop_all() {
  stop_issuer
  for pid in ${PROVIDER_PIDS[@]+"${PROVIDER_PIDS[@]}"}; do kill "$pid" 2>/dev/null || true; done
  for pid in ${PROVIDER_PIDS[@]+"${PROVIDER_PIDS[@]}"}; do wait "$pid" 2>/dev/null || true; done
}
trap stop_all EXIT

echo "work dir  $WORK"
echo "issuer    $SRC, commit $(git -C "$SRC" rev-parse HEAD 2>/dev/null || echo unknown)"
echo "wallet    eu.europa.ec.eudi:eudi-lib-jvm-openid4vci-kt:$(sed -n 's/^openid4vci = "\(.*\)"/\1/p' "$HERE/issuance/gradle/libs.versions.toml")"

# shellcheck source=../production.sh
. "$HERE/../production.sh"
# Built with the conformance_production tag, so that the issuer can run
# its production setup (the production profile), and the Wallet
# Provider at all.
build_production "$WORK" "$SRC" issuer=./cmd/conformance-issuer walletprovider=./interop/walletprovider
(cd "$SRC" && go run ./interop/eudi/scripts/setup-issuer -out "$WORK" -port "$PORT" -offers-port "$OFFERS_PORT")
(cd "$HERE/issuance" && ./gradlew --quiet --no-configuration-cache installDist)
DRIVER="$HERE/issuance/build/install/eudi-issuance-interop/bin/eudi-issuance-interop"

# start_issuer runs the issuer with issuer.json changed by the jq filter
# $2, its profile; the rest are jq's arguments.
start_issuer() {  # $1 the profile's name, $2 a jq filter; then jq arguments
  local name="$1" filter="$2"
  shift 2
  stop_issuer
  jq "$@" "$filter" "$WORK/issuer.json" > "$WORK/issuer-$name.json"
  "$WORK/issuer" -config "$WORK/issuer-$name.json" >> "$WORK/issuer-$name.log" 2>&1 &
  ISSUER_PID=$!
  for _ in $(seq 1 50); do
    if curl -s -o /dev/null --max-time 1 --cacert "$WORK/tls-ca.pem" "$ISSUER/.well-known/openid-credential-issuer"; then return 0; fi
    sleep 0.2
  done
  echo "the issuer did not start; see $WORK/issuer-$name.log" >&2
  exit 2
}

# The status lists' ttl of the production profile's Wallet Provider, in
# seconds: how long the issuer may cache one, and so how long its
# revocation control waits.
PROVIDER_STATUS_TTL=2

# start_providers starts the production profile's two Wallet Providers,
# OID4VCgo's walletprovider.Provider as a deployment runs it (sealed
# SQLite stores, its status lists served), the second under a CA the
# issuer doesn't trust, naming the same identifier; and the wallet's
# agent for each, one registered instance. The driver gets its
# attestations through the agents.
start_providers() {
  local client
  client="$(jq -r '.client_id' "$WORK/driver.json")"
  start_wallet_provider "$WORK/walletprovider" "$WORK/wallet-provider" "$WP_PORT" $((WP_PORT + 1)) "$client" \
    -identifier "$(jq -r '.attester_issuer' "$WORK/driver.json")" -status-list-ttl "${PROVIDER_STATUS_TTL}s"
  PROVIDER_PIDS+=($!)
  start_wallet_provider "$WORK/walletprovider" "$WORK/other-wallet-provider" $((WP_PORT + 2)) $((WP_PORT + 3)) "$client" \
    -identifier "$(jq -r '.attester_issuer' "$WORK/driver.json")" -ca-name "OID4VCgo interop untrusted Wallet Provider CA"
  PROVIDER_PIDS+=($!)
  wait_ready "http://127.0.0.1:$((WP_PORT + 1))/ready" "http://127.0.0.1:$((WP_PORT + 3))/ready"
  start_provider_agent "$WORK/walletprovider" "$WORK/wallet-provider" "$WP_PORT" $((WP_PORT + 4))
  PROVIDER_PIDS+=($!)
  start_provider_agent "$WORK/walletprovider" "$WORK/other-wallet-provider" $((WP_PORT + 2)) $((WP_PORT + 5))
  PROVIDER_PIDS+=($!)
  wait_ready "http://127.0.0.1:$((WP_PORT + 4))/ready" "http://127.0.0.1:$((WP_PORT + 5))/ready"
  # The driver's configuration: the agents, and the trusted provider's
  # admin listener (its revocation control) and ttl.
  # shellcheck disable=SC2016 # jq's variables, not the shell's
  jq --arg agent "http://127.0.0.1:$((WP_PORT + 4))" --arg other "http://127.0.0.1:$((WP_PORT + 5))" \
    --arg admin "http://127.0.0.1:$((WP_PORT + 1))" --arg ttl "$PROVIDER_STATUS_TTL" \
    '.wallet_provider_agent = $agent | .other_wallet_provider_agent = $other
      | .wallet_provider_admin = $admin | .wallet_provider_status_ttl_seconds = $ttl' \
    "$WORK/driver.json" > "$WORK/driver-production.json"
}

# The production setup (cmd/conformance-issuer's production): the
# Authorization Server and Credential Issuer under production
# assurance, sealed SQLite stores, the access token key loaded from the
# config, jwt proofs that must carry a key attestation
# (haip.RecommendedIssuerConfig), DPoP nonces; the client's Wallet
# Attestations and the Key Attestations trusted by their x5c chain to
# the Wallet Provider's CA, and their status checked on its lists. Those
# are on loopback, under its own TLS certificate: the one setting a
# deployment wouldn't make (attestation_status_allow_loopback; see
# README.md).
# shellcheck disable=SC2016 # jq's variables, not the shell's
PRODUCTION_FILTER='.production = {database_path: $db, sealing_key: $key, access_token_signing_key_pem: $atk,
    attestation_status_tls_trust_anchors_pem: $wptls, attestation_status_allow_loopback: true}
  | .client.attester_trust_anchors_pem = $wpca
  | .key_attestation = {trust_anchor_pem: $wpca}
  | .dpop_nonces = true'

fail=0
for profile in $PROFILES; do
  driver_config="$WORK/driver.json"
  args=()
  case "$profile" in
    base) filter='.' ;;
    key-attestation) filter='.key_attestation.jwt_proof_requires_key_attestation = true' ;;
    deferred) filter='.deferred = true' ;;
    dpop-nonces) filter='.dpop_nonces = true' ;;
    production)
      start_providers
      driver_config="$WORK/driver-production.json"
      filter="$PRODUCTION_FILTER"
      args=(--arg db "$WORK/issuer-production.db" --arg key "$(sealing_key)" --arg atk "$(access_token_key)"
        --rawfile wpca "$WORK/wallet-provider/ca.pem" --rawfile wptls "$WORK/wallet-provider/tls-cert.pem") ;;
    *) echo "unknown profile $profile" >&2; exit 2 ;;
  esac
  echo "### issuer profile: $profile"
  start_issuer "$profile" "$filter" ${args[@]+"${args[@]}"}
  # The driver prints the ok/FAIL lines; its stack traces and the
  # library's own logging go to the log.
  if ! "$DRIVER" "$driver_config" "$profile" 2>> "$WORK/driver-$profile.log"; then fail=1; fi
  stop_issuer
  # The attestations' status checks, made by fetching the provider's
  # list: once before the revocation control, and again after it, once
  # the cached list's ttl had passed. A run in which the issuer fetched
  # nothing checked no status at all.
  if [[ "$profile" = production ]]; then
    fetches="$(grep -c ' served GET "/statuslists/{start}/{n}" 200' "$WORK/wallet-provider/wallet-provider.log" || true)"
    if [[ "$fetches" -ge 2 ]]; then echo "  ok    the issuer fetched the Wallet Provider's status list $fetches times"
    else echo "  FAIL  the issuer fetched the Wallet Provider's status list before and after the revocation (fetched $fetches times)"; fail=1; fi
  fi
done

if [[ "$fail" -eq 0 ]]; then echo "RESULT: every credential issued and verified, and every control refused"; else echo "RESULT: FAILED"; fi
exit "$fail"
