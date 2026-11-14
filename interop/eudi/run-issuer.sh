#!/usr/bin/env bash
# The EUDI reference wallet library, eudi-lib-jvm-openid4vci-kt, obtains
# credentials from OID4VCgo's cmd/conformance-issuer: SD-JWT VC and
# mdoc PIDs, by the pre-authorized code and the authorization code
# flows, with every proof type, batches, encryption, signed metadata,
# deferral, notifications and DPoP nonces; EUDI's own SD-JWT VC verifier
# checks what's issued; then controls that must be refused. The issuer
# runs in five configurations in turn, its profiles, the fifth its
# production setup, every attestation from OID4VCgo's Wallet Provider
# (interop/walletprovider); with POSTGRES_URL, a sixth runs that setup
# as two instances sharing a PostgreSQL database behind one URL
# (production-scaled). See README.md.
#
#   interop/eudi/run-issuer.sh
#   PROFILES="base deferred" interop/eudi/run-issuer.sh
#   POSTGRES_URL=postgres://postgres@localhost:5432/postgres?sslmode=disable interop/eudi/run-issuer.sh
#
# Needs go, a JDK (17 or later), curl and jq; the driver's dependencies
# come from Maven Central, pinned and checksum-verified. Exits 0 only if
# every case passes and every control is refused.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="${OID4VCGO_SRC:-$(cd "$HERE/../.." && pwd)}"
PORT="${PORT:-18446}"
OFFERS_PORT="${OFFERS_PORT:-18447}"
# The production profiles' Wallet Providers (a trusted one and one
# under a CA the issuer doesn't trust), their admin listeners and the
# wallet's agents for them: PORT+2 to PORT+7.
WP_PORT="${WP_PORT:-$((PORT + 2))}"
# The production-scaled profile's: the empty PostgreSQL database its two
# instances share, and the instances' listeners, behind
# interop/splitproxy on PORT: PORT+8 and PORT+9, the first's offers
# listener on PORT+10 (the second's is OFFERS_PORT, the driver's).
POSTGRES_URL="${POSTGRES_URL:-}"
SCALED_PORT="${SCALED_PORT:-$((PORT + 8))}"
PROFILES="${PROFILES:-base key-attestation deferred dpop-nonces production${POSTGRES_URL:+ production-scaled}}"
WORK="${WORK:-$(mktemp -d)}"
ISSUER="https://localhost:$PORT"

if [[ " $PROFILES " = *" production-scaled "* && -z "$POSTGRES_URL" ]]; then
  echo "the production-scaled profile needs POSTGRES_URL, an empty PostgreSQL database" >&2
  exit 2
fi
for p in "$PORT" "$OFFERS_PORT" $(seq "$WP_PORT" $((WP_PORT + 5))) $(seq "$SCALED_PORT" $((SCALED_PORT + 2))); do
  if (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then
    echo "port $p is in use; set PORT / OFFERS_PORT / WP_PORT / SCALED_PORT" >&2
    exit 2
  fi
done

# The issuer: one process, or the production-scaled profile's two
# instances and their proxy.
ISSUER_PIDS=()
stop_issuer() {
  for pid in ${ISSUER_PIDS[@]+"${ISSUER_PIDS[@]}"}; do kill "$pid" 2>/dev/null || true; done
  for pid in ${ISSUER_PIDS[@]+"${ISSUER_PIDS[@]}"}; do wait "$pid" 2>/dev/null || true; done
  ISSUER_PIDS=()
}
# The production profiles' Wallet Providers and agents.
PROVIDER_PIDS=()
stop_providers() {
  for pid in ${PROVIDER_PIDS[@]+"${PROVIDER_PIDS[@]}"}; do kill "$pid" 2>/dev/null || true; done
  for pid in ${PROVIDER_PIDS[@]+"${PROVIDER_PIDS[@]}"}; do wait "$pid" 2>/dev/null || true; done
  PROVIDER_PIDS=()
}
stop_all() {
  stop_issuer
  stop_providers
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
build_production "$WORK" "$SRC" issuer=./cmd/conformance-issuer walletprovider=./interop/walletprovider splitproxy=./interop/splitproxy
(cd "$SRC" && go run ./interop/eudi/scripts/setup-issuer -out "$WORK" -port "$PORT" -offers-port "$OFFERS_PORT")
(cd "$HERE/issuance" && ./gradlew --quiet --no-configuration-cache installDist)
DRIVER="$HERE/issuance/build/install/eudi-issuance-interop/bin/eudi-issuance-interop"

# wait_issuer waits for the issuer to answer at $1, failing the run if
# it doesn't within 10 s; its log is $2.
wait_issuer() {  # $1 its URL, $2 its log
  for _ in $(seq 1 50); do
    if curl -s -o /dev/null --max-time 1 --cacert "$WORK/tls-ca.pem" "$1/.well-known/openid-credential-issuer"; then return 0; fi
    sleep 0.2
  done
  echo "the issuer did not start; see $2" >&2
  exit 2
}

# start_issuer runs the issuer with issuer.json changed by the jq filter
# $2, its profile; the rest are jq's arguments.
start_issuer() {  # $1 the profile's name, $2 a jq filter; then jq arguments
  local name="$1" filter="$2"
  shift 2
  stop_issuer
  jq "$@" "$filter" "$WORK/issuer.json" > "$WORK/issuer-$name.json"
  "$WORK/issuer" -config "$WORK/issuer-$name.json" >> "$WORK/issuer-$name.log" 2>&1 &
  ISSUER_PIDS+=($!)
  wait_issuer "$ISSUER" "$WORK/issuer-$name.log"
}

# The production-scaled profile's split, interop/splitproxy's routes:
# the path each goes to, instance a or b. A request whose DPoP proof
# carries no nonce goes to the other instance, which answers it with a
# nonce challenge (-dpop-nonce-split), so each retry carries a nonce the
# instance it reaches didn't issue. So PAR is at a, the consent (its
# page and decision, which the binary keeps in memory between them) at
# b; the Token Endpoint at a, redeeming codes b issued, and
# pre-authorized codes minted by b's offers listener; the Nonce Endpoint
# at a, the Credential Endpoint at b, taking a's c_nonces and access
# tokens; and the Notification Endpoint at a, taking b's
# notification_ids. The rest (metadata, JWKS, status lists) goes to
# each in turn.
SPLIT_ROUTES=(/par=a /authorize=b /token=a /nonce=a /credential=b /notification=a /deferred_credential=a /credential-offer=a)

# start_scaled runs the production setup as two instances sharing the
# PostgreSQL database, behind interop/splitproxy at the issuer's URL:
# issuer.json changed by the jq filter $1 (with the rest, jq's
# arguments), then each instance's listeners. Each logs to
# issuer-production-scaled-<instance>.log, the proxy to splitproxy.log.
start_scaled() {  # $1 a jq filter; then jq arguments
  local filter="$1" i port offers routes=()
  shift
  stop_issuer
  jq "$@" "$filter" "$WORK/issuer.json" > "$WORK/issuer-production-scaled.json"
  for i in a b; do
    if [[ "$i" = a ]]; then port="$SCALED_PORT" offers=$((SCALED_PORT + 2)); else port=$((SCALED_PORT + 1)) offers="$OFFERS_PORT"; fi
    jq --arg addr "127.0.0.1:$port" --arg offers "127.0.0.1:$offers" '.listen_addr = $addr | .offers.listen_addr = $offers' \
      "$WORK/issuer-production-scaled.json" > "$WORK/issuer-production-scaled-$i.json"
    "$WORK/issuer" -config "$WORK/issuer-production-scaled-$i.json" >> "$WORK/issuer-production-scaled-$i.log" 2>&1 &
    ISSUER_PIDS+=($!)
  done
  wait_issuer "https://localhost:$SCALED_PORT" "$WORK/issuer-production-scaled-a.log"
  wait_issuer "https://localhost:$((SCALED_PORT + 1))" "$WORK/issuer-production-scaled-b.log"
  # The proxy serves the issuer's own TLS certificate, as a load
  # balancer terminating TLS for it does.
  jq -r '.tls_certificate_pem' "$WORK/issuer.json" > "$WORK/splitproxy-cert.pem"
  (umask 077 && jq -r '.tls_private_key_pem' "$WORK/issuer.json" > "$WORK/splitproxy-key.pem")
  for i in "${SPLIT_ROUTES[@]}"; do routes+=(-route "$i"); done
  "$WORK/splitproxy" -addr "127.0.0.1:$PORT" -cert "$WORK/splitproxy-cert.pem" -key "$WORK/splitproxy-key.pem" \
    -backend-ca "$WORK/tls-ca.pem" -backend-server-name localhost -dpop-nonce-split \
    -backend "a=https://127.0.0.1:$SCALED_PORT" -backend "b=https://127.0.0.1:$((SCALED_PORT + 1))" "${routes[@]}" \
    >> "$WORK/splitproxy.log" 2>&1 &
  ISSUER_PIDS+=($!)
  wait_issuer "$ISSUER" "$WORK/splitproxy.log"
}

# The status lists' ttl of the production profiles' Wallet Provider, in
# seconds: how long the issuer may cache one, and so how long its
# revocation control waits.
PROVIDER_STATUS_TTL=2

# start_providers starts a production profile's two Wallet Providers,
# OID4VCgo's walletprovider.Provider as a deployment runs it (sealed
# SQLite stores, its status lists served), the second under a CA the
# issuer doesn't trust, naming the same identifier; and the wallet's
# agent for each, one registered instance. The driver gets its
# attestations through the agents. Each profile has its own, in
# $1wallet-provider and $1other-wallet-provider, as each revokes its
# instance; the driver's configuration is $2.
start_providers() {  # $1 the providers' directories' prefix, $2 the driver's configuration
  local prefix="$1" out="$2" client
  stop_providers
  client="$(jq -r '.client_id' "$WORK/driver.json")"
  start_wallet_provider "$WORK/walletprovider" "$WORK/${prefix}wallet-provider" "$WP_PORT" $((WP_PORT + 1)) "$client" \
    -identifier "$(jq -r '.attester_issuer' "$WORK/driver.json")" -status-list-ttl "${PROVIDER_STATUS_TTL}s"
  PROVIDER_PIDS+=($!)
  start_wallet_provider "$WORK/walletprovider" "$WORK/${prefix}other-wallet-provider" $((WP_PORT + 2)) $((WP_PORT + 3)) "$client" \
    -identifier "$(jq -r '.attester_issuer' "$WORK/driver.json")" -ca-name "OID4VCgo interop untrusted Wallet Provider CA"
  PROVIDER_PIDS+=($!)
  wait_ready "http://127.0.0.1:$((WP_PORT + 1))/ready" "http://127.0.0.1:$((WP_PORT + 3))/ready"
  start_provider_agent "$WORK/walletprovider" "$WORK/${prefix}wallet-provider" "$WP_PORT" $((WP_PORT + 4))
  PROVIDER_PIDS+=($!)
  start_provider_agent "$WORK/walletprovider" "$WORK/${prefix}other-wallet-provider" $((WP_PORT + 2)) $((WP_PORT + 5))
  PROVIDER_PIDS+=($!)
  wait_ready "http://127.0.0.1:$((WP_PORT + 4))/ready" "http://127.0.0.1:$((WP_PORT + 5))/ready"
  # The driver's configuration: the agents, the trusted provider's
  # admin listener (its revocation control) and ttl, and the split's
  # routes, which only the production-scaled profile reads.
  # shellcheck disable=SC2016 # jq's variables, not the shell's
  jq --arg agent "http://127.0.0.1:$((WP_PORT + 4))" --arg other "http://127.0.0.1:$((WP_PORT + 5))" \
    --arg admin "http://127.0.0.1:$((WP_PORT + 1))" --arg ttl "$PROVIDER_STATUS_TTL" --arg routes "${SPLIT_ROUTES[*]}" \
    '.wallet_provider_agent = $agent | .other_wallet_provider_agent = $other
      | .wallet_provider_admin = $admin | .wallet_provider_status_ttl_seconds = $ttl
      | .split_routes = ($routes | split(" ") | map(split("=") | {(.[0]): .[1]}) | add)' \
    "$WORK/driver.json" > "$out"
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
# The production-scaled profile's: the same setup in the PostgreSQL
# database in place of the SQLite file, as instances of a horizontally
# scaled deployment (server.DeploymentHorizontallyScaled), sharing the
# c_nonce key as well as the others, each sweeping the stores every
# second; and a Token Status List, its indices reserved in the shared
# store by whichever instance issues.
# shellcheck disable=SC2016 # jq's variables, not the shell's
SCALED_FILTER="$PRODUCTION_FILTER"'
  | .production |= (del(.database_path) + {database_url: $pg, horizontally_scaled: true, nonce_key: $nonce, sweep_interval: "1s"})
  | .status_lists = {}'

# check_status_fetches checks the issuer fetched the Wallet Provider's
# status list, logged in $1: once before the revocation control, and
# again after it, once the cached list's ttl had passed. A run in which
# the issuer fetched nothing checked no status at all.
check_status_fetches() {  # $1 the trusted provider's log
  local fetches
  fetches="$(grep -c ' served GET "/statuslists/{start}/{n}" 200' "$1" || true)"
  if [[ "$fetches" -ge 2 ]]; then echo "  ok    the issuer fetched the Wallet Provider's status list $fetches times"
  else echo "  FAIL  the issuer fetched the Wallet Provider's status list before and after the revocation (fetched $fetches times)"; fail=1; fi
}

# check_scaled checks, from the instances' own logs and the proxy's,
# that the production-scaled profile's requests were split: each
# instance served the endpoints its routes name, and recorded the audit
# events of what it served; and each instance swept the shared stores,
# none failing.
check_scaled() {
  local i log want
  for i in a b; do
    if [[ "$i" = a ]]; then want='"/par" 201|"/token" 200|"/nonce" 200|"/notification" 204'; else want='"/credential" 200'; fi
    log="$WORK/issuer-production-scaled-$i.log"
    served="$(grep -oE "instance=$i [A-Z]+ ($want) " "$WORK/splitproxy.log" | sed -E 's/^instance=. [A-Z]+ "([^"]+)" ([0-9]+) $/\1 \2/' | sort | uniq -c | awk '{print $2 " " $3 " x" $1}' | paste -sd, - || true)"
    echo "        instance $i served: $served"
    if [[ "$(grep -cE "instance=$i [A-Z]+ ($want) " "$WORK/splitproxy.log" || true)" -gt 0 ]] \
        && [[ "$(grep -c "instance=$i .* why=dpop-nonce-split" "$WORK/splitproxy.log" || true)" -gt 0 ]]; then
      echo "  ok    instance $i served its routes, and the nonce challenges for the other's"
    else echo "  FAIL  instance $i served none of its routes, or no nonce challenge (see splitproxy.log)"; fail=1; fi
    if grep -q 'audit: credential issuer event' "$log" && { [[ "$i" = b ]] || grep -q 'audit: authorization server event' "$log"; }; then
      echo "  ok    instance $i recorded the audit events of what it served"
    else echo "  FAIL  instance $i recorded no audit events of what it served (see $log)"; fail=1; fi
    if [[ "$(grep -c 'sweep: deleted' "$log" || true)" -gt 0 ]] && ! grep -q 'sweep: FAILED' "$log"; then
      echo "  ok    instance $i swept the shared stores $(grep -c 'sweep: deleted' "$log") times, none failing"
    else echo "  FAIL  instance $i: $(grep 'sweep: FAILED' "$log" | head -1 || echo 'never swept')"; fail=1; fi
  done
}

fail=0
for profile in $PROFILES; do
  driver_config="$WORK/driver.json"
  args=()
  case "$profile" in
    base) filter='.' ;;
    key-attestation) filter='.key_attestation.jwt_proof_requires_key_attestation = true' ;;
    deferred) filter='.deferred = true' ;;
    dpop-nonces) filter='.dpop_nonces = true' ;;
    production | production-scaled)
      if [[ "$profile" = production ]]; then prefix="" filter="$PRODUCTION_FILTER"; else prefix="scaled-" filter="$SCALED_FILTER"; fi
      driver_config="$WORK/driver-$profile.json"
      start_providers "$prefix" "$driver_config"
      args=(--arg db "$WORK/issuer-production.db" --arg key "$(sealing_key)" --arg atk "$(access_token_key)"
        --arg pg "$POSTGRES_URL" --arg nonce "$(sealing_key)"
        --rawfile wpca "$WORK/${prefix}wallet-provider/ca.pem" --rawfile wptls "$WORK/${prefix}wallet-provider/tls-cert.pem") ;;
    *) echo "unknown profile $profile" >&2; exit 2 ;;
  esac
  echo "### issuer profile: $profile"
  if [[ "$profile" = production-scaled ]]; then start_scaled "$filter" "${args[@]}"
  else start_issuer "$profile" "$filter" ${args[@]+"${args[@]}"}; fi
  # The driver prints the ok/FAIL lines; its stack traces and the
  # library's own logging go to the log.
  if ! "$DRIVER" "$driver_config" "$profile" 2>> "$WORK/driver-$profile.log"; then fail=1; fi
  stop_issuer
  case "$profile" in
    production) check_status_fetches "$WORK/wallet-provider/wallet-provider.log" ;;
    production-scaled) check_status_fetches "$WORK/scaled-wallet-provider/wallet-provider.log"; check_scaled ;;
  esac
done

if [[ "$fail" -eq 0 ]]; then echo "RESULT: every credential issued and verified, and every control refused"; else echo "RESULT: FAILED"; fi
exit "$fail"
