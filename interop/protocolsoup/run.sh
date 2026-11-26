#!/usr/bin/env bash
# OID4VCgo against ProtocolSoup (ParleSec/ProtocolSoup), its images
# built from a pinned commit, in four directions:
#
#   our wallet → ProtocolSoup's     cmd/conformance-issuer's production
#     Verifier                      setup issues SD-JWT VC and mdoc PIDs
#                                   to walletflow, attested by OID4VCgo's
#                                   Wallet Provider, which presents them
#                                   to ProtocolSoup's signed requests in
#                                   its HAIP mode (x509_hash, DCQL, the
#                                   response encrypted, direct_post.jwt)
#                                   and, the SD-JWT VC, to an x509_san_dns
#                                   request; ProtocolSoup trusts the
#                                   issuer's CAs by its trust anchor
#                                   settings
#   our wallet ← ProtocolSoup's     its HAIP configurations, by
#     issuer (issuer.sh)            pre-authorized code with a tx_code: a
#                                   Wallet Attestation and a Key
#                                   Attestation from OID4VCgo's Wallet
#                                   Provider, DPoP, encrypted requests and
#                                   responses, batches, deferred issuance
#   their wallet ← our issuer,      ProtocolSoup's wallet harness, driven
#   their wallet → our verifier     over its HTTP API (holder.sh)
#     (holder.sh)
#
# then controls that one side or the other must refuse, each by its
# reason. See README.md.
#
#   interop/protocolsoup/run.sh
#   PROTOCOLSOUP_REF=master interop/protocolsoup/run.sh
#
# PROTOCOLSOUP_REF builds ProtocolSoup's images from another commit,
# branch or tag of its repository instead of the pinned commit.
#
# Needs docker, go, jq, curl and openssl. Exits 0 only if every case
# behaves as expected.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="${OID4VCGO_SRC:-$(cd "$HERE/../.." && pwd)}"

# master on 2026-11-25. Move it only after reading what changed
# (README.md, "Moving the pin").
PROTOCOLSOUP_PIN=477f40421d73bb4f1ee6d59a94368abc3ca3bc7b
PROTOCOLSOUP_REF="${PROTOCOLSOUP_REF:-$PROTOCOLSOUP_PIN}"
[[ "$PROTOCOLSOUP_REF" =~ ^[0-9A-Za-z._/-]+$ ]] || { echo "bad PROTOCOLSOUP_REF: '$PROTOCOLSOUP_REF'" >&2; exit 2; }
PROTOCOLSOUP_REPO=https://github.com/ParleSec/ProtocolSoup.git

# ProtocolSoup's VC service (OpenID4VCI issuer and OpenID4VP verifier
# in one process) is https://localhost:$PS_PORT to the wallet, through
# serve's TLS proxy to its container's published port, $PS_INNER_PORT.
# The wallet harness's API is $HARNESS_PORT. What ProtocolSoup's
# containers reach on this host (OID4VCgo's issuer and verifiers, for
# the harness) is $HOST, which they map to this host.
HOST=oid4vcgo.test
BASE_PORT="${BASE_PORT:-21800}"
PS_PORT=$((BASE_PORT + 1)) PS_INNER_PORT=$((BASE_PORT + 2)) HARNESS_PORT=$((BASE_PORT + 3))
# OID4VCgo's issuer (named localhost, for walletflow's development
# fetcher) and its offers listener; OID4VCgo's Wallet Provider and its
# admin listener, then another one, under a CA nobody trusts.
ISSUER_PORT=$((BASE_PORT + 4)) OFFERS_PORT=$((BASE_PORT + 5))
WP_PORT=$((BASE_PORT + 6)) WP_ADMIN_PORT=$((BASE_PORT + 7))
OTHER_WP_PORT=$((BASE_PORT + 8)) OTHER_WP_ADMIN_PORT=$((BASE_PORT + 9))
# The ports holder.sh uses, as $HOST: OID4VCgo's issuer, through
# serve's tap, and its verifiers, from $VERIFIER_PORT on.
HOLDER_ISSUER_PORT=$((BASE_PORT + 10)) HOLDER_ISSUER_INNER_PORT=$((BASE_PORT + 11)) HOLDER_OFFERS_PORT=$((BASE_PORT + 12))
VERIFIER_PORT=$((BASE_PORT + 13)) # behind the tap, listening at the port 10 above
# The wallet harness's API, and two more, for controls: one whose
# attester CA nobody trusts, one trusting another CA for credentials.
UNTRUSTED_HARNESS_PORT=$((BASE_PORT + 14)) OTHER_HARNESS_PORT=$((BASE_PORT + 15))
LAST_PORT=$((BASE_PORT + 26))
WORK="${WORK:-$(mktemp -d)}"
NAME="${COMPOSE_PROJECT_NAME:-oid4vcgo-protocolsoup}"
# The client_id interop/eudi/scripts/setup-issuer registers, which the
# Wallet Provider attests the wallet as.
CLIENT_ID=oid4vcgo-eudi-interop-wallet

for p in $(seq "$PS_PORT" "$LAST_PORT"); do
  if (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then
    echo "port $p is in use; set BASE_PORT" >&2
    exit 2
  fi
done

# ProtocolSoup's containers reach this host's listeners as $HOST:
# Docker Desktop maps host-gateway to the host's loopback; on Linux
# it's the default bridge's gateway, which serve's taps then bind.
TAP_BIND=127.0.0.1
if [[ "$(uname)" = Linux ]]; then
  TAP_BIND="$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')"
fi

PIDS=()
# shellcheck disable=SC2329 # run by the EXIT trap
cleanup() {
  for pid in ${PIDS[@]+"${PIDS[@]}"}; do kill "$pid" 2>/dev/null || true; done
  for pid in ${PIDS[@]+"${PIDS[@]}"}; do wait "$pid" 2>/dev/null || true; done
  for c in vc redis wallet harness-untrusted-attester harness-other-anchors; do
    docker logs "$NAME-$c" > "$WORK/protocolsoup-$c.log" 2>&1 || true
    docker rm -f "$NAME-$c" >/dev/null 2>&1 || true
  done
  docker network rm "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "work dir      $WORK"
echo "oid4vcgo      $SRC, commit $(git -C "$SRC" rev-parse HEAD 2>/dev/null || echo unknown)"

# ProtocolSoup's images, built from $PROTOCOLSOUP_REF as its
# docker-compose.yml builds them: the VC service (cmd/server-vc, the
# OpenID4VCI and OpenID4VP plugins with the OAuth 2.0 and OIDC ones
# its authorization code grant needs) and the wallet harness. With
# PROTOCOLSOUP_IMAGES set ("VC_IMAGE WALLET_IMAGE"), those are used
# instead. With PROTOCOLSOUP_IMAGE_CACHE, a directory, images built
# for a commit are saved there (images.tar, images.txt naming them)
# and loaded from it for the same commit (the workflow caches it).
CACHE="${PROTOCOLSOUP_IMAGE_CACHE:-}"
if [[ -z "${PROTOCOLSOUP_IMAGES:-}" && -n "$CACHE" && -s "$CACHE/images.tar" ]] \
    && [[ "$(cut -d' ' -f1 "$CACHE/images.txt" 2>/dev/null)" = "protocolsoup-vc:$PROTOCOLSOUP_REF" ]]; then
  docker load -q -i "$CACHE/images.tar" >/dev/null
  PROTOCOLSOUP_IMAGES="$(cat "$CACHE/images.txt")"
fi
if [[ -z "${PROTOCOLSOUP_IMAGES:-}" ]]; then
  rm -rf "$WORK/protocolsoup-src"
  git init -q "$WORK/protocolsoup-src"
  git -C "$WORK/protocolsoup-src" fetch -q --depth 1 "$PROTOCOLSOUP_REPO" "$PROTOCOLSOUP_REF"
  git -C "$WORK/protocolsoup-src" checkout -q FETCH_HEAD
  PSOUP_COMMIT="$(git -C "$WORK/protocolsoup-src" rev-parse HEAD)"
  docker build -q -f "$WORK/protocolsoup-src/docker/Dockerfile.backend" --build-arg SERVICE_CMD=./cmd/server-vc \
    -t "protocolsoup-vc:$PSOUP_COMMIT" "$WORK/protocolsoup-src" >/dev/null
  docker build -q -f "$WORK/protocolsoup-src/docker/Dockerfile.wallet-harness" \
    -t "protocolsoup-wallet:$PSOUP_COMMIT" "$WORK/protocolsoup-src" >/dev/null
  PROTOCOLSOUP_IMAGES="protocolsoup-vc:$PSOUP_COMMIT protocolsoup-wallet:$PSOUP_COMMIT"
  if [[ -n "$CACHE" ]]; then
    mkdir -p "$CACHE"
    # shellcheck disable=SC2086 # the two image names
    docker save -o "$CACHE/images.tar" $PROTOCOLSOUP_IMAGES
    echo "$PROTOCOLSOUP_IMAGES" > "$CACHE/images.txt"
  fi
fi
read -r VC_IMAGE WALLET_IMAGE <<< "$PROTOCOLSOUP_IMAGES"
echo "protocolsoup  $PROTOCOLSOUP_REF: $VC_IMAGE $WALLET_IMAGE"

# shellcheck source=../production.sh
. "$HERE/../production.sh"
mkdir -p "$WORK/issuer-files"
build_production "$WORK" "$SRC" issuer=./cmd/conformance-issuer walletprovider=./interop/walletprovider \
  verifier=./cmd/conformance-verifier
(cd "$SRC" && go build -o "$WORK/serve" ./interop/waltid/scripts/serve \
  && go build -o "$WORK/wallet" ./interop/waltid/scripts/wallet \
  && go run ./interop/eudi/scripts/setup-issuer -out "$WORK/issuer-files" -port "$ISSUER_PORT" -offers-port "$OFFERS_PORT" \
  && go run ./interop/protocolsoup/scripts/setup -out "$WORK" -host "$HOST" \
    -attester "$(jq -r '.attester_issuer' "$WORK/issuer-files/driver.json")")
cd "$WORK"
jq -r '.issuer_ca_pem' issuer-files/driver.json > issuer-ca.pem
jq -r '.iaca_pem' issuer-files/driver.json > iaca.pem

# OID4VCgo's Wallet Providers, walletprovider.Provider over sealed
# SQLite stores as a deployment runs it: the one ProtocolSoup's issuer
# and OID4VCgo's issuer trust for Wallet Attestations and Key
# Attestations, attesting the wallet as the client OID4VCgo's issuer
# expects; and one under another CA, naming the same client.
ATTESTER="$(jq -r '.attester_issuer' issuer-files/driver.json)"
start_wallet_provider "$WORK/walletprovider" "$WORK/wallet-provider" "$WP_PORT" "$WP_ADMIN_PORT" "$CLIENT_ID" \
  -identifier "$ATTESTER" -ca-name "OID4VCgo ProtocolSoup interop Wallet Provider CA"
PIDS+=($!)
start_wallet_provider "$WORK/walletprovider" "$WORK/other-wallet-provider" "$OTHER_WP_PORT" "$OTHER_WP_ADMIN_PORT" "$CLIENT_ID" \
  -identifier "$ATTESTER" -ca-name "OID4VCgo ProtocolSoup interop untrusted Wallet Provider CA"
PIDS+=($!)
wait_ready "http://127.0.0.1:$WP_ADMIN_PORT/ready" "http://127.0.0.1:$OTHER_WP_ADMIN_PORT/ready"

# OID4VCgo's issuer, as a deployment runs it (its production setup:
# production assurance, sealed SQLite stores, jwt proofs that must
# carry a Key Attestation, DPoP nonces), its Wallet Attestations and
# Key Attestations trusted by their x5c chain to the Wallet Provider's
# CA and their status checked on its lists, fetched from loopback
# (attestation_status_allow_loopback, the one setting a deployment
# wouldn't make). Its credentials carry no status list reference:
# ProtocolSoup's Verifier fetches status lists only from public
# addresses (README finding 1), which nothing of a CI run has.
# shellcheck disable=SC2016 # jq's variables, not the shell's
jq --arg issuer "https://localhost:$ISSUER_PORT" --arg addr "127.0.0.1:$ISSUER_PORT" --arg offers "127.0.0.1:$OFFERS_PORT" \
  --arg db "$WORK/issuer.db" --arg seal "$(sealing_key)" --arg atk "$(access_token_key)" \
  --rawfile cert tls-cert.pem --rawfile tlskey tls-key.pem \
  --rawfile wpca wallet-provider/ca.pem --rawfile wptls wallet-provider/tls-cert.pem \
  '.issuer = $issuer | .listen_addr = $addr | .offers.listen_addr = $offers | del(.status_lists)
    | .tls_certificate_pem = $cert | .tls_private_key_pem = $tlskey | .dpop_nonces = true
    | .client.attester_trust_anchors_pem = $wpca | .key_attestation = {trust_anchor_pem: $wpca}
    | .production = {database_path: $db, sealing_key: $seal, access_token_signing_key_pem: $atk,
        attestation_status_tls_trust_anchors_pem: $wptls, attestation_status_allow_loopback: true}' \
  issuer-files/issuer.json > issuer.json
./issuer -config issuer.json > issuer.log 2>&1 &
PIDS+=($!)

# ProtocolSoup's VC service, as its docker-compose.yml runs its
# federation service (SHOWCASE_ENV demo, its replay stores in Redis),
# with DPoP nonces at its authorization server and its resource
# endpoints, as its hosted deployment runs, but: its base URL the TLS proxy's; its Verifier's request object
# signer setup's, under the run's CA, which OID4VCgo's wallet trusts
# for Verifiers; trusting OID4VCgo's issuer's SD-JWT VC CA and IACA
# for presentations, and the Wallet Provider's CA for the Wallet
# Attestations and Key Attestations its issuer takes. Its mdoc and
# SD-JWT VC signing keys and IACA it makes at startup, into
# protocolsoup-pki/.
mkdir -p protocolsoup-pki
docker network create "$NAME" >/dev/null
# redis:8-alpine, pinned by digest like the parties' images.
docker run -d --name "$NAME-redis" --network "$NAME" redis:8-alpine@sha256:5af80107c1eeecb484a2269b80a26d12bfa6521787da4663bd9f19f60a163483 redis-server --save '' --appendonly no >/dev/null
docker run -d --name "$NAME-vc" --network "$NAME" -p "127.0.0.1:$PS_INNER_PORT:8080" \
  -v "$WORK/protocolsoup-pki:/app/mdoc-pki" -e SHOWCASE_MDOC_PKI_PATH=/app/mdoc-pki \
  -e SHOWCASE_DPOP_NONCE_REQUIRED=true -e SHOWCASE_DPOP_RESOURCE_NONCE_REQUIRED=true \
  -e SHOWCASE_ENV=demo -e SHOWCASE_BASE_URL="https://localhost:$PS_PORT" -e OAUTH2_REPLAY_REDIS_URL="redis://$NAME-redis:6379/0" \
  -e OID4VP_X509_SANDNS_CERT_CHAIN_PEM="$(cat verifier-chain.pem)" -e OID4VP_X509_SANDNS_PRIVATE_KEY_PEM="$(cat verifier-key.pem)" \
  -e OID4VP_SD_JWT_TRUST_ANCHOR_PEM="$(cat issuer-ca.pem)" -e MDOC_IACA_ROOT_PEM="$(cat iaca.pem)" \
  -e OID4VCI_CLIENT_ATTESTATION_TRUST_ANCHOR_PEM="$(cat wallet-provider/ca.pem)" \
  -e OID4VCI_KEY_ATTESTATION_TRUST_ANCHOR_PEM="$(cat wallet-provider/ca.pem)" \
  "$VC_IMAGE" >/dev/null
./serve -dir . -proxy "127.0.0.1:$PS_PORT=http://127.0.0.1:$PS_INNER_PORT" > serve.log 2>&1 &
PIDS+=($!)

PS="https://localhost:$PS_PORT"
api() { curl -sS --max-time 30 --cacert ca.pem "$@"; }
JSON='Content-Type: application/json'
for _ in $(seq 1 120); do
  if api -o /dev/null -f "$PS/health" 2>/dev/null; then break; fi
  sleep 1
done
api -o /dev/null -f "$PS/health" || { echo "ProtocolSoup did not start; see $WORK/protocolsoup-vc.log" >&2; exit 2; }
wait_ready "https://localhost:$ISSUER_PORT/.well-known/openid-credential-issuer"
# ProtocolSoup's IACA, which signs its SD-JWT VC signer's certificate
# as well as its Document Signer's. Copied out of the container: on
# Linux the files it writes into the bind mount are root's, mode 0600.
for _ in $(seq 1 50); do
  docker cp "$NAME-vc:/app/mdoc-pki/iaca_root.pem" protocolsoup-iaca.pem 2>/dev/null && [[ -s protocolsoup-iaca.pem ]] && break
  sleep 0.2
done
[[ -s protocolsoup-iaca.pem ]] || { echo "ProtocolSoup wrote no IACA certificate; see $WORK/protocolsoup-vc.log" >&2; exit 2; }

# pace keeps the run under ProtocolSoup's rate limit, 100 requests a
# minute from one client (its core.RateLimiter, which every protocol
# endpoint is behind, keyed on X-Forwarded-For from a private peer,
# serve's proxy): once 40 requests have gone through the proxy (its
# log, a line each) since the window began, it waits for the window's
# minute to pass. A window and the next hold at most 80 and a case's.
WINDOW_START=$SECONDS WINDOW_LINES=0
pace() {
  local lines
  lines="$(wc -l < serve.log)"
  if [[ $((lines - WINDOW_LINES)) -ge 40 ]]; then
    if [[ $((SECONDS - WINDOW_START)) -lt 61 ]]; then sleep $((61 - SECONDS + WINDOW_START)); fi
    WINDOW_START=$SECONDS WINDOW_LINES="$lines"
  fi
}

fail=0
ok() { echo "  ok    $1"; }
bad() { echo "  FAIL  $1"; fail=1; }
note() { echo "  note  $1"; }

# offer is a pre-authorized code offer of OID4VCgo's issuer's
# configuration $1, by reference.
offer() {
  local config="$1"
  curl -sS --max-time 30 -X POST -H "$JSON" \
    --data "$(jq -cn --arg c "$config" '{grant: "pre-authorized_code", credential_configuration_ids: [$c], by_reference: true}')" \
    "http://127.0.0.1:$OFFERS_PORT/offers" | jq -r '.uri'
}
SDJWT="$(jq -r '.sdjwt_configuration_id' issuer-files/driver.json)" MDOC="$(jq -r '.mdoc_configuration_id' issuer-files/driver.json)"
VCT="$(jq -r '.vct' issuer-files/driver.json)" DOCTYPE="$(jq -r '.doctype' issuer-files/driver.json)" NS="$(jq -r '.namespace' issuer-files/driver.json)"
# The DCQL queries ProtocolSoup's requests carry: family_name (and the
# SD-JWT VC's birth_date) alone, so that what's disclosed shows.
SDJWT_QUERY="$(jq -cn --arg v "$VCT" '{credentials: [{id: "pid", format: "dc+sd-jwt", meta: {vct_values: [$v]},
  claims: [{path: ["family_name"]}, {path: ["birth_date"]}]}]}')"
MDOC_QUERY="$(jq -cn --arg d "$DOCTYPE" --arg n "$NS" '{credentials: [{id: "pid", format: "mso_mdoc", meta: {doctype_value: $d},
  claims: [{path: [$n, "family_name"]}]}]}')"

# request has ProtocolSoup's Verifier create a request for DCQL query
# $2, in $3 ("haip" for its HAIP mode, x509_hash; or a client_id
# prefix, x509_san_dns), response mode $4; its answer is in
# $1-request.json, and it prints the openid4vp:// link the wallet
# opens.
request() {  # $1 name, $2 query, $3 haip or a client_id prefix, $4 response mode
  local name="$1" query="$2" mode="$3" response_mode="$4"
  api -X POST -H "$JSON" --data "$(jq -cn --argjson q "$query" --arg m "$mode" --arg r "$response_mode" '
    {dcql_query: $q, response_mode: $r, request_uri_method: "post"}
    + if $m == "haip" then {profile: "haip"} else {client_id_scheme: $m} end')" "$PS/oid4vp/request/create" > "$name-request.json"
  jq -r '"openid4vp://?client_id=\(.client_id | @uri)&request_uri=\(.request_uri | @uri)&request_uri_method=\(.request_uri_method)"' "$name-request.json"
}
# present has OID4VCgo's wallet redeem an offer of configuration $2,
# attested by the Wallet Provider, and answer ProtocolSoup's request
# (as request, $3 the query, $4 the mode, $5 the response mode); the
# rest are the wallet's options. Its outcome is in $1-wallet.json,
# ProtocolSoup's verdict in $1-result.json.
present() {  # $1 name, $2 configuration, $3 query, $4 mode, $5 response mode; then the wallet's options
  local name="$1" config="$2" query="$3" mode="$4" response_mode="$5" link
  shift 5
  pace
  link="$(request "$name" "$query" "$mode" "$response_mode")"
  # -crl-set none: no CA of the run publishes a CRL.
  ./wallet -tls-ca ca.pem -issuer-ca issuer-ca.pem -mdoc-issuer-ca iaca.pem -verifier-ca ca.pem -crl-set none \
    -wallet-provider "https://localhost:$WP_PORT" -wallet-provider-tls wallet-provider/tls-cert.pem -client-id "$CLIENT_ID" \
    -offer "$(offer "$config")" -request "$link" -out "$name-wallet.json" "$@" >> "wallet-$name.log" 2>&1 \
    || echo '{"stage": "wallet", "error": "the wallet failed; see its log"}' > "$name-wallet.json"
  api "$PS/oid4vp/result/$(jq -r .request_id "$name-request.json")" > "$name-result.json" || true
}
why() {  # $1 name: the wallet's stage and error, and ProtocolSoup's verdict
  local name="$1"
  echo "wallet $(jq -c '{stage, error, tampered: (.tampered.changed // null)} | with_entries(select(.value != null))' "$name-wallet.json" 2>/dev/null | cut -c1-300)," \
    "verifier $(jq -c '{status, policy: .result.policy | {code, reason_codes, reasons}}' "$name-result.json" 2>/dev/null | cut -c1-400)"
}
# accepted reports whether ProtocolSoup accepted presentation $1: the
# wallet done, the verifier's policy allowed, its nonce, audience,
# expiry and holder binding each validated.
accepted() {
  local name="$1"
  jq -e '.stage == "done"' "$name-wallet.json" >/dev/null 2>&1 \
    && jq -e '.status == "completed" and .result.policy.allowed == true and .result.nonce_validated and .result.audience_validated
      and .result.expiry_validated and .result.holder_binding_verified' "$name-result.json" >/dev/null 2>&1
}
disclosed() {  # $1 name: what ProtocolSoup says was disclosed
  jq -c '.result.credential_evidence.disclosed_claims // .result.credential_evidence | keys? // .' "$1-result.json" 2>/dev/null | cut -c1-200
}

echo "### OID4VCgo's issuer → OID4VCgo's wallet → ProtocolSoup's Verifier"
# The SD-JWT VC PID: to ProtocolSoup's HAIP mode (x509_hash, the
# response encrypted, its enc values A128GCM and A256GCM), to its
# general profile's x509_san_dns client (direct_post.jwt, the one
# response mode walletflow answers).
for c in "sdjwt haip direct_post.jwt" "sdjwt-san-dns x509_san_dns direct_post.jwt -accept-x509-san-dns"; do
  read -r name mode response_mode flag <<< "$c"
  present "$name" "$SDJWT" "$SDJWT_QUERY" "$mode" "$response_mode" ${flag:+"$flag"}
  if accepted "$name" && jq -e '(.result.credential_evidence.disclosed_claims | keys) == ["birth_date", "family_name"]' "$name-result.json" >/dev/null; then
    ok "$name: presented to a signed $(jq -r '.client_id | split(":")[0]' "$name-request.json") request ($(jq -r .profile "$name-request.json") profile, $response_mode); ProtocolSoup verified it, its issuer by its chain, disclosed $(disclosed "$name")"
  else bad "$name: $(why "$name")"; fi
done
# Its response encryption key, in each encrypted request's
# client_metadata (README, "What ProtocolSoup sends").
echo "        observed: $(jq -c -s '[.[].observed.verifier_jwks]' sdjwt-wallet.json sdjwt-san-dns-wallet.json)"
if jq -s -e 'all(.[].observed.verifier_jwks; length == 1 and .[0].alg == "ECDH-ES" and (.[0].kid | length > 0))' \
    sdjwt-wallet.json sdjwt-san-dns-wallet.json >/dev/null; then
  ok "observed: ProtocolSoup's response encryption JWK carries alg ECDH-ES and a kid"
else bad "observed: ProtocolSoup's response encryption JWK changed: $(jq -c -s '[.[].observed.verifier_jwks]' sdjwt-wallet.json sdjwt-san-dns-wallet.json)"; fi

# refused checks ProtocolSoup refused presentation $1: the wallet's
# response delivered (ProtocolSoup answers a refused one 200 too, its
# verdict kept for GET /oid4vp/result), its policy denied, its first
# reason code $2, that reason containing $3.
refused() {  # $1 name, $2 reason code, $3 in the reason, $4 what the control is
  local name="$1" code="$2" reason="$3" what="$4"
  if jq -e '.stage == "done" or .stage == "response"' "$name-wallet.json" >/dev/null 2>&1 \
      && jq -e --arg c "$code" --arg r "$reason" '.status == "completed" and .result.policy.allowed == false
        and .result.policy.reason_codes[0] == $c and (.result.policy.reasons[0] | contains($r))' "$name-result.json" >/dev/null 2>&1; then
    ok "control: $what: ProtocolSoup refuses it ($(jq -r '.result.policy.reason_codes | join(",")' "$name-result.json"): $(jq -r '.result.policy.reasons[0]' "$name-result.json" | cut -c1-200))"
  else bad "control: $what: $(why "$name")"; fi
}

# Negative presentations: the wallet's transport changes the SD-JWT VC
# presentation on its way to ProtocolSoup (interop/waltid/scripts/
# wallet's -tamper, tamper.go): it replaces the request object's
# response encryption key with its own, signs the request again with
# ProtocolSoup's signer key (setup's verifier-key.pem), decrypts the
# wallet's response, makes its one change and encrypts it again to
# ProtocolSoup. The relay case changes nothing else and must be
# accepted; each other case differs from it in its one change.
present tamper-relay "$SDJWT" "$SDJWT_QUERY" haip direct_post.jwt -tamper relay -verifier2-key verifier-key.pem
if accepted tamper-relay && jq -e '.tampered.changed == "nothing"' tamper-relay-wallet.json >/dev/null 2>&1; then
  ok "sdjwt, relayed through the transport's own key and changed in nothing else: ProtocolSoup verified it"
else bad "sdjwt, relayed: $(why tamper-relay)"; fi
for c in "nonce|nonce_mismatch|kb-jwt nonce mismatch|Key Binding JWT's nonce" \
  "aud|audience_mismatch|kb-jwt audience mismatch|Key Binding JWT's aud" \
  "disclosure|disclosure_invalid|disclosure digest for claim \"{claim}\" is not referenced by the issuer payload|disclosure's value (its digest no longer the Issuer's)" \
  "issuer|credential_signature_invalid|external SD-JWT issuer trust validation failed|Issuer-signed JWT signed again under a self-signed certificate, which"; do
  IFS='|' read -r mode code reason what <<< "$c"
  present "tamper-$mode" "$SDJWT" "$SDJWT_QUERY" haip direct_post.jwt -tamper "$mode" -verifier2-key verifier-key.pem
  # The transport changes the presentation's first disclosure, whose
  # claim depends on the wallet's order: the reason must name that one.
  claim=$(jq -r '.tampered.changed // "" | capture("^disclosure (?<c>.+)'"'"'s value$").c // ""' "tamper-$mode-wallet.json" 2>/dev/null || true)
  reason=${reason//\{claim\}/$claim}
  refused "tamper-$mode" "$code" "$reason" "the $what another"
done

# The wallet's own refusal: it trusts an unrelated CA for Verifiers.
present untrusted-verifier "$SDJWT" "$SDJWT_QUERY" haip direct_post.jwt -verifier-ca other-ca.pem
if jq -e '.stage == "request" and (.error | contains("untrusted verifier: wallet: verifier certificate: certchain: certificate chain does not verify against a trusted root"))' \
    untrusted-verifier-wallet.json >/dev/null 2>&1 && jq -e '.status == "pending"' untrusted-verifier-result.json >/dev/null 2>&1; then
  ok "control: the wallet trusts an unrelated Verifier CA: it refuses ProtocolSoup's request, for its signer's chain, and presents nothing"
else bad "control: an untrusted Verifier: $(why untrusted-verifier)"; fi

# The Digital Credentials API (OpenID4VP 1.0 Appendix A), which
# ProtocolSoup's Verifier takes through its API alone (dc_api.jwt):
# the run stands in for the page and the browser, as with EUDIPLO
# (interop/eudiplo/README.md, "The Digital Credentials API"). It has
# ProtocolSoup sign a HAIP request for the page's origin, hands the
# wallet what navigator.credentials.get() hands the platform
# ({protocol, data, origin}; the wallet's -dcapi), and posts what the
# wallet hands back to ProtocolSoup's response endpoint with the
# request_id, as its page would.
ORIGIN=https://shop.protocolsoup.test
dcapi() {  # $1 name, $2 the origin the wallet is handed
  local name="$1" origin="$2"
  pace
  api -X POST -H "$JSON" --data "$(jq -cn --argjson q "$SDJWT_QUERY" --arg o "$ORIGIN" \
    '{dcql_query: $q, response_mode: "dc_api.jwt", profile: "haip", origin: $o}')" "$PS/oid4vp/request/create" > "$name-request.json"
  jq --arg o "$origin" '{protocol: "openid4vp-v1-signed", data: {request: .request}, origin: $o}' "$name-request.json" > "$name-dcapi.json"
  ./wallet -tls-ca ca.pem -issuer-ca issuer-ca.pem -mdoc-issuer-ca iaca.pem -verifier-ca ca.pem -crl-set none \
    -wallet-provider "https://localhost:$WP_PORT" -wallet-provider-tls wallet-provider/tls-cert.pem -client-id "$CLIENT_ID" \
    -offer "$(offer "$SDJWT")" -dcapi "$name-dcapi.json" -out "$name-wallet.json" >> "wallet-$name.log" 2>&1 \
    || echo '{"stage": "wallet", "error": "the wallet failed; see its log"}' > "$name-wallet.json"
  if jq -e '.stage == "done"' "$name-wallet.json" >/dev/null 2>&1; then
    api -o "$name-post.json" -X POST -H "$JSON" \
      --data "$(jq -c --arg id "$(jq -r .request_id "$name-request.json")" '.dcapi.data + {request_id: $id}' "$name-wallet.json")" "$PS/oid4vp/response" || true
  fi
  api "$PS/oid4vp/result/$(jq -r .request_id "$name-request.json")" > "$name-result.json" || true
}
dcapi dcapi "$ORIGIN"
if accepted dcapi && jq -e '(.result.credential_evidence.disclosed_claims | keys) == ["birth_date", "family_name"]' dcapi-result.json >/dev/null 2>&1; then
  ok "dcapi: presented over the DC API (openid4vp-v1-signed, dc_api.jwt) to a signed x509_hash HAIP request for $ORIGIN; ProtocolSoup verified it, disclosed $(disclosed dcapi)"
else bad "dcapi: $(why dcapi) $(head -c 200 dcapi-post.json 2>/dev/null)"; fi
# The wallet handed another origin than the request's expected_origins
# names: it refuses the request, and answers nothing.
dcapi dcapi-origin https://other.protocolsoup.test
if jq -e '.stage == "request" and (.error | contains("expected_origins"))' dcapi-origin-wallet.json >/dev/null 2>&1 \
    && jq -e '.status == "pending"' dcapi-origin-result.json >/dev/null 2>&1; then
  ok "control: a DC API request from another origin than its expected_origins: the wallet refuses it ($(jq -r .error dcapi-origin-wallet.json | cut -c1-160))"
else bad "control: a DC API request from another origin: $(why dcapi-origin)"; fi

# Known gaps of ProtocolSoup's, noted rather than failed; the run
# fails once either changes (README.md).
# Finding 2: ProtocolSoup's mdoc verification requires a Document
# Signer certificate to carry Basic Constraints (CA=false), which ISO/IEC
# 18013-5 Annex B's Document Signer profile doesn't include, and
# OID4VCgo's issuer's leaves out: the mdoc PID is refused at its issuer
# check, the response decrypted and its DeviceResponse decoded.
present mdoc "$MDOC" "$MDOC_QUERY" haip direct_post.jwt
if jq -e '.stage == "done"' mdoc-wallet.json >/dev/null 2>&1 \
    && jq -e '.result.policy.reason_codes == ["device_auth_invalid"]
      and any(.result.policy.reasons[]; contains("document-signer certificate must have Basic Constraints CA=false"))' mdoc-result.json >/dev/null 2>&1; then
  note "ProtocolSoup refuses the mdoc PID, its Document Signer certificate without Basic Constraints (README finding 2): $(jq -r '.result.policy.reasons[0]' mdoc-result.json | cut -c1-200)"
else bad "README finding 2 has changed: the mdoc PID: $(why mdoc)"; fi
# shellcheck source=issuer.sh
. "$HERE/issuer.sh"
# shellcheck source=holder.sh
. "$HERE/holder.sh"

if [[ "$fail" -eq 0 ]]; then echo "RESULT: every case behaved as expected"; else echo "RESULT: FAILED (logs in $WORK)"; fi
exit "$fail"
