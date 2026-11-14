#!/usr/bin/env bash
# OID4VCgo's cmd/conformance-wallet-vp presents to the EUDI reference
# Verifier Endpoint (eu-digital-identity-wallet/eudi-srv-verifier-endpoint),
# run from its published image: SD-JWT VC and mdoc PIDs over
# direct_post.jwt, under both its haip and openid4vp profiles, and over
# the Digital Credentials API, with the verifier checking each
# credential's Token Status List and the SD-JWT VC's Type Metadata,
# fetched over TLS it verifies; then controls that must be refused,
# among them a credential of each format revoked partway through the
# run. The status lists are published by OID4VCgo's statuslist package
# (an Allocator and a Publisher, in scripts/serve -publish), as an
# issuer publishes them.
# The wallet checks the verifier's Access Certificate against its CA's
# CRL, which it fetches over https from the distribution point the
# certificate names (served by the wallet process itself, from
# setup's CA), and refuses it once the CA revokes it or has no current
# CRL.
# The wallet fetches each request as the wallet package does, verifying
# the verifier's TLS certificate; the SD-JWT VC and mdoc presentations
# run again through walletflow (its engine "walletflow"), as a wallet
# app makes them. See README.md.
#
#   interop/eudi/run-verifier.sh
#   VERIFIER_IMAGE=ghcr.io/eu-digital-identity-wallet/eudi-srv-verifier-endpoint:edge interop/eudi/run-verifier.sh
#
# Needs docker, go, jq, curl and openssl. Exits 0 only if every
# presentation is accepted and every control refused.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="${OID4VCGO_SRC:-$(cd "$HERE/../.." && pwd)}"
# v0.12.0, read from ghcr.io on 2026-11-08. Move it only after reading
# the release's changes.
VERIFIER_IMAGE="${VERIFIER_IMAGE:-ghcr.io/eu-digital-identity-wallet/eudi-srv-verifier-endpoint@sha256:b56390f2078f9ce705f2b20db86fdd52297c0a587dd4110c82f173c223a3a07f}"
PORT="${PORT:-18443}"
WALLET_PORT="${WALLET_PORT:-18444}"
SERVE_PORT="${SERVE_PORT:-18445}"
ADMIN_PORT="${ADMIN_PORT:-18446}"
CRL_PORT="${CRL_PORT:-18448}"
WORK="${WORK:-$(mktemp -d)}"
CONTAINER="${CONTAINER:-oid4vcgo-eudi-verifier}"
VERIFIER="https://localhost:$PORT"
WALLET="https://localhost:$WALLET_PORT"
# WALLET_ASSURANCE=production runs walletflow as a wallet app runs it
# instead (README.md, "The wallet at production assurance"): in a
# container on ../prodnet.sh's network, which reaches the verifier at
# VERIFIER_HOST, not loopback, and only the cases that ask that of it.
WALLET_ASSURANCE="${WALLET_ASSURANCE:-development}"
VERIFIER_HOST=localhost
CURL_TO=()
case "$WALLET_ASSURANCE" in
  development) ;;
  production)
    # shellcheck source=../prodnet.sh
    . "$HERE/../prodnet.sh"
    VERIFIER_HOST=verifier.eudi.test
    VERIFIER="https://$VERIFIER_HOST:8443"
    # The script's own requests reach the verifier on loopback by that
    # name.
    CURL_TO=(--connect-to "$VERIFIER_HOST:8443:127.0.0.1:$PORT")
    PRODNET="$CONTAINER-prodnet"
    ;;
  *) echo "WALLET_ASSURANCE is development or production, not '$WALLET_ASSURANCE'" >&2; exit 2 ;;
esac
# The keystore holds throwaway, per-run keys, under a per-run password.
KEYSTORE_PASSWORD="$(openssl rand -hex 16)"

for p in "$PORT" "$WALLET_PORT" "$SERVE_PORT" "$ADMIN_PORT" "$CRL_PORT"; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then
    echo "port $p is in use; set PORT / WALLET_PORT / SERVE_PORT / ADMIN_PORT / CRL_PORT" >&2
    exit 2
  fi
done

# The verifier reaches serve, on this host, as host.docker.internal.
# Docker Desktop resolves that name itself and reaches the host's
# loopback; on Linux it's mapped to the bridge's gateway, which serve
# then listens on.
ADD_HOST=()
SERVE_BIND=127.0.0.1
if [[ "$(uname)" = Linux ]]; then
  ADD_HOST=(--add-host host.docker.internal:host-gateway)
  SERVE_BIND="$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')"
fi
SERVE_URL="https://host.docker.internal:$SERVE_PORT"

WALLET_PID=""
SERVE_PID=""
stop_wallet() {
  if [[ "$WALLET_ASSURANCE" = production ]]; then
    docker logs "$CONTAINER-wallet" >> "$WORK/wallet.log" 2>&1 || true
    docker rm -f "$CONTAINER-wallet" >/dev/null 2>&1 || true
  fi
  if [[ -n "$WALLET_PID" ]]; then
    kill "$WALLET_PID" 2>/dev/null || true
    wait "$WALLET_PID" 2>/dev/null || true
    WALLET_PID=""
  fi
}
cleanup() {
  stop_wallet
  if [[ -n "$SERVE_PID" ]]; then kill "$SERVE_PID" 2>/dev/null || true; fi
  docker logs "$CONTAINER" > "$WORK/verifier.log" 2>&1 || true
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  if [[ -n "${PRODNET:-}" ]]; then prodnet_remove "$PRODNET"; fi
}
trap cleanup EXIT

echo "work dir  $WORK"
echo "wallet    $SRC, commit $(git -C "$SRC" rev-parse HEAD 2>/dev/null || echo unknown)"
echo "verifier  $VERIFIER_IMAGE"

(cd "$SRC" && go build -o "$WORK/wallet" ./cmd/conformance-wallet-vp \
  && go build -o "$WORK/serve" ./interop/eudi/scripts/serve \
  && go run ./interop/eudi/scripts/setup -out "$WORK" -serve-url "$SERVE_URL" -verifier-curve P-521 -crl-host "localhost:$CRL_PORT" \
    -verifier-host "$VERIFIER_HOST")
if [[ "$WALLET_ASSURANCE" = production ]]; then
  prodnet_build "$SRC" "$WORK" ./cmd/conformance-wallet-vp
  prodnet_create "$PRODNET"
fi
cd "$WORK"
# serve publishes the status lists as an issuer does: an Allocator hands
# each credential its index and keeps its status, and a Publisher signs
# the list from it on each fetch, by the credential's issuer (the SD-JWT
# VC's key and certificate, the mdoc's Document Signer). Its admin
# listener is the issuer's side: allocate an index, change a status.
./serve -dir . -addr "$SERVE_BIND:$SERVE_PORT" -publish -admin "127.0.0.1:$ADMIN_PORT" > serve.log 2>&1 &
SERVE_PID=$!
ADMIN="http://127.0.0.1:$ADMIN_PORT"
for _ in $(seq 1 50); do
  if curl -s -o /dev/null --max-time 1 -X POST "$ADMIN/status"; then break; fi
  sleep 0.2
done
# allocate prints a fresh index of list $1 (jwt or cwt).
allocate() { curl -sSf --max-time 10 -X POST "$ADMIN/allocate?list=$1" | jq -er '.idx'; }
# set_status sets index $2 of list $1 to status $3, as the issuer
# revokes (INVALID) or suspends a credential.
set_status() {
  curl -sSf --max-time 10 -X POST -H 'Content-Type: application/json' \
    -d "$(jq -cn --arg l "$1" --argjson i "$2" --arg s "$3" '{list: $l, idx: $i, status: $s}')" "$ADMIN/status" >/dev/null
}
# Each fixture credential its own index, valid; the controls below
# revoke credentials of their own.
for format in sdjwt:jwt mdoc:cwt; do
  idx="$(allocate "${format#*:}")"
  jq --argjson idx "$idx" '.status_list_idx = $idx' "wallet-${format%%:*}.json" > tmp.json && mv tmp.json "wallet-${format%%:*}.json"
done
# The verifier trusts serve's CA through the image's ca-certificates
# buildpack, which adds each certificate in a binding of that type to
# the JVM's trust store.
mkdir -p bindings/serve-ca
echo ca-certificates > bindings/serve-ca/type
cp serve-ca.pem bindings/serve-ca/serve-ca.pem
openssl pkcs12 -export -inkey verifier-key.pem -in verifier-chain.pem -name access_certificate \
  -passout "pass:$KEYSTORE_PASSWORD" -out keystore.p12
chmod 644 keystore.p12
# The verifier's x509_hash client_id: the Access Certificate's hash.
CLIENT_ID_HASH="$(openssl x509 -in verifier-chain.pem -outform DER | openssl dgst -sha256 -binary \
  | openssl base64 -A | tr '+/' '-_' | tr -d '=')"

# The image's buildpack caps direct memory at 10 MB, which TLS in the
# JVM soon exhausts (OutOfDirectMemoryError): JAVA_TOOL_OPTIONS raises
# it. The PID in both formats is classified as a PID; the verifier
# refuses a credential it can't classify. No intended uses are
# configured: each transaction carries registration-certificate.jws
# instead. Status checks are on (the default); Type Metadata is
# required for every SD-JWT VC, resolved from serve and checked against
# the credential's vct#integrity. The self-signed profile, which would
# make the verifier's HTTP client trust any certificate, stays off. It
# signs its Request Objects ES512 with a P-521 Access Certificate, as
# its own docker-compose configures it.
CLASSIFICATIONS='{"pid":{"vcts":["urn:eudi:pid:1"],"docTypes":["eu.europa.ec.eudi.pid.1"]},"qeaa":{"vcts":[],"docTypes":[]},"pubeaa":{"vcts":[],"docTypes":[]},"eaa":[]}'
start_verifier() {  # $1 the Client Identifier Prefix, $2 the client_id without it
  local prefix="$1" original="$2"
  if docker inspect "$CONTAINER" >/dev/null 2>&1; then
    docker logs "$CONTAINER" >> "$WORK/verifier.log" 2>&1 || true
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  fi
  docker run -d --name "$CONTAINER" --platform linux/amd64 -p "127.0.0.1:$PORT:8443" ${ADD_HOST[@]+"${ADD_HOST[@]}"} \
    -v "$WORK:/certs:ro" -v "$WORK/bindings:/bindings:ro" -e SERVICE_BINDING_ROOT=/bindings \
    -e SERVER_PORT=8443 -e SERVER_SSL_ENABLED=true \
    -e SERVER_SSL_CERTIFICATE=file:/certs/tls-cert.pem -e SERVER_SSL_CERTIFICATE_PRIVATE_KEY=file:/certs/tls-key.pem \
    -e JAVA_TOOL_OPTIONS=-XX:MaxDirectMemorySize=128M \
    -e VERIFIER_VALIDATION_STATUSCHECK_ENABLED=true \
    -e VERIFIER_VALIDATION_SDJWTVC_TYPEMETADATA_POLICY=always_required \
    -e VERIFIER_VALIDATION_SDJWTVC_TYPEMETADATA_RESOLUTION_VCTS_0_VCT=urn:eudi:pid:1 \
    -e VERIFIER_VALIDATION_SDJWTVC_TYPEMETADATA_RESOLUTION_VCTS_0_URL="$SERVE_URL/type-metadata/pid" \
    -e VERIFIER_VALIDATION_SDJWTVC_TYPEMETADATA_RESOLUTION_INTEGRITY_ENABLED=true \
    -e VERIFIER_PUBLICURL="$VERIFIER" \
    -e VERIFIER_CLIENTIDPREFIX="$prefix" -e VERIFIER_ORIGINALCLIENTID="$original" \
    -e VERIFIER_INTENDEDUSES= -e VERIFIER_ATTESTATIONCLASSIFICATIONS="$CLASSIFICATIONS" \
    -e VERIFIER_ACCESS_CERTIFICATE_SIGNING_ALGORITHM=ES512 \
    -e VERIFIER_ACCESS_CERTIFICATE_KEYSTORE=file:///certs/keystore.p12 -e VERIFIER_ACCESS_CERTIFICATE_KEYSTORE_TYPE=pkcs12 \
    -e VERIFIER_ACCESS_CERTIFICATE_KEYSTORE_PASSWORD="$KEYSTORE_PASSWORD" \
    -e VERIFIER_ACCESS_CERTIFICATE_ALIAS=access_certificate -e VERIFIER_ACCESS_CERTIFICATE_PASSWORD="$KEYSTORE_PASSWORD" \
    "$VERIFIER_IMAGE" >/dev/null
  for _ in $(seq 1 150); do
    if docker logs "$CONTAINER" 2>&1 | grep -q 'Started VerifierEndpointApplication'; then break; fi
    if [[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER")" != true ]]; then break; fi
    sleep 2
  done
  if ! docker logs "$CONTAINER" 2>&1 | grep -q 'Started VerifierEndpointApplication'; then
    docker logs "$CONTAINER" 2>&1 | grep -E 'APPLICATION FAILED|Reason|Caused by' | head -5 >&2 || true
    echo "the verifier did not start; see $WORK/verifier.log" >&2
    exit 2
  fi
  if [[ "$WALLET_ASSURANCE" = production ]]; then prodnet_attach "$PRODNET" "$CONTAINER" "$VERIFIER_HOST"; fi
}
start_verifier x509_hash "$CLIENT_ID_HASH"

# The wallet verifies the verifier's TLS certificate, which setup makes
# self-signed for localhost, against TLS_ANCHOR: its own, unless a
# control says otherwise. It checks the Access Certificate for
# revocation (verifier_crl) against the CRL its CA's distribution point
# serves, which the wallet process publishes itself (crl_publisher):
# CRL, a current one revoking nothing, unless a control says otherwise.
TLS_ANCHOR=tls-cert.pem
CRL=verifier-ca-crl.pem
start_wallet() {  # $1 the wallet config, $2 the CA it trusts for the verifier, $3 optional status list index
  local config="$1" verifier_ca="$2" idx="${3:-}"
  stop_wallet
  jq --arg addr "127.0.0.1:$WALLET_PORT" --rawfile ca "$verifier_ca" --arg idx "$idx" --rawfile tls "$TLS_ANCHOR" \
    --arg crladdr "127.0.0.1:$CRL_PORT" --rawfile crl "$CRL" --rawfile crlurl verifier-ca-crl-url.txt \
    --rawfile crlpath verifier-ca-crl-path.txt --rawfile crlissuer verifier-ca.pem \
    --rawfile crltls crl-tls-cert.pem --rawfile crlkey crl-tls-key.pem \
    '.listen_addr = $addr | .verifier_trust_anchors_pem = $ca
     | if $idx == "" then . else .status_list_idx = ($idx | tonumber) end
     | .verifier_tls_trust_anchors_pem = $tls
     | .crl_publisher = {listen_addr: $crladdr, tls_certificate_pem: $crltls, tls_private_key_pem: $crlkey,
                         crls: {($crlpath): $crl}}
     | .verifier_crl = {distribution_points: [{url: $crlurl, issuer_pem: $crlissuer}], tls_trust_anchors_pem: $crltls}' \
    "$config" > wallet.json
  if [[ "$WALLET_ASSURANCE" = production ]]; then
    # walletflow at production assurance, in its container: its own
    # client, TLS verified against TLS_ANCHOR as the system's roots, the
    # verifier's host the one it may reach at a private address.
    jq --arg host "$VERIFIER_HOST" '.assurance = "production" | .listen_addr = ":8443" | .allowed_private_hosts = [$host] | del(.verifier_tls_trust_anchors_pem)' \
      wallet.json > wallet-production.json
    prodnet_start "$PRODNET" "$WORK" "$TLS_ANCHOR" "$CONTAINER-wallet" "127.0.0.1:$WALLET_PORT:8443" \
      conformance-wallet-vp-linux -config /work/wallet-production.json
  else
    ./wallet -config wallet.json >> wallet.log 2>&1 &
    WALLET_PID=$!
  fi
  for _ in $(seq 1 50); do
    if curl -sk -o /dev/null --max-time 1 "$WALLET/"; then return 0; fi
    sleep 0.2
  done
  echo "the wallet did not start; see $WORK/wallet.log" >&2
  exit 2
}

# The DCQL queries for the PID, asking for two claims.
SDJWT_QUERY='{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["family_name"]},{"path":["given_name"]}]}]}'
MDOC_QUERY='{"credentials":[{"id":"pid","format":"mso_mdoc","meta":{"doctype_value":"eu.europa.ec.eudi.pid.1"},"claims":[{"path":["eu.europa.ec.eudi.pid.1","family_name"]},{"path":["eu.europa.ec.eudi.pid.1","given_name"]}]}]}'
# One the wallet holds nothing for.
UNHELD_QUERY='{"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},"claims":[{"path":["org.iso.18013.5.1","family_name"]}]}]}'

fail=0
ok() { local what="$1"; echo "  ok    $what"; }
bad() { local what="$1"; echo "  FAIL  $what"; fail=1; }

# init_transaction writes the verifier's answer to init.json and sets TID.
init_transaction() {  # $1 dcql, $2 profile, $3 issuer chain file, $4 request_uri_method
  local dcql="$1" profile="$2" chain="$3" method="$4"
  jq -n --argjson q "$dcql" --arg profile "$profile" --rawfile chain "$chain" --arg method "$method" \
    --rawfile rc registration-certificate.jws --arg redirect "$VERIFIER/public/css/style.css?response_code={RESPONSE_CODE}" \
    '{dcql_query: $q, nonce: ("n-" + (now | tostring)), jar_mode: "by_reference", request_uri_method: $method,
      response_mode: "direct_post.jwt", profile: $profile, issuer_chain: $chain,
      registration_certificate: $rc, wallet_response_redirect_uri_template: $redirect}' > init-request.json
  curl -sk "${CURL_TO[@]+"${CURL_TO[@]}"}" --max-time 30 -X POST -H 'Content-Type: application/json' -d @init-request.json \
    "$VERIFIER/ui/presentations" > init.json
  TID="$(jq -r '.transaction_id // empty' init.json)"
  [[ -n "$TID" ]] || { echo "        the verifier refused the transaction: $(cat init.json)"; return 1; }
}

# authorize hands the wallet the request, as a same-device launch would.
authorize() {  # $1 output file, $2 optional client_id
  local out="$1" client_id="${2:-}" q
  q="$(jq -r --arg cid "$client_id" \
    '"client_id=" + ((if $cid == "" then .client_id else $cid end) | @uri) + "&request_uri=" + (.request_uri | @uri) + "&request_uri_method=" + .request_uri_method' init.json)"
  curl -sk --max-time 60 -o "$out" "$WALLET/authorize?$q" || true
}

result() {  # $1 output file, $2 optional response_code
  local out="$1" code="${2:-}"
  curl -sk "${CURL_TO[@]+"${CURL_TO[@]}"}" --max-time 30 -o "$out" "$VERIFIER/ui/presentations/$TID${code:+?response_code=$code}" || true
}

events() {
  curl -sk "${CURL_TO[@]+"${CURL_TO[@]}"}" --max-time 30 "$VERIFIER/ui/presentations/$TID/events" \
    | jq -r '.events[]? | "        event: " + .event + (if .cause then ": " + (.cause | tostring | .[0:300]) else "" end)' || true
}

# invalid_vp_token reports whether the verifier refused the transaction's
# vp_token, as the wallet posted it, for a cause containing $1: its
# events say why, and the wallet saw the refusal. A transaction the
# wallet never answered, or one refused for anything else, isn't.
invalid_vp_token() {  # $1 what the cause must contain, $2 the wallet's output
  local want="$1" out="$2"
  curl -sk "${CURL_TO[@]+"${CURL_TO[@]}"}" --max-time 30 -o "events-$TID.json" "$VERIFIER/ui/presentations/$TID/events" || true
  grep -q 'wallet: verifier rejected the authorization response: status 400 InvalidVpToken' "$out" \
    && jq -e --arg want "$want" '[.events[]? | select(.event == "Wallet failed to post response")
      | .cause | tostring | select(startswith("vp_token is not valid: ") and contains($want))] | length >= 1' \
      "events-$TID.json" >/dev/null 2>&1
}

# present runs one presentation, which must be accepted: the wallet
# follows the redirect, and the verifier releases the vp_token for its
# response_code.
present() {  # $1 label, $2 dcql, $3 profile, $4 issuer chain file, $5 request_uri_method
  local name="$1" dcql="$2" profile="$3" chain="$4" method="$5"
  echo "== $name"
  init_transaction "$dcql" "$profile" "$chain" "$method" || { bad "$name: transaction initialized"; return; }
  authorize "wallet-$name.txt"
  local code
  code="$(grep -oE 'response_code=[A-Za-z0-9-]+' "wallet-$name.txt" | head -1 | cut -d= -f2 || true)"
  if [[ -n "$code" ]]; then ok "the wallet presented and followed the redirect"
  else bad "the wallet presented ($(head -c 300 "wallet-$name.txt"))"; events; return; fi
  result "result-$name.json" "$code"
  if jq -e '.vp_token.pid | length == 1' "result-$name.json" >/dev/null 2>&1; then ok "the verifier accepted the vp_token"
  else bad "the verifier accepted the vp_token ($(head -c 300 "result-$name.json"))"; events; fi
}

# refused runs one presentation the verifier must refuse, for a cause
# containing $4.
refused() {  # $1 label, $2 dcql, $3 issuer chain file, $4 the cause
  local name="$1" dcql="$2" chain="$3" want="$4"
  if init_transaction "$dcql" haip "$chain" get; then
    authorize "wallet-$name.txt"
    result "result-$name.json"
    if jq -e '.vp_token' "result-$name.json" >/dev/null 2>&1; then bad "the verifier accepted it"
    elif invalid_vp_token "$want" "wallet-$name.txt"; then ok "the verifier refused it: $want"
    else bad "the verifier refused it for $want ($(head -c 200 "wallet-$name.txt" | tr -s '\n' ' '))"; events; fi
  else bad "transaction initialized"; fi
}

# The production run: walletflow at production assurance presents both
# formats by each request_uri_method, x509_hash and x509_san_dns, and
# refuses what the development run's walletflow-relevant controls show
# it refusing. Each control differs from a presentation that passes in
# the one thing it names.
if [[ "$WALLET_ASSURANCE" = production ]]; then
  # present_production is present, checking walletflow answered.
  present_production() {  # present's arguments
    local name="$1"
    present "$@"
    if grep -q 'walletflow answered pid\.' "wallet-$name.txt"; then ok "walletflow answered the query, at production assurance"
    else bad "walletflow answered the query"; fi
  }
  # refused_production runs a transaction for the query, which the
  # wallet must refuse before answering, for $2: walletflow's error,
  # REQUEST_URI in it the transaction's request_uri.
  refused_production() {  # $1 label, $2 why, $3 optional client_id to launch with
    local name="$1" want="$2" client_id="${3:-}"
    echo "== production control: $name"
    if init_transaction "$SDJWT_QUERY" haip issuer-ca.pem get; then
      want="walletflow: presentation request: ${want//REQUEST_URI/$(jq -r '.request_uri' init.json)}"
      authorize "$name.txt" "$client_id"
      result "$name.json"
      if jq -e '.vp_token != null' "$name.json" >/dev/null 2>&1; then bad "the wallet presented"
      elif grep -qF "$want" "$name.txt"; then ok "the wallet refused: $want"
      else bad "the wallet refused, for $want ($(head -c 300 "$name.txt" | tr -s '\n' ' '))"; fi
    else bad "transaction initialized"; fi
  }
  for format in sdjwt mdoc; do
    jq '.engine = "walletflow"' "wallet-$format.json" > "wallet-$format-walletflow.json"
  done
  start_wallet wallet-sdjwt-walletflow.json verifier-ca.pem
  present_production production-sdjwt-haip "$SDJWT_QUERY" haip issuer-ca.pem get
  present_production production-sdjwt-haip-post "$SDJWT_QUERY" haip issuer-ca.pem post
  refused_production production-mismatch \
    "wallet: parse authorization request: client_id \"x509_hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\" does not match x5c leaf's own x509_hash" \
    "x509_hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  start_wallet wallet-mdoc-walletflow.json verifier-ca.pem
  present_production production-mdoc-haip "$MDOC_QUERY" haip iaca.pem get
  present_production production-mdoc-haip-post "$MDOC_QUERY" haip iaca.pem post

  UNTRUSTED='wallet: parse authorization request: untrusted verifier: wallet: verifier certificate: '
  start_wallet wallet-sdjwt-walletflow.json other-ca.pem
  refused_production production-untrusted-verifier \
    "${UNTRUSTED}certchain: certificate chain does not verify against a trusted root: x509: certificate signed by unknown authority"
  CRL=verifier-ca-crl-revoking.pem start_wallet wallet-sdjwt-walletflow.json verifier-ca.pem
  refused_production production-revoked-verifier \
    "${UNTRUSTED}certchain: revocation: no verified path passes it: certrevocation: certificate is revoked"
  CRL=verifier-ca-crl-expired.pem start_wallet wallet-sdjwt-walletflow.json verifier-ca.pem
  refused_production production-no-crl-verifier \
    "${UNTRUSTED}certchain: revocation: no verified path passes it: certchain: revocation couldn't be decided: certrevocation: no current CRL from the certificate's issuer"
  # The verifier's TLS certificate, which walletflow's client checks
  # against the system's roots: here another CA's.
  TLS_ANCHOR=other-ca.pem start_wallet wallet-sdjwt-walletflow.json verifier-ca.pem
  refused_production production-untrusted-tls \
    'wallet: fetch authorization request: fetch request_uri: fapihttp: Get "REQUEST_URI": tls: failed to verify certificate: x509: certificate signed by unknown authority'

  echo "== production: the verifier restarted with client_id x509_san_dns:$VERIFIER_HOST"
  start_verifier x509_san_dns "$VERIFIER_HOST"
  jq '.accept_x509_san_dns = true | .engine = "walletflow"' wallet-sdjwt.json > wallet-sdjwt-san-dns-walletflow.json
  start_wallet wallet-sdjwt-san-dns-walletflow.json verifier-ca.pem
  for method in get post; do
    present_production "production-sdjwt-san-dns-$method" "$SDJWT_QUERY" openid4vp issuer-ca.pem "$method"
    if jq -e --arg cid "x509_san_dns:$VERIFIER_HOST" '.client_id == $cid' init.json >/dev/null 2>&1; then ok "the request's client_id was x509_san_dns:$VERIFIER_HOST"
    else bad "the request's client_id was x509_san_dns:$VERIFIER_HOST ($(jq -r '.client_id' init.json))"; fi
  done

  if [[ "$fail" -eq 0 ]]; then echo "RESULT: every presentation at production assurance accepted, and every control refused"; else echo "RESULT: FAILED"; fi
  exit "$fail"
fi

# This control runs first, while the verifier has no Type Metadata
# cached: it checks vct#integrity only when it resolves it (see below).
echo "== control: an SD-JWT VC whose vct#integrity doesn't match its Type Metadata"
jq '.vct_integrity = "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="' wallet-sdjwt.json > wallet-sdjwt-integrity.json
start_wallet wallet-sdjwt-integrity.json verifier-ca.pem
INTEGRITY_FAILURE='{"error":"TypeMetadataResolutionFailure","description":"unable to resolve sd-jwt vc type metadata, sub-resource integrity validation fails"}'
refused sdjwt-integrity "$SDJWT_QUERY" issuer-ca.pem "$INTEGRITY_FAILURE"

start_wallet wallet-sdjwt.json verifier-ca.pem
present sdjwt-haip "$SDJWT_QUERY" haip issuer-ca.pem get
present sdjwt-openid4vp "$SDJWT_QUERY" openid4vp issuer-ca.pem get

echo "== control: the same request again, after it was answered"
authorize replay.txt
# The answered transaction's own request_uri, which the verifier no
# longer serves: the wallet's refusal names that fetch.
replayed="wallet: fetch authorization request: fetch request_uri: fapihttp: response has an unexpected status code: 400"
if grep -q 'Presented' replay.txt; then bad "the verifier served the request twice"
elif grep -qF "$replayed" replay.txt; then ok "refused: $replayed"
else bad "refused, as $replayed ($(head -c 200 replay.txt | tr -s '\n' ' '))"; fi

echo "== control: the verifier trusts an unrelated issuer CA"
if init_transaction "$SDJWT_QUERY" haip other-ca.pem get; then
  authorize untrusted-issuer.txt
  result untrusted-issuer.json
  want='{"error":"IssuerCertificateIsNotTrusted","description":"sd-jwt vc issuer certificate is not trusted"}'
  if jq -e '.vp_token' untrusted-issuer.json >/dev/null 2>&1; then bad "the verifier accepted it"
  elif invalid_vp_token "$want" untrusted-issuer.txt; then ok "the verifier refused the credential: $want"
  else bad "the verifier refused the credential for $want ($(head -c 200 untrusted-issuer.txt | tr -s '\n' ' '))"; events; fi
else bad "transaction initialized"; fi

# wallet_refused checks the wallet refused the request for $2, in its
# output $1, and that the verifier got no vp_token for it.
wallet_refused() {  # $1 the wallet's output, $2 why, $3 the verifier's result
  local out="$1" want="$2" res="$3"
  if jq -e '.vp_token' "$res" >/dev/null 2>&1; then bad "the wallet presented"
  elif grep -qF "$want" "$out"; then ok "the wallet refused: $want"
  else bad "the wallet refused, for $want ($(head -c 200 "$out" | tr -s '\n' ' '))"; fi
}

echo "== control: a launch whose client_id isn't the signed request's"
if init_transaction "$SDJWT_QUERY" haip issuer-ca.pem get; then
  authorize mismatch.txt "x509_hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  result mismatch.json
  wallet_refused mismatch.txt \
    "wallet: parse authorization request: client_id \"x509_hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\" does not match x5c leaf's own x509_hash \"$(jq -r '.client_id' init.json)\"" \
    mismatch.json
else bad "transaction initialized"; fi

echo "== control: a query for a credential the wallet doesn't hold"
if init_transaction "$UNHELD_QUERY" haip iaca.pem get; then
  authorize unheld.txt
  result unheld.json
  want='Sent error response: access_denied: wallet: present credentials: wallet: match dcql query: credential query "mdl": no held credential satisfies this credential query'
  if jq -e '.error == "access_denied"' unheld.json >/dev/null 2>&1 && grep -qF "$want" unheld.txt; then
    ok "the verifier received the wallet's access_denied, for holding no mDL"
  else bad "the verifier received access_denied, for holding no mDL ($(head -c 300 unheld.json); $(head -c 300 unheld.txt))"; events; fi
else bad "transaction initialized"; fi

# request_uri_method=post: the wallet posts its wallet_metadata, which
# the verifier reads as RFC 8414 metadata (issuer and
# response_types_supported required), and signs the Request Object for
# the aud its issuer names (OpenID4VP 1.0 §5.8, §5.10).
present sdjwt-haip-post "$SDJWT_QUERY" haip issuer-ca.pem post

# What the verifier sends that the wallet is lenient about
# (SPECIFICATIONS.md, "Known leniencies"): its response encryption
# key, whose alg OpenID4VP 1.0 §8.3 requires and the wallet doesn't.
# Asserted as v0.12.0 sends it, so a change is noticed. Read from a
# Request Object of its own transaction, which nothing answers.
ENCRYPTION_KEYS='[{"kty":"EC","crv":"P-256","alg":"ECDH-ES","kid":true}]'
echo "== observed: the verifier's response encryption key"
if init_transaction "$SDJWT_QUERY" haip issuer-ca.pem get; then
  curl -s --max-time 30 --cacert tls-cert.pem -o observed-request.jwt "$(jq -r '.request_uri' init.json)" || true
  observed="$(jq -cR 'split(".")[1] | gsub("-"; "+") | gsub("_"; "/") | @base64d | fromjson
    | [.client_metadata.jwks.keys[] | {kty, crv, alg: (.alg // "absent"), kid: has("kid")}]' observed-request.jwt 2>/dev/null || true)"
  echo "        client_metadata.jwks: ${observed:-unreadable}"
  if [[ "$observed" == "$ENCRYPTION_KEYS" ]]; then ok "as v0.12.0 sends it"
  else bad "as v0.12.0 sends it, $ENCRYPTION_KEYS: if a later image changed it, update README.md and this check"; fi
else bad "transaction initialized"; fi

echo "== control: the wallet trusts an unrelated CA for the verifier"
start_wallet wallet-sdjwt.json other-ca.pem
if init_transaction "$SDJWT_QUERY" haip issuer-ca.pem get; then
  authorize untrusted-verifier.txt
  result untrusted-verifier.json
  wallet_refused untrusted-verifier.txt \
    'wallet: parse authorization request: untrusted verifier: wallet: verifier certificate: certchain: certificate chain does not verify against a trusted root: x509: certificate signed by unknown authority' \
    untrusted-verifier.json
else bad "transaction initialized"; fi

# The Access Certificate's revocation: its CA's CRL, at the
# distribution point the certificate names, revokes it; then the CA
# publishes no current CRL (its distribution point serves one past its
# nextUpdate), so the wallet can't tell. Either way it must refuse the
# request, for that reason, before answering it.
REVOCATION_REFUSAL='wallet: parse authorization request: untrusted verifier: wallet: verifier certificate: certchain: revocation: no verified path passes it: '
echo "== control: the Access Certificate's CA revoked it"
CRL=verifier-ca-crl-revoking.pem start_wallet wallet-sdjwt.json verifier-ca.pem
if init_transaction "$SDJWT_QUERY" haip issuer-ca.pem get; then
  authorize revoked-verifier.txt
  result revoked-verifier.json
  wallet_refused revoked-verifier.txt "${REVOCATION_REFUSAL}certrevocation: certificate is revoked" revoked-verifier.json
else bad "transaction initialized"; fi

echo "== control: the Access Certificate's CA publishes no current CRL"
CRL=verifier-ca-crl-expired.pem start_wallet wallet-sdjwt.json verifier-ca.pem
if init_transaction "$SDJWT_QUERY" haip issuer-ca.pem get; then
  authorize no-crl-verifier.txt
  result no-crl-verifier.json
  wallet_refused no-crl-verifier.txt \
    "${REVOCATION_REFUSAL}certchain: revocation couldn't be decided: certrevocation: no current CRL from the certificate's issuer" \
    no-crl-verifier.json
else bad "transaction initialized"; fi

# revoked_partway presents a credential at a fresh index of list $2,
# which the verifier must accept; the issuer then sets that index to
# $5 (INVALID: revoked, or SUSPENDED), and the same credential,
# presented again, must be refused for its status, $6: the two
# presentations differ in that status alone.
revoked_partway() {  # $1 label, $2 list, $3 wallet config, $4 dcql and issuer chain, as "query chain"; $5 the status, $6 the cause
  local name="$1" list="$2" config="$3" query chain="${4#* }" status="$5" want="$6" idx
  query="${4%% *}"
  echo "== control: $name, $status partway through the run"
  idx="$(allocate "$list")"
  start_wallet "$config" verifier-ca.pem "$idx"
  present "$name-$status-before" "${!query}" haip "$chain" get
  set_status "$list" "$idx" "$status"
  echo "        the issuer set index $idx of /statuslists/$list to $status"
  refused "$name-$status" "${!query}" "$chain" "$want"
}
revoked_partway sdjwt jwt wallet-sdjwt.json "SDJWT_QUERY issuer-ca.pem" INVALID \
  '{"error":"StatusNotValid","description":"Status is not Valid"}'
revoked_partway sdjwt jwt wallet-sdjwt.json "SDJWT_QUERY issuer-ca.pem" SUSPENDED \
  '{"error":"StatusNotValid","description":"Status is not Valid"}'

echo "== an SD-JWT VC whose vct#integrity doesn't match, once the verifier has the Type Metadata cached"
# Not a control: v0.12.0 caches resolved Type Metadata by vct alone and
# checks vct#integrity only on a miss, so it's expected to accept this.
start_wallet wallet-sdjwt-integrity.json verifier-ca.pem
if init_transaction "$SDJWT_QUERY" haip issuer-ca.pem get; then
  authorize wallet-sdjwt-integrity-cached.txt
  result result-sdjwt-integrity-cached.json
  if jq -e '.vp_token' result-sdjwt-integrity-cached.json >/dev/null 2>&1; then
    echo "  note  accepted, as expected of v0.12.0 (see README.md)"
  elif invalid_vp_token "$INTEGRITY_FAILURE" wallet-sdjwt-integrity-cached.txt; then
    echo "  note  refused: the verifier now checks vct#integrity on a cache hit; make this a control"
  else
    # Refused for anything else, this presentation, the accepted one's
    # but for vct#integrity, shows something else broke.
    bad "accepted, or refused for its vct#integrity ($(head -c 200 wallet-sdjwt-integrity-cached.txt | tr -s '\n' ' '))"; events
  fi
else bad "transaction initialized"; fi

revoked_partway mdoc cwt wallet-mdoc.json "MDOC_QUERY iaca.pem" INVALID \
  "DeviceResponse contains invalid documents: Document at index '0' with docType 'eu.europa.ec.eudi.pid.1' contains the following errors: 'DocumentHasBeenRevoked'"

start_wallet wallet-mdoc.json verifier-ca.pem
present mdoc-haip "$MDOC_QUERY" haip iaca.pem get
present mdoc-openid4vp "$MDOC_QUERY" openid4vp iaca.pem get
present mdoc-haip-post "$MDOC_QUERY" haip iaca.pem post

echo "== mdoc over the Digital Credentials API"
ORIGIN=https://verifier.example.com
jq -n --argjson q "$MDOC_QUERY" --rawfile chain iaca.pem --rawfile rc registration-certificate.jws --arg origin "$ORIGIN" \
  '{dcql_query: $q, nonce: ("n-" + (now | tostring)), origin: $origin, issuer_chain: $chain,
    registration_certificate: $rc}' > init-request.json
curl -sk --max-time 30 -X POST -H 'Content-Type: application/json' -d @init-request.json \
  "$VERIFIER/ui/presentations/dc-api" > init.json
TID="$(jq -r '.transaction_id // empty' init.json)"
if [[ -z "$TID" ]]; then
  bad "transaction initialized ($(head -c 300 init.json))"
else
  jq --arg origin "$ORIGIN" '{protocol: "openid4vp-v1-signed", data: {request: .request}, origin: $origin}' init.json > dcapi-request.json
  curl -sk --max-time 60 -X POST -H 'Content-Type: application/json' -d @dcapi-request.json "$WALLET/dcapi" > dcapi-answer.json || true
  if jq -e '.result.data.response' dcapi-answer.json >/dev/null 2>&1; then
    ok "the wallet answered with an encrypted response"
    curl -sk --max-time 30 -o dcapi-post.txt -w '%{http_code}' -X POST \
      --data-urlencode "response=$(jq -r '.result.data.response' dcapi-answer.json)" \
      "$VERIFIER/ui/presentations/$TID/dc-api" > dcapi-post-status.txt || true
    result result-dcapi.json
    if jq -e '.vp_token.pid | length == 1' result-dcapi.json >/dev/null 2>&1; then ok "the verifier accepted the vp_token"
    else bad "the verifier accepted the vp_token (POST $(cat dcapi-post-status.txt): $(head -c 300 dcapi-post.txt); $(head -c 300 result-dcapi.json))"; events; fi
  else
    bad "the wallet answered ($(head -c 300 dcapi-answer.json))"
  fi
fi

# walletflow (the wallet's engine "walletflow"): the same PID
# presentations, through walletflow.Wallet.StartPresentation and
# Presentation.Respond, by GET and by request_uri_method=post, whose
# wallet_metadata is walletflow's own. Each is accepted as above: the
# wallet follows the redirect, and the verifier releases the vp_token
# for its response_code.
# present_walletflow is present, checking walletflow answered.
present_walletflow() {  # present's arguments, its label starting walletflow-
  present "$@"
  if grep -q 'walletflow answered pid\.' "wallet-$1.txt"; then ok "walletflow answered the query"
  else bad "walletflow answered the query"; fi
}
for format in sdjwt mdoc; do
  jq '.engine = "walletflow"' "wallet-$format.json" > "wallet-$format-walletflow.json"
done
start_wallet wallet-sdjwt-walletflow.json verifier-ca.pem
present_walletflow walletflow-sdjwt-haip "$SDJWT_QUERY" haip issuer-ca.pem get
present_walletflow walletflow-sdjwt-haip-post "$SDJWT_QUERY" haip issuer-ca.pem post
start_wallet wallet-mdoc-walletflow.json verifier-ca.pem
present_walletflow walletflow-mdoc-haip "$MDOC_QUERY" haip iaca.pem get
present_walletflow walletflow-mdoc-haip-post "$MDOC_QUERY" haip iaca.pem post

echo "== control: the wallet doesn't trust the verifier's TLS certificate"
TLS_ANCHOR=other-ca.pem start_wallet wallet-sdjwt.json verifier-ca.pem
if init_transaction "$SDJWT_QUERY" haip issuer-ca.pem get; then
  authorize untrusted-tls.txt
  result untrusted-tls.json
  wallet_refused untrusted-tls.txt \
    "wallet: fetch authorization request: fetch request_uri: fapihttp: Get \"$(jq -r '.request_uri' init.json)\": verifier tls certificate: x509: certificate signed by unknown authority" \
    untrusted-tls.json
else bad "transaction initialized"; fi

# x509_san_dns (OpenID4VP 1.0 §5.9.3): the verifier again, now with the
# client_id x509_san_dns:localhost, the Access Certificate's dNSName and
# its response_uri's host. HAIP 1.0 §5 has a Verifier use x509_hash, so
# these run under the verifier's openid4vp profile; the wallet accepts
# the prefix only with accept_x509_san_dns, and on a POST fetch says so
# in its wallet_metadata's client_id_prefixes_supported.
echo "== x509_san_dns: the verifier restarted with client_id x509_san_dns:localhost"
start_verifier x509_san_dns localhost
jq '.accept_x509_san_dns = true' wallet-sdjwt.json > wallet-sdjwt-san-dns.json
jq '.engine = "walletflow"' wallet-sdjwt-san-dns.json > wallet-sdjwt-san-dns-walletflow.json
for engine in "" walletflow; do
  start_wallet "wallet-sdjwt-san-dns${engine:+-$engine}.json" verifier-ca.pem
  for method in get post; do
    present${engine:+_$engine} "${engine:+$engine-}sdjwt-san-dns-$method" "$SDJWT_QUERY" openid4vp issuer-ca.pem "$method"
    if jq -e '.client_id == "x509_san_dns:localhost"' init.json >/dev/null 2>&1; then ok "the request's client_id was x509_san_dns:localhost"
    else bad "the request's client_id was x509_san_dns:localhost ($(jq -r '.client_id' init.json))"; fi
  done
done

echo "== control: an x509_san_dns request, to a wallet not opted in"
start_wallet wallet-sdjwt.json verifier-ca.pem
if init_transaction "$SDJWT_QUERY" openid4vp issuer-ca.pem get; then
  authorize san-dns-not-accepted.txt
  result san-dns-not-accepted.json
  wallet_refused san-dns-not-accepted.txt \
    "wallet: parse authorization request: client_id \"x509_san_dns:localhost\" does not match x5c leaf's own x509_hash \"x509_hash:$CLIENT_ID_HASH\"" \
    san-dns-not-accepted.json
else bad "transaction initialized"; fi

# Each check the verifier made, it made by fetching from serve: a run in
# which it fetched nothing didn't check status or Type Metadata at all.
echo "== the verifier fetched the status lists and the Type Metadata"
for path in /statuslists/jwt /statuslists/cwt /type-metadata/pid; do
  if grep -q "served GET $path\$" serve.log; then ok "fetched $path"; else bad "fetched $path"; fi
done
if grep -q 'not found' serve.log; then bad "asked serve for something else: $(grep 'not found' serve.log | head -3)"; fi

if [[ "$fail" -eq 0 ]]; then echo "RESULT: every presentation accepted, and every control refused"; else echo "RESULT: FAILED"; fi
exit "$fail"
