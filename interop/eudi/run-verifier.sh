#!/usr/bin/env bash
# OID4VCgo's cmd/conformance-wallet-vp presents to the EUDI reference
# Verifier Endpoint (eu-digital-identity-wallet/eudi-srv-verifier-endpoint),
# run from its published image: SD-JWT VC and mdoc PIDs over
# direct_post.jwt, under both its haip and openid4vp profiles, and over
# the Digital Credentials API; then
# controls that must be refused. See README.md.
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
WORK="${WORK:-$(mktemp -d)}"
CONTAINER=oid4vcgo-eudi-verifier
VERIFIER="https://localhost:$PORT"
WALLET="https://localhost:$WALLET_PORT"
# The keystore holds throwaway, per-run keys.
KEYSTORE_PASSWORD=interop

for p in "$PORT" "$WALLET_PORT"; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then
    echo "port $p is in use; set PORT / WALLET_PORT" >&2
    exit 2
  fi
done

WALLET_PID=""
stop_wallet() {
  if [ -n "$WALLET_PID" ]; then
    kill "$WALLET_PID" 2>/dev/null || true
    wait "$WALLET_PID" 2>/dev/null || true
    WALLET_PID=""
  fi
}
cleanup() {
  stop_wallet
  docker logs "$CONTAINER" > "$WORK/verifier.log" 2>&1 || true
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "work dir  $WORK"
echo "wallet    $SRC, commit $(git -C "$SRC" rev-parse HEAD 2>/dev/null || echo unknown)"
echo "verifier  $VERIFIER_IMAGE"

(cd "$SRC" && go build -o "$WORK/wallet" ./cmd/conformance-wallet-vp && go run ./interop/eudi/scripts/setup -out "$WORK")
cd "$WORK"
openssl pkcs12 -export -inkey verifier-key.pem -in verifier-chain.pem -name access_certificate \
  -passout "pass:$KEYSTORE_PASSWORD" -out keystore.p12
chmod 644 keystore.p12
# The verifier's x509_hash client_id: the Access Certificate's hash.
CLIENT_ID_HASH="$(openssl x509 -in verifier-chain.pem -outform DER | openssl dgst -sha256 -binary \
  | openssl base64 -A | tr '+/' '-_' | tr -d '=')"

# The image's buildpack caps direct memory at 10 MB, which TLS in the
# JVM soon exhausts (OutOfDirectMemoryError): JAVA_TOOL_OPTIONS raises
# it. The PID in both formats is classified as a PID; the verifier refuses
# a credential it can't classify. No intended uses are configured: each
# transaction carries registration-certificate.jws instead.
CLASSIFICATIONS='{"pid":{"vcts":["urn:eudi:pid:1"],"docTypes":["eu.europa.ec.eudi.pid.1"]},"qeaa":{"vcts":[],"docTypes":[]},"pubeaa":{"vcts":[],"docTypes":[]},"eaa":[]}'
docker run -d --name "$CONTAINER" --platform linux/amd64 -p "127.0.0.1:$PORT:8443" -v "$WORK:/certs:ro" \
  -e SERVER_PORT=8443 -e SERVER_SSL_ENABLED=true \
  -e SERVER_SSL_CERTIFICATE=file:/certs/tls-cert.pem -e SERVER_SSL_CERTIFICATE_PRIVATE_KEY=file:/certs/tls-key.pem \
  -e SPRING_PROFILES_ACTIVE=self-signed \
  -e JAVA_TOOL_OPTIONS=-XX:MaxDirectMemorySize=128M \
  -e VERIFIER_PUBLICURL="$VERIFIER" \
  -e VERIFIER_CLIENTIDPREFIX=x509_hash -e VERIFIER_ORIGINALCLIENTID="$CLIENT_ID_HASH" \
  -e VERIFIER_INTENDEDUSES= -e VERIFIER_ATTESTATIONCLASSIFICATIONS="$CLASSIFICATIONS" \
  -e VERIFIER_ACCESS_CERTIFICATE_SIGNING_ALGORITHM=ES256 \
  -e VERIFIER_ACCESS_CERTIFICATE_KEYSTORE=file:///certs/keystore.p12 -e VERIFIER_ACCESS_CERTIFICATE_KEYSTORE_TYPE=pkcs12 \
  -e VERIFIER_ACCESS_CERTIFICATE_KEYSTORE_PASSWORD="$KEYSTORE_PASSWORD" \
  -e VERIFIER_ACCESS_CERTIFICATE_ALIAS=access_certificate -e VERIFIER_ACCESS_CERTIFICATE_PASSWORD="$KEYSTORE_PASSWORD" \
  "$VERIFIER_IMAGE" >/dev/null
for _ in $(seq 1 150); do
  if docker logs "$CONTAINER" 2>&1 | grep -q 'Started VerifierEndpointApplication'; then break; fi
  if [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER")" != true ]; then break; fi
  sleep 2
done
if ! docker logs "$CONTAINER" 2>&1 | grep -q 'Started VerifierEndpointApplication'; then
  docker logs "$CONTAINER" 2>&1 | grep -E 'APPLICATION FAILED|Reason|Caused by' | head -5 >&2 || true
  echo "the verifier did not start; see $WORK/verifier.log" >&2
  exit 2
fi

start_wallet() {  # $1 the wallet config, $2 the CA it trusts for the verifier
  stop_wallet
  jq --arg addr "127.0.0.1:$WALLET_PORT" --rawfile ca "$2" \
    '.listen_addr = $addr | .verifier_trust_anchors_pem = $ca' "$1" > wallet.json
  ./wallet -config wallet.json >> wallet.log 2>&1 &
  WALLET_PID=$!
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
ok() { echo "  ok    $1"; }
bad() { echo "  FAIL  $1"; fail=1; }

# init_transaction writes the verifier's answer to init.json and sets TID.
init_transaction() {  # $1 dcql, $2 profile, $3 issuer chain file, $4 request_uri_method
  jq -n --argjson q "$1" --arg profile "$2" --rawfile chain "$3" --arg method "$4" \
    --rawfile rc registration-certificate.jws --arg redirect "$VERIFIER/public/css/style.css?response_code={RESPONSE_CODE}" \
    '{dcql_query: $q, nonce: ("n-" + (now | tostring)), jar_mode: "by_reference", request_uri_method: $method,
      response_mode: "direct_post.jwt", profile: $profile, issuer_chain: $chain,
      registration_certificate: $rc, wallet_response_redirect_uri_template: $redirect}' > init-request.json
  curl -sk --max-time 30 -X POST -H 'Content-Type: application/json' -d @init-request.json \
    "$VERIFIER/ui/presentations" > init.json
  TID="$(jq -r '.transaction_id // empty' init.json)"
  [ -n "$TID" ] || { echo "        the verifier refused the transaction: $(cat init.json)"; return 1; }
}

# authorize hands the wallet the request, as a same-device launch would.
authorize() {  # $1 output file, $2 optional client_id
  local q
  q="$(jq -r --arg cid "${2:-}" \
    '"client_id=" + ((if $cid == "" then .client_id else $cid end) | @uri) + "&request_uri=" + (.request_uri | @uri) + "&request_uri_method=" + .request_uri_method' init.json)"
  curl -sk --max-time 60 -o "$1" "$WALLET/authorize?$q" || true
}

result() {  # $1 output file, $2 optional response_code
  curl -sk --max-time 30 -o "$1" "$VERIFIER/ui/presentations/$TID${2:+?response_code=$2}" || true
}

events() {
  curl -sk --max-time 30 "$VERIFIER/ui/presentations/$TID/events" \
    | jq -r '.events[]? | "        event: " + .event + (if .cause then ": " + (.cause | tostring | .[0:300]) else "" end)' || true
}

# present runs one presentation, which must be accepted: the wallet
# follows the redirect, and the verifier releases the vp_token for its
# response_code.
present() {  # $1 label, $2 dcql, $3 profile, $4 issuer chain file, $5 request_uri_method
  local name="$1"
  echo "== $name"
  init_transaction "$2" "$3" "$4" "$5" || { bad "$name: transaction initialized"; return; }
  authorize "wallet-$name.txt"
  local code
  code="$(grep -oE 'response_code=[A-Za-z0-9-]+' "wallet-$name.txt" | head -1 | cut -d= -f2 || true)"
  if [ -n "$code" ]; then ok "the wallet presented and followed the redirect"
  else bad "the wallet presented ($(head -c 300 "wallet-$name.txt"))"; events; return; fi
  result "result-$name.json" "$code"
  if jq -e '.vp_token.pid | length == 1' "result-$name.json" >/dev/null 2>&1; then ok "the verifier accepted the vp_token"
  else bad "the verifier accepted the vp_token ($(head -c 300 "result-$name.json"))"; events; fi
}

start_wallet wallet-sdjwt.json verifier-ca.pem
present sdjwt-haip "$SDJWT_QUERY" haip issuer-ca.pem get
present sdjwt-openid4vp "$SDJWT_QUERY" openid4vp issuer-ca.pem get

echo "== control: the same request again, after it was answered"
authorize replay.txt
if grep -q 'Presented' replay.txt; then bad "the verifier served the request twice"; else ok "refused: $(head -c 200 replay.txt | tr -s '\n' ' ')"; fi

echo "== control: the verifier trusts an unrelated issuer CA"
if init_transaction "$SDJWT_QUERY" haip other-ca.pem get; then
  authorize untrusted-issuer.txt
  result untrusted-issuer.json
  if jq -e '.vp_token' untrusted-issuer.json >/dev/null 2>&1; then bad "the verifier accepted it"
  else ok "the verifier refused the credential"; events | grep -i 'failed' || true; fi
else bad "transaction initialized"; fi

echo "== control: a launch whose client_id isn't the signed request's"
if init_transaction "$SDJWT_QUERY" haip issuer-ca.pem get; then
  authorize mismatch.txt "x509_hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  result mismatch.json
  if jq -e '.vp_token' mismatch.json >/dev/null 2>&1; then bad "the wallet presented"
  else ok "the wallet refused: $(head -c 200 mismatch.txt | tr -s '\n' ' ')"; fi
else bad "transaction initialized"; fi

echo "== control: a query for a credential the wallet doesn't hold"
if init_transaction "$UNHELD_QUERY" haip iaca.pem get; then
  authorize unheld.txt
  result unheld.json
  if jq -e '.error == "access_denied"' unheld.json >/dev/null 2>&1; then ok "the verifier received the wallet's access_denied"
  else bad "the verifier received access_denied ($(head -c 300 unheld.json))"; events; fi
else bad "transaction initialized"; fi

echo "== control: the wallet trusts an unrelated CA for the verifier"
start_wallet wallet-sdjwt.json other-ca.pem
if init_transaction "$SDJWT_QUERY" haip issuer-ca.pem get; then
  authorize untrusted-verifier.txt
  result untrusted-verifier.json
  if jq -e '.vp_token' untrusted-verifier.json >/dev/null 2>&1; then bad "the wallet presented"
  else ok "the wallet refused: $(head -c 200 untrusted-verifier.txt | tr -s '\n' ' ')"; fi
else bad "transaction initialized"; fi

start_wallet wallet-mdoc.json verifier-ca.pem
present mdoc-haip "$MDOC_QUERY" haip iaca.pem get
present mdoc-openid4vp "$MDOC_QUERY" openid4vp iaca.pem get

echo "== mdoc over the Digital Credentials API"
ORIGIN=https://verifier.example.com
jq -n --argjson q "$MDOC_QUERY" --rawfile chain iaca.pem --rawfile rc registration-certificate.jws --arg origin "$ORIGIN" \
  '{dcql_query: $q, nonce: ("n-" + (now | tostring)), origin: $origin, issuer_chain: $chain,
    registration_certificate: $rc}' > init-request.json
curl -sk --max-time 30 -X POST -H 'Content-Type: application/json' -d @init-request.json \
  "$VERIFIER/ui/presentations/dc-api" > init.json
TID="$(jq -r '.transaction_id // empty' init.json)"
if [ -z "$TID" ]; then
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

[ "$fail" -eq 0 ] && echo "RESULT: every presentation accepted, and every control refused" || echo "RESULT: FAILED"
exit "$fail"
