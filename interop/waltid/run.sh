#!/usr/bin/env bash
# OID4VCgo against walt.id's Community Stack v2 (walt-id/waltid-identity:
# Issuer2, Verifier2 and Wallet2), run from its published images pinned
# by digest, in all four directions:
#
#   our wallet ← Issuer2           SD-JWT VC and mdoc PIDs and an mDL, by
#                                  pre-authorized code, each checked as
#                                  OID4VCgo's wallet does
#   our wallet → Verifier2         a signed x509_hash request, the response
#                                  encrypted (direct_post.jwt)
#   Wallet2 ← our issuer           cmd/conformance-issuer (HAIP): a Wallet
#                                  Attestation from a stand-in Wallet
#                                  Provider, DPoP, both formats
#   Wallet2 → our verifier         those PIDs, to cmd/conformance-verifier:
#                                  x509_hash, direct_post.jwt, each
#                                  request_uri_method
#
# then controls that one side or the other must refuse. See README.md.
#
#   interop/waltid/run.sh
#   WALTID_TAG=latest interop/waltid/run.sh
#
# Needs docker, go, jq, curl, openssl and keytool. Exits 0 only if
# every case behaves as expected.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="${OID4VCGO_SRC:-$(cd "$HERE/../.." && pwd)}"

# v1.2.1, read from Docker Hub on 2026-11-10, and the commit of its tag,
# whose docker-compose/ configs the services run with. Move them only
# after reading the release's changes (README.md, "Moving the pins").
WALTID_COMMIT=cf3c836cc78a9e64b2fd87933527327972e014da # v1.2.1
if [[ -n "${WALTID_TAG:-}" ]]; then
  ISSUER2_IMAGE="waltid/issuer-api2:$WALTID_TAG"
  VERIFIER2_IMAGE="waltid/verifier-api2:$WALTID_TAG"
  WALLET2_IMAGE="waltid/wallet-api2:$WALTID_TAG"
else
  ISSUER2_IMAGE=waltid/issuer-api2@sha256:9cb23f2cd34bf73eddcd4b3715553bdb39fc1d1009f77ff11c92082eae41fd83
  VERIFIER2_IMAGE=waltid/verifier-api2@sha256:acd56d414b95c9b47558845060cb34cf138fa6fdae3aeff7e0ac1f1e53c25624
  WALLET2_IMAGE=waltid/wallet-api2@sha256:7937cfe2450e5521e272615179baef66f805459df391f2321b2f20ad92468614
fi
# Each service's docker-compose/<service>/config, by SHA-256.
WALTID_FILES=(
  "issuer-api2/config/_features.conf 312cc7c6221ba757f927688319404a031159eaa1bb452c733b38c98c63c0e87f"
  "issuer-api2/config/authentication-service.conf dec1d2728d18404052a84a4abefb21cc21f7f72e1626fda0264430cad720bc4c"
  "issuer-api2/config/credential-issuer-metadata.conf 267a8d49150b86900f7fc259c8358745292b538a388f37e91dc0c3ca12d6d5f9"
  "issuer-api2/config/dev-mode.conf b76458c6a1a0a89cf224c8441d95a9e2495913dff17aec537e3772a4cba48aa9"
  "issuer-api2/config/issuer-service.conf eddcfb5c5c3d1129b28f35f9b68d290191ad2312d40e3683f46d0da4eac446f5"
  "issuer-api2/config/issuer2-profiles.conf d84f7bd874c3ec72dd69460ba12cc177629e5abb791bf70a4d7a35bb3f96d07c"
  "issuer-api2/config/network-fetch-guard.conf a293ad67bed469a7ef79c5c95e30c700d3459bc7cdfe0cb69b8b2d2665c6ec1d"
  "issuer-api2/config/persistence.conf 100c2b037adf67b5eb8e44077f28667e55379155fd862418aad7df552e8e4cbd"
  "issuer-api2/config/web.conf 0d9f4ce1f732ecac6e34707c38d73fb8d384681b9a40b97a5200461419f16666"
  "verifier-api2/config/_features.conf c385206f3b30f998c7ce40caaaab40f7599c5be4c3eb410ea96b20609a1f695b"
  "verifier-api2/config/dev-mode.conf b76458c6a1a0a89cf224c8441d95a9e2495913dff17aec537e3772a4cba48aa9"
  "verifier-api2/config/network-fetch-guard.conf a293ad67bed469a7ef79c5c95e30c700d3459bc7cdfe0cb69b8b2d2665c6ec1d"
  "verifier-api2/config/transaction-data-profiles.conf 9087d40991d5159d9dcb198a9e89e0a78058242d32972af9881a982779414760"
  "verifier-api2/config/verifier-service.conf 9aab1b80e2bf8bd488fc24c220fda403c5045705ed02a3af2ecedfa64857a07d"
  "verifier-api2/config/web.conf ac374989da630b9437b64ac6d5d6bb5496f36cb3d384a81c5d6b5f100dd0754d"
  "wallet-api2/config/_features.conf 327d736d3c6e31fc20ea64f96ac67a17738b7538a78792e23884ef76873c56e3"
  "wallet-api2/config/auth.conf 54fbf0af0ccfa77cd72063f3ece37539bf0a7c0aac9f93f3a8ce70ddfe4df77d"
  "wallet-api2/config/dev-mode.conf c86a5344daea4d945339a04942615eeb871f3b08e358fc3d84a7e62adf021547"
  "wallet-api2/config/network-fetch-guard.conf a293ad67bed469a7ef79c5c95e30c700d3459bc7cdfe0cb69b8b2d2665c6ec1d"
  "wallet-api2/config/transaction-data-profiles.conf f3511b275797df569ba8738dededc653856054f607e0149c1de261b25442055a"
  "wallet-api2/config/wallet-service.conf 2b4ac8336b0152facf30924f4274878d28c081721ace3a5ea57cbd2681b872fd"
  "wallet-api2/config/wallet2-persistence.conf afbf5ffcce1745a1946f3598174a04090e9db6577ae85822b0a524190fba8a45"
  "wallet-api2/config/web.conf 7bf11be61e8f30b4f4987b76c575fb4355f38b13ccee3ef1d68d729942c52eee"
)

# Two names, both in the run's TLS certificate. Issuer2 and Verifier2,
# which only OID4VCgo's wallet calls, are localhost: its fetcher reaches
# loopback, in development, for a loopback name alone. What Wallet2
# calls from its container (OID4VCgo's issuer and verifiers, the
# attester) is HOST, which the container maps to this host, and curl
# dials on SERVE_BIND.
HOST=waltid.test
BASE_PORT="${BASE_PORT:-21400}"
ISSUER2_HTTP=$((BASE_PORT + 1)) VERIFIER2_HTTP=$((BASE_PORT + 2)) WALLET2_HTTP=$((BASE_PORT + 3))
ISSUER2_PORT=$((BASE_PORT + 11)) VERIFIER2_PORT=$((BASE_PORT + 12))
ISSUER_PORT=$((BASE_PORT + 21)) OFFERS_PORT=$((BASE_PORT + 22)) ATTESTER_PORT=$((BASE_PORT + 26))
VERIFIER_PORT=$((BASE_PORT + 31)) # and the next three
WORK="${WORK:-$(mktemp -d)}"
NAME="${COMPOSE_PROJECT_NAME:-oid4vcgo-waltid}"
# The client_id interop/eudi/scripts/setup-issuer registers, which the
# stand-in Wallet Provider's attestations name.
CLIENT_ID=oid4vcgo-eudi-interop-wallet

for p in "$ISSUER2_HTTP" "$VERIFIER2_HTTP" "$WALLET2_HTTP" "$ISSUER2_PORT" "$VERIFIER2_PORT" "$ISSUER_PORT" "$OFFERS_PORT" \
  "$ATTESTER_PORT" "$VERIFIER_PORT" $((VERIFIER_PORT + 1)) $((VERIFIER_PORT + 2)) $((VERIFIER_PORT + 3)); do
  if (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then
    echo "port $p is in use; set BASE_PORT" >&2
    exit 2
  fi
done

# The containers reach this host's listeners as $HOST: Docker Desktop
# maps host-gateway to the host's loopback; on Linux it's the default
# bridge's gateway, which the listeners then bind.
SERVE_BIND=127.0.0.1
if [[ "$(uname)" = Linux ]]; then
  SERVE_BIND="$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')"
fi

PIDS=()
# shellcheck disable=SC2329 # run by the EXIT trap
cleanup() {
  for pid in ${PIDS[@]+"${PIDS[@]}"}; do kill "$pid" 2>/dev/null || true; done
  for pid in ${PIDS[@]+"${PIDS[@]}"}; do wait "$pid" 2>/dev/null || true; done
  for s in issuer2 verifier2 wallet2; do
    docker logs "$NAME-$s" > "$WORK/$s.log" 2>&1 || true
    docker rm -f "$NAME-$s" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

echo "work dir    $WORK"
echo "oid4vcgo    $SRC, commit $(git -C "$SRC" rev-parse HEAD 2>/dev/null || echo unknown)"
echo "walt.id     $ISSUER2_IMAGE $VERIFIER2_IMAGE $WALLET2_IMAGE"

# walt.id's configs, refused unless each has its pinned SHA-256; then
# setup's blocks appended, which HOCON reads as replacing what they set.
for entry in "${WALTID_FILES[@]}"; do
  read -r path sum <<< "$entry"
  out="$WORK/waltid/$path"
  mkdir -p "$(dirname "$out")"
  curl -sSfL --max-time 60 -o "$out" "https://raw.githubusercontent.com/walt-id/waltid-identity/$WALTID_COMMIT/docker-compose/$path"
  if [[ "$(openssl dgst -sha256 -r "$out" | cut -d' ' -f1)" != "$sum" ]]; then
    echo "$path doesn't have the pinned SHA-256" >&2
    exit 2
  fi
done

mkdir -p "$WORK/issuer-files"
(cd "$SRC" && go build -o "$WORK/serve" ./interop/waltid/scripts/serve \
  && go build -o "$WORK/wallet" ./interop/waltid/scripts/wallet \
  && go build -o "$WORK/verifier" ./cmd/conformance-verifier \
  && go build -o "$WORK/issuer" ./cmd/conformance-issuer \
  && go run ./interop/eudi/scripts/setup-issuer -out "$WORK/issuer-files" -port "$ISSUER_PORT" -offers-port "$OFFERS_PORT")
cd "$WORK"
# OID4VCgo's issuer's credentials chain to these: its verifiers trust
# them.
jq -r '.issuer_ca_pem' issuer-files/driver.json > issuer-ca.pem
jq -r '.iaca_pem' issuer-files/driver.json > iaca.pem
(cd "$SRC" && go run ./interop/waltid/scripts/setup -out "$WORK" -host "$HOST" -bind "$SERVE_BIND" \
  -issuer-ca "$WORK/issuer-ca.pem" -iaca "$WORK/iaca.pem" \
  -issuer2-port "$ISSUER2_PORT" -verifier2-port "$VERIFIER2_PORT" -attester-port "$ATTESTER_PORT" -verifier-port "$VERIFIER_PORT")

cat issuer2-profiles.conf >> waltid/issuer-api2/config/issuer2-profiles.conf
cat issuer2-service.conf >> waltid/issuer-api2/config/issuer-service.conf
cat verifier2-service.conf >> waltid/verifier-api2/config/verifier-service.conf
cat wallet2-service.conf >> waltid/wallet-api2/config/wallet-service.conf
cat wallet2-features.conf >> waltid/wallet-api2/config/_features.conf
# Wallet2's JVM trusts the run's CA for TLS, and nothing else.
keytool -importcert -noprompt -alias oid4vcgo-waltid-interop -file ca.pem -keystore truststore.p12 \
  -storetype PKCS12 -storepass changeit >/dev/null
# OID4VCgo's issuer, as interop/eudi/run-issuer.sh runs it, named $HOST
# under the run's TLS certificate, listening where the containers reach
# it.
jq --arg issuer "https://$HOST:$ISSUER_PORT" --arg addr "$SERVE_BIND:$ISSUER_PORT" \
  --rawfile cert tls-cert.pem --rawfile key tls-key.pem \
  '.issuer = $issuer | .listen_addr = $addr | .tls_certificate_pem = $cert | .tls_private_key_pem = $key' \
  issuer-files/issuer.json > issuer.json
echo trusted > attester-mode

run_service() {  # $1 name, $2 image, $3 its config directory, $4 host port, $5 its port; then docker options
  local name="$1" image="$2" dir="$3" port="$4" inner="$5"; shift 5
  docker run -d --name "$NAME-$name" -p "127.0.0.1:$port:$inner" --add-host "$HOST:host-gateway" \
    -e SERVICE_HOST="$HOST" -e ISSUER_API2_PORT=7005 -e VERIFIER_API2_PORT=7004 -e WALLET_API2_PORT=7006 \
    -v "$WORK/waltid/$dir/config:/waltid-$dir/config" "$@" "$image" >/dev/null
}
run_service issuer2 "$ISSUER2_IMAGE" issuer-api2 "$ISSUER2_HTTP" 7005
run_service verifier2 "$VERIFIER2_IMAGE" verifier-api2 "$VERIFIER2_HTTP" 7004
run_service wallet2 "$WALLET2_IMAGE" wallet-api2 "$WALLET2_HTTP" 7006 -v "$WORK/truststore.p12:/trust/truststore.p12:ro" \
  -e JAVA_TOOL_OPTIONS="-Djavax.net.ssl.trustStore=/trust/truststore.p12 -Djavax.net.ssl.trustStorePassword=changeit -Djavax.net.ssl.trustStoreType=PKCS12"

./serve -dir . -proxy "127.0.0.1:$ISSUER2_PORT=http://127.0.0.1:$ISSUER2_HTTP" -proxy "127.0.0.1:$VERIFIER2_PORT=http://127.0.0.1:$VERIFIER2_HTTP" \
  -attester "$SERVE_BIND:$ATTESTER_PORT" -attester-config issuer-files/driver.json -attester-mode attester-mode > serve.log 2>&1 &
PIDS+=($!)
./issuer -config issuer.json > issuer.log 2>&1 &
PIDS+=($!)
for v in sdjwt mdoc untrusted-access untrusted-issuer; do
  ./verifier -config "verifier-$v.json" > "verifier-$v.log" 2>&1 &
  PIDS+=($!)
done

# tls GETs or POSTs a URL at $HOST, verifying its TLS certificate.
tls() { curl -sS --max-time 60 --cacert ca.pem --resolve "$HOST:${1##*:}:$SERVE_BIND" "${@:2}"; }

for url in "http://127.0.0.1:$ISSUER2_HTTP/issuer2/profiles" "http://127.0.0.1:$VERIFIER2_HTTP/api.json" \
  "http://127.0.0.1:$WALLET2_HTTP/api.json"; do
  for _ in $(seq 1 120); do
    if curl -sf -o /dev/null --max-time 2 "$url"; then continue 2; fi
    sleep 1
  done
  echo "$url did not start; see $WORK/*.log" >&2
  exit 2
done
for port in "$ISSUER2_PORT" "$VERIFIER2_PORT"; do
  for _ in $(seq 1 50); do
    if curl -s -o /dev/null --max-time 2 --cacert ca.pem "https://localhost:$port/"; then continue 2; fi
    sleep 0.2
  done
  echo "https://localhost:$port did not start; see $WORK/*.log" >&2
  exit 2
done
for port in "$ISSUER_PORT" "$VERIFIER_PORT" $((VERIFIER_PORT + 1)) $((VERIFIER_PORT + 2)) $((VERIFIER_PORT + 3)); do
  for _ in $(seq 1 50); do
    if tls "$port" -o /dev/null "https://$HOST:$port/" 2>/dev/null; then continue 2; fi
    sleep 0.2
  done
  echo "https://$HOST:$port did not start; see $WORK/*.log" >&2
  exit 2
done

fail=0
ok() { echo "  ok    $1"; }
bad() { echo "  FAIL  $1"; fail=1; }

# issuer2_offer is a pre-authorized code offer of Issuer2's profile $1.
issuer2_offer() {
  curl -sS --max-time 30 -X POST -H 'Content-Type: application/json' \
    --data "$(jq -cn --arg p "$1" '{profileId: $p, authMethod: "PRE_AUTHORIZED"}')" \
    "http://127.0.0.1:$ISSUER2_HTTP/issuer2/credential-offers" | jq -r '.credentialOffer'
}

# our_offer is a pre-authorized code offer of OID4VCgo's issuer's
# configuration $1, by reference.
our_offer() {
  curl -sS --max-time 30 -X POST -H 'Content-Type: application/json' \
    --data "$(jq -cn --arg c "$1" '{grant: "pre-authorized_code", credential_configuration_ids: [$c], by_reference: true}')" \
    "http://127.0.0.1:$OFFERS_PORT/offers" | jq -r '.uri'
}

# wallet runs OID4VCgo's wallet; its outcome is in $1.json.
wallet() {  # $1 name; then the wallet's options
  local name="$1"; shift
  ./wallet -tls-ca ca.pem -out "$name.json" "$@" >> "wallet-$name.log" 2>&1 \
    || echo '{"stage": "wallet", "error": "the wallet failed; see its log"}' > "$name.json"
}

why() {  # $1 file
  jq -c '{stage, status, error} | with_entries(select(.value != null))' "$1" 2>/dev/null | cut -c1-300 || head -c 300 "$1"
}

echo "### OID4VCgo's wallet ← walt.id Issuer2"
for profile in eudiPidSdJwt eudiPidMdoc isoMdl; do
  wallet "receive-$profile" -issuer-ca ca.pem -verifier-ca ca.pem -offer "$(issuer2_offer "$profile")"
  if jq -e '.stage == "done" and (.received | length == 1)' "receive-$profile.json" >/dev/null; then
    ok "$profile: issued and checked ($(jq -r '.received[0] | "\(.format) \(.configuration_id)"' "receive-$profile.json"))"
  else bad "$profile: $(why "receive-$profile.json")"; fi
done
wallet receive-untrusted-issuer -issuer-ca other-ca.pem -verifier-ca ca.pem -offer "$(issuer2_offer eudiPidSdJwt)"
if jq -e '.stage != "done" and (.received | length == 0) and (.failed[0] // .error | test("certificate"))' receive-untrusted-issuer.json >/dev/null; then
  ok "control: a credential from an issuer the wallet doesn't trust is refused ($(jq -r '.failed[0] // .error' receive-untrusted-issuer.json | cut -c1-120))"
else bad "control: a credential from an untrusted issuer: $(why receive-untrusted-issuer.json)"; fi

echo "### OID4VCgo's wallet → walt.id Verifier2"
# session creates a Verifier2 session for DCQL query $2, signed and
# encrypted unless $1 is "plain"; it prints the session's id and link.
session() {  # $1 signed or plain, $2 the DCQL query
  local signed=true
  if [[ "$1" = plain ]]; then signed=false; fi
  curl -sS --max-time 30 -X POST -H 'Content-Type: application/json' \
    --data "$(jq -cn --argjson q "$2" --argjson s "$signed" \
      '{flow_type: "cross_device", core_flow: {signed_request: $s, encrypted_response: $s, dcql_query: $q}}')" \
    "http://127.0.0.1:$VERIFIER2_HTTP/verification-session/create" | jq -r '"\(.sessionId) \(.bootstrapAuthorizationRequestUrl)"'
}
session_status() { curl -sS --max-time 30 "http://127.0.0.1:$VERIFIER2_HTTP/verification-session/$1/info" | jq -r '.status'; }
PID_QUERY='{"credentials": [{"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": ["urn:eudi:pid:1"]}, "claims": [{"path": ["family_name"]}]}]}'
MDL_QUERY='{"credentials": [{"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}, "claims": [{"path": ["org.iso.18013.5.1", "family_name"]}]}]}'
for case in "pid eudiPidSdJwt $PID_QUERY" "mdl isoMdl $MDL_QUERY"; do
  read -r name profile query <<< "$case"
  read -r id link <<< "$(session signed "$query")"
  wallet "present-$name" -issuer-ca ca.pem -verifier-ca ca.pem -offer "$(issuer2_offer "$profile")" -request "$link"
  status="$(session_status "$id")"
  if jq -e '.stage == "done"' "present-$name.json" >/dev/null && [[ "$status" = SUCCESSFUL ]]; then
    ok "$name: presented to a signed x509_hash request, encrypted; Verifier2 accepted it"
  else bad "$name: wallet $(why "present-$name.json"), Verifier2 $status"; fi
done
read -r id link <<< "$(session plain "$PID_QUERY")"
wallet present-unsigned -issuer-ca ca.pem -verifier-ca ca.pem -offer "$(issuer2_offer eudiPidSdJwt)" -request "$link"
if jq -e '.stage == "request"' present-unsigned.json >/dev/null && [[ "$(session_status "$id")" != SUCCESSFUL ]]; then
  ok "control: an unsigned request naming an x509_hash client is refused ($(jq -r '.error' present-unsigned.json | cut -c1-120))"
else bad "control: an unsigned x509_hash request: $(why present-unsigned.json)"; fi
wallet present-untrusted-verifier -issuer-ca ca.pem -verifier-ca other-ca.pem -offer "$(issuer2_offer eudiPidSdJwt)" \
  -request "$(session signed "$PID_QUERY" | cut -d' ' -f2)"
if jq -e '.stage == "request" and (.error | test("untrusted verifier"))' present-untrusted-verifier.json >/dev/null; then
  ok "control: a Verifier whose Access Certificate the wallet doesn't trust is refused"
else bad "control: an untrusted Verifier: $(why present-untrusted-verifier.json)"; fi

W="http://127.0.0.1:$WALLET2_HTTP"
# wallet2 creates a Wallet2 wallet with a P-256 key, printing its id.
wallet2() {
  local id
  id="$(curl -sS --max-time 30 -X POST -H 'Content-Type: application/json' --data '{}' "$W/wallet" | jq -r '.walletId')"
  curl -sS --max-time 30 -o /dev/null -X POST -H 'Content-Type: application/json' \
    --data '{"backend": "jwk", "keyType": "secp256r1"}' "$W/wallet/$id/keys/generate"
  echo "$id"
}
receive2() {  # $1 wallet, $2 offer; then a client_id: Wallet2's answer to stdout
  curl -sS --max-time 90 -X POST -H 'Content-Type: application/json' \
    --data "$(jq -cn --arg o "$2" --arg c "${3:-}" '{offerUrl: $o} + (if $c == "" then {} else {clientId: $c} end)')" \
    "$W/wallet/$1/credentials/receive"
}
present2() {  # $1 wallet, $2 request: Wallet2's answer to stdout
  curl -sS --max-time 90 -X POST -H 'Content-Type: application/json' \
    --data "$(jq -cn --arg r "$2" '{requestUrl: $r}')" "$W/wallet/$1/credentials/present"
}
# authorize starts a session on the verifier at port $1, as a
# same-device page would, and prints the openid4vp:// launch.
authorize() { tls "$1" -o /dev/null -w '%{redirect_url}' "https://$HOST:$1/authorize?request_uri_method=$2"; }
# redeem follows Wallet2's redirect_to in $1 and redeems its
# response_code: the verifier's outcome is in $2.
redeem() {
  local redirect port
  redirect="$(jq -r '.redirect_to // .verifier_response.redirect_uri // empty' "$1" 2>/dev/null || true)"
  if [[ -z "$redirect" ]]; then echo '{"status": "no redirect_to"}' > "$2"; return; fi
  port="$(sed -E 's|https://[^:/]+:([0-9]+).*|\1|' <<< "$redirect")"
  tls "$port" -o /dev/null "$redirect" || true
  tls "$port" -o "$2" "${redirect/\?response_code=//redeem?response_code=}" || true
}

echo "### walt.id Wallet2 ← OID4VCgo's issuer"
holder="$(wallet2)"
for config in eu.europa.ec.eudi.pid_vc_sd_jwt eu.europa.ec.eudi.pid_mso_mdoc; do
  receive2 "$holder" "$(our_offer "$config")" "$CLIENT_ID" > "wallet2-receive-$config.json" || true
  if jq -e '.credentialIds | length == 1' "wallet2-receive-$config.json" >/dev/null 2>&1; then
    ok "$config: issued to Wallet2 (Wallet Attestation, DPoP)"
  else bad "$config: $(head -c 300 "wallet2-receive-$config.json")"; fi
done
echo untrusted > attester-mode
other="$(wallet2)"
receive2 "$other" "$(our_offer eu.europa.ec.eudi.pid_vc_sd_jwt)" "$CLIENT_ID" > wallet2-receive-untrusted-attester.json || true
echo trusted > attester-mode
if grep -q invalid_client wallet2-receive-untrusted-attester.json && ! jq -e '.credentialIds | length > 0' wallet2-receive-untrusted-attester.json >/dev/null 2>&1; then
  ok "control: a Wallet Attestation from an attester the issuer doesn't trust is refused"
else bad "control: the issuer took a Wallet Attestation from an untrusted attester"; fi

echo "### walt.id Wallet2 → OID4VCgo's verifier, with those PIDs"
for method in none get post; do
  present2 "$holder" "$(authorize "$VERIFIER_PORT" "$method")" > "wallet2-present-pid-$method.json"
  redeem "wallet2-present-pid-$method.json" "result-pid-$method.json"
  if jq -e '.status == "verified" and (.credentials.cred1 | has("family_name") and has("given_name"))' "result-pid-$method.json" >/dev/null; then
    ok "sd-jwt pid, request_uri_method $method: verified (issuer, holder binding, response encrypted)"
  else bad "sd-jwt pid, request_uri_method $method: $(why "result-pid-$method.json")"; fi
done
present2 "$holder" "$(authorize $((VERIFIER_PORT + 1)) get)" > wallet2-present-mdoc.json
redeem wallet2-present-mdoc.json result-mdoc.json
if jq -e '.status == "verified" and (.credentials.cred1["eu.europa.ec.eudi.pid.1"] | keys == ["family_name", "given_name"])' result-mdoc.json >/dev/null; then
  ok "mdoc pid: verified, only the requested elements disclosed"
else bad "mdoc pid: $(why result-mdoc.json)"; fi
present2 "$holder" "$(authorize $((VERIFIER_PORT + 2)) get)" > wallet2-present-untrusted-access.json || true
redeem wallet2-present-untrusted-access.json result-untrusted-access.json
if grep -q X509TrustAnchorMismatch wallet2-present-untrusted-access.json && ! jq -e '.status == "verified"' result-untrusted-access.json >/dev/null 2>&1; then
  ok "control: Wallet2 doesn't answer a Verifier whose Access Certificate it doesn't trust"
else bad "control: Wallet2 answered an untrusted Verifier"; fi
present2 "$holder" "$(authorize $((VERIFIER_PORT + 3)) get)" > wallet2-present-untrusted-issuer.json || true
redeem wallet2-present-untrusted-issuer.json result-untrusted-issuer.json
if ! jq -e '.status == "verified"' result-untrusted-issuer.json >/dev/null 2>&1; then
  ok "control: the verifier refuses a credential from an issuer it doesn't trust ($(why result-untrusted-issuer.json))"
else bad "control: the verifier accepted a credential from an untrusted issuer"; fi

if [[ "$fail" -eq 0 ]]; then echo "RESULT: every case passed, and every control refused"; else echo "RESULT: FAILED"; fi
exit "$fail"
