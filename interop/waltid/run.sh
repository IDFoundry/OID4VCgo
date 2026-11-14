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
#                                  Provider, DPoP, both formats; then
#                                  its dpop-nonces, deferred and
#                                  key-attestation profiles
#   Wallet2 → our verifier         those PIDs, to cmd/conformance-verifier:
#                                  x509_hash, direct_post.jwt, each
#                                  request_uri_method; and through
#                                  verifier.Transactions under production
#                                  assurance, as a deployment runs it
#   our issuer → our wallet →      the issuer's production setup, the
#     Verifier2                    wallet attested by OID4VCgo's Wallet
#                                  Provider (interop/walletprovider);
#                                  Verifier2 checks the credentials'
#                                  status
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
# OID4VCgo's issuer listens here, behind serve's tap on ISSUER_PORT,
# which logs what Wallet2 sends it.
ISSUER_INNER_PORT=$((BASE_PORT + 23))
# A second instance of OID4VCgo's issuer, for OID4VCgo's wallet, named
# localhost (walletflow's development fetcher reaches loopback for a
# loopback name alone), with its offers listener; Verifier2 fetches its
# status lists through serve's tap on STATUS_TAP_PORT, as $HOST.
STATUS_ISSUER_PORT=$((BASE_PORT + 27)) STATUS_OFFERS_PORT=$((BASE_PORT + 28)) STATUS_TAP_PORT=$((BASE_PORT + 29))
VERIFIER_PORT=$((BASE_PORT + 31)) # and the next three
# OID4VCgo's wallet publishes the run CA's CRL here, at the distribution
# point Issuer2's and Verifier2's certificates name, and checks them
# against it (scripts/wallet's -crl-set).
CRL_PORT=$((BASE_PORT + 41))
# OID4VCgo's Wallet Provider, which attests OID4VCgo's wallet to the
# issuer's production setup, and its admin listener; and the
# transactions-engine Verifier for the SD-JWT VC PID.
WP_PORT=$((BASE_PORT + 42)) WP_ADMIN_PORT=$((BASE_PORT + 43)) TX_VERIFIER_PORT=$((BASE_PORT + 44))
WORK="${WORK:-$(mktemp -d)}"
NAME="${COMPOSE_PROJECT_NAME:-oid4vcgo-waltid}"
# The client_id interop/eudi/scripts/setup-issuer registers, which the
# stand-in Wallet Provider's attestations name.
CLIENT_ID=oid4vcgo-eudi-interop-wallet

for p in "$ISSUER2_HTTP" "$VERIFIER2_HTTP" "$WALLET2_HTTP" "$ISSUER2_PORT" "$VERIFIER2_PORT" "$ISSUER_PORT" "$OFFERS_PORT" \
  "$ISSUER_INNER_PORT" "$ATTESTER_PORT" "$STATUS_ISSUER_PORT" "$STATUS_OFFERS_PORT" "$STATUS_TAP_PORT" "$VERIFIER_PORT" $((VERIFIER_PORT + 1)) $((VERIFIER_PORT + 2)) $((VERIFIER_PORT + 3)) "$CRL_PORT" \
  "$WP_PORT" "$WP_ADMIN_PORT" "$TX_VERIFIER_PORT"; do
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
ISSUER_PID=""
# shellcheck disable=SC2329 # run by the EXIT trap
cleanup() {
  if [[ -n "$ISSUER_PID" ]]; then kill "$ISSUER_PID" 2>/dev/null || true; wait "$ISSUER_PID" 2>/dev/null || true; fi
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
  curl -sSfL --proto '=https' --max-time 60 -o "$out" "https://raw.githubusercontent.com/walt-id/waltid-identity/$WALTID_COMMIT/docker-compose/$path"
  if [[ "$(openssl dgst -sha256 -r "$out" | cut -d' ' -f1)" != "$sum" ]]; then
    echo "$path doesn't have the pinned SHA-256" >&2
    exit 2
  fi
done

mkdir -p "$WORK/issuer-files"
# shellcheck source=../production.sh
. "$HERE/../production.sh"
# Built with the conformance_production tag: the verifier and the
# issuer run their production setups (below), and the Wallet Provider
# runs at all.
build_production "$WORK" "$SRC" verifier=./cmd/conformance-verifier issuer=./cmd/conformance-issuer \
  walletprovider=./interop/walletprovider
(cd "$SRC" && go build -o "$WORK/serve" ./interop/waltid/scripts/serve \
  && go build -o "$WORK/wallet" ./interop/waltid/scripts/wallet \
  && go run ./interop/eudi/scripts/setup-issuer -out "$WORK/issuer-files" -port "$ISSUER_PORT" -offers-port "$OFFERS_PORT")
cd "$WORK"
# OID4VCgo's issuer's credentials chain to these: its verifiers trust
# them.
jq -r '.issuer_ca_pem' issuer-files/driver.json > issuer-ca.pem
jq -r '.iaca_pem' issuer-files/driver.json > iaca.pem
(cd "$SRC" && go run ./interop/waltid/scripts/setup -out "$WORK" -host "$HOST" -bind "$SERVE_BIND" \
  -issuer-ca "$WORK/issuer-ca.pem" -iaca "$WORK/iaca.pem" \
  -issuer2-port "$ISSUER2_PORT" -verifier2-port "$VERIFIER2_PORT" -attester-port "$ATTESTER_PORT" -verifier-port "$VERIFIER_PORT" \
  -crl-port "$CRL_PORT")

cat issuer2-profiles.conf >> waltid/issuer-api2/config/issuer2-profiles.conf
cat issuer2-service.conf >> waltid/issuer-api2/config/issuer-service.conf
cat verifier2-service.conf >> waltid/verifier-api2/config/verifier-service.conf
cat wallet2-service.conf >> waltid/wallet-api2/config/wallet-service.conf
cat wallet2-features.conf >> waltid/wallet-api2/config/_features.conf
# Wallet2's JVM trusts the run's CA for TLS, and nothing else.
keytool -importcert -noprompt -alias oid4vcgo-waltid-interop -file ca.pem -keystore truststore.p12 \
  -storetype PKCS12 -storepass changeit >/dev/null
# OID4VCgo's issuer, as interop/eudi/run-issuer.sh runs it, named $HOST
# under the run's TLS certificate, on loopback behind serve's tap,
# which listens where the containers reach it.
jq --arg issuer "https://$HOST:$ISSUER_PORT" --arg addr "127.0.0.1:$ISSUER_INNER_PORT" \
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
# Verifier2 fetches OID4VCgo's issuer's status lists, and Wallet2 calls
# the issuer, both over TLS under the run's CA.
TRUST=(-v "$WORK/truststore.p12:/trust/truststore.p12:ro"
  -e JAVA_TOOL_OPTIONS="-Djavax.net.ssl.trustStore=/trust/truststore.p12 -Djavax.net.ssl.trustStorePassword=changeit -Djavax.net.ssl.trustStoreType=PKCS12")
run_service verifier2 "$VERIFIER2_IMAGE" verifier-api2 "$VERIFIER2_HTTP" 7004 "${TRUST[@]}"
run_service wallet2 "$WALLET2_IMAGE" wallet-api2 "$WALLET2_HTTP" 7006 "${TRUST[@]}"

./serve -dir . -proxy "127.0.0.1:$ISSUER2_PORT=http://127.0.0.1:$ISSUER2_HTTP" -proxy "127.0.0.1:$VERIFIER2_PORT=http://127.0.0.1:$VERIFIER2_HTTP" \
  -tap "$SERVE_BIND:$ISSUER_PORT=https://127.0.0.1:$ISSUER_INNER_PORT" -tap "$SERVE_BIND:$STATUS_TAP_PORT=https://127.0.0.1:$STATUS_ISSUER_PORT" -tap-name "$HOST" \
  -attester "$SERVE_BIND:$ATTESTER_PORT" -attester-config issuer-files/driver.json -attester-mode attester-mode > serve.log 2>&1 &
PIDS+=($!)

# start_issuer (re)starts OID4VCgo's issuer in a profile of
# interop/eudi/run-issuer.sh's: issuer.json changed by the jq filter $2.
start_issuer() {  # $1 the profile's name, $2 a jq filter
  local name="$1" filter="$2"
  if [[ -n "$ISSUER_PID" ]]; then kill "$ISSUER_PID" 2>/dev/null || true; wait "$ISSUER_PID" 2>/dev/null || true; fi
  jq "$filter" issuer.json > "issuer-$name.json"
  ./issuer -config "issuer-$name.json" >> "issuer-$name.log" 2>&1 &
  ISSUER_PID=$!
  for _ in $(seq 1 50); do
    if curl -s -o /dev/null --max-time 1 --cacert ca.pem --resolve "$HOST:$ISSUER_INNER_PORT:127.0.0.1" \
      "https://$HOST:$ISSUER_INNER_PORT/.well-known/openid-credential-issuer"; then return 0; fi
    sleep 0.2
  done
  echo "the issuer did not start in profile $name; see $WORK/issuer-$name.log" >&2
  exit 2
}
start_issuer base .
# The verifiers but the first as a deployment runs a Verifier: served by
# verifier.Transactions (the transactions engine, request_uri_method
# post), under verifier.AssuranceProduction, its transactions in a
# sealed SQLite file. The SD-JWT VC verifier runs as both: on the
# default engine at development assurance, which serves each
# request_uri_method a case asks for, and as the transactions engine
# on TX_VERIFIER_PORT.
# shellcheck disable=SC2016 # jq's variables, not the shell's
TX_FILTER='.engine = "transactions" | .production = {database_path: $db, sealing_key: $key}'
jq --arg addr "$SERVE_BIND:$TX_VERIFIER_PORT" --arg base "https://$HOST:$TX_VERIFIER_PORT" --arg db "$WORK/verifier-sdjwt-tx.db" \
  --arg key "$(sealing_key)" ".listen_addr = \$addr | .base_url = \$base | $TX_FILTER" verifier-sdjwt.json > verifier-sdjwt-tx.json
for v in mdoc untrusted-access untrusted-issuer; do
  jq --arg db "$WORK/verifier-$v.db" --arg key "$(sealing_key)" "$TX_FILTER" "verifier-$v.json" > "verifier-$v-tx.json"
  mv "verifier-$v-tx.json" "verifier-$v.json"
done
for v in sdjwt sdjwt-tx mdoc untrusted-access untrusted-issuer; do
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
for port in "$ISSUER_PORT" "$VERIFIER_PORT" $((VERIFIER_PORT + 1)) $((VERIFIER_PORT + 2)) $((VERIFIER_PORT + 3)) "$TX_VERIFIER_PORT"; do
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
JSON='Content-Type: application/json'
# Why OID4VCgo refuses a chain to a CA it doesn't trust, in the wallet
# and the verifier alike.
UNTRUSTED_ISSUER='certchain: certificate chain does not verify against a trusted root: x509: certificate signed by unknown authority'
# Why OID4VCgo's wallet refuses a certificate the run's CA revoked, and
# one it can't check: its CRL, at the distribution point the
# certificate names, is past its nextUpdate.
REVOKED='certchain: revocation: no verified path passes it: certrevocation: certificate is revoked'
NO_CURRENT_CRL="certchain: revocation: no verified path passes it: certchain: revocation couldn't be decided: certrevocation: no current CRL from the certificate's issuer"

# issuer2_offer is a pre-authorized code offer of Issuer2's profile $1.
issuer2_offer() {
  local profile="$1"
  curl -sS --max-time 30 -X POST -H "$JSON" \
    --data "$(jq -cn --arg p "$profile" '{profileId: $p, authMethod: "PRE_AUTHORIZED"}')" \
    "http://127.0.0.1:$ISSUER2_HTTP/issuer2/credential-offers" | jq -r '.credentialOffer'
}

# our_offer is a pre-authorized code offer of OID4VCgo's issuer's
# configuration $1, by reference.
our_offer() {
  local config="$1"
  curl -sS --max-time 30 -X POST -H "$JSON" \
    --data "$(jq -cn --arg c "$config" '{grant: "pre-authorized_code", credential_configuration_ids: [$c], by_reference: true}')" \
    "http://127.0.0.1:$OFFERS_PORT/offers" | jq -r '.uri'
}

# wallet runs OID4VCgo's wallet; its outcome is in $1.json.
wallet() {  # $1 name; then the wallet's options
  local name="$1"; shift
  ./wallet -tls-ca ca.pem -out "$name.json" "$@" >> "wallet-$name.log" 2>&1 \
    || echo '{"stage": "wallet", "error": "the wallet failed; see its log"}' > "$name.json"
}

why() {  # $1 file
  local file="$1"
  jq -c '{stage, status, error} | with_entries(select(.value != null))' "$file" 2>/dev/null | cut -c1-300 || head -c 300 "$file"
}

echo "### OID4VCgo's wallet ← walt.id Issuer2"
for profile in eudiPidSdJwt eudiPidMdoc isoMdl; do
  wallet "receive-$profile" -issuer-ca ca.pem -verifier-ca ca.pem -offer "$(issuer2_offer "$profile")"
  if jq -e '.stage == "done" and (.received | length == 1)' "receive-$profile.json" >/dev/null; then
    ok "$profile: issued and checked ($(jq -r '.received[0] | "\(.format) \(.configuration_id)"' "receive-$profile.json"))"
  else bad "$profile: $(why "receive-$profile.json")"; fi
done
wallet receive-untrusted-issuer -issuer-ca other-ca.pem -verifier-ca ca.pem -offer "$(issuer2_offer eudiPidSdJwt)"
# Refused as the credential is checked, for its issuer's chain: not
# before it was issued, and not for anything else about it.
if jq -e --arg want "$UNTRUSTED_ISSUER" '.stage == "credential" and (.received | length == 0)
    and (.error | contains("is invalid: wallet: verify issued credential: issuer certificate: " + $want))' \
    receive-untrusted-issuer.json >/dev/null; then
  ok "control: a credential from an issuer the wallet doesn't trust is refused, for its chain"
else bad "control: a credential from an untrusted issuer: $(why receive-untrusted-issuer.json)"; fi

# Every credential above was checked against the run CA's current CRL,
# which the wallet fetched over https from the distribution point
# Issuer2's certificates name. Here the CA revokes them, then publishes
# no current CRL: the credential must be refused for that reason.
for c in "revoked-issuer REVOKED revoked" "expired NO_CURRENT_CRL without-current-crl"; do
  read -r set why name <<< "$c"
  wallet "receive-crl-$name" -issuer-ca ca.pem -verifier-ca ca.pem -crl-set "$set" -offer "$(issuer2_offer eudiPidSdJwt)"
  if jq -e --arg want "${!why}" '.stage == "credential" and (.received | length == 0)
      and (.error | contains("is invalid: wallet: verify issued credential: issuer certificate: " + $want))' \
      "receive-crl-$name.json" >/dev/null; then
    ok "control: a credential whose signer's CA $( [[ $set = expired ]] && echo 'publishes no current CRL' || echo 'revoked it') is refused, for that"
  else bad "control: a credential, CRL set $set: $(why "receive-crl-$name.json")"; fi
done

# What Issuer2 sent of what SPECIFICATIONS.md's "Known leniencies"
# concern, as the wallet's transport read it, asserted as 1.2.1 sends
# it so that a change is noticed (README.md, "What walt.id sends"): a
# DPoP token_type for each of its pre-authorized code tokens, and no
# credential_request_encryption, so no request encryption key at all.
for profile in eudiPidSdJwt eudiPidMdoc isoMdl; do
  echo "        observed ($profile): $(jq -c '.observed | {token_types, issuer_metadata, credential_request_encryption}' "receive-$profile.json")"
done
if jq -s -e 'all(.[].observed; .token_types == ["DPoP"] and .issuer_metadata >= 1 and (.credential_request_encryption | not))' \
    receive-eudiPidSdJwt.json receive-eudiPidMdoc.json receive-isoMdl.json >/dev/null; then
  ok "observed: Issuer2's Token Responses are token_type DPoP, and its metadata has no credential_request_encryption"
else bad "observed: what Issuer2 sends changed: $(jq -c -s '[.[].observed]' receive-eudiPidSdJwt.json receive-eudiPidMdoc.json receive-isoMdl.json | head -c 300)"; fi

echo "### OID4VCgo's wallet → walt.id Verifier2"
# session creates a Verifier2 session for DCQL query $2, signed and
# encrypted unless $1 is "plain"; it prints the session's id and link.
session() {  # $1 signed or plain, $2 the DCQL query
  local mode="$1" query="$2" signed=true
  if [[ "$mode" = plain ]]; then signed=false; fi
  curl -sS --max-time 30 -X POST -H "$JSON" \
    --data "$(jq -cn --argjson q "$query" --argjson s "$signed" \
      '{flow_type: "cross_device", core_flow: {signed_request: $s, encrypted_response: $s, dcql_query: $q}}')" \
    "http://127.0.0.1:$VERIFIER2_HTTP/verification-session/create" | jq -r '"\(.sessionId) \(.bootstrapAuthorizationRequestUrl)"'
}
session_status() {
  local id="$1"
  curl -sS --max-time 30 "http://127.0.0.1:$VERIFIER2_HTTP/verification-session/$id/info" | jq -r '.status'
}
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
# Its response encryption key, in each signed request's client_metadata:
# one key, with the alg and kid OpenID4VP 1.0 §8.3 asks for, as 1.2.1
# sends it (README.md, "What walt.id sends").
echo "        observed: $(jq -c -s '[.[].observed.verifier_jwks]' present-pid.json present-mdl.json)"
if jq -s -e 'all(.[].observed.verifier_jwks; length == 1 and .[0].alg == "ECDH-ES" and (.[0].kid | startswith("response-encryption-")))' \
    present-pid.json present-mdl.json >/dev/null; then
  ok "observed: Verifier2's response encryption JWK carries alg ECDH-ES and a kid"
else bad "observed: Verifier2's response encryption JWK changed: $(jq -c -s '[.[].observed.verifier_jwks]' present-pid.json present-mdl.json)"; fi

# Negative presentations: the wallet's transport changes the SD-JWT VC
# presentation on its way to Verifier2 (scripts/wallet/tamper.go). It
# relays the response through a key of its own, so the relay case,
# which changes nothing else, must be accepted; each other case differs
# from it in one change, which Verifier2 must refuse. The query asks for
# birthdate too, the PID's one selectively disclosable claim, so there
# is a disclosure to change.
TAMPER_QUERY='{"credentials": [{"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": ["urn:eudi:pid:1"]}, "claims": [{"path": ["family_name"]}, {"path": ["birthdate"]}]}]}'
session_info() {
  local id="$1"
  curl -sS --max-time 30 "http://127.0.0.1:$VERIFIER2_HTTP/verification-session/$id/info"
}
tamper() {  # $1 mode: the session's info in tamper-$1-info.json, the wallet's outcome in tamper-$1.json
  local mode="$1" id link
  read -r id link <<< "$(session signed "$TAMPER_QUERY")"
  wallet "tamper-$mode" -issuer-ca ca.pem -verifier-ca ca.pem -offer "$(issuer2_offer eudiPidSdJwt)" -request "$link" \
    -tamper "$mode" -verifier2-key verifier2-key.pem
  session_info "$id" > "tamper-$mode-info.json"
}
tampered() {  # $1 mode: what was changed, Verifier2's answer and the session's status
  echo "$(jq -c '.tampered | {changed, reply}' "tamper-$1.json" 2>/dev/null | head -c 400), session $(jq -r '.status' "tamper-$1-info.json" 2>/dev/null)"
}
tamper relay
if jq -e '.stage == "done" and .tampered.changed == "nothing" and .tampered.reply.status == 200' tamper-relay.json >/dev/null \
    && jq -e '.status == "SUCCESSFUL"' tamper-relay-info.json >/dev/null; then
  ok "pid, relayed through the transport's own key and changed in nothing else: Verifier2 accepted it"
else bad "pid, relayed: $(why tamper-relay.json); $(tampered relay)"; fi
# refused_by_policy checks Verifier2 refused the presentation $1 changed
# by its VP policy $2: its answer to the response, which the wallet sees,
# and the session's status.
refused_by_policy() {  # $1 mode, $2 the policy, $3 what was changed
  local mode="$1" policy="$2" changed="$3"
  if jq -e --arg c "$changed" --arg p "Presentation validation failed. Failed VP policies: pid/dc+sd-jwt/$2" \
      '.stage == "response" and (.tampered.changed | startswith($c)) and .tampered.reply.status == 400
       and (.tampered.reply.body | fromjson | .error == "invalid_request" and .error_description == $p)' \
      "tamper-$mode.json" >/dev/null 2>&1 \
      && jq -e '.status == "FAILED"' "tamper-$mode-info.json" >/dev/null 2>&1; then
    ok "control: Verifier2 refuses a presentation whose $changed is another (400 invalid_request, VP policy $policy)"
  else bad "control: $changed changed: $(why "tamper-$mode.json"); $(tampered "$mode")"; fi
}
tamper nonce
refused_by_policy nonce nonce-check "KB-JWT nonce"
tamper aud
refused_by_policy aud audience-check "KB-JWT aud"
# A disclosure whose digest the Issuer-signed JWT doesn't carry (RFC
# 9901 §7.1): refused, for its digest. Verifier2 answers it as a
# dependency being unavailable (503 temporarily_unavailable), which
# tells a Wallet to try again, not as an invalid presentation: README
# finding 7, asserted as 1.2.1 answers so that a change is noticed.
tamper disclosure
DISCLOSURE_REFUSAL='Verification could not be completed because a dependency was unavailable: Invalid disclosures: 1 disclosures provided but only 0 are reachable from the payload hashes. Per RFC 9901 §7.1 step 5 this SD-JWT MUST be rejected.'
if jq -e --arg want "$DISCLOSURE_REFUSAL" '.stage == "response" and (.tampered.changed | startswith("disclosure "))
     and .tampered.reply.status == 503
     and (.tampered.reply.body | fromjson | .error == "temporarily_unavailable" and .error_description == $want)' \
    tamper-disclosure.json >/dev/null 2>&1 \
    && jq -e '.status == "FAILED"' tamper-disclosure-info.json >/dev/null 2>&1; then
  ok "control: Verifier2 refuses a presentation with a changed disclosure, for its digest (as 503 temporarily_unavailable: README finding 7)"
else bad "control: a changed disclosure: $(why tamper-disclosure.json); $(tampered disclosure)"; fi
# README finding 3: Verifier2 checks an SD-JWT VC's signature against
# its own x5c, not that the chain reaches a trust anchor. A known
# upstream gap, so a note, not a failure; but the run fails if it
# changes, so that the finding and this note are revisited.
tamper issuer
if jq -e '.stage == "done" and .tampered.changed == "Issuer-signed JWT signed by a self-signed certificate" and .tampered.reply.status == 200' \
    tamper-issuer.json >/dev/null 2>&1 && jq -e '.status == "SUCCESSFUL"' tamper-issuer-info.json >/dev/null 2>&1; then
  echo "  note  Verifier2 accepts a PID signed again by a self-signed certificate nobody configured it with (README finding 3): $(tampered issuer)"
else bad "a PID signed by a self-signed certificate: README finding 3 has changed (Verifier2 no longer accepts it); make it a control: $(why tamper-issuer.json); $(tampered issuer)"; fi

read -r id link <<< "$(session plain "$PID_QUERY")"
wallet present-unsigned -issuer-ca ca.pem -verifier-ca ca.pem -offer "$(issuer2_offer eudiPidSdJwt)" -request "$link"
# Verifier2 serves this request object as plain JSON: the wallet must
# refuse it as the request_uri's answer, for not being a signed one.
if jq -e '.stage == "request" and (.received | length == 1)
    and (.error | contains("fetch request_uri: fapihttp: response has an unexpected content type: got \"application/json\", want \"application/oauth-authz-req+jwt\""))' \
    present-unsigned.json >/dev/null && [[ "$(session_status "$id")" != SUCCESSFUL ]]; then
  ok "control: an unsigned request naming an x509_hash client is refused, as no signed request object"
else bad "control: an unsigned x509_hash request: $(why present-unsigned.json)"; fi
wallet present-untrusted-verifier -issuer-ca ca.pem -verifier-ca other-ca.pem -offer "$(issuer2_offer eudiPidSdJwt)" \
  -request "$(session signed "$PID_QUERY" | cut -d' ' -f2)"
if jq -e --arg want "$UNTRUSTED_ISSUER" '.stage == "request" and (.received | length == 1)
    and (.error | contains("parse authorization request: untrusted verifier: wallet: verifier certificate: " + $want))' \
    present-untrusted-verifier.json >/dev/null; then
  ok "control: a Verifier whose Access Certificate the wallet doesn't trust is refused, for its chain"
else bad "control: an untrusted Verifier: $(why present-untrusted-verifier.json)"; fi

# Verifier2's Access Certificate, checked against the run CA's CRL in
# every presentation above, here revoked by it.
wallet present-revoked-verifier -issuer-ca ca.pem -verifier-ca ca.pem -crl-set revoked-verifier \
  -offer "$(issuer2_offer eudiPidSdJwt)" -request "$(session signed "$PID_QUERY" | cut -d' ' -f2)"
if jq -e --arg want "$REVOKED" '.stage == "request" and (.received | length == 1)
    and (.error | contains("parse authorization request: untrusted verifier: wallet: verifier certificate: " + $want))' \
    present-revoked-verifier.json >/dev/null; then
  ok "control: a Verifier whose Access Certificate the CA revoked is refused, for that"
else bad "control: a revoked Verifier: $(why present-revoked-verifier.json)"; fi

echo "### OID4VCgo's issuer → OID4VCgo's wallet → walt.id Verifier2: status lists"
# Verifier2 checks the Token Status List entry of credentials OID4VCgo's
# issuer issued, from the list the issuer publishes (statuslist's
# Allocator and Publisher, in cmd/conformance-issuer): its VC policies
# are the signature and credential-status, IETF, value 0 (VALID). The
# wallet redeems the issuer's offer, attested by OID4VCgo's Wallet
# Provider (interop/walletprovider: walletprovider.Provider over sealed
# SQLite stores, its status lists served), then presents to a signed,
# encrypted session. In each control the issuer
# revokes the credentials after issuing them (POST /status, the
# wallet's -revoke), before the wallet presents one: the control
# differs from the case before it in that status alone.
#
# The issuer is a second instance of the base profile's, named
# localhost for OID4VCgo's wallet, its status lists published as
# https://$HOST:$STATUS_TAP_PORT/statuslists/1 (status_lists.base_url),
# which Verifier2 reaches through serve's tap. It runs its production
# setup (cmd/conformance-issuer's production): production assurance,
# sealed SQLite stores (its status lists' reservations among them),
# jwt proofs that must carry a key attestation, DPoP nonces; Wallet
# Attestations and Key Attestations trusted by their x5c chain to the
# Wallet Provider's CA, and their status checked on its lists, which
# it fetches from loopback (attestation_status_allow_loopback: the one
# setting a deployment wouldn't make; README.md).
start_wallet_provider "$WORK/walletprovider" "$WORK/wallet-provider" "$WP_PORT" "$WP_ADMIN_PORT" "$CLIENT_ID" \
  -identifier "$(jq -r '.attester_issuer' issuer-files/driver.json)"
PIDS+=($!)
wait_ready "http://127.0.0.1:$WP_ADMIN_PORT/ready"
# shellcheck disable=SC2016 # jq's variables, not the shell's
jq --arg issuer "https://localhost:$STATUS_ISSUER_PORT" --arg addr "127.0.0.1:$STATUS_ISSUER_PORT" \
  --arg offers "127.0.0.1:$STATUS_OFFERS_PORT" --arg lists "https://$HOST:$STATUS_TAP_PORT" \
  --arg db "$WORK/issuer-status.db" --arg key "$(sealing_key)" --arg atk "$(access_token_key)" \
  --rawfile wpca wallet-provider/ca.pem --rawfile wptls wallet-provider/tls-cert.pem \
  '.issuer = $issuer | .listen_addr = $addr | .offers.listen_addr = $offers | .status_lists.base_url = $lists
    | .production = {database_path: $db, sealing_key: $key, access_token_signing_key_pem: $atk,
        attestation_status_tls_trust_anchors_pem: $wptls, attestation_status_allow_loopback: true}
    | .client.attester_trust_anchors_pem = $wpca | .key_attestation = {trust_anchor_pem: $wpca} | .dpop_nonces = true' \
  issuer.json > issuer-status.json
./issuer -config issuer-status.json > issuer-status.log 2>&1 &
PIDS+=($!)
for _ in $(seq 1 50); do
  if curl -s -o /dev/null --max-time 1 --cacert ca.pem "https://localhost:$STATUS_ISSUER_PORT/.well-known/openid-credential-issuer"; then break; fi
  sleep 0.2
done
STATUS_POLICIES='{"vc_policies": ["signature", {"policy": "credential-status", "argument": {"discriminator": "ietf", "value": 0}}]}'
status_session() {  # $1 the DCQL query: prints the session's id and link
  curl -sS --max-time 30 -X POST -H "$JSON" \
    --data "$(jq -cn --argjson q "$1" --argjson p "$STATUS_POLICIES" \
      '{flow_type: "cross_device", core_flow: {signed_request: true, encrypted_response: true, dcql_query: $q, policies: $p}}')" \
    "http://127.0.0.1:$VERIFIER2_HTTP/verification-session/create" | jq -r '"\(.sessionId) \(.bootstrapAuthorizationRequestUrl)"'
}
status_offer() {  # $1 the configuration: an offer of it by OID4VCgo's second issuer
  curl -sS --max-time 30 -X POST -H "$JSON" \
    --data "$(jq -cn --arg c "$1" '{grant: "pre-authorized_code", credential_configuration_ids: [$c], by_reference: true}')" \
    "http://127.0.0.1:$STATUS_OFFERS_PORT/offers" | jq -r '.uri'
}
OUR_VCT="$(jq -r '.vct' issuer-files/driver.json)" OUR_DOCTYPE="$(jq -r '.doctype' issuer-files/driver.json)"
OUR_NAMESPACE="$(jq -r '.namespace' issuer-files/driver.json)"
OUR_PID_QUERY="$(jq -cn --arg v "$OUR_VCT" '{credentials: [{id: "pid", format: "dc+sd-jwt", meta: {vct_values: [$v]}, claims: [{path: ["family_name"]}]}]}')"
OUR_MDOC_QUERY="$(jq -cn --arg d "$OUR_DOCTYPE" --arg n "$OUR_NAMESPACE" '{credentials: [{id: "pid", format: "mso_mdoc", meta: {doctype_value: $d}, claims: [{path: [$n, "family_name"]}]}]}')"
# status_present has OID4VCgo's wallet redeem an offer of configuration
# $2 and present it to a status-checking session for query $3; $4,
# "revoked", has the issuer revoke it first. The wallet's outcome is in
# status-$1.json, the session's info in status-$1-info.json.
status_present() {  # $1 name, $2 configuration, $3 query, $4 "valid" or "revoked"
  local name="$1" config="$2" query="$3" id link revoke=()
  if [[ "$4" = revoked ]]; then revoke=(-revoke "http://127.0.0.1:$STATUS_OFFERS_PORT/status"); fi
  read -r id link <<< "$(status_session "$query")"
  # -crl-set none: OID4VCgo's issuer's CAs (setup-issuer's) publish no
  # CRL, so this wallet checks no certificate's revocation here.
  wallet "status-$name" -issuer-ca issuer-ca.pem -mdoc-issuer-ca iaca.pem -verifier-ca ca.pem -crl-set none \
    -wallet-provider "https://localhost:$WP_PORT" -wallet-provider-tls wallet-provider/tls-cert.pem -client-id "$CLIENT_ID" \
    -offer "$(status_offer "$config")" ${revoke[@]+"${revoke[@]}"} -request "$link"
  # Verifier2's first status check can outlast the wallet's wait for
  # its answer (on an emulated image, its status policy's first run
  # took 17 s): the session says what it decided once it has.
  for _ in $(seq 1 30); do
    session_info "$id" > "status-$name-info.json"
    if jq -e '.status == "SUCCESSFUL" or .status == "FAILED"' "status-$name-info.json" >/dev/null 2>&1; then break; fi
    sleep 1
  done
}
# answered reports whether the wallet's response reached Verifier2: it
# finished, or it gave up waiting for Verifier2's answer to it.
answered() {
  jq -e '.stage == "done" or (.stage == "response" and (.error | contains("may or may not have reached the verifier")))' "$1" >/dev/null 2>&1
}
# status_policy prints the credential-status policy's results in the
# session status-$1-info.json: success, and error when it failed.
status_policy() {
  jq -c '[.. | objects | select((.policy? | type) == "object" and .policy.id? == "credential-status")
    | {success, error: (.error // .result.error // null)}]' "status-$1-info.json" 2>/dev/null | head -c 600
}
STATUS_REFUSAL='Status validation failed: expected one of [0], but got 1'
for case in "pid eu.europa.ec.eudi.pid_vc_sd_jwt OUR_PID_QUERY" "mdoc eu.europa.ec.eudi.pid_mso_mdoc OUR_MDOC_QUERY"; do
  read -r name config query <<< "$case"
  status_present "$name" "$config" "${!query}" valid
  if answered "status-$name.json" && jq -e '.received[0].status_lists | length >= 1' "status-$name.json" >/dev/null 2>&1 \
      && jq -e '.status == "SUCCESSFUL"' "status-$name-info.json" >/dev/null 2>&1 \
      && [[ "$(status_policy "$name")" == *'"success":true'* ]]; then
    ok "$name from OID4VCgo's issuer, its status list entry $(jq -r '.received[0].status_lists[0]' "status-$name.json" | sed 's|.*/statuslists|/statuslists|'): Verifier2's credential-status policy passed, and it accepted it"
  else bad "$name from OID4VCgo's issuer: wallet $(why "status-$name.json"), session $(jq -r '.status' "status-$name-info.json" 2>/dev/null), credential-status $(status_policy "$name")"; fi
  status_present "$name-revoked" "$config" "${!query}" revoked
  if jq -e '(.revoked | length >= 1) and .stage != "done"' "status-$name-revoked.json" >/dev/null 2>&1 \
      && jq -e '.status == "FAILED"' "status-$name-revoked-info.json" >/dev/null 2>&1 \
      && [[ "$(status_policy "$name-revoked")" == *'"success":false'*"$STATUS_REFUSAL"* ]]; then
    ok "control: $name revoked by OID4VCgo's issuer after issuance: Verifier2 refuses it, by its credential-status policy ($STATUS_REFUSAL)"
  else bad "control: $name revoked by the issuer: wallet $(why "status-$name-revoked.json"), revoked $(jq -c '.revoked' "status-$name-revoked.json" 2>/dev/null), session $(jq -r '.status' "status-$name-revoked-info.json" 2>/dev/null), credential-status $(status_policy "$name-revoked")"; fi
done
# Each check Verifier2 made, it made by fetching the list from the
# issuer, through serve's tap, which nothing else calls: a run in which
# it fetched nothing didn't check status at all.
for path in /statuslists/1 /statuslists/1/cwt; do
  if grep -q " tap: GET \"$path\" 200" serve.log; then ok "Verifier2 fetched $path from OID4VCgo's issuer: $(grep " tap: GET \"$path\" 200" serve.log | head -1 | sed 's/.* | //')"
  else bad "Verifier2 fetched $path from OID4VCgo's issuer ($(grep ' tap: GET "/statuslists' serve.log | head -3 | sed 's/.* tap: //' | tr '\n' ';'))"; fi
done
# The issuer checked the wallet's attestations' status by fetching the
# Wallet Provider's list, the attestations being the provider's.
if grep -q ' served GET "/statuslists/{start}/{n}" 200' wallet-provider/wallet-provider.log \
    && grep -q ' served POST "/v1/wallet-attestation" 200' wallet-provider/wallet-provider.log \
    && grep -q ' served POST "/v1/key-attestation" 200' wallet-provider/wallet-provider.log; then
  ok "the Wallet Provider attested the wallet, and the issuer fetched its status list"
else bad "the Wallet Provider attested the wallet, and the issuer fetched its status list ($(grep ' served ' wallet-provider/wallet-provider.log | tail -5 | tr '\n' ';'))"; fi

W="http://127.0.0.1:$WALLET2_HTTP"
# wallet2 creates a Wallet2 wallet with a P-256 key, printing its id.
wallet2() {
  local id
  id="$(curl -sS --max-time 30 -X POST -H "$JSON" --data '{}' "$W/wallet" | jq -r '.walletId')"
  curl -sS --max-time 30 -o /dev/null -X POST -H "$JSON" \
    --data '{"backend": "jwk", "keyType": "secp256r1"}' "$W/wallet/$id/keys/generate"
  echo "$id"
}
receive2() {  # $1 wallet, $2 offer; then a client_id: Wallet2's answer to stdout
  local id="$1" offer="$2" client="${3:-}"
  curl -sS --max-time 90 -X POST -H "$JSON" \
    --data "$(jq -cn --arg o "$offer" --arg c "$client" '{offerUrl: $o} + (if $c == "" then {} else {clientId: $c} end)')" \
    "$W/wallet/$id/credentials/receive"
}
present2() {  # $1 wallet, $2 request: Wallet2's answer to stdout
  local id="$1" request="$2"
  curl -sS --max-time 90 -X POST -H "$JSON" \
    --data "$(jq -cn --arg r "$request" '{requestUrl: $r}')" "$W/wallet/$id/credentials/present"
}
# authorize starts a session on the verifier at port $1, as a
# same-device page would, and prints the openid4vp:// launch.
authorize() {
  local port="$1" method="$2"
  tls "$port" -o /dev/null -w '%{redirect_url}' "https://$HOST:$port/authorize?request_uri_method=$method"
}
# tx_authorize begins a request on the transactions verifier at port
# $1, as a deployment's page does, its browser binding kept in the
# cookie jar $2, and prints the openid4vp:// launch.
tx_authorize() {
  tls "$1" -c "$2" -o /dev/null -w '%{redirect_url}' "https://$HOST:$1/authorize"
}
# tx_result saves the transactions verifier's page for the request
# Wallet2 answered ($1, its answer): its redirect_to, the redirect_uri
# that redeems the response_code, when it has one, else the request's
# own page, /result/{id}, for the launch $2; both in the browser whose
# cookie jar is $3. Its HTML entities are decoded into $4.
tx_result() {
  local answer="$1" launch="$2" jar="$3" out="$4" url port
  url="$(jq -r '.redirect_to // .verifier_response.redirect_uri // empty' "$answer" 2>/dev/null || true)"
  if [[ -z "$url" ]]; then
    url="$(sed -E 's/.*[?&]request_uri=([^&]*).*/\1/' <<< "$launch")"
    url="$(printf '%b' "${url//%/\\x}")"
    url="${url/\/request\///result/}"
  fi
  port="$(sed -E 's|https://[^:/]+:([0-9]+).*|\1|' <<< "$url")"
  tls "$port" -b "$jar" "$url" 2>/dev/null \
    | sed -e 's/&#34;/"/g' -e "s/&#39;/'/g" -e 's/&lt;/</g' -e 's/&gt;/>/g' -e 's/&amp;/\&/g' > "$out" || true
}

# redeem follows Wallet2's redirect_to in $1 and redeems its
# response_code: the verifier's outcome is in $2.
redeem() {
  local answer="$1" outcome="$2" redirect port
  redirect="$(jq -r '.redirect_to // .verifier_response.redirect_uri // empty' "$answer" 2>/dev/null || true)"
  if [[ -z "$redirect" ]]; then echo '{"status": "no redirect_to"}' > "$outcome"; return; fi
  port="$(sed -E 's|https://[^:/]+:([0-9]+).*|\1|' <<< "$redirect")"
  tls "$port" -o /dev/null "$redirect" || true
  tls "$port" -o "$outcome" "${redirect/\?response_code=//redeem?response_code=}" || true
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
# Wallet2 reports the issuer's error code alone, not its description,
# so the reason is pinned by what differs from the cases above, which
# pass: the stand-in attester signed with its other key, and the
# issuer answered the Token Request, where Wallet2 presents the
# attestation, with 401 invalid_client.
if grep -q 'attester: untrusted attestation for' serve.log \
    && jq -e '.code == "401" and .message == "invalid_client" and .cause1_exception == "TokenRequestException"' \
      wallet2-receive-untrusted-attester.json >/dev/null 2>&1; then
  ok "control: a Wallet Attestation from an attester the issuer doesn't trust is refused (invalid_client at the Token Request)"
else bad "control: a Wallet Attestation from an untrusted attester: $(head -c 300 wallet2-receive-untrusted-attester.json)"; fi

echo "### walt.id Wallet2 → OID4VCgo's verifier, with those PIDs"
for method in none get post; do
  present2 "$holder" "$(authorize "$VERIFIER_PORT" "$method")" > "wallet2-present-pid-$method.json"
  redeem "wallet2-present-pid-$method.json" "result-pid-$method.json"
  if jq -e '.status == "verified" and (.credentials.cred1 | has("family_name") and has("given_name"))' "result-pid-$method.json" >/dev/null; then
    ok "sd-jwt pid, request_uri_method $method: verified (issuer, holder binding, response encrypted)"
  else bad "sd-jwt pid, request_uri_method $method: $(why "result-pid-$method.json")"; fi
done
# The rest through verifier.Transactions under production assurance:
# the result page, in the browser that began the request, says what
# the verifier decided.
launch="$(tx_authorize "$TX_VERIFIER_PORT" tx-pid.cookies)"
present2 "$holder" "$launch" > wallet2-present-pid-tx.json
tx_result wallet2-present-pid-tx.json "$launch" tx-pid.cookies result-pid-tx.html
if grep -q '<h1>Verification succeeded</h1>' result-pid-tx.html && grep -q '"family_name"' result-pid-tx.html \
    && grep -q '"given_name"' result-pid-tx.html; then
  ok "sd-jwt pid through verifier.Transactions under production assurance, request_uri_method post: verified, released to the browser that asked"
else bad "sd-jwt pid through verifier.Transactions: $(sed 's/<[^>]*>/ /g' result-pid-tx.html | head -c 300)"; fi
launch="$(tx_authorize $((VERIFIER_PORT + 1)) tx-mdoc.cookies)"
present2 "$holder" "$launch" > wallet2-present-mdoc.json
tx_result wallet2-present-mdoc.json "$launch" tx-mdoc.cookies result-mdoc.html
if grep -q '<h1>Verification succeeded</h1>' result-mdoc.html && grep -q '"family_name"' result-mdoc.html \
    && grep -q '"given_name"' result-mdoc.html && ! grep -qE '"(birth_date|nationality|issuing_country)"' result-mdoc.html; then
  ok "mdoc pid through verifier.Transactions under production assurance: verified, only the requested elements disclosed"
else bad "mdoc pid: $(sed 's/<[^>]*>/ /g' result-mdoc.html | head -c 300)"; fi
launch="$(tx_authorize $((VERIFIER_PORT + 2)) tx-untrusted-access.cookies)"
present2 "$holder" "$launch" > wallet2-present-untrusted-access.json || true
if jq -e '.id == "SignedAuthorizationRequestValidationException" and (.message | contains("X509TrustAnchorMismatch"))' \
    wallet2-present-untrusted-access.json >/dev/null 2>&1 \
    && ! jq -e '.redirect_to // .verifier_response.redirect_uri' wallet2-present-untrusted-access.json >/dev/null 2>&1; then
  ok "control: Wallet2 doesn't answer a Verifier whose Access Certificate it doesn't trust (X509TrustAnchorMismatch)"
else bad "control: a Verifier whose Access Certificate Wallet2 doesn't trust: $(head -c 300 wallet2-present-untrusted-access.json)"; fi
launch="$(tx_authorize $((VERIFIER_PORT + 3)) tx-untrusted-issuer.cookies)"
present2 "$holder" "$launch" > wallet2-present-untrusted-issuer.json || true
tx_result wallet2-present-untrusted-issuer.json "$launch" tx-untrusted-issuer.cookies result-untrusted-issuer.html
# Refused by the verifier, for the issuer's chain (its verifier.Reason
# untrusted_issuer, and the error): not a presentation that never
# arrived, nor one refused for something else.
if grep -q '<h1>Verification failed</h1>' result-untrusted-issuer.html \
    && grep -qF '<pre>reason: untrusted_issuer</pre>' result-untrusted-issuer.html \
    && grep -qF "verifier: resolve issuer key: $UNTRUSTED_ISSUER" result-untrusted-issuer.html; then
  ok "control: the verifier refuses a credential from an issuer it doesn't trust, for its chain (untrusted_issuer)"
else bad "control: a credential from an issuer the verifier doesn't trust: $(sed 's/<[^>]*>/ /g' result-untrusted-issuer.html | head -c 400)"; fi

echo "### walt.id Wallet2 ← OID4VCgo's issuer, its other profiles"
# The base profile's issuances above, as the tap saw them. Of what
# SPECIFICATIONS.md's "Known leniencies" concern, Wallet2 sends a Client
# Attestation PoP with the iss draft-07 §5.2 requires (the client_id);
# its DPoP proofs' jwk has no alg, which RFC 9449 doesn't ask for.
# Asserted as 1.2.1 sends them, so that a change is noticed (README.md,
# "What walt.id sends").
grep ' tap: ' serve.log > tap-base.log || true
SENT_TOKEN="\"/token\" 200 | pop iss=\"$CLIENT_ID\" claims=aud,exp,iat,iss,jti | dpop typ=\"dpop+jwt\" alg=\"ES256\" jwk.alg=absent nonce=false claims=htm,htu,iat,jti"
echo "        observed: $(grep -F "$SENT_TOKEN" tap-base.log | head -1 | sed 's/.* tap: //')"
if [[ "$(grep -cF "$SENT_TOKEN" tap-base.log)" -ge 2 ]] && ! grep -q 'pop iss=absent' tap-base.log; then
  ok "observed: Wallet2's Client Attestation PoP names the client_id as iss, each time"
else bad "observed: what Wallet2 sends the Token Endpoint changed: $(grep '"/token"' tap-base.log | head -3 | sed 's/.* tap: //' | tr '\n' ';')"; fi

# receive_profile has a fresh Wallet2 wallet redeem an offer of the
# SD-JWT VC PID from the issuer in profile $1; its answer is in
# wallet2-$1.json, and what it sent, as the tap saw it, in tap-$1.log.
receive_profile() {
  local profile="$1" from
  PROFILE_WALLET="$(wallet2)"
  from="$(wc -l < serve.log)"
  receive2 "$PROFILE_WALLET" "$(our_offer eu.europa.ec.eudi.pid_vc_sd_jwt)" "$CLIENT_ID" > "wallet2-$profile.json" || true
  tail -n +"$((from + 1))" serve.log | grep ' tap: ' | sed 's/.* tap: //' > "tap-$profile.log" || true
}

start_issuer dpop-nonces '.dpop_nonces = true'
receive_profile dpop-nonces
# The issuer challenges at the Token Endpoint (400 use_dpop_nonce, with
# a DPoP-Nonce, RFC 9449 §8) and the Credential Endpoint (401, §9);
# Wallet2 retries each with the nonce.
if jq -e '.credentialIds | length == 1' wallet2-dpop-nonces.json >/dev/null 2>&1 \
    && grep -q '^POST "/token" 400 .*nonce=false.*dpop-nonce-sent' tap-dpop-nonces.log \
    && grep -q '^POST "/token" 200 .*nonce=true' tap-dpop-nonces.log \
    && grep -q '^POST "/credential" 401 .*nonce=false.*challenge=use_dpop_nonce' tap-dpop-nonces.log \
    && grep -q '^POST "/credential" 200 .*nonce=true' tap-dpop-nonces.log; then
  ok "dpop-nonces: issued; the Token and Credential Endpoints each asked for a DPoP nonce, and Wallet2 retried with it"
else bad "dpop-nonces: $(head -c 300 wallet2-dpop-nonces.json); $(tr '\n' ';' < tap-dpop-nonces.log | head -c 600)"; fi

start_issuer deferred '.deferred = true'
receive_profile deferred
# Wallet2 keeps the deferred credential's handle; resuming it polls the
# Deferred Credential Endpoint once the interval the issuer asked for
# has passed (earlier, it answers "deferred" without polling).
handle="$(curl -sS --max-time 30 "$W/wallet/$PROFILE_WALLET/credentials/receive/deferred" | jq -r '.[0].id // empty' 2>/dev/null || true)"
from="$(wc -l < serve.log)"
if [[ -n "$handle" ]]; then
  for _ in 1 2 3 4; do
    curl -sS --max-time 90 -X POST "$W/wallet/$PROFILE_WALLET/credentials/receive/deferred/$handle" > wallet2-deferred-resumed.json || true
    if ! jq -e '.type == "deferred"' wallet2-deferred-resumed.json >/dev/null 2>&1; then break; fi
    sleep "$(jq -r '[.credentials[0].intervalSeconds // 5, 10] | min' wallet2-deferred-resumed.json)"
  done
fi
tail -n +"$((from + 1))" serve.log | grep ' tap: ' | sed 's/.* tap: //' > tap-deferred-poll.log || true
if [[ -n "$handle" ]] && grep -q '^POST "/credential" 202' tap-deferred.log \
    && grep -q '^POST "/[a-z_-]*deferred[a-z_-]*" 200' tap-deferred-poll.log \
    && jq -e '.type == "stored" and (.credentialIds | length == 1)' wallet2-deferred-resumed.json >/dev/null 2>&1; then
  ok "deferred: deferred (202), then issued from the Deferred Credential Endpoint when Wallet2 resumed it"
else bad "deferred: handle '$handle'; $(head -c 300 wallet2-deferred.json); $(head -c 300 wallet2-deferred-resumed.json 2>/dev/null); $(tr '\n' ';' < tap-deferred-poll.log | head -c 300)"; fi

start_issuer key-attestation '.key_attestation.jwt_proof_requires_key_attestation = true'
receive_profile key-attestation
# Not a control: the Wallet2 service attaches no key attestation
# provider, and its REST keys aren't the Crypto2 keys one needs
# (README.md, "What isn't covered"), so it stops before its Credential
# Request when the issuer requires a key attestation. If it's issued,
# the run says so.
KA_REFUSAL='Key attestation requires a Crypto2 holder key'
if jq -e '.credentialIds | length == 1' wallet2-key-attestation.json >/dev/null 2>&1; then
  echo "  note  key-attestation: issued: Wallet2 now sends a key attestation; make this a case"
elif jq -e --arg want "$KA_REFUSAL" '.code == "400" and .message == $want' wallet2-key-attestation.json >/dev/null 2>&1 \
    && ! grep -q '"/credential"' tap-key-attestation.log; then
  echo "  note  key-attestation: not supported by Wallet2 1.2.1, which sent no Credential Request: $KA_REFUSAL"
else bad "key-attestation: neither issued nor refused before its Credential Request: $(head -c 300 wallet2-key-attestation.json)"; fi

if [[ "$fail" -eq 0 ]]; then echo "RESULT: every case passed, and every control refused"; else echo "RESULT: FAILED"; fi
exit "$fail"
