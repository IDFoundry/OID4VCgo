#!/usr/bin/env bash
# OID4VCgo's wallet against EUDIPLO's Verifier
# (openwallet-foundation-labs/eudiplo), run from its published image
# pinned by digest:
#
#   our issuer → our wallet →     cmd/conformance-issuer's production
#     EUDIPLO's Verifier          setup issues SD-JWT VC and mdoc PIDs,
#                                 the wallet (walletflow) attested by
#                                 OID4VCgo's Wallet Provider; EUDIPLO's
#                                 signed x509_hash request, DCQL, the
#                                 response encrypted (direct_post.jwt),
#                                 each credential trusted by EUDIPLO's
#                                 trust list naming the issuer's CAs and
#                                 its Token Status List entry checked;
#                                 then the same over the Digital
#                                 Credentials API (dc_api.jwt) and, for
#                                 the mdoc, ISO/IEC TS 18013-7 Annex C
#                                 (org-iso-mdoc)
#
# then controls EUDIPLO must refuse, each by the reason its session
# gives (failureCode, errorReason): a credential the issuer revoked,
# presentations changed on their way to EUDIPLO, an Annex C answer for
# another origin; and the wallet's own refusals. Then (issuer.sh):
#
#   EUDIPLO's issuer →            pre-authorized code offers with a
#     our wallet                  tx_code, SD-JWT VC and mdoc PIDs in
#                                 batches, DPoP, encrypted requests and
#                                 responses, Wallet and Key Attestations
#                                 from a second instance of OID4VCgo's
#                                 Wallet Provider, which EUDIPLO's trust
#                                 list names; the wallet checks each
#                                 credential's status on EUDIPLO's lists
#
# and controls, each refused by EUDIPLO's OAuth error or the wallet's
# own. See README.md.
#
#   interop/eudiplo/run.sh
#   EUDIPLO_TAG=latest interop/eudiplo/run.sh
#
# Needs docker, go, jq, curl and openssl. Exits 0 only if every case
# behaves as expected.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="${OID4VCGO_SRC:-$(cd "$HERE/../.." && pwd)}"

# 10.1.0, read from ghcr.io on 2026-11-25. Move it only after reading
# the release's changes (README.md, "Moving the pin").
EUDIPLO_IMAGE=ghcr.io/eudiplo/eudiplo@sha256:917406fe2be9843a2dadfa3d835ec6da1b00b19fee65523f282ca97134065462 # 10.1.0
if [[ -n "${EUDIPLO_TAG:-}" ]]; then EUDIPLO_IMAGE="ghcr.io/eudiplo/eudiplo:$EUDIPLO_TAG"; fi

# EUDIPLO is https://localhost:$EUDIPLO_PORT to the wallet, terminating
# TLS itself; what it fetches from its container (OID4VCgo's issuer's
# status lists) is $HOST, which the container maps to this host.
HOST=eudiplo.test
BASE_PORT="${BASE_PORT:-21700}"
EUDIPLO_PORT=$((BASE_PORT + 1))
# OID4VCgo's issuer (named localhost, for walletflow's development
# fetcher) and its offers listener; serve's tap in front of its status
# lists, as $HOST; OID4VCgo's Wallet Provider and its admin listener.
ISSUER_PORT=$((BASE_PORT + 2)) OFFERS_PORT=$((BASE_PORT + 3)) TAP_PORT=$((BASE_PORT + 4))
WP_PORT=$((BASE_PORT + 5)) WP_ADMIN_PORT=$((BASE_PORT + 6))
# The Wallet Provider EUDIPLO's issuer trusts (issuer.sh), its admin
# listener, and a second tap, in front of its status lists, as $HOST.
EWP_PORT=$((BASE_PORT + 7)) EWP_ADMIN_PORT=$((BASE_PORT + 8)) EWP_TAP_PORT=$((BASE_PORT + 9))
WORK="${WORK:-$(mktemp -d)}"
NAME="${COMPOSE_PROJECT_NAME:-oid4vcgo-eudiplo}"
# The client_id interop/eudi/scripts/setup-issuer registers, which the
# Wallet Provider attests the wallet as.
CLIENT_ID=oid4vcgo-eudi-interop-wallet

for p in $(seq "$EUDIPLO_PORT" "$EWP_TAP_PORT"); do
  if (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then
    echo "port $p is in use; set BASE_PORT" >&2
    exit 2
  fi
done

# EUDIPLO's container reaches this host's listeners as $HOST: Docker
# Desktop maps host-gateway to the host's loopback; on Linux it's the
# default bridge's gateway, which the tap then binds.
TAP_BIND=127.0.0.1
if [[ "$(uname)" = Linux ]]; then
  TAP_BIND="$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')"
fi

PIDS=()
# shellcheck disable=SC2329 # run by the EXIT trap
cleanup() {
  for pid in ${PIDS[@]+"${PIDS[@]}"}; do kill "$pid" 2>/dev/null || true; done
  for pid in ${PIDS[@]+"${PIDS[@]}"}; do wait "$pid" 2>/dev/null || true; done
  docker logs "$NAME" > "$WORK/eudiplo.log" 2>&1 || true
  docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "work dir    $WORK"
echo "oid4vcgo    $SRC, commit $(git -C "$SRC" rev-parse HEAD 2>/dev/null || echo unknown)"
echo "eudiplo     $EUDIPLO_IMAGE"

# shellcheck source=../production.sh
. "$HERE/../production.sh"
mkdir -p "$WORK/issuer-files"
build_production "$WORK" "$SRC" issuer=./cmd/conformance-issuer walletprovider=./interop/walletprovider
(cd "$SRC" && go build -o "$WORK/serve" ./interop/waltid/scripts/serve \
  && go build -o "$WORK/wallet" ./interop/waltid/scripts/wallet \
  && go run ./interop/eudi/scripts/setup-issuer -out "$WORK/issuer-files" -port "$ISSUER_PORT" -offers-port "$OFFERS_PORT")
cd "$WORK"
jq -r '.issuer_ca_pem' issuer-files/driver.json > issuer-ca.pem
jq -r '.iaca_pem' issuer-files/driver.json > iaca.pem
# The Wallet Provider for EUDIPLO's issuer, a second instance of
# OID4VCgo's (issuer.sh): its status lists published as
# https://$HOST:$EWP_TAP_PORT/statuslists (its -base-url), where
# EUDIPLO fetches them through serve's second tap.
start_wallet_provider "$WORK/walletprovider" "$WORK/wallet-provider-eudiplo" "$EWP_PORT" "$EWP_ADMIN_PORT" "$CLIENT_ID" \
  -base-url "https://$HOST:$EWP_TAP_PORT" -ca-name "OID4VCgo EUDIPLO interop Wallet Provider CA"
PIDS+=($!)
wait_ready "http://127.0.0.1:$EWP_ADMIN_PORT/ready"
(cd "$SRC" && go run ./interop/eudiplo/scripts/setup -out "$WORK" -host "$HOST" -issuer-ca "$WORK/issuer-ca.pem" -iaca "$WORK/iaca.pem" \
  -wallet-provider-ca "$WORK/wallet-provider-eudiplo/ca.pem" -public-url "https://localhost:$EUDIPLO_PORT")

# OID4VCgo's issuer, as a deployment runs it (its production setup:
# production assurance, sealed SQLite stores, its status lists'
# reservations among them, jwt proofs that must carry a Key
# Attestation, DPoP nonces), its Wallet Attestations and Key
# Attestations trusted by their x5c chain to the Wallet Provider's CA
# and their status checked on its lists, which it fetches from
# loopback (attestation_status_allow_loopback, the one setting a
# deployment wouldn't make). Its status lists are published as
# https://$HOST:$TAP_PORT/statuslists/1 (status_lists.base_url), which
# EUDIPLO fetches through serve's tap; the tap logs each fetch.
start_wallet_provider "$WORK/walletprovider" "$WORK/wallet-provider" "$WP_PORT" "$WP_ADMIN_PORT" "$CLIENT_ID" \
  -identifier "$(jq -r '.attester_issuer' issuer-files/driver.json)"
PIDS+=($!)
wait_ready "http://127.0.0.1:$WP_ADMIN_PORT/ready"
# shellcheck disable=SC2016 # jq's variables, not the shell's
jq --arg issuer "https://localhost:$ISSUER_PORT" --arg addr "127.0.0.1:$ISSUER_PORT" \
  --arg offers "127.0.0.1:$OFFERS_PORT" --arg lists "https://$HOST:$TAP_PORT" \
  --arg db "$WORK/issuer.db" --arg key "$(sealing_key)" --arg atk "$(access_token_key)" \
  --rawfile cert tls-cert.pem --rawfile tlskey tls-key.pem \
  --rawfile wpca wallet-provider/ca.pem --rawfile wptls wallet-provider/tls-cert.pem \
  '.issuer = $issuer | .listen_addr = $addr | .offers.listen_addr = $offers | .status_lists.base_url = $lists
    | .tls_certificate_pem = $cert | .tls_private_key_pem = $tlskey
    | .production = {database_path: $db, sealing_key: $key, access_token_signing_key_pem: $atk,
        attestation_status_tls_trust_anchors_pem: $wptls, attestation_status_allow_loopback: true}
    | .client.attester_trust_anchors_pem = $wpca | .key_attestation = {trust_anchor_pem: $wpca} | .dpop_nonces = true' \
  issuer-files/issuer.json > issuer.json
./issuer -config issuer.json > issuer.log 2>&1 &
PIDS+=($!)
./serve -dir . -tap "$TAP_BIND:$TAP_PORT=https://127.0.0.1:$ISSUER_PORT" -tap-name localhost > serve.log 2>&1 &
PIDS+=($!)
# The second tap dials the Wallet Provider under its own, self-signed,
# TLS certificate: its directory's ca.pem.
mkdir -p ewp-tap
cp tls-cert.pem tls-key.pem ewp-tap/ && cp wallet-provider-eudiplo/tls-cert.pem ewp-tap/ca.pem
./serve -dir ewp-tap -tap "$TAP_BIND:$EWP_TAP_PORT=https://127.0.0.1:$EWP_PORT" -tap-name localhost > ewp-serve.log 2>&1 &
PIDS+=($!)

# EUDIPLO, as its docker-compose.yml runs it, but: its config folder
# (FOLDER, CONFIG_FOLDER) setup's, imported at startup into a fresh
# SQLite database (CONFIG_IMPORT_MODE replace, aborting on any variable
# it can't resolve); its own TLS listener under the run's CA, which it
# also fetches its own trust lists from, inside its container
# (INTERNAL_URL: PUBLIC_URL's port is this host's); the run's
# CA, and only it beside Node's roots, for the status lists it fetches
# (NODE_ENV production, the image's, verifies their TLS); outbound
# calls to $HOST only, which is a private address
# (OUTBOUND_URL_ALLOW_PRIVATE_NETWORK, OUTBOUND_URL_ALLOWED_HOSTS); and
# each session's failures logged with it (LOG_SESSION_STORE errors),
# for the controls' reasons. The secrets are this run's.
mkdir -p eudiplo/tls
cp tls-cert.pem tls-key.pem ca.pem eudiplo/tls/
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" -p "127.0.0.1:$EUDIPLO_PORT:3000" --add-host "$HOST:host-gateway" \
  -v "$WORK/eudiplo:/app/config" \
  -e MASTER_SECRET="$(openssl rand -hex 32)" -e AUTH_CLIENT_ID=root -e AUTH_CLIENT_SECRET="$(openssl rand -hex 32)" \
  -e PUBLIC_URL="https://localhost:$EUDIPLO_PORT" -e INTERNAL_URL=https://localhost:3000 \
  -e TLS_ENABLED=true -e TLS_CERT_PATH=/app/config/tls/tls-cert.pem -e TLS_KEY_PATH=/app/config/tls/tls-key.pem \
  -e NODE_EXTRA_CA_CERTS=/app/config/tls/ca.pem \
  -e OUTBOUND_URL_ALLOW_PRIVATE_NETWORK=true -e OUTBOUND_URL_ALLOWED_HOSTS="$HOST" \
  -e CONFIG_IMPORT_MODE=replace -e CONFIG_VARIABLE_STRICT=abort -e LOG_ENABLE_SESSION_LOGGER=true -e LOG_SESSION_STORE=errors \
  -e STATUS_IMMEDIATE_UPDATE=true \
  "$EUDIPLO_IMAGE" >/dev/null

E="https://localhost:$EUDIPLO_PORT"
api() { curl -sS --max-time 30 --cacert ca.pem "$@"; }
for _ in $(seq 1 120); do
  if api -o /dev/null -f "$E/health" 2>/dev/null; then break; fi
  sleep 1
done
api -o /dev/null -f "$E/health" || { echo "EUDIPLO did not start; see $WORK/eudiplo.log" >&2; exit 2; }
for _ in $(seq 1 50); do
  if curl -s -o /dev/null --max-time 1 --cacert ca.pem "https://localhost:$ISSUER_PORT/.well-known/openid-credential-issuer"; then break; fi
  sleep 0.2
done
echo "eudiplo     $(docker inspect -f '{{index .Config.Labels "org.opencontainers.image.version"}} {{.Image}}' "$NAME" 2>/dev/null)"

# The tenant's API client, setup's: a token for EUDIPLO's management
# API. Every case below asks for family_name (and the SD-JWT VC's
# birth_date) alone, and checks EUDIPLO received no given_name.
TOKEN="$(api -X POST "$E/api/oauth2/token" -d grant_type=client_credentials \
  --data-urlencode client_id="$(jq -r .id client.json)" --data-urlencode client_secret="$(jq -r .secret client.json)" | jq -r .access_token)"
AUTH="Authorization: Bearer $TOKEN"
JSON='Content-Type: application/json'

fail=0
ok() { echo "  ok    $1"; }
bad() { echo "  FAIL  $1"; fail=1; }

# request creates a cross-device request of presentation config $1,
# printing its session id and the link the wallet opens.
request() {
  local config="$1"
  api -X POST -H "$AUTH" -H "$JSON" --data "$(jq -cn --arg c "$config" '{response_type: "uri", requestId: $c}')" \
    "$E/api/verifier/offer" | jq -r '"\(.session) \(.crossDeviceUri)"'
}
# session writes session $1's outcome (status, failureCode,
# errorReason, outcome, credentials) to $2-session.json, and its log to
# $2-session-log.json.
session() {
  local id="$1" name="$2"
  api -H "$AUTH" "$E/api/session/$id" | jq '{status, failureCode, errorReason, outcome, credentials}' > "$name-session.json"
  api -H "$AUTH" "$E/api/session/$id/logs" > "$name-session-log.json" 2>/dev/null || true
}
# offer is a pre-authorized code offer of OID4VCgo's issuer's
# configuration $1, by reference.
offer() {
  local config="$1"
  api -X POST -H "$JSON" \
    --data "$(jq -cn --arg c "$config" '{grant: "pre-authorized_code", credential_configuration_ids: [$c], by_reference: true}')" \
    "http://127.0.0.1:$OFFERS_PORT/offers" | jq -r '.uri'
}
# present has OID4VCgo's wallet redeem an offer of configuration $2,
# attested by the Wallet Provider, and answer a request of EUDIPLO's
# presentation config $3; the rest are the wallet's options. Its
# outcome is in $1-wallet.json, the session's in $1-session.json.
present() {
  local name="$1" config="$2" pres="$3" id link
  shift 3
  read -r id link <<< "$(request "$pres")"
  # -crl-set none: no CA of the run publishes a CRL.
  ./wallet -tls-ca ca.pem -issuer-ca issuer-ca.pem -mdoc-issuer-ca iaca.pem -verifier-ca ca.pem -crl-set none \
    -wallet-provider "https://localhost:$WP_PORT" -wallet-provider-tls wallet-provider/tls-cert.pem -client-id "$CLIENT_ID" \
    -offer "$(offer "$config")" -request "$link" -out "$name-wallet.json" "$@" >> "wallet-$name.log" 2>&1 \
    || echo '{"stage": "wallet", "error": "the wallet failed; see its log"}' > "$name-wallet.json"
  session "$id" "$name"
}
why() {  # $1 name: the wallet's stage and error, and the session's outcome
  local name="$1"
  echo "wallet $(jq -c '{stage, error, tampered: (.tampered.changed // null)} | with_entries(select(.value != null))' "$name-wallet.json" 2>/dev/null | cut -c1-300)," \
    "session $(jq -c '{status, failureCode, errorReason}' "$name-session.json" 2>/dev/null | cut -c1-300)"
}
SDJWT=eu.europa.ec.eudi.pid_vc_sd_jwt MDOC=eu.europa.ec.eudi.pid_mso_mdoc

echo "### OID4VCgo's issuer → OID4VCgo's wallet → EUDIPLO's Verifier"
for case in "sdjwt $SDJWT pid-sdjwt" "mdoc $MDOC pid-mdoc"; do
  read -r name config pres <<< "$case"
  present "$name" "$config" "$pres"
  if jq -e '.stage == "done" and (.received[0].status_lists | length >= 1)' "$name-wallet.json" >/dev/null 2>&1 \
      && jq -e '.status == "completed" and .outcome.result == "success" and (.outcome.credentials[0].verified == true)
        and (.credentials[0].values[0] | has("family_name") and (has("given_name") | not))' "$name-session.json" >/dev/null 2>&1; then
    ok "$name: presented to a signed x509_hash request, encrypted; EUDIPLO verified it, its issuer matched by the trust list ($(jq -r '.outcome.credentials[0].trust.matchedIssuer // "?"' "$name-session.json")), disclosed $(jq -c '[.credentials[0].values[0] | keys[]]' "$name-session.json")"
  else bad "$name: $(why "$name")"; fi
done

# Each was checked against its status list entry: EUDIPLO fetched the
# issuer's list, through serve's tap, which nothing else calls (the
# SD-JWT VC's as a JWT, the mdoc's as a CWT).
for path in /statuslists/1 /statuslists/1/cwt; do
  if grep -q " tap: GET \"$path\" 200" serve.log; then ok "EUDIPLO fetched $path from OID4VCgo's issuer: $(grep " tap: GET \"$path\" 200" serve.log | head -1 | sed 's/.* | //')"
  else bad "EUDIPLO fetched $path from OID4VCgo's issuer ($(grep ' tap: GET' serve.log | head -3 | sed 's/.* tap: //' | tr '\n' ';'))"; fi
done

# EUDIPLO's response encryption key, in each signed request's
# client_metadata: one key, with the alg and kid OpenID4VP 1.0 §8.3
# asks for, as 10.1.0 sends it (README.md, "What EUDIPLO sends").
echo "        observed: $(jq -c -s '[.[].observed.verifier_jwks]' sdjwt-wallet.json mdoc-wallet.json)"
if jq -s -e 'all(.[].observed.verifier_jwks; length == 1 and .[0].alg == "ECDH-ES" and (.[0].kid | length > 0))' \
    sdjwt-wallet.json mdoc-wallet.json >/dev/null; then
  ok "observed: EUDIPLO's response encryption JWK carries alg ECDH-ES and a kid"
else bad "observed: EUDIPLO's response encryption JWK changed: $(jq -c -s '[.[].observed.verifier_jwks]' sdjwt-wallet.json mdoc-wallet.json)"; fi

# refused checks EUDIPLO refused presentation $1: the wallet's response
# answered 400, the session failed by the verifier's decision, its
# failureCode $2 ("" for a failure EUDIPLO doesn't classify) and its
# errorReason containing $3; with $5, the session's log (its errors,
# LOG_SESSION_STORE) contains that too. A failure of the run itself
# (setup, the wallet before its response) is not a refusal.
refused() {  # $1 name, $2 failureCode or "", $3 in errorReason, $4 what the control is[, $5 in the session's log]
  local name="$1" code="$2" reason="$3" what="$4" logged="${5:-}"
  if jq -e '.stage == "response" and (.error | contains("verifier rejected the authorization response: status 400"))' \
      "$name-wallet.json" >/dev/null 2>&1 \
      && jq -e --arg c "$code" --arg r "$reason" '.status == "failed" and .outcome.source == "verifier"
        and (.failureCode // "") == $c and (.errorReason | contains($r))' "$name-session.json" >/dev/null 2>&1 \
      && { [[ -z "$logged" ]] || jq -e --arg l "$logged" 'any(.[]; .message | contains($l))' "$name-session-log.json" >/dev/null 2>&1; }; then
    ok "control: $what: EUDIPLO refuses it ($(jq -r '"\(.failureCode // "unclassified"): \(.errorReason)"' "$name-session.json" | cut -c1-200)${logged:+; its log: $logged})"
  else bad "control: $what: $(why "$name"), log $(jq -c '[.[].message]' "$name-session-log.json" 2>/dev/null | cut -c1-300)"; fi
}

# Revocation: OID4VCgo's issuer revokes every copy it issued (its POST
# /status, the wallet's -revoke) before the wallet presents one, so
# each control differs from the case above in that status alone.
# EUDIPLO caches a status list for its ttl, five minutes without one
# (the issuer's tokens carry none), so the run clears the tenant's
# cached status lists first (DELETE /api/cache/status-list), and
# checks the tap saw EUDIPLO fetch the list again.
# A revoked SD-JWT VC is refused unclassified, its errorReason naming
# the status; a revoked mdoc as trust_list_unavailable ("The trusted
# list could not be loaded"), the status named only in the session's
# log: README finding 1, asserted as 10.1.0 answers so that a change is
# noticed.
for case in "sdjwt $SDJWT pid-sdjwt /statuslists/1" "mdoc $MDOC pid-mdoc /statuslists/1/cwt"; do
  read -r name config pres path <<< "$case"
  before="$(grep -c " tap: GET \"$path\" 200" serve.log || true)"
  api -o /dev/null -X DELETE -H "$AUTH" "$E/api/cache/status-list"
  present "$name-revoked" "$config" "$pres" -revoke "http://127.0.0.1:$OFFERS_PORT/status"
  if ! jq -e '.revoked | length >= 1' "$name-revoked-wallet.json" >/dev/null 2>&1; then
    bad "control: $name revoked: the issuer revoked nothing: $(why "$name-revoked")"; continue
  fi
  after="$(grep -c " tap: GET \"$path\" 200" serve.log || true)"
  if [[ "$after" -le "$before" ]]; then bad "control: $name revoked: EUDIPLO didn't fetch $path again ($before, then $after fetches)"; fi
  if [[ "$name" = sdjwt ]]; then
    refused "$name-revoked" "" "Presentation validation failed: Status is not valid" "the SD-JWT VC revoked by OID4VCgo's issuer after issuance"
  else
    refused "$name-revoked" trust_list_unavailable "The trusted list could not be loaded" \
      "the mdoc revoked by OID4VCgo's issuer after issuance (README finding 1)" "is not Valid (0), but is instead '1'"
  fi
done

# Negative presentations: the wallet's transport changes the SD-JWT VC
# presentation on its way to EUDIPLO (interop/waltid/scripts/wallet's
# -tamper, tamper.go), as an attacker relaying it would: it replaces
# the request object's response encryption key with its own, signs the
# request again with EUDIPLO's Access Certificate key (setup's
# verifier-key.pem), decrypts the wallet's response, makes its one
# change, and encrypts it again to EUDIPLO. The relay case changes
# nothing else and must be accepted; each other case differs from it in
# its one change.
present tamper-relay "$SDJWT" pid-sdjwt -tamper relay -verifier2-key verifier-key.pem
if jq -e '.stage == "done" and .tampered.changed == "nothing" and .tampered.reply.status == 200' tamper-relay-wallet.json >/dev/null 2>&1 \
    && jq -e '.status == "completed"' tamper-relay-session.json >/dev/null 2>&1; then
  ok "sdjwt, relayed through the transport's own key and changed in nothing else: EUDIPLO verified it"
else bad "sdjwt, relayed: $(why tamper-relay)"; fi
for c in "nonce|Key Binding JWT's nonce|Presentation validation failed: Verify Error: Invalid Nonce" \
  "aud|Key Binding JWT's aud|Presentation validation failed: Invalid key binding JWT audience" \
  "disclosure|disclosure's value (its digest no longer the Issuer's)|Presentation validation failed: Unreferenced disclosure(s) detected in SD-JWT"; do
  IFS='|' read -r mode what reason <<< "$c"
  present "tamper-$mode" "$SDJWT" pid-sdjwt -tamper "$mode" -verifier2-key verifier-key.pem
  refused "tamper-$mode" "" "$reason" "the $what another"
done
# The Issuer-signed JWT signed again under a self-signed certificate,
# which no trust list names.
present tamper-issuer "$SDJWT" pid-sdjwt -tamper issuer -verifier2-key verifier-key.pem
refused tamper-issuer trust_chain_not_trusted "The credential issuer is not in the trusted list." \
  "the Issuer-signed JWT signed again under a self-signed certificate"

# The wallet's own refusals, before it presents. EUDIPLO's request
# names the issuers its trust list holds by their key identifiers
# (trusted_authorities, aki): for the config trusting only a CA that
# issued nothing, the wallet holds no credential that answers it.
present untrusted-issuer "$SDJWT" pid-sdjwt-untrusted
if jq -e '.stage == "selection" and (.error | contains("no held credential satisfies this credential query"))' \
    untrusted-issuer-wallet.json >/dev/null 2>&1 && jq -e '.status == "fetched"' untrusted-issuer-session.json >/dev/null 2>&1; then
  ok "control: a request whose trusted_authorities name only an unrelated CA: the wallet finds no credential that answers it, and presents nothing"
else bad "control: trusted_authorities naming an unrelated CA: $(why untrusted-issuer)"; fi
present untrusted-verifier "$SDJWT" pid-sdjwt -verifier-ca other-ca.pem
if jq -e '.stage == "request" and (.error | contains("untrusted verifier: wallet: verifier certificate: certchain: certificate chain does not verify against a trusted root"))' \
    untrusted-verifier-wallet.json >/dev/null 2>&1; then
  ok "control: the wallet trusts an unrelated Verifier CA: it refuses EUDIPLO's request, for its Access Certificate's chain"
else bad "control: an untrusted Verifier: $(why untrusted-verifier)"; fi

echo "### OID4VCgo's issuer → OID4VCgo's wallet → EUDIPLO's Verifier, over the Digital Credentials API"
# The run stands in for the page and the browser, as a Verifier's page
# and the platform do (README.md, "The Digital Credentials API"): it
# creates the request for the page's origin, hands the wallet what
# navigator.credentials.get() hands the platform ({protocol, data,
# origin}; the wallet's -dcapi, walletflow's StartDCAPIPresentation or
# StartMdocPresentation), and posts what the wallet hands back to
# EUDIPLO's response_uri, as the page does.
ORIGIN=https://shop.eudiplo.test
# dcapi_present has the wallet redeem an offer of configuration $2 and
# answer the DC API request in $1-request.json from origin $3; it
# posts the answer's data, the jq filter $4 of it, to $5, and writes
# EUDIPLO's answer to $1-post.json and the session $6's outcome to
# $1-session.json.
dcapi_present() {  # $1 name, $2 configuration, $3 origin, $4 jq filter, $5 response_uri, $6 session id
  local name="$1" config="$2" origin="$3" filter="$4" uri="$5" id="$6"
  jq --arg o "$origin" '.origin = $o' "$name-request.json" > "$name-dcapi.json"
  ./wallet -tls-ca ca.pem -issuer-ca issuer-ca.pem -mdoc-issuer-ca iaca.pem -verifier-ca ca.pem -crl-set none \
    -wallet-provider "https://localhost:$WP_PORT" -wallet-provider-tls wallet-provider/tls-cert.pem -client-id "$CLIENT_ID" \
    -offer "$(offer "$config")" -dcapi "$name-dcapi.json" -out "$name-wallet.json" >> "wallet-$name.log" 2>&1 \
    || echo '{"stage": "wallet", "error": "the wallet failed; see its log"}' > "$name-wallet.json"
  if jq -e '.stage == "done"' "$name-wallet.json" >/dev/null 2>&1; then
    api -o "$name-post.json" -w '%{http_code}' -X POST -H "$JSON" --data "$(jq -c ".dcapi.data | $filter" "$name-wallet.json")" "$uri" \
      > "$name-post-status.txt" || true
  fi
  session "$id" "$name"
}
dcapi_why() {  # $1 name
  local name="$1"
  echo "$(why "$name"), EUDIPLO answered $(cat "$name-post-status.txt" 2>/dev/null) $(head -c 300 "$name-post.json" 2>/dev/null)"
}

# OpenID4VP over the DC API: EUDIPLO's signed request object
# (openid4vp-v1-signed, response_mode dc_api.jwt), read from the
# session (requestObject), as its docs have the backend hand it to the
# page; the page posts the wallet's data unchanged to the request's
# response_uri.
for case in "dcapi-sdjwt $SDJWT pid-sdjwt" "dcapi-mdoc $MDOC pid-mdoc"; do
  read -r name config pres <<< "$case"
  id="$(api -X POST -H "$AUTH" -H "$JSON" \
    --data "$(jq -cn --arg c "$pres" --arg o "$ORIGIN" '{response_type: "dc-api", requestId: $c, expected_origin: $o}')" \
    "$E/api/verifier/offer" | jq -r '.session')"
  api -H "$AUTH" "$E/api/session/$id" | jq '{protocol: "openid4vp-v1-signed", data: {request: .requestObject}}' > "$name-request.json"
  uri="$(jq -r '.data.request | split(".")[1] | gsub("-"; "+") | gsub("_"; "/") | @base64d | fromjson | .response_uri' "$name-request.json")"
  dcapi_present "$name" "$config" "$ORIGIN" . "$uri" "$id"
  if [[ "$(cat "$name-post-status.txt" 2>/dev/null)" = 200 ]] \
      && jq -e '.status == "completed" and .outcome.result == "success"
        and (.credentials[0].values[0] | has("family_name") and (has("given_name") | not))' "$name-session.json" >/dev/null 2>&1; then
    ok "$name: presented over the DC API (openid4vp-v1-signed, dc_api.jwt) to a signed x509_hash request bound to $ORIGIN; EUDIPLO verified it, disclosed $(jq -c '[.credentials[0].values[0] | keys[]]' "$name-session.json")"
  else bad "$name: $(dcapi_why "$name")"; fi
done

# ISO/IEC TS 18013-7 Annex C (org-iso-mdoc): EUDIPLO's DeviceRequest,
# signed by its Access Certificate (readerAuth), and EncryptionInfo; the
# page posts the wallet's EncryptedResponse as {"data": ...}.
annexc() {  # $1 name, $2 the origin the wallet is handed
  local name="$1" origin="$2" reply
  reply="$(api -X POST -H "$AUTH" -H "$JSON" \
    --data "$(jq -cn --arg o "$ORIGIN" '{response_type: "iso-18013-7", requestId: "pid-mdoc-annexc", expected_origin: $o}')" \
    "$E/api/verifier/offer")"
  jq '{protocol: "org-iso-mdoc", data: {deviceRequest: .org_iso_mdoc.device_request, encryptionInfo: .org_iso_mdoc.encryption_info}}' \
    <<< "$reply" > "$name-request.json"
  dcapi_present "$name" "$MDOC" "$origin" '{data: .response}' "$(jq -r '.org_iso_mdoc.response_uri' <<< "$reply")" "$(jq -r '.session' <<< "$reply")"
}
annexc annexc "$ORIGIN"
if [[ "$(cat annexc-post-status.txt 2>/dev/null)" = 200 ]] && jq -e '.dcapi.reader != null' annexc-wallet.json >/dev/null 2>&1 \
    && jq -e '.status == "completed" and .outcome.result == "success"' annexc-session.json >/dev/null 2>&1; then
  ok "annexc: the mdoc presented over org-iso-mdoc (Annex C) to a request EUDIPLO signed, its reader recognized ($(jq -r '.dcapi.reader' annexc-wallet.json)); EUDIPLO verified it, disclosed $(jq -c '.credentials[0].claims // .credentials[0]' annexc-session.json | cut -c1-200)"
else bad "annexc: $(dcapi_why annexc)"; fi
# The same, the wallet handed another origin than the page's: its
# answer's session transcript, and so its HPKE info, is another, which
# EUDIPLO must refuse. The two differ in the origin alone.
annexc annexc-origin https://other.eudiplo.test
if [[ "$(cat annexc-origin-post-status.txt 2>/dev/null)" = 400 ]] && jq -e '.message == "HPKE decryption failed"' annexc-origin-post.json >/dev/null 2>&1 \
    && jq -e '.status == "failed" and .errorReason == "HPKE decryption failed"' annexc-origin-session.json >/dev/null 2>&1; then
  ok "control: an Annex C answer made for another origin: EUDIPLO refuses it, for its HPKE info (400, HPKE decryption failed)"
else bad "control: an Annex C answer for another origin: $(dcapi_why annexc-origin)"; fi

# shellcheck source=issuer.sh
. "$HERE/issuer.sh"

if [[ "$fail" -eq 0 ]]; then echo "RESULT: every case behaved as expected"; else echo "RESULT: FAILED"; fi
exit "$fail"
