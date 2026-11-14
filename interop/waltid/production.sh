# shellcheck shell=bash
# Sourced by run.sh under WALLET_ASSURANCE=production, once setup's
# files and walt.id's configs are in WORK: OID4VCgo's wallet, walletflow
# at production assurance (scripts/wallet's -assurance production), with
# Issuer2 and Verifier2. README.md, "The wallet at production
# assurance", says what that is and what isn't production's.
#
# The wallet runs in a container on ../prodnet.sh's network, where
# serve, in a container of its own, terminates TLS for Issuer2 and
# Verifier2 as ISSUER2_HOST and VERIFIER2_HOST, the names their base
# URLs carry (setup's -issuer2-host, -verifier2-host), the two hosts the
# wallet may reach at a private address (-allowed-private-host). Its TLS
# roots are the system's: the run's CA. The cases are the development run's for
# those two parties, but the negative presentations, whose tampering
# transport production's client doesn't take; each control differs from
# a case that passes in the one thing it names. It sets fail.

# shellcheck source=../prodnet.sh
. "$HERE/../prodnet.sh"
# shellcheck disable=SC2153 # NAME, like HERE, SRC and WORK, is run.sh's
PRODNET="$NAME-prodnet"
# shellcheck disable=SC2329 # run by the EXIT trap
production_cleanup() {
  docker logs "$NAME-tls" > "$WORK/tls.log" 2>&1 || true
  docker rm -f "$NAME-tls" "$NAME-wallet" >/dev/null 2>&1 || true
  prodnet_remove "$PRODNET"
}
trap 'production_cleanup; cleanup' EXIT

prodnet_build "$SRC" "$WORK" ./interop/waltid/scripts/wallet ./interop/waltid/scripts/serve
prodnet_create "$PRODNET"
run_service issuer2 "$ISSUER2_IMAGE" issuer-api2 "$ISSUER2_HTTP" 7005
run_service verifier2 "$VERIFIER2_IMAGE" verifier-api2 "$VERIFIER2_HTTP" 7004
prodnet_attach "$PRODNET" "$NAME-issuer2" issuer2-api
prodnet_attach "$PRODNET" "$NAME-verifier2" verifier2-api
# serve's TLS proxies, on the ports the base URLs name.
docker run -d --name "$NAME-tls" --network "$PRODNET" --network-alias "$ISSUER2_HOST" --network-alias "$VERIFIER2_HOST" \
  --user "$(id -u):$(id -g)" -v "$WORK:/work" -w /work --entrypoint /work/serve-linux "$PRODNET_IMAGE" -dir /work \
  -proxy ":$ISSUER2_PORT=http://issuer2-api:7005" -proxy ":$VERIFIER2_PORT=http://verifier2-api:7004" >/dev/null

for url in "http://127.0.0.1:$ISSUER2_HTTP/issuer2/profiles" "http://127.0.0.1:$VERIFIER2_HTTP/api.json"; do
  for _ in $(seq 1 120); do
    if curl -sf -o /dev/null --max-time 2 "$url"; then continue 2; fi
    sleep 1
  done
  echo "$url did not start; see $WORK/*.log" >&2
  exit 2
done
for _ in $(seq 1 50); do
  if [[ "$(docker logs "$NAME-tls" 2>&1 | grep -c 'listening on')" -ge 2 ]]; then break; fi
  sleep 0.2
done
echo "the wallet's network: $PRODNET ($(prodnet_subnet "$PRODNET")), Issuer2 as $ISSUER2_HOST:$ISSUER2_PORT, Verifier2 as $VERIFIER2_HOST:$VERIFIER2_PORT"

fail=0
ok() { local what="$1"; echo "  ok    $what"; }
bad() { local what="$1"; echo "  FAIL  $what"; fail=1; }
JSON='Content-Type: application/json'
UNTRUSTED='certchain: certificate chain does not verify against a trusted root: x509: certificate signed by unknown authority'
REVOKED='certchain: revocation: no verified path passes it: certrevocation: certificate is revoked'
NO_CURRENT_CRL="certchain: revocation: no verified path passes it: certchain: revocation couldn't be decided: certrevocation: no current CRL from the certificate's issuer"

issuer2_offer() {  # $1 Issuer2's profile: a pre-authorized code offer of it
  local profile="$1"
  curl -sS --max-time 30 -X POST -H "$JSON" \
    --data "$(jq -cn --arg p "$profile" '{profileId: $p, authMethod: "PRE_AUTHORIZED"}')" \
    "http://127.0.0.1:$ISSUER2_HTTP/issuer2/credential-offers" | jq -r '.credentialOffer'
}
# wallet runs the wallet at production assurance, with stores of its
# own; its outcome is in $1.json.
wallet() {  # $1 name; then the wallet's options
  local name="$1"; shift
  prodnet_run "$PRODNET" "$WORK" ca.pem "$NAME-wallet" wallet-linux -tls-ca ca.pem -out "$name.json" \
    -assurance production -store "store-$name" -allowed-private-host "$ISSUER2_HOST" -allowed-private-host "$VERIFIER2_HOST" \
    "$@" >> "wallet-$name.log" 2>&1 \
    || echo '{"stage": "wallet", "error": "the wallet failed; see its log"}' > "$name.json"
}
why() {  # $1 file
  local file="$1"
  jq -c '{stage, error} | with_entries(select(.value != null))' "$file" 2>/dev/null | cut -c1-300 || head -c 300 "$file"
}
session() {  # $1 signed or plain, $2 the DCQL query: the session's id and link
  local mode="$1" query="$2" signed=true
  if [[ "$mode" = plain ]]; then signed=false; fi
  curl -sS --max-time 30 -X POST -H "$JSON" \
    --data "$(jq -cn --argjson q "$query" --argjson s "$signed" \
      '{flow_type: "cross_device", core_flow: {signed_request: $s, encrypted_response: $s, dcql_query: $q}}')" \
    "http://127.0.0.1:$VERIFIER2_HTTP/verification-session/create" | jq -r '"\(.sessionId) \(.bootstrapAuthorizationRequestUrl)"'
}
session_status() {  # $1 the session's id
  local id="$1"
  curl -sS --max-time 30 "http://127.0.0.1:$VERIFIER2_HTTP/verification-session/$id/info" | jq -r '.status'
}

echo "### OID4VCgo's wallet, at production assurance ← walt.id Issuer2"
for profile in eudiPidSdJwt eudiPidMdoc isoMdl; do
  wallet "production-receive-$profile" -issuer-ca ca.pem -verifier-ca ca.pem -offer "$(issuer2_offer "$profile")"
  if jq -e '.stage == "done" and (.received | length == 1)' "production-receive-$profile.json" >/dev/null; then
    ok "$profile: issued and checked at production assurance ($(jq -r '.received[0] | "\(.format) \(.configuration_id)"' "production-receive-$profile.json"))"
  else bad "$profile: $(why "production-receive-$profile.json")"; fi
done
# refused_credential is the controls' check: refused as the credential is checked,
# for the reason $2, not before it was issued or for anything else.
refused_credential() {  # $1 name, $2 why
  local name="$1" want="$2"
  if jq -e --arg want "$want" '.stage == "credential" and (.received | length == 0)
      and (.error | contains("is invalid: wallet: verify issued credential: issuer certificate: " + $want))' "$name.json" >/dev/null; then
    ok "control: refused, for $want"
  else bad "control: $(why "$name.json")"; fi
}
wallet production-receive-untrusted-issuer -issuer-ca other-ca.pem -verifier-ca ca.pem -offer "$(issuer2_offer eudiPidSdJwt)"
refused_credential production-receive-untrusted-issuer "$UNTRUSTED"
wallet production-receive-crl-revoked -issuer-ca ca.pem -verifier-ca ca.pem -crl-set revoked-issuer -offer "$(issuer2_offer eudiPidSdJwt)"
refused_credential production-receive-crl-revoked "$REVOKED"
wallet production-receive-crl-expired -issuer-ca ca.pem -verifier-ca ca.pem -crl-set expired -offer "$(issuer2_offer eudiPidSdJwt)"
refused_credential production-receive-crl-expired "$NO_CURRENT_CRL"

echo "### OID4VCgo's wallet, at production assurance → walt.id Verifier2"
PID_QUERY='{"credentials": [{"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": ["urn:eudi:pid:1"]}, "claims": [{"path": ["family_name"]}]}]}'
MDL_QUERY='{"credentials": [{"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}, "claims": [{"path": ["org.iso.18013.5.1", "family_name"]}]}]}'
for case in "pid eudiPidSdJwt $PID_QUERY" "mdl isoMdl $MDL_QUERY"; do
  read -r name profile query <<< "$case"
  read -r id link <<< "$(session signed "$query")"
  wallet "production-present-$name" -issuer-ca ca.pem -verifier-ca ca.pem -offer "$(issuer2_offer "$profile")" -request "$link"
  status="$(session_status "$id")"
  if jq -e '.stage == "done"' "production-present-$name.json" >/dev/null && [[ "$status" = SUCCESSFUL ]]; then
    ok "$name: presented at production assurance to a signed x509_hash request, encrypted; Verifier2 accepted it"
  else bad "$name: wallet $(why "production-present-$name.json"), Verifier2 $status"; fi
done
# refused_request checks the wallet received the PID, then refused the
# request, for $2.
refused_request() {  # $1 name, $2 why
  local name="$1" want="$2"
  if jq -e --arg want "$want" '.stage == "request" and (.received | length == 1) and (.error | contains($want))' "$name.json" >/dev/null; then
    ok "control: refused, for $want"
  else bad "control: $(why "$name.json")"; fi
}
read -r id link <<< "$(session plain "$PID_QUERY")"
wallet production-present-unsigned -issuer-ca ca.pem -verifier-ca ca.pem -offer "$(issuer2_offer eudiPidSdJwt)" -request "$link"
refused_request production-present-unsigned \
  'fetch request_uri: fapihttp: response has an unexpected content type: got "application/json", want "application/oauth-authz-req+jwt"'
if [[ "$(session_status "$id")" = SUCCESSFUL ]]; then bad "the unsigned request's session succeeded"; fi
wallet production-present-untrusted-verifier -issuer-ca ca.pem -verifier-ca other-ca.pem -offer "$(issuer2_offer eudiPidSdJwt)" \
  -request "$(session signed "$PID_QUERY" | cut -d' ' -f2)"
refused_request production-present-untrusted-verifier "parse authorization request: untrusted verifier: wallet: verifier certificate: $UNTRUSTED"
wallet production-present-revoked-verifier -issuer-ca ca.pem -verifier-ca ca.pem -crl-set revoked-verifier \
  -offer "$(issuer2_offer eudiPidSdJwt)" -request "$(session signed "$PID_QUERY" | cut -d' ' -f2)"
refused_request production-present-revoked-verifier "parse authorization request: untrusted verifier: wallet: verifier certificate: $REVOKED"

if [[ "$fail" -eq 0 ]]; then echo "RESULT: every case at production assurance behaved as expected"; else echo "RESULT: FAILED"; fi
