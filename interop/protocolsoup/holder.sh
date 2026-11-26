# Sourced by run.sh, after the issuer's cases: ProtocolSoup's wallet
# harness (cmd/walletharness), driven over its HTTP API, as holder:
# OID4VCgo's issuer issues it SD-JWT VC and mdoc PIDs (POST
# /api/import), attested by the harness's own attester key, under a
# CA of its own that the issuer trusts; then it presents them to
# OID4VCgo's verifier (POST /api/resolve, /api/present). Both are
# $HOST to the harness, through serve's taps. Then controls, each
# refused for its reason. See README.md.

# OID4VCgo's issuer for the harness, in profiles (start_hissuer): as
# run.sh's, but listening on $HOLDER_ISSUER_INNER_PORT, named
# https://$HOST:$HOLDER_ISSUER_PORT, the tap in front of it; its
# client's Wallet Attestations trusted to the harness's attester CA as
# well as the Wallet Provider's; and every credential with a Token
# Status List entry, its lists at https://localhost:$HOLDER_ISSUER_INNER_PORT,
# where OID4VCgo's verifiers fetch them; and its Key Attestations
# trusted to the harness's CA. Its production setup requires a Key
# Attestation in every jwt proof, which the harness's don't satisfy
# (README finding 5): the harness's cases run it at development
# assurance (the dev profile, as interop/credo/run.sh runs it for
# Credo's holder), without Key Attestations.
HISSUER="https://$HOST:$HOLDER_ISSUER_PORT"
cat harness-ca.pem wallet-provider/ca.pem > holder-attester-cas.pem
# shellcheck disable=SC2016 # jq's variables, not the shell's
jq --arg issuer "$HISSUER" --arg addr "127.0.0.1:$HOLDER_ISSUER_INNER_PORT" --arg offers "127.0.0.1:$HOLDER_OFFERS_PORT" \
  --arg lists "https://localhost:$HOLDER_ISSUER_INNER_PORT" --rawfile cas holder-attester-cas.pem \
  --argjson sl "$(jq '.status_lists' issuer-files/issuer.json)" \
  '.issuer = $issuer | .listen_addr = $addr | .offers.listen_addr = $offers | .status_lists = $sl + {base_url: $lists}
    | .client.attester_trust_anchors_pem = $cas | .key_attestation = {trust_anchor_pem: $cas}' issuer.json > holder-issuer.json
DEV='del(.production, .key_attestation)'
HISSUER_PID=""
# start_hissuer (re)starts the holder issuer in profile $1:
# holder-issuer.json changed by the jq filter $2 ($cas, the attester
# CAs, to hand), its stores fresh.
start_hissuer() {  # $1 the profile's name, $2 a jq filter
  local name="$1" filter="$2"
  if [[ -n "$HISSUER_PID" ]]; then kill "$HISSUER_PID" 2>/dev/null || true; wait "$HISSUER_PID" 2>/dev/null || true; fi
  # shellcheck disable=SC2016 # jq's variables, not the shell's
  jq --arg db "$WORK/holder-issuer-$name.db" --arg seal "$(sealing_key)" --rawfile cas holder-attester-cas.pem \
    ".production.database_path = \$db | .production.sealing_key = \$seal | $filter" holder-issuer.json > "holder-issuer-$name.json"
  ./issuer -config "holder-issuer-$name.json" >> "holder-issuer-$name.log" 2>&1 &
  HISSUER_PID=$!
  PIDS+=("$HISSUER_PID")
  wait_ready "https://localhost:$HOLDER_ISSUER_INNER_PORT/.well-known/openid-credential-issuer" "http://127.0.0.1:$HOLDER_OFFERS_PORT/offers"
}
# The taps: the issuer's, and the verifier's (start_verifier), each
# logging what the harness sent.
./serve -dir . -tap "$TAP_BIND:$HOLDER_ISSUER_PORT=https://127.0.0.1:$HOLDER_ISSUER_INNER_PORT" \
  -tap "$TAP_BIND:$VERIFIER_PORT=https://127.0.0.1:$((VERIFIER_PORT + 10))" -tap-name localhost > holder-serve.log 2>&1 &
PIDS+=($!)

# hoffer is a pre-authorized code offer of the holder issuer's
# configuration $1, by reference, with the tx_code $2 if given.
hoffer() {  # $1 configuration, $2 a tx_code
  local config="$1" tx="${2:-}"
  curl -sS --max-time 30 -X POST -H "$JSON" \
    --data "$(jq -cn --arg c "$config" --arg t "$tx" '{grant: "pre-authorized_code", credential_configuration_ids: [$c], by_reference: true}
      + (if $t == "" then {} else {tx_code: $t} end)')" "http://127.0.0.1:$HOLDER_OFFERS_PORT/offers" | jq -r '.uri'
}

echo "### OID4VCgo's issuer → OID4VCgo's wallet → ProtocolSoup's Verifier, a credential with a status"
# The holder issuer named localhost, as run.sh's issuer is, for
# OID4VCgo's wallet, which reaches it directly.
start_hissuer localhost ".issuer = \"https://localhost:$HOLDER_ISSUER_INNER_PORT\""
# Finding 1: the SD-JWT VC PID with a status list reference, which
# ProtocolSoup's Verifier won't fetch, at a private address
# (https://localhost here, as anything of a CI run): it refuses the
# credential, for its status, unchecked. A known gap, so a note; the
# run fails once it changes. The case differs from run.sh's sdjwt in
# its issuer's status lists alone.
pace
link="$(request status-private "$SDJWT_QUERY" haip direct_post.jwt)"
./wallet -tls-ca ca.pem -issuer-ca issuer-ca.pem -mdoc-issuer-ca iaca.pem -verifier-ca ca.pem -crl-set none \
  -wallet-provider "https://localhost:$WP_PORT" -wallet-provider-tls wallet-provider/tls-cert.pem -client-id "$CLIENT_ID" \
  -offer "$(hoffer "$SDJWT")" -request "$link" -out status-private-wallet.json >> wallet-status-private.log 2>&1 \
  || echo '{"stage": "wallet", "error": "the wallet failed; see its log"}' > status-private-wallet.json
api "$PS/oid4vp/result/$(jq -r .request_id status-private-request.json)" > status-private-result.json || true
if jq -e '.stage == "done" and (.received[0].status_lists | length >= 1)' status-private-wallet.json >/dev/null 2>&1 \
    && jq -e '.result.policy.reason_codes == ["credential_status_invalid"]' status-private-result.json >/dev/null 2>&1 \
    && grep -q 'status list URI must not target private or local addresses' status-private-result.json; then
  note "ProtocolSoup refuses the SD-JWT VC whose status list is at a private address, unfetched (README finding 1): $(jq -r '.result.policy.reasons[0]' status-private-result.json | cut -c1-160)"
else bad "README finding 1 has changed: a status list at a private address: $(why status-private) $(head -c 300 status-private-result.json)"; fi

echo "### OID4VCgo's issuer → ProtocolSoup's wallet harness"
start_hissuer harness "$DEV"
# start_harness (re)starts the wallet harness $1, as docker-compose.yml
# runs its wallet service but: its API on loopback port $2; OID4VCgo's
# issuer and verifier its two trusted hosts (WALLET_ISSUER_BASE_URL,
# WALLET_TARGET_BASE_URL), as the harness reaches only public
# addresses besides; the run's CA its TLS roots (SSL_CERT_FILE), and
# its trust anchor for Verifiers' request objects; OID4VCgo's issuer's
# CAs its trust anchors for credentials (WALLET_MDOC_IACA_ROOT_PEM,
# which it checks SD-JWT VCs' x5c against too); its attester key the
# file $3, attesting it as OID4VCgo's issuer's client and naming its
# attester. The rest are environment settings that replace these.
start_harness() {  # $1 name, $2 port, $3 attester key file; then -e settings
  local name="$1" port="$2" attester="$3"
  shift 3
  docker rm -f "$NAME-$name" >/dev/null 2>&1 || true
  docker run -d --name "$NAME-$name" --add-host "$HOST:host-gateway" -p "127.0.0.1:$port:8080" \
    -v "$WORK/ca.pem:/run/trust/ca.pem:ro" -e SSL_CERT_FILE=/run/trust/ca.pem -e WALLET_LISTEN_ADDR=:8080 \
    -e WALLET_ISSUER_BASE_URL="$HISSUER" -e WALLET_TARGET_BASE_URL="https://$HOST:$VERIFIER_PORT" \
    -e WALLET_VERIFIER_X509_TRUST_ANCHOR_PEM="$(cat ca.pem)" -e WALLET_MDOC_IACA_ROOT_PEM="$(cat iaca.pem issuer-ca.pem)" \
    -e WALLET_CLIENT_ATTESTATION_ATTESTER_JWK_JSON="$(cat "$attester")" \
    -e WALLET_CLIENT_ATTESTATION_KEY_ATTESTATION_JWK_JSON="$(cat harness-key-attester.json)" \
    -e WALLET_CLIENT_ATTESTATION_ISSUER="$ATTESTER" -e WALLET_OID4VCI_ATTESTED_CLIENT_ID="$CLIENT_ID" \
    "$@" "$WALLET_IMAGE" >/dev/null
  for _ in $(seq 1 50); do
    if curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$port/health"; then return 0; fi
    sleep 0.2
  done
  echo "the wallet harness $name did not start; see docker logs $NAME-$name" >&2
  exit 2
}
start_harness wallet "$HARNESS_PORT" harness-attester.json
# harness calls the harness on port $1's POST $2 with the JSON $3, in
# this run's wallet session; its answer is in $4, its status in
# $4.status.
SESSION="oid4vcgo-$RANDOM"
harness() {  # $1 port, $2 path, $3 body, $4 file
  local port="$1" path="$2" body="$3" out="$4"
  curl -sS --max-time 60 -o "$out" -w '%{http_code}' -X POST -H "$JSON" -H "X-Wallet-Session: $SESSION" --data "$body" \
    "http://127.0.0.1:$port$path" > "$out.status" || echo 000 > "$out.status"
}
# himport has the harness on port $1 redeem the offer $3, with the
# tx_code $4 if given; its answer is in $2-import.json.
himport() {  # $1 port, $2 name, $3 offer, $4 tx_code
  local port="$1" name="$2" offer="$3" tx="${4:-}"
  harness "$port" /api/import "$(jq -cn --arg o "$offer" --arg t "$tx" '{offer: $o} + (if $t == "" then {} else {tx_code: $t} end)')" "$name-import.json"
}
hwhy() {  # $1 file: the harness's answer, briefly
  echo "$(cat "$1.status" 2>/dev/null) $(jq -c '{error, error_description, credential_format, credential_configuration_id} | with_entries(select(.value != null))' "$1" 2>/dev/null | cut -c1-400)"
}
# The tap's log of the holder issuer from line $1 on.
htap() { tail -n +"$(($1 + 1))" holder-serve.log | grep ' tap: ' | sed 's/.* tap: //' || true; }

# himported checks the harness took case $1's credential, of format
# $2 and configuration $3, and the tap saw the issuer answer its Token
# Request (a Wallet Attestation PoP among it) and Credential Request.
himported() {  # $1 name, $2 format, $3 configuration
  [[ "$(cat "$1-import.json.status")" = 200 ]] \
    && jq -e --arg f "$2" --arg c "$3" '.credential_format == $f and .credential_configuration_id == $c' "$1-import.json" >/dev/null 2>&1 \
    && grep -q '^POST "/token" 200 | pop ' "tap-$1.log" && grep -q '^POST "/credential" 200' "tap-$1.log"
}
# hreceive has the harness on port $1 redeem an offer of configuration
# $3 (with the tx_code $4, the harness given $5 instead if set); its
# answer is in $2-import.json, what the tap saw in tap-$2.log.
hreceive() {  # $1 port, $2 name, $3 configuration, $4 the offer's tx_code, $5 the harness's
  local port="$1" name="$2" config="$3" tx="${4:-}" given="${5:-${4:-}}" from
  from="$(wc -l < holder-serve.log)"
  himport "$port" "$name" "$(hoffer "$config" "$tx")" "$given"
  htap "$from" > "tap-$name.log"
}
hreceive "$HARNESS_PORT" harness-sdjwt "$SDJWT"
if himported harness-sdjwt dc+sd-jwt "$SDJWT"; then
  ok "harness-sdjwt: issued to the harness (its Wallet Attestation, DPoP), which checked it by its chain"
else bad "harness-sdjwt: $(hwhy harness-sdjwt-import.json); tap $(tr '\n' ';' < tap-harness-sdjwt.log | head -c 300)"; fi
hreceive "$HARNESS_PORT" harness-tx-code "$SDJWT" 493817
if himported harness-tx-code dc+sd-jwt "$SDJWT"; then ok "harness-tx-code: issued, its pre-authorized code redeemed with a tx_code"
else bad "harness-tx-code: $(hwhy harness-tx-code-import.json)"; fi
# What the harness sent the Token Endpoint, as the tap saw it.
echo "        observed: $(grep -hF '"/token" 200' tap-harness-sdjwt.log | head -1)"

# Controls. hrefused checks case $1's import was refused (400), its
# error and description containing $2, the refusing side's reason.
hrefused() {  # $1 name, $2 in the error, $3 what the control is
  if [[ "$(cat "$1-import.json.status")" = 400 ]] \
      && jq -e --arg r "$2" '"\(.error): \(.error_description)" | contains($r)' "$1-import.json" >/dev/null 2>&1; then
    ok "control: $3: refused ($(jq -r '"\(.error): \(.error_description)"' "$1-import.json" | cut -c1-240))"
  else bad "control: $3: $(hwhy "$1-import.json")"; fi
}
hreceive "$HARNESS_PORT" harness-wrong-tx-code "$SDJWT" 493817 493810
hrefused harness-wrong-tx-code 'tx_code does not match' \
  "a wrong tx_code: OID4VCgo's issuer refuses it, which the harness reports"
# The harness's Wallet Attestation signed under other-ca.pem, which the
# issuer doesn't trust; the case differs from harness-sdjwt in that
# alone.
start_harness harness-untrusted-attester "$UNTRUSTED_HARNESS_PORT" untrusted-harness-attester.json
hreceive "$UNTRUSTED_HARNESS_PORT" harness-untrusted-attester "$SDJWT"
if ! grep -q '^POST "/token" 401 | pop ' tap-harness-untrusted-attester.log; then
  bad "control: an untrusted attester: the tap saw no 401 Token Response: $(tr '\n' ';' < tap-harness-untrusted-attester.log | head -c 300)"
fi
hrefused harness-untrusted-attester 'invalid_client' \
  "a Wallet Attestation under a CA OID4VCgo's issuer doesn't trust, at its Token Endpoint (401)"
# The harness trusting only other-ca.pem for credentials: it refuses
# OID4VCgo's issuer's, for its chain.
start_harness harness-other-anchors "$OTHER_HARNESS_PORT" harness-attester.json -e WALLET_MDOC_IACA_ROOT_PEM="$(cat other-ca.pem)"
hreceive "$OTHER_HARNESS_PORT" harness-untrusted-issuer "$SDJWT"
hrefused harness-untrusted-issuer 'validate credential x5c chain: verify certificate chain: x509: certificate signed by unknown authority' \
  "the harness trusts another CA for credentials: it refuses the SD-JWT VC, for its chain"

# Known gaps, noted rather than failed; the run fails once either
# changes (README.md).
# Finding 2, as the harness has it: it refuses the mdoc PID, its
# Document Signer certificate without Basic Constraints.
hreceive "$HARNESS_PORT" harness-mdoc "$MDOC"
if [[ "$(cat harness-mdoc-import.json.status)" = 400 ]] && grep -q '^POST "/credential" 200' tap-harness-mdoc.log \
    && jq -e '.error_description | contains("mdoc: document-signer certificate must have Basic Constraints CA=false")' harness-mdoc-import.json >/dev/null 2>&1; then
  note "the harness refuses the mdoc PID it was issued, its Document Signer certificate without Basic Constraints (README finding 2)"
else bad "README finding 2 has changed: the harness and the mdoc PID: $(hwhy harness-mdoc-import.json)"; fi
# Finding 5: the harness's Key Attestations carry no exp, which a jwt
# proof's must (OpenID4VCI 1.0 Appendix D.1): the issuer's production
# setup, which requires one in every jwt proof, refuses them. The
# profile differs from the harness's cases in its production setup.
start_hissuer production .
hreceive "$HARNESS_PORT" harness-production "$SDJWT"
start_hissuer harness "$DEV"
if grep -q '^POST "/token" 200' tap-harness-production.log \
    && jq -e '.error_description | contains("invalid_proof") and contains("its key_attestation has no exp, which the jwt proof type requires (Appendix D.1)")' \
      harness-production-import.json >/dev/null 2>&1; then
  note "OID4VCgo's issuer under its production setup refuses the harness's Key Attestation, which has no exp (README finding 5)"
else bad "README finding 5 has changed: the harness to the production issuer: $(hwhy harness-production-import.json)"; fi

echo "### ProtocolSoup's wallet harness → OID4VCgo's verifier"
# OID4VCgo's verifier (cmd/conformance-verifier, its default engine),
# in profiles (start_verifier): a signed x509_hash request under
# setup's our-verifier Access Certificate, the response encrypted
# (direct_post.jwt), checking the SD-JWT VC's chain to the issuer's CA
# and its Token Status List entry, fetched from the holder issuer. It
# is https://$HOST:$VERIFIER_PORT, the tap in front of it, which the
# harness trusts as its target (WALLET_TARGET_BASE_URL).
VERIFIER_INNER=$((VERIFIER_PORT + 10))
# shellcheck disable=SC2016 # jq's variables, not the shell's
jq -n --rawfile cert tls-cert.pem --rawfile key tls-key.pem --rawfile access our-verifier-cert.pem \
  --rawfile accesskey our-verifier-key.pem --rawfile ca ca.pem --rawfile issuerca issuer-ca.pem --arg vct "$VCT" \
  --arg addr "127.0.0.1:$VERIFIER_INNER" --arg base "https://$HOST:$VERIFIER_PORT" \
  '{listen_addr: $addr, base_url: $base, tls_certificate_pem: $cert, tls_private_key_pem: $key,
    client_certificate_pem: $access, client_private_key_pem: $accesskey, vct: $vct, claims: ["family_name", "given_name"],
    credential_issuer_trust_anchors_pem: $issuerca, status_list_trust_anchors_pem: $issuerca,
    status_list_tls_trust_anchors_pem: $ca, status_list_allow_loopback: true}' > verifier.json
VERIFIER_PID=""
# start_verifier (re)starts the verifier in profile $1: verifier.json
# changed by the jq filter $2, which reads $ucert and $ukey (the
# untrusted Access Certificate's) and $other (other-ca.pem).
start_verifier() {  # $1 the profile's name, $2 a jq filter
  local name="$1" filter="$2"
  if [[ -n "$VERIFIER_PID" ]]; then kill "$VERIFIER_PID" 2>/dev/null || true; wait "$VERIFIER_PID" 2>/dev/null || true; fi
  jq --rawfile ucert untrusted-verifier-cert.pem --rawfile ukey untrusted-verifier-key.pem --rawfile other other-ca.pem \
    "$filter" verifier.json > "verifier-$name.json"
  ./verifier -config "verifier-$name.json" >> "verifier-$name.log" 2>&1 &
  VERIFIER_PID=$!
  PIDS+=("$VERIFIER_PID")
  wait_ready "https://localhost:$VERIFIER_INNER/"
}
# hpresent has the verifier begin a request, as a same-device page
# would (its /authorize, request_uri_method post), and the harness
# resolve it (/api/resolve) and answer it (/api/present) with its
# stored credential of configuration $2, the holder approving the
# Verifier unless $3 is false; the answers are in $1-resolve.json and
# $1-present.json, the verifier's verdict, redeemed from the
# redirect_uri the harness was answered with, in $1-verdict.json.
VERIFIER_AT=(--resolve "$HOST:$VERIFIER_PORT:$TAP_BIND" --cacert ca.pem)
hpresent() {  # $1 name, $2 configuration, $3 approve the Verifier
  local name="$1" config="$2" approve="${3:-true}" launch uri redirect
  launch="$(curl -sS --max-time 30 "${VERIFIER_AT[@]}" -o /dev/null -w '%{redirect_url}' "https://$HOST:$VERIFIER_PORT/authorize?request_uri_method=post")"
  uri="$(sed -E 's/.*[?&]request_uri=([^&]*).*/\1/' <<< "$launch")"
  uri="$(printf '%b' "${uri//%/\\x}")"
  harness "$HARNESS_PORT" /api/resolve "$(jq -cn --arg u "$uri" '{request_uri: $u, request_uri_method: "post"}')" "$name-resolve.json"
  harness "$HARNESS_PORT" /api/present "$(jq -cn --slurpfile r "$name-resolve.json" --arg c "$config" --argjson a "$approve" \
    '{request: $r[0].request, request_id: $r[0].request_id, approve_external_trust: $a, credential_configuration_id: $c}')" "$name-present.json"
  redirect="$(jq -r '.upstream_body.redirect_uri? // empty' "$name-present.json" 2>/dev/null || true)"
  if [[ -z "$redirect" ]]; then echo '{"status": "no redirect_uri"}' > "$name-verdict.json"; return; fi
  curl -sS --max-time 30 "${VERIFIER_AT[@]}" -o "$name-verdict.json" "${redirect/\?response_code=//redeem?response_code=}" || true
}
hpwhy() {  # $1 name: the harness's answers and the verifier's verdict
  echo "resolve $(hwhy "$1-resolve.json"), present $(cat "$1-present.json.status" 2>/dev/null) $(jq -c '{error, error_description, upstream_status, upstream_body}' "$1-present.json" 2>/dev/null | cut -c1-300), verdict $(head -c 300 "$1-verdict.json" 2>/dev/null)"
}
start_verifier sdjwt .
hpresent present-sdjwt "$SDJWT"
if [[ "$(cat present-sdjwt-present.json.status)" = 200 ]] && jq -e '.upstream_status == 200' present-sdjwt-present.json >/dev/null 2>&1 \
    && jq -e '.status == "verified" and (.credentials.cred1 | has("family_name") and has("given_name") and (has("birth_date") | not))' \
      present-sdjwt-verdict.json >/dev/null 2>&1; then
  ok "present-sdjwt: the harness presented the SD-JWT VC PID to a signed x509_hash request, encrypted; OID4VCgo's verifier verified it (issuer, holder binding, status), only the requested claims disclosed"
else bad "present-sdjwt: $(hpwhy present-sdjwt)"; fi
# Controls. The holder not approving the Verifier, one the harness
# doesn't know (approve_external_trust false): the harness answers
# nothing. The case differs from present-sdjwt in that alone.
hpresent present-unapproved "$SDJWT" false
if [[ "$(cat present-unapproved-present.json.status)" = 400 ]] \
    && jq -e '.error_description | contains("external verifier trust approval is required")' present-unapproved-present.json >/dev/null 2>&1 \
    && jq -e '.status == "no redirect_uri"' present-unapproved-verdict.json >/dev/null 2>&1; then
  ok "control: the holder doesn't approve the Verifier: the harness presents nothing ($(jq -r .error_description present-unapproved-present.json))"
else bad "control: an unapproved Verifier: $(hpwhy present-unapproved)"; fi
# The verifier's Access Certificate under other-ca.pem, which the
# harness doesn't trust: it refuses the request, approved or not, for
# its chain.
start_verifier untrusted-access '.client_certificate_pem = $ucert | .client_private_key_pem = $ukey'
hpresent present-untrusted-verifier "$SDJWT"
if [[ "$(cat present-untrusted-verifier-present.json.status)" = 400 ]] \
    && jq -e '.error_description | contains("request object verification failed: validate request object x5c chain: verify certificate chain: x509: certificate signed by unknown authority")' \
      present-untrusted-verifier-present.json >/dev/null 2>&1 && jq -e '.status == "no redirect_uri"' present-untrusted-verifier-verdict.json >/dev/null 2>&1; then
  ok "control: a Verifier whose Access Certificate the harness doesn't trust: it refuses the request, approved by the holder, for its chain"
else bad "control: an untrusted Verifier: $(hpwhy present-untrusted-verifier)"; fi
# The verifier trusting another CA for issuers: it refuses the
# credential, for its issuer's chain.
start_verifier untrusted-issuer '.credential_issuer_trust_anchors_pem = $other'
hpresent present-untrusted-issuer "$SDJWT"
# vrefused checks the verifier refused case $1's presentation, which
# the harness delivered: its verdict failed for the reason $2.
vrefused() {  # $1 name, $2 the verifier's reason, $3 what the control is
  if jq -e '.upstream_status == 200' "$1-present.json" >/dev/null 2>&1 \
      && jq -e --arg r "$2" '.status == "failed" and (.error | contains($r))' "$1-verdict.json" >/dev/null 2>&1; then
    ok "control: $3: OID4VCgo's verifier refuses it ($(jq -r .error "$1-verdict.json" | cut -c1-200))"
  else bad "control: $3: $(hpwhy "$1")"; fi
}
vrefused present-untrusted-issuer 'verifier: resolve issuer key: certchain: certificate chain does not verify against a trusted root' \
  "a credential from an issuer the verifier doesn't trust, for its chain"
# A PID the issuer revokes once issued (its POST /status, the entry
# its status claim names): the verifier refuses it, for its status.
# The case differs from present-sdjwt in the credential's status alone:
# the harness presents the newest credential of the configuration.
start_verifier revoked .
hreceive "$HARNESS_PORT" harness-revoked "$SDJWT"
jq -r '.credential_jwt | split("~")[0] | split(".")[1] | gsub("-"; "+") | gsub("_"; "/") | @base64d | fromjson | .status.status_list
  | {uri, idx, status: "INVALID"}' harness-revoked-import.json > revoke.json 2>/dev/null || echo '{}' > revoke.json
curl -sS --max-time 30 -X POST -H "$JSON" --data @revoke.json "http://127.0.0.1:$HOLDER_OFFERS_PORT/status" > revoked.json || true
hpresent present-revoked "$SDJWT"
if jq -e '.status == "INVALID"' revoked.json >/dev/null 2>&1; then
  vrefused present-revoked 'verifier: credential status: statuslist: the referenced token'"'"'s status is INVALID (revoked)' \
    "a PID its issuer revoked once issued, for its status"
else bad "control: a revoked PID: the issuer revoked nothing: $(head -c 200 revoked.json) $(hwhy harness-revoked-import.json)"; fi
stop_holder() {
  for pid in "$HISSUER_PID" "$VERIFIER_PID"; do kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; done
}
stop_holder
