#!/usr/bin/env bash
# The EUDI reference wallet library eudi-lib-jvm-openid4vp-kt presents
# to OID4VCgo's cmd/conformance-verifier: interop/eudi/presentation, a
# JVM driver on it, resolves and validates each request and sends the
# response, its vp_token an SD-JWT VC built with eudi-lib-jvm-sdjwt-kt
# or an mdoc DeviceResponse built with Multipaz. The verifier checks
# each credential's issuer, holder binding and Token Status List; then
# controls that one side or the other must refuse. See README.md.
#
#   interop/eudi/run-wallet.sh
#
# Needs go, a JDK (21 or later), jq, curl and openssl. Exits 0 only if
# every presentation is accepted and every control refused.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="${OID4VCGO_SRC:-$(cd "$HERE/../.." && pwd)}"
PORT="${PORT:-20443}"
MDOC_PORT="${MDOC_PORT:-20444}"
SERVE_PORT="${SERVE_PORT:-20445}"
TX_PORT="${TX_PORT:-20446}"
TX_MDOC_PORT="${TX_MDOC_PORT:-20447}"
WORK="${WORK:-$(mktemp -d)}"
SDJWT_VERIFIER="https://localhost:$PORT"
MDOC_VERIFIER="https://localhost:$MDOC_PORT"
SERVE_URL="https://localhost:$SERVE_PORT"
TX_VERIFIER="https://localhost:$TX_PORT"
TX_MDOC_VERIFIER="https://localhost:$TX_MDOC_PORT"
# The page origin the Digital Credentials API requests are for.
ORIGIN=https://verifier.oid4vcgo-interop.example

for p in "$PORT" "$MDOC_PORT" "$SERVE_PORT" "$TX_PORT" "$TX_MDOC_PORT"; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then
    echo "port $p is in use; set PORT / MDOC_PORT / SERVE_PORT / TX_PORT / TX_MDOC_PORT" >&2
    exit 2
  fi
done

PIDS=()
cleanup() {
  for pid in ${PIDS[@]+"${PIDS[@]}"}; do kill "$pid" 2>/dev/null || true; done
  for pid in ${PIDS[@]+"${PIDS[@]}"}; do wait "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT

echo "work dir  $WORK"
echo "verifier  $SRC, commit $(git -C "$SRC" rev-parse HEAD 2>/dev/null || echo unknown)"

# shellcheck source=../production.sh
. "$HERE/../production.sh"
# Built with the conformance_production tag, so that its transactions
# engine can run as a deployment's Verifier does (below).
build_production "$WORK" "$SRC" verifier=./cmd/conformance-verifier
(cd "$SRC" && go build -o "$WORK/serve" ./interop/eudi/scripts/serve \
  && go run ./interop/eudi/scripts/setup -out "$WORK" -serve-url "$SERVE_URL" -serve-hosts localhost)
(cd "$HERE/presentation" && ./gradlew --quiet --no-daemon installDist)
DRIVER="$HERE/presentation/build/install/eudi-presentation-driver/bin/eudi-presentation-driver"
echo "wallet    $(find "$HERE/presentation/build/install/eudi-presentation-driver/lib" -name 'eudi-lib-jvm-*.jar' -o -name 'multipaz-jvm-*.jar' \
  | sed -E 's|.*/||; s|\.jar$||' | sort | tr '\n' ' ')"
cd "$WORK"

# The verifier's config, from setup's files: the Access Certificate is
# its x509_hash Client Identifier (the wallet trusts its CA), the
# issuer CA (or IACA) the credentials' trust anchor and the status
# lists' signers', and serve's CA the status list fetch's TLS.
openssl x509 -in verifier-chain.pem -out verifier-cert.pem
verifier_config() {  # $1 port; then jq arguments adding the format's fields
  local port="$1"; shift
  jq -n --arg addr "127.0.0.1:$port" --arg base "https://localhost:$port" \
    --rawfile tls_cert tls-cert.pem --rawfile tls_key tls-key.pem \
    --rawfile client_cert verifier-cert.pem --rawfile client_key verifier-key.pem \
    --rawfile serve_ca serve-ca.pem --arg origin "$ORIGIN" "$@"
}
# shellcheck disable=SC2016 # jq's variables, not the shell's
verifier_config "$PORT" --rawfile ca issuer-ca.pem \
  '{listen_addr: $addr, base_url: $base, tls_certificate_pem: $tls_cert, tls_private_key_pem: $tls_key,
    client_certificate_pem: $client_cert, client_private_key_pem: $client_key,
    credential_issuer_trust_anchors_pem: $ca, vct: "urn:eudi:pid:1", claims: ["family_name", "given_name"],
    status_list_trust_anchors_pem: $ca, status_list_tls_trust_anchors_pem: $serve_ca, status_list_allow_loopback: true,
    dc_api_origins: [$origin]}' > verifier-sdjwt.json
# shellcheck disable=SC2016
verifier_config "$MDOC_PORT" --rawfile ca iaca.pem \
  '{listen_addr: $addr, base_url: $base, tls_certificate_pem: $tls_cert, tls_private_key_pem: $tls_key,
    client_certificate_pem: $client_cert, client_private_key_pem: $client_key,
    credential_format: "mso_mdoc", doctype: "eu.europa.ec.eudi.pid.1", namespace: "eu.europa.ec.eudi.pid.1",
    mdoc_claims: ["family_name", "given_name"], mdoc_trust_anchor_pem: $ca,
    status_list_trust_anchors_pem: $ca, status_list_tls_trust_anchors_pem: $serve_ca, status_list_allow_loopback: true,
    dc_api_origins: [$origin]}' > verifier-mdoc.json
# Both verifiers again, as a deployment runs a Verifier: served by
# verifier.Transactions (the transactions engine), whose links ask for
# request_uri_method=post (TransactionsConfig.RequestURIMethodPost),
# under verifier.AssuranceProduction, its transactions in a sealed
# SQLite file (sqlstore, sealing.AESGCMSealer). The status policy is
# the same as above; its fetcher may reach loopback, where serve
# publishes the lists, which TransactionsConfig.Status refuses under
# production, so the binary runs that policy as the Accept instead
# (conformance/verifier/README.md's "Transactions engine"). The
# transactions engine serves no Digital Credentials API.
tx_config() {  # $1 port, $2 the default engine's config, $3 database file
  local port="$1" from="$2" db="$3"
  # shellcheck disable=SC2016 # jq's variables, not the shell's
  jq --arg addr "127.0.0.1:$port" --arg base "https://localhost:$port" --arg db "$WORK/$db" --arg key "$(sealing_key)" \
    '.listen_addr = $addr | .base_url = $base | del(.dc_api_origins)
      | .engine = "transactions" | .production = {database_path: $db, sealing_key: $key}' "$from"
}
tx_config "$TX_PORT" verifier-sdjwt.json verifier-transactions.db > verifier-transactions.json
tx_config "$TX_MDOC_PORT" verifier-mdoc.json verifier-transactions-mdoc.db > verifier-transactions-mdoc.json

./serve -dir . -addr "127.0.0.1:$SERVE_PORT" > serve.log 2>&1 &
PIDS+=($!)
./verifier -config verifier-sdjwt.json > verifier-sdjwt.log 2>&1 &
PIDS+=($!)
./verifier -config verifier-mdoc.json > verifier-mdoc.log 2>&1 &
PIDS+=($!)
./verifier -config verifier-transactions.json > verifier-transactions.log 2>&1 &
PIDS+=($!)
./verifier -config verifier-transactions-mdoc.json > verifier-transactions-mdoc.log 2>&1 &
PIDS+=($!)
# The transactions engine's /authorize begins a request: its readiness
# is probed at /result/{id}, which answers 404 for an unknown one.
for url in "$SDJWT_VERIFIER/authorize" "$MDOC_VERIFIER/authorize" "$TX_VERIFIER/result/probe" "$TX_MDOC_VERIFIER/result/probe" "$SERVE_URL/statuslists/jwt"; do
  for _ in $(seq 1 50); do
    if curl -sk -o /dev/null --max-time 1 "$url"; then continue 2; fi
    sleep 0.2
  done
  echo "$url did not start; see $WORK/*.log" >&2
  exit 2
done

fail=0
ok() { echo "  ok    $1"; }
bad() { echo "  FAIL  $1"; fail=1; }

# authorize starts a session on verifier $1, as a same-device page
# would, and prints the openid4vp:// launch it redirects to.
authorize() {  # $1 verifier, $2 request_uri_method (post, get or none)
  local verifier="$1" method="$2"
  curl -sk --max-time 30 -o /dev/null -w '%{redirect_url}' "$verifier/authorize?request_uri_method=$method"
}

# drive runs the driver; its outcome is in $1.json.
drive() {  # $1 name, $2 mode (redirect or dcapi); then the driver's options
  local name="$1" mode="$2"; shift 2
  "$DRIVER" "$mode" --out "$name.json" --verifier-ca verifier-ca.pem --tls-ca tls-cert.pem "$@" \
    >> "driver-$name.log" 2>&1 || echo '{"resolved": false, "stage": "driver", "error": "the driver failed; see its log"}' > "$name.json"
}

# redeem follows the redirect_uri of $1.json and redeems its
# response_code, as the same-device page's backend would: the
# verifier's outcome is in result-$1.json.
redeem() {  # $1 name
  local name="$1" redirect
  redirect="$(jq -r '.redirect_uri // empty' "$name.json")"
  if [[ -z "$redirect" ]]; then echo '{"status": "no redirect_uri"}' > "result-$name.json"; return; fi
  curl -sk --max-time 30 -o /dev/null "$redirect" || true
  curl -sk --max-time 30 -o "result-$name.json" "${redirect/\?response_code=//redeem?response_code=}" || true
}

why() {  # $1 file
  local file="$1"
  jq -c '{status, error} | with_entries(select(.value != null))' "$file" 2>/dev/null | cut -c1-300 || head -c 300 "$file"
}
explain() {  # $1 driver outcome
  local outcome="$1"
  jq -r '"\(.stage // "-"): \(.error // "-")"' "$outcome" | cut -c1-300
}

# released checks the claims the verifier released in $1: the two the
# query asks for, and none of the PID's others (an mdoc's are under its
# namespace).
released() {  # $1 file
  local file="$1"
  jq -e '.credentials.cred1 | (.["eu.europa.ec.eudi.pid.1"] // .)
    | .family_name == "Dupont" and .given_name == "Jean"
      and ([keys[] | select(IN("birth_date", "nationalities", "issuing_country", "issuing_authority"))] | length == 0)' "$file" >/dev/null
}

# present runs a redirect-flow presentation that must be accepted, and
# checks the claims the verifier released for it.
present() {  # $1 name, $2 verifier, $3 request_uri_method; then driver options
  local name="$1" verifier="$2" method="$3"; shift 3
  echo "== $name"
  drive "$name" redirect --uri "$(authorize "$verifier" "$method")" "$@"
  if jq -e '.dispatch == "accepted"' "$name.json" >/dev/null; then
    ok "the wallet resolved the request and the verifier took the response ($(jq -r '.encryption' "$name.json"))"
  else bad "the wallet presented ($(explain "$name.json"))"; return; fi
  redeem "$name"
  if jq -e '.status == "verified"' "result-$name.json" >/dev/null; then ok "the verifier verified it, released for the response_code"
  else bad "the verifier verified it ($(why "result-$name.json"))"; return; fi
  if released "result-$name.json"; then
    ok "the verifier released the requested claims, and only those"
  else bad "the released claims ($(jq -c '.credentials' "result-$name.json" | cut -c1-300))"; fi
}

# verifier_refused checks the verifier's outcome in $1 is a refusal
# whose error contains $2: one for another reason, or no outcome at all
# (the driver failed, the response never arrived), isn't.
verifier_refused() {  # $1 the verifier's outcome, $2 why
  local result="$1" want="$2"
  if jq -e --arg want "$want" '.status == "failed" and (.error | contains($want))' "$result" >/dev/null; then
    ok "the verifier refused it: $want"
  else bad "the verifier refused it, for $want ($(why "$result"))"; fi
}

# refused runs a redirect-flow presentation the verifier must refuse,
# for an error containing $3.
refused() {  # $1 name, $2 verifier, $3 why; then driver options
  local name="$1" verifier="$2" want="$3"; shift 3
  echo "== control: $name"
  drive "$name" redirect --uri "$(authorize "$verifier" post)" "$@"
  if ! jq -e '.resolved' "$name.json" >/dev/null; then bad "the wallet presented ($(explain "$name.json"))"; return; fi
  redeem "$name"
  verifier_refused "result-$name.json" "$want"
}

# tx_begin begins a request on the transactions verifier $1 at its
# /authorize, as a deployment's page does, its browser binding kept in
# the cookie jar $2, and prints the openid4vp:// launch it redirects to.
tx_begin() {  # $1 verifier, $2 cookie jar
  curl -sk --max-time 30 -c "$2" -o /dev/null -w '%{redirect_url}' "$1/authorize"
}

# tx_page saves the transactions verifier's page $2 for the browser
# whose cookie jar is $3 to $4, its HTML entities decoded, so that a
# refusal's text reads as the verifier logged it.
tx_page() {  # $1 verifier, $2 path or absolute URL, $3 cookie jar, $4 output
  local url="$2"
  [[ "$url" = https://* ]] || url="$1$url"
  curl -sk --max-time 30 -b "$3" "$url" 2>/dev/null \
    | sed -e 's/&#34;/"/g' -e "s/&#39;/'/g" -e 's/&lt;/</g' -e 's/&gt;/>/g' -e 's/&amp;/\&/g' > "$4" || true
}

# tx_present runs a presentation to the transactions verifier $2 that
# must be accepted: the redirect back to its redirect_uri, in the
# browser that began the request, redeems the response_code for the
# result page, which must hold the two requested claims and none of the
# PID's others.
tx_present() {  # $1 name, $2 verifier; then driver options
  local name="$1" verifier="$2"; shift 2
  echo "== $name"
  drive "$name" redirect --uri "$(tx_begin "$verifier" "$name.cookies")" "$@"
  if jq -e '.dispatch == "accepted"' "$name.json" >/dev/null; then
    ok "the wallet resolved the request and the verifier took the response ($(jq -r '.encryption' "$name.json"))"
  else bad "the wallet presented ($(explain "$name.json"))"; return; fi
  tx_page "$verifier" "$(jq -r '.redirect_uri // empty' "$name.json")" "$name.cookies" "result-$name.html"
  if grep -q '<h1>Verification succeeded</h1>' "result-$name.html" \
      && grep -q 'Dupont' "result-$name.html" && grep -q 'Jean' "result-$name.html" \
      && ! grep -qE 'birth_date|nationalities|issuing_country|issuing_authority' "result-$name.html"; then
    ok "the verifier verified it and released the requested claims, and only those, to the browser that asked"
  else bad "the verifier verified it ($(head -c 300 "result-$name.html"))"; fi
}

# tx_refused runs a presentation the transactions verifier $2 must
# refuse: the request's page, shown to the browser that began it, must
# report the refusal with its verifier.Reason $3 (on a "reason: " line)
# and an error containing $4. $3 "accept" is the status policy's
# refusal, which the binary runs as TransactionsConfig.Accept (above):
# an error of the Accept's own, with no verifier.Reason, so the page
# must have no reason line. A refusal for another reason, or none,
# fails the control.
tx_refused() {  # $1 name, $2 verifier, $3 reason, $4 why; then driver options
  local name="$1" verifier="$2" reason="$3" want="$4" uri id reason_line
  shift 4
  reason_line="<pre>reason: $reason</pre>"
  [[ "$reason" != accept ]] || reason_line=""
  echo "== control: $name"
  uri="$(tx_begin "$verifier" "$name.cookies")"
  drive "$name" redirect --uri "$uri" "$@"
  if ! jq -e '.resolved' "$name.json" >/dev/null; then bad "the wallet presented ($(explain "$name.json"))"; return; fi
  # The request's ID is the last segment of its request_uri.
  id="$(sed -E 's/.*[?&]request_uri=([^&]*).*/\1/; s/.*%2F//' <<< "$uri")"
  tx_page "$verifier" "/result/$id" "$name.cookies" "result-$name.html"
  if grep -q '<h1>Verification failed</h1>' "result-$name.html" && grep -qF -- "$want" "result-$name.html" \
      && if [[ -n "$reason_line" ]]; then grep -qF "$reason_line" "result-$name.html"; else ! grep -q '<pre>reason: ' "result-$name.html"; fi; then
    ok "the verifier refused it: $reason, $want"
  else bad "the verifier refused it, for $reason, $want ($(sed 's/<[^>]*>/ /g' "result-$name.html" | head -c 400))"; fi
}

# wallet_refused checks the driver's outcome in $1 is the wallet library
# refusing to resolve the request, for an error containing $2: not the
# driver failing, nor a refusal for another reason.
wallet_refused() {  # $1 the driver's outcome, $2 why
  local outcome="$1" want="$2"
  if jq -e --arg want "$want" '.resolved == false and .stage == "resolve" and (.error | contains($want))' "$outcome" >/dev/null; then
    ok "the wallet refused: $(explain "$outcome")"
  else bad "the wallet refused, for $want ($(jq -c . "$outcome" | cut -c1-300))"; fi
}

# wallet_refuses runs a request the wallet must refuse to resolve, for
# an error containing $3.
wallet_refuses() {  # $1 name, $2 launch URI, $3 why; then driver options
  local name="$1" uri="$2" want="$3"; shift 3
  echo "== control: $name"
  drive "$name" redirect --uri "$uri" "$@"
  wallet_refused "$name.json" "$want"
}

# Why OID4VCgo's verifier refuses each control.
UNTRUSTED_ISSUER='verifier: resolve issuer key: certchain: certificate chain does not verify against a trusted root: x509: certificate signed by unknown authority'
REVOKED="verifier: credential status: statuslist: the referenced token's status is INVALID (revoked)"
KB_JWT_FOR="verifier: verify: a presentation isn't bound to this request: sdjwtvc: key binding JWT: sdjwtvc: key binding JWT is for another request:"
DEVICE_SIGNATURE="verifier: verify device signature: a presentation isn't bound to this request: mdoc: verify DeviceSignature: cose: ES256 signature verification failed"

# dcapi starts a Digital Credentials API session on verifier $1, runs
# the driver as the platform's wallet with --origin, and posts its
# answer back as the page would; the verifier's outcome is in
# result-$2.json.
dcapi() {  # $1 verifier, $2 name, $3 origin the platform reports; then driver options
  local verifier="$1" name="$2" origin="$3"; shift 3
  curl -sk --max-time 30 -X POST -o "request-$name.json" "$verifier/dcapi/request?origin=$(jq -rn --arg o "$ORIGIN" '$o | @uri')"
  drive "$name" dcapi --request "request-$name.json" --origin "$origin" "$@"
  if jq -e '.response' "$name.json" >/dev/null; then
    jq -c '.response' "$name.json" > "answer-$name.json"
    curl -sk --max-time 30 -o "result-$name.json" -X POST -H 'Content-Type: application/json' \
      --data-binary @"answer-$name.json" "$verifier/dcapi/response/$(jq -r '.id' "request-$name.json")" || true
  else
    echo '{"status": "no answer"}' > "result-$name.json"
  fi
}

SDJWT=(--wallet wallet-sdjwt.json)
MDOC=(--wallet wallet-mdoc.json)

echo "#### SD-JWT VC (dc+sd-jwt), the default engine"
present sdjwt-post "$SDJWT_VERIFIER" post "${SDJWT[@]}"
if jq -e '.request_uri_fetch | .method == "POST" and (.wallet_nonce | length > 0)
    and (.content_type | startswith("application/x-www-form-urlencoded"))
    and (.accept | split(",") | map(ltrimstr(" ") | split(";")[0]) | index("application/oauth-authz-req+jwt"))' \
    result-sdjwt-post.json >/dev/null; then
  ok "request_uri_method post: the wallet fetched the request with a form POST, a wallet_nonce and Accept $(jq -r '.request_uri_fetch.accept' result-sdjwt-post.json)"
else bad "request_uri_method post: fetched with $(jq -c '.request_uri_fetch | del(.wallet_metadata)' result-sdjwt-post.json)"; fi
jq '.request_uri_fetch.wallet_metadata | fromjson' result-sdjwt-post.json > wallet-metadata.json
if jq -e '(.client_id_prefixes_supported | index("x509_hash")) and .vp_formats_supported["dc+sd-jwt"] and .vp_formats_supported.mso_mdoc
    and (.request_object_signing_alg_values_supported | index("ES256"))' wallet-metadata.json >/dev/null; then
  ok "its wallet_metadata: $(jq -c . wallet-metadata.json | cut -c1-400)"
else bad "its wallet_metadata ($(jq -c . wallet-metadata.json | cut -c1-400))"; fi

echo "== the response_code redeemed again"
code="$(curl -sk --max-time 30 -o redeem-again.json -w '%{http_code}' \
  "$(jq -r '.redirect_uri | sub("\\?response_code="; "/redeem?response_code=")' sdjwt-post.json)")"
if [[ "$code" = 403 ]] && jq -e '.error == "no result for this response_code"' redeem-again.json >/dev/null 2>&1; then
  ok "refused (HTTP $code, no result for this response_code)"
else bad "refused (HTTP $code: $(head -c 200 redeem-again.json))"; fi

present sdjwt-get "$SDJWT_VERIFIER" get "${SDJWT[@]}"
if jq -e '.request_uri_fetch | .method == "GET" and (has("wallet_nonce") | not)' result-sdjwt-get.json >/dev/null; then
  ok "request_uri_method get: the wallet fetched the request with GET"
else bad "request_uri_method get: fetched with $(jq -c '.request_uri_fetch' result-sdjwt-get.json)"; fi

present sdjwt-no-method "$SDJWT_VERIFIER" none "${SDJWT[@]}"
if jq -e '.request_uri_fetch.method == "GET"' result-sdjwt-no-method.json >/dev/null; then
  ok "no request_uri_method: the wallet fetched the request with GET"
else bad "no request_uri_method: fetched with $(jq -c '.request_uri_fetch' result-sdjwt-no-method.json)"; fi

# verifier.Transactions: /authorize binds the request to this browser
# by a cookie, the wallet POSTs to the request_uri with its
# wallet_metadata (to which Transactions narrows the Request Object's
# client_metadata) and wallet_nonce, and the redirect back, in the
# same browser, redeems the response_code for the result page.
echo "#### SD-JWT VC through verifier.Transactions, under production assurance"
tx_present sdjwt-transactions "$TX_VERIFIER" "${SDJWT[@]}"
# This verifier's first request, fetched once.
fetches="$(grep 'request object fetched with ' verifier-transactions.log | sed 's/.*fetched with //' | tr '\n' ' ')"
if [[ "$fetches" = "POST " ]]; then ok "the wallet fetched the request with POST"
else bad "the wallet fetched the request with POST (fetched with: ${fetches:-nothing})"; fi
tx_present sdjwt-transactions-a256gcm "$TX_VERIFIER" "${SDJWT[@]}" --enc A256GCM
if jq -e '.encryption == "ECDH-ES/A256GCM"' sdjwt-transactions-a256gcm.json >/dev/null; then ok "the response was encrypted with A256GCM"
else bad "the response was encrypted with A256GCM ($(jq -r '.encryption' sdjwt-transactions-a256gcm.json))"; fi
tx_present sdjwt-transactions-get-only-wallet "$TX_VERIFIER" "${SDJWT[@]}" --request-uri-methods get
if [[ "$(grep 'request object fetched with ' verifier-transactions.log | tail -1 | sed 's/.*fetched with //')" = GET ]]; then
  ok "request_uri_method post to a wallet without post: it fetched the request with GET"
else bad "request_uri_method post to a wallet without post: fetched with GET ($(grep 'request object fetched with ' verifier-transactions.log | tail -1))"; fi

tx_refused revoked "$TX_VERIFIER" accept "$REVOKED" "${SDJWT[@]}" --variant revoked
tx_refused untrusted-issuer "$TX_VERIFIER" untrusted_issuer "$UNTRUSTED_ISSUER" "${SDJWT[@]}" --variant untrusted-issuer
tx_refused kb-jwt-wrong-nonce "$TX_VERIFIER" holder_binding "$KB_JWT_FOR its nonce does not match the expected value" "${SDJWT[@]}" --variant wrong-nonce
tx_refused kb-jwt-wrong-aud "$TX_VERIFIER" holder_binding "$KB_JWT_FOR its aud does not match the expected audience" "${SDJWT[@]}" --variant wrong-audience
tx_refused no-kb-jwt "$TX_VERIFIER" invalid_credential "verifier: verify: sdjwtvc: key binding is required but no Key Binding JWT was presented" \
  "${SDJWT[@]}" --variant no-key-binding
tx_refused unrequested-claim "$TX_VERIFIER" unrequested_claims 'verifier: the presentation discloses claims the query didn'"'"'t ask for: "birth_date"' \
  "${SDJWT[@]}" --variant extra-claim

echo "== SD-JWT VC over the Digital Credentials API (openid4vp-v1-signed)"
dcapi "$SDJWT_VERIFIER" sdjwt-dcapi "$ORIGIN" "${SDJWT[@]}"
if jq -e '.status == "verified"' result-sdjwt-dcapi.json >/dev/null && released result-sdjwt-dcapi.json; then
  ok "the verifier verified the response the wallet assembled ($(jq -r '.encryption' sdjwt-dcapi.json))"
else bad "the verifier verified it ($(explain sdjwt-dcapi.json); $(why result-sdjwt-dcapi.json))"; fi
echo "== control: the same Digital Credentials API answer posted again"
code="$(curl -sk --max-time 30 -o dcapi-again.json -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
  --data-binary @answer-sdjwt-dcapi.json "$SDJWT_VERIFIER/dcapi/response/$(jq -r '.id' request-sdjwt-dcapi.json)")"
if [[ "$code" = 409 ]] && jq -e '.error == "the request has already been answered"' dcapi-again.json >/dev/null 2>&1; then
  ok "refused (HTTP $code, the request has already been answered)"
else bad "refused (HTTP $code: $(head -c 200 dcapi-again.json))"; fi

echo "== control: the holder declines"
drive decline redirect --uri "$(authorize "$SDJWT_VERIFIER" post)" "${SDJWT[@]}" --variant decline
redeem decline
if jq -e '.status == "failed" and .error == "verifier: wallet returned error \"access_denied\""' result-decline.json >/dev/null; then
  ok "the verifier received the wallet's access_denied"
else bad "the verifier received access_denied ($(explain decline.json); $(why result-decline.json))"; fi

echo "== control: the same response posted again, after it was answered"
drive replay redirect --uri "$(authorize "$SDJWT_VERIFIER" post)" "${SDJWT[@]}" --variant replay
redeem replay
# The answered session is no longer pending: nothing decrypts the replay.
if jq -e '.status == "verified"' result-replay.json >/dev/null \
    && jq -e '.replay_status == 400 and (.replay_body | startswith("response did not decrypt against any pending session"))' replay.json >/dev/null; then
  ok "the first was verified, the replay refused (HTTP 400, response did not decrypt against any pending session)"
else bad "the replay refused ($(jq -c '{dispatch, replay_status, replay_body}' replay.json); $(why result-replay.json))"; fi

wallet_refuses untrusted-verifier "$(authorize "$SDJWT_VERIFIER" post)" 'InvalidJarJwt(cause=Untrusted x5c)' \
  "${SDJWT[@]}" --verifier-ca other-ca.pem
wallet_refuses http-request-uri "$(authorize "$SDJWT_VERIFIER" post | sed 's/request_uri=https%3A/request_uri=http%3A/')" \
  "threw IllegalArgumentException: URL must use HTTPS: http://localhost:$PORT/request/" "${SDJWT[@]}"
wallet_refuses client-id-mismatch \
  "$(authorize "$SDJWT_VERIFIER" post | sed -E 's/client_id=x509_hash%3A[A-Za-z0-9_-]+/client_id=x509_hash%3AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/')" \
  'InvalidJarJwt(cause=ClientId mismatch. JAR request x509_hash:AAAAAAAAAAAAAAAA' \
  "${SDJWT[@]}"

# The verifier builds a session's Request Object on its first fetch and
# serves that same object to every later one: fetched first here, the
# object the wallet gets doesn't carry the wallet_nonce it sends.
for prefetch in post get; do
  uri="$(authorize "$SDJWT_VERIFIER" post)"
  request_uri="$(sed -E 's/.*[?&]request_uri=([^&]*).*/\1/' <<< "$uri")"
  request_uri="$(printf '%b' "${request_uri//%/\\x}")"
  if [[ "$prefetch" = post ]]; then
    curl -sk --max-time 30 -o /dev/null -X POST --data-urlencode wallet_nonce=an-earlier-wallet-nonce "$request_uri"
    wallet_refuses request-object-with-another-wallet-nonce "$uri" \
      'InvalidJarJwt(cause=Mismatch of wallet_nonce. Expected ' "${SDJWT[@]}"
    if ! jq -e '.error | endswith(", actual an-earlier-wallet-nonce)")' request-object-with-another-wallet-nonce.json >/dev/null; then
      bad "the Request Object carried the earlier wallet_nonce ($(explain request-object-with-another-wallet-nonce.json))"
    fi
  else
    curl -sk --max-time 30 -o /dev/null "$request_uri"
    wallet_refuses request-object-without-the-wallet-nonce "$uri" \
      'InvalidJarJwt(cause=Mismatch of wallet_nonce. Expected ' "${SDJWT[@]}"
    if ! jq -e '.error | endswith(", actual null)")' request-object-without-the-wallet-nonce.json >/dev/null; then
      bad "the Request Object carried no wallet_nonce ($(explain request-object-without-the-wallet-nonce.json))"
    fi
  fi
done

echo "== control: a signed Digital Credentials API request under the openid4vp-v1-unsigned protocol"
dcapi "$SDJWT_VERIFIER" dcapi-unsigned-protocol "$ORIGIN" "${SDJWT[@]}" --protocol openid4vp-v1-unsigned
wallet_refused dcapi-unsigned-protocol.json \
  'DcApiExchangeProtocolNotMatchesReceivedRequest(cause=Exchange protocol is openid4vp-v1-unsigned but request is not Unsigned.)'

echo "== control: a Digital Credentials API request from another origin"
dcapi "$SDJWT_VERIFIER" dcapi-other-origin https://attacker.example "${SDJWT[@]}"
wallet_refused dcapi-other-origin.json UnexpectedOrigin

echo "== control: a Digital Credentials API presentation whose KB-JWT aud is the client_id, not origin:<origin>"
dcapi "$SDJWT_VERIFIER" dcapi-wrong-aud "$ORIGIN" "${SDJWT[@]}" --variant wrong-audience
verifier_refused result-dcapi-wrong-aud.json "$KB_JWT_FOR its aud does not match the expected audience"

echo "#### mdoc (mso_mdoc), the default engine"
present mdoc-post "$MDOC_VERIFIER" post "${MDOC[@]}"
present mdoc-get "$MDOC_VERIFIER" get "${MDOC[@]}"

echo "== mdoc over the Digital Credentials API (openid4vp-v1-signed)"
dcapi "$MDOC_VERIFIER" mdoc-dcapi "$ORIGIN" "${MDOC[@]}"
if jq -e '.status == "verified"' result-mdoc-dcapi.json >/dev/null && released result-mdoc-dcapi.json; then
  ok "the verifier verified the response the wallet assembled ($(jq -r '.encryption' mdoc-dcapi.json))"
else bad "the verifier verified it ($(explain mdoc-dcapi.json); $(why result-mdoc-dcapi.json))"; fi

echo "== control: an mdoc over the Digital Credentials API whose SessionTranscript names the client_id, not the origin"
dcapi "$MDOC_VERIFIER" mdoc-dcapi-wrong-origin "$ORIGIN" "${MDOC[@]}" --variant wrong-audience
verifier_refused result-mdoc-dcapi-wrong-origin.json "$DEVICE_SIGNATURE"

echo "#### mdoc through verifier.Transactions, under production assurance"
tx_present mdoc-transactions "$TX_MDOC_VERIFIER" "${MDOC[@]}"
tx_refused mdoc-revoked "$TX_MDOC_VERIFIER" accept "$REVOKED" "${MDOC[@]}" --variant revoked
tx_refused mdoc-untrusted-issuer "$TX_MDOC_VERIFIER" untrusted_issuer "$UNTRUSTED_ISSUER" "${MDOC[@]}" --variant untrusted-issuer
tx_refused mdoc-transcript-wrong-nonce "$TX_MDOC_VERIFIER" holder_binding "$DEVICE_SIGNATURE" "${MDOC[@]}" --variant wrong-nonce
tx_refused mdoc-transcript-wrong-client-id "$TX_MDOC_VERIFIER" holder_binding "$DEVICE_SIGNATURE" "${MDOC[@]}" --variant wrong-audience
tx_refused mdoc-unrequested-element "$TX_MDOC_VERIFIER" unrequested_claims \
  'verifier: the presentation discloses data elements the query didn'"'"'t ask for: "eu.europa.ec.eudi.pid.1/birth_date"' \
  "${MDOC[@]}" --variant extra-claim

# Each status check the verifier made, it made by fetching from serve:
# a run in which it fetched nothing checked no status at all.
echo "== the verifier fetched the status lists"
for path in /statuslists/jwt /statuslists/cwt; do
  if grep -q "served GET $path\$" serve.log; then ok "fetched $path"; else bad "fetched $path"; fi
done

if [[ "$fail" -eq 0 ]]; then echo "RESULT: every presentation accepted, and every control refused"; else echo "RESULT: FAILED"; fi
exit "$fail"
