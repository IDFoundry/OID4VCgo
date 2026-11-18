#!/usr/bin/env bash
# OID4VCgo's wallet against Credo (openwallet-foundation/credo-ts), from
# its published npm packages pinned by interop/credo/driver's
# package-lock.json:
#
#   our wallet ← Credo's issuer     OpenID4VCI 1.0: an SD-JWT VC PID and an
#                                   mDL by pre-authorized code, DPoP and a
#                                   Wallet Attestation from OID4VCgo's
#                                   Wallet Provider required, each
#                                   credential checked as the wallet does
#   our wallet → Credo's verifier   OpenID4VP 1.0: DCQL, a signed
#                                   x509_hash request, the response
#                                   encrypted (direct_post.jwt)
#
# then controls that one side or the other must refuse, each by its
# reason. interop/credo/driver is Credo, one agent as Credential
# Issuer and Verifier, driven over its control API; OID4VCgo's wallet is
# interop/waltid/scripts/wallet (walletflow). See README.md.
#
#   interop/credo/run.sh
#   CREDO_VERSION=latest interop/credo/run.sh
#
# CREDO_VERSION builds the driver against another Credo release (an npm
# version or dist-tag) instead of the pinned one, without the lock.
#
# Needs go, node (22 or later) and npm, jq, curl and openssl. Exits 0
# only if every case behaves as expected.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="${OID4VCGO_SRC:-$(cd "$HERE/../.." && pwd)}"
WORK="${WORK:-$(mktemp -d)}"
BASE_PORT="${BASE_PORT:-21600}"
# Credo's protocol endpoints (HTTPS) and its control API; OID4VCgo's
# Wallet Provider and its admin listener; then another Wallet Provider,
# under a CA Credo doesn't trust.
CREDO_PORT=$((BASE_PORT + 1)) CONTROL_PORT=$((BASE_PORT + 2))
WP_PORT=$((BASE_PORT + 3)) OTHER_WP_PORT=$((BASE_PORT + 5))
for p in $(seq "$CREDO_PORT" $((BASE_PORT + 6))); do
  if (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then
    echo "port $p is in use; set BASE_PORT" >&2
    exit 2
  fi
done
CREDO_URL="https://localhost:$CREDO_PORT"
CONTROL="http://127.0.0.1:$CONTROL_PORT"
CLIENT_ID=oid4vcgo-credo-interop-wallet

PIDS=()
# shellcheck disable=SC2329 # run by the EXIT trap
cleanup() {
  for pid in ${PIDS[@]+"${PIDS[@]}"}; do kill "$pid" 2>/dev/null || true; done
  for pid in ${PIDS[@]+"${PIDS[@]}"}; do wait "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT

echo "work dir  $WORK"
echo "oid4vcgo  $SRC, commit $(git -C "$SRC" rev-parse HEAD 2>/dev/null || echo unknown)"

# shellcheck source=../production.sh
. "$HERE/../production.sh"
build_production "$WORK" "$SRC" walletprovider=./interop/walletprovider
(cd "$SRC" && go build -o "$WORK/wallet" ./interop/waltid/scripts/wallet \
  && go run ./interop/credo/scripts/setup -out "$WORK" -issuer-url "$CREDO_URL/oid4vci/credo")

# askar_sha256 pins Askar's native library, by release and platform:
# the archive askar-nodejs's install script would fetch, unchecked, from
# Askar's GitHub releases. Moving the pin to an askar-nodejs that names
# another release adds its checksums here (README, "Moving the pin").
askar_sha256() {  # $1 release/archive
  local key="$1"
  case "$key" in
    v0.5.0/library-linux-x86_64.tar.gz) echo dc243dbfce814905810532885b21945fd62ed5ae3fb006f38c3ecd7c698a2adb ;;
    v0.5.0/library-linux-aarch64.tar.gz) echo 0f5bb24d397b7c329523059d7243f6d0dbcdf419c2a40b4164ce4607ad45dbf5 ;;
    v0.5.0/library-darwin-universal.tar.gz) echo 249f70967fe529433efa135689fedd9d4413a672a2ccca11be6b7ca8161d846d ;;
    *) echo "" ;;
  esac
}

# askar_library puts askar-nodejs's native library in its native/
# directory, checked against askar_sha256.
askar_library() {
  local pkg=node_modules/@openwallet-foundation/askar-nodejs
  local version host archive platform arch sum
  version=$(node -p "require('./$pkg/package.json').binary.version")
  host=$(node -p "require('./$pkg/package.json').binary.host")
  case "$(uname -s)" in
    Linux) platform=linux; case "$(uname -m)" in x86_64) arch=x86_64 ;; aarch64|arm64) arch=aarch64 ;; *) arch=$(uname -m) ;; esac ;;
    Darwin) platform=darwin; arch=universal ;;
    *) echo "no Askar library for $(uname -s)" >&2; return 1 ;;
  esac
  archive="library-$platform-$arch.tar.gz"
  sum=$(askar_sha256 "$version/$archive")
  [[ -n "$sum" ]] || { echo "no pinned checksum for Askar $version $archive: add it to askar_sha256" >&2; return 1; }
  curl -fsSL --max-time 120 -o "$archive" "$host/$version/$archive"
  echo "$sum  $archive" | shasum -a 256 -c - >/dev/null || { echo "Askar $version $archive: checksum mismatch" >&2; return 1; }
  mkdir -p "$pkg/native"
  tar -xzf "$archive" -C "$pkg/native"
  rm -f "$archive"
}

# The driver, built in the work dir from the checkout's sources: the
# pinned release by its lock (npm ci), or CREDO_VERSION's. No package's
# install script runs: the one native library they would fetch, Askar's,
# is fetched by askar_library and checked; the others' prebuilt binaries
# ship in their packages.
mkdir -p "$WORK/driver"
cp -R "$HERE/driver/package.json" "$HERE/driver/package-lock.json" "$HERE/driver/tsconfig.json" "$HERE/driver/src" "$WORK/driver/"
(
  cd "$WORK/driver"
  npm ci --ignore-scripts --no-audit --no-fund --loglevel=error
  if [[ -n "${CREDO_VERSION:-}" ]]; then
    [[ "$CREDO_VERSION" =~ ^[0-9A-Za-z.+-]+$ ]] || { echo "bad CREDO_VERSION: '$CREDO_VERSION'" >&2; exit 2; }
    npm install --ignore-scripts --no-audit --no-fund --loglevel=error --no-save \
      "@credo-ts/core@$CREDO_VERSION" "@credo-ts/openid4vc@$CREDO_VERSION" "@credo-ts/node@$CREDO_VERSION" "@credo-ts/askar@$CREDO_VERSION"
  fi
  askar_library
  npx --no-install tsc -p tsconfig.json
)
echo "credo     $(cd "$WORK/driver" && node -p "['core','openid4vc','node','askar'].map(p => '@credo-ts/' + p + '@' + require('./node_modules/@credo-ts/' + p + '/package.json').version).join(' ')")"
echo "node      $(node --version)"

cd "$WORK"
# OID4VCgo's Wallet Providers, walletprovider.Provider over sealed
# SQLite stores as a deployment runs it: the one Credo trusts for Wallet
# Attestations, and one under another CA, naming the same client.
start_wallet_provider "$WORK/walletprovider" "$WORK/wallet-provider" "$WP_PORT" $((WP_PORT + 1)) "$CLIENT_ID" \
  -ca-name "OID4VCgo Credo interop wallet provider CA"
PIDS+=($!)
start_wallet_provider "$WORK/walletprovider" "$WORK/other-wallet-provider" "$OTHER_WP_PORT" $((OTHER_WP_PORT + 1)) "$CLIENT_ID" \
  -ca-name "OID4VCgo Credo interop untrusted wallet provider CA"
PIDS+=($!)
wait_ready "http://127.0.0.1:$((WP_PORT + 1))/ready" "http://127.0.0.1:$((OTHER_WP_PORT + 1))/ready"

# Credo, trusting the first provider's CA for Wallet Attestations.
jq --rawfile wp wallet-provider/ca.pem '. + {attester_anchors: [$wp]}' credo.json > credo-run.json
node driver/build/main.js --config credo-run.json --base-url "$CREDO_URL" --port "$CREDO_PORT" --control-port "$CONTROL_PORT" \
  --log-level "${CREDO_LOG_LEVEL:-info}" > credo.log 2>&1 &
PIDS+=($!)
for _ in $(seq 1 100); do
  if grep -q '"ready":true' credo.log; then break; fi
  if grep -q '"ready":false' credo.log; then cat credo.log >&2; exit 2; fi
  sleep 0.2
done
grep -q '"ready":true' credo.log || { echo "Credo did not start; see $WORK/credo.log" >&2; exit 2; }

fail=0
ok() { echo "  ok    $1"; }
bad() { echo "  FAIL  $1"; fail=1; }
JSON='Content-Type: application/json'
# Why OID4VCgo's wallet refuses a chain to a CA it doesn't trust, and
# why Credo does.
UNTRUSTED='certchain: certificate chain does not verify against a trusted root: x509: certificate signed by unknown authority'
CREDO_UNTRUSTED='No trusted certificate was found while validating the X.509 chain'

# offer creates Credo's pre-authorized code offer of configuration $1,
# with a tx_code if $2 is true; it writes {id, offer, tx_code} to $3.
offer() {  # $1 configuration, $2 tx_code, $3 file
  local config="$1" tx_code="$2" out="$3"
  curl -sS --max-time 30 -X POST -H "$JSON" \
    --data "$(jq -cn --arg c "$config" --argjson t "$tx_code" '{configuration_ids: [$c], tx_code: $t}')" "$CONTROL/issuer/offers" > "$out"
}
issuance() { local id="$1"; curl -sS --max-time 30 "$CONTROL/issuer/sessions/$id"; }
# request creates Credo's request for DCQL query $1, signed unless $2 is
# false; it writes {id, request} to $3.
request() {  # $1 query, $2 signed, $3 file
  local query="$1" signed="$2" out="$3"
  curl -sS --max-time 30 -X POST -H "$JSON" \
    --data "$(jq -cn --argjson q "$query" --argjson s "$signed" '{query: $q, signed: $s}')" "$CONTROL/verifier/requests" > "$out"
}
verification() { local id="$1"; curl -sS --max-time 30 "$CONTROL/verifier/sessions/$id"; }

# wallet runs OID4VCgo's wallet under HAIP, attested by the trusted
# Wallet Provider unless the options name another; its outcome is in
# $1.json.
wallet() {  # $1 name; then the wallet's options
  local name="$1"; shift
  ./wallet -tls-ca ca.pem -mdoc-issuer-ca iaca.pem -crl-set none -haip -client-id "$CLIENT_ID" -out "$name.json" "$@" \
    >> "wallet-$name.log" 2>&1 || echo '{"stage": "wallet", "error": "the wallet failed; see its log"}' > "$name.json"
}
TRUSTED_WP=(-wallet-provider "https://localhost:$WP_PORT" -wallet-provider-tls wallet-provider/tls-cert.pem)
OTHER_WP=(-wallet-provider "https://localhost:$OTHER_WP_PORT" -wallet-provider-tls other-wallet-provider/tls-cert.pem)
why() {  # $1 file
  local file="$1"
  jq -c '{stage, error} | with_entries(select(.value != null))' "$file" 2>/dev/null | cut -c1-400 || head -c 400 "$file"
}

echo "### OID4VCgo's wallet ← Credo's issuer"
for c in "pid-sd-jwt dc+sd-jwt" "mdl-mdoc mso_mdoc"; do
  read -r config format <<< "$c"
  offer "$config" false "offer-$config.json"
  wallet "receive-$config" -issuer-ca ca.pem -verifier-ca ca.pem "${TRUSTED_WP[@]}" -offer "$(jq -r .offer "offer-$config.json")"
  state="$(issuance "$(jq -r .id "offer-$config.json")" | jq -r .state)"
  if jq -e --arg f "$format" '.stage == "done" and (.received | length == 1) and .received[0].format == $f
      and .observed.token_types == ["DPoP"]' "receive-$config.json" >/dev/null && [[ "$state" = Completed ]]; then
    ok "$config: issued (Wallet Attestation, DPoP) and checked ($(jq -r '.received[0] | "\(.format) \(.configuration_id)"' "receive-$config.json"))"
  else bad "$config: wallet $(why "receive-$config.json"), Credo's session $state"; fi
done

offer pid-sd-jwt true offer-tx-code.json
wallet receive-tx-code -issuer-ca ca.pem -verifier-ca ca.pem "${TRUSTED_WP[@]}" -offer "$(jq -r .offer offer-tx-code.json)" \
  -tx-code "$(jq -r .tx_code offer-tx-code.json)"
if jq -e '.stage == "done" and (.received | length == 1)' receive-tx-code.json >/dev/null; then
  ok "pid-sd-jwt with a tx_code: issued"
else bad "pid-sd-jwt with a tx_code: $(why receive-tx-code.json)"; fi
# The same, the tx_code's last digit another: Credo refuses the Token
# Request, for its tx_code.
offer pid-sd-jwt true offer-wrong-tx-code.json
wrong="$(jq -r '.tx_code | .[:-1] + (if .[-1:] == "0" then "1" else "0" end)' offer-wrong-tx-code.json)"
wallet receive-wrong-tx-code -issuer-ca ca.pem -verifier-ca ca.pem "${TRUSTED_WP[@]}" -offer "$(jq -r .offer offer-wrong-tx-code.json)" -tx-code "$wrong"
if jq -e '.stage == "token" and (.error | contains("token error response: invalid_grant: Invalid '"'tx_code'"' provided"))' \
    receive-wrong-tx-code.json >/dev/null; then
  ok "control: Credo refuses a wrong tx_code (invalid_grant, for its tx_code)"
else bad "control: a wrong tx_code: $(why receive-wrong-tx-code.json)"; fi

wallet receive-untrusted-issuer -issuer-ca other-ca.pem -verifier-ca ca.pem "${TRUSTED_WP[@]}" \
  -offer "$(offer pid-sd-jwt false offer-untrusted-issuer.json && jq -r .offer offer-untrusted-issuer.json)"
# Refused as the credential is checked, for its issuer's chain.
if jq -e --arg want "$UNTRUSTED" '.stage == "credential" and (.received | length == 0)
    and (.error | contains("is invalid: wallet: verify issued credential: issuer certificate: " + $want))' \
    receive-untrusted-issuer.json >/dev/null; then
  ok "control: a credential from an issuer the wallet doesn't trust is refused, for its chain"
else bad "control: a credential from an untrusted issuer: $(why receive-untrusted-issuer.json)"; fi

# The Wallet Attestation from the provider Credo doesn't trust: refused
# at the Token Endpoint, for its chain.
offer pid-sd-jwt false offer-untrusted-attester.json
wallet receive-untrusted-attester -issuer-ca ca.pem -verifier-ca ca.pem "${OTHER_WP[@]}" -offer "$(jq -r .offer offer-untrusted-attester.json)"
if jq -e --arg why "$CREDO_UNTRUSTED" '.stage == "token"
    and (.error | contains("token error response: invalid_client: Error verifying client attestation. client attestation jwt verification failed. " + $why))' \
    receive-untrusted-attester.json >/dev/null; then
  ok "control: Credo refuses a Wallet Attestation from a provider it doesn't trust (invalid_client, for its chain)"
else bad "control: an untrusted Wallet Provider: $(why receive-untrusted-attester.json)"; fi

# Credo's metadata says a pre-authorized code is redeemable with no
# client authentication, though its Token Endpoint requires a Wallet
# Attestation (README finding 1): the wallet's default profile, which
# takes that at its word, is refused. A known gap, so a note; the run
# fails if it changes.
offer pid-sd-jwt false offer-anonymous.json
./wallet -tls-ca ca.pem -mdoc-issuer-ca iaca.pem -crl-set none -client-id "$CLIENT_ID" -out receive-anonymous.json \
  -issuer-ca ca.pem -verifier-ca ca.pem "${TRUSTED_WP[@]}" -offer "$(jq -r .offer offer-anonymous.json)" >> wallet-receive-anonymous.log 2>&1 || true
if jq -e '.stage == "token" and (.error | contains("invalid_client: Missing required client attestation parameters"))' \
    receive-anonymous.json >/dev/null; then
  echo "  note  Credo advertises anonymous pre-authorized code redemption but refuses it (README finding 1): $(why receive-anonymous.json)"
else bad "README finding 1 has changed: the wallet's default profile, redeeming anonymously: $(why receive-anonymous.json)"; fi

echo "### OID4VCgo's wallet → Credo's verifier"
PID_QUERY='{"credentials": [{"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": ["urn:eudi:pid:1"]}, "claims": [{"path": ["family_name"]}, {"path": ["birthdate"]}]}]}'
MDL_QUERY='{"credentials": [{"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}, "claims": [{"path": ["org.iso.18013.5.1", "family_name"]}]}]}'
# present receives configuration $2 from Credo's issuer and presents it
# to Credo's request for query $3 (signed unless $4 is false); the
# wallet's outcome is in present-$1.json, Credo's session in
# present-$1-session.json. The rest are the wallet's options.
present() {  # $1 name, $2 configuration, $3 query, $4 signed; then the wallet's options
  local name="$1" config="$2" query="$3" signed="$4"; shift 4
  offer "$config" false "offer-present-$name.json"
  request "$query" "$signed" "request-$name.json"
  wallet "present-$name" -issuer-ca ca.pem "${TRUSTED_WP[@]}" -offer "$(jq -r .offer "offer-present-$name.json")" \
    -request "$(jq -r .request "request-$name.json")" "$@"
  verification "$(jq -r .id "request-$name.json")" > "present-$name-session.json"
}
session() { local name="$1"; jq -c '{state, error} | with_entries(select(.value != null))' "present-$name-session.json" 2>/dev/null | cut -c1-400; }

present pid pid-sd-jwt "$PID_QUERY" true -verifier-ca ca.pem
if jq -e '.stage == "done" and .query_ids == ["pid"]' present-pid.json >/dev/null \
    && jq -e '.state == "ResponseVerified" and .presented.pid[0].family_name == "Mustermann" and .presented.pid[0].birthdate == "1964-08-12"
      and (.presented.pid[0] | has("given_name") | not)' present-pid-session.json >/dev/null; then
  ok "pid: presented to a signed x509_hash request, encrypted; Credo verified it, only the requested claims disclosed"
else bad "pid: wallet $(why present-pid.json), Credo $(session pid)"; fi
present mdl mdl-mdoc "$MDL_QUERY" true -verifier-ca ca.pem
if jq -e '.stage == "done" and .query_ids == ["mdl"]' present-mdl.json >/dev/null \
    && jq -e '.state == "ResponseVerified" and .presented.mdl[0]["org.iso.18013.5.1.mDL"]["org.iso.18013.5.1"] == {family_name: "Mustermann"}' \
      present-mdl-session.json >/dev/null; then
  ok "mdl: presented to a signed x509_hash request, encrypted; Credo verified it, only the requested element disclosed"
else bad "mdl: wallet $(why present-mdl.json), Credo $(session mdl)"; fi
# Its response encryption key, in each signed request's client_metadata:
# one key, with the alg and kid OpenID4VP 1.0 §8.3 asks for (README,
# "What Credo sends").
echo "        observed: $(jq -c -s '[.[].observed.verifier_jwks]' present-pid.json present-mdl.json)"
if jq -s -e 'all(.[].observed.verifier_jwks; length == 1 and .[0].alg == "ECDH-ES" and .[0].kid != "absent")' \
    present-pid.json present-mdl.json >/dev/null; then
  ok "observed: Credo's response encryption JWK carries alg ECDH-ES and a kid"
else bad "observed: Credo's response encryption JWK changed: $(jq -c -s '[.[].observed.verifier_jwks]' present-pid.json present-mdl.json)"; fi

# Negative presentations: the wallet's transport changes the SD-JWT VC
# presentation on its way to Credo (interop/waltid/scripts/wallet's
# -tamper, tamper.go): it relays the response through a key of its
# own, so the relay case, which changes nothing else, must be accepted;
# each other case differs from it in one change, which Credo must
# refuse.
tamper() {  # $1 mode
  local mode="$1"
  present "tamper-$mode" pid-sd-jwt "$PID_QUERY" true -verifier-ca ca.pem -tamper "$mode" -verifier2-key verifier-key.pem
}
tampered() { local mode="$1"; echo "$(jq -c '.tampered | {changed, reply}' "present-tamper-$mode.json" 2>/dev/null | cut -c1-400), Credo $(session "tamper-$mode")"; }
tamper relay
if jq -e '.stage == "done" and .tampered.changed == "nothing" and .tampered.reply.status == 200' present-tamper-relay.json >/dev/null \
    && jq -e '.state == "ResponseVerified"' present-tamper-relay-session.json >/dev/null; then
  ok "pid, relayed through the transport's own key and changed in nothing else: Credo verified it"
else bad "pid, relayed: $(why present-tamper-relay.json); $(tampered relay)"; fi
# refused checks Credo refused the presentation mode $1 changed: its
# answer to the response (400 invalid_request), and its session's
# error, which names the reason $3.
refused() {  # $1 mode, $2 what was changed, $3 Credo's reason
  local mode="$1" changed="$2" reason="$3"
  if jq -e --arg c "$changed" '.stage == "response" and (.tampered.changed | startswith($c)) and .tampered.reply.status == 400
       and (.tampered.reply.body | fromjson | .error == "invalid_request")' "present-tamper-$mode.json" >/dev/null 2>&1 \
      && jq -e --arg r "$reason" '.state == "Error" and (.error | contains($r))' "present-tamper-$mode-session.json" >/dev/null 2>&1; then
    ok "control: Credo refuses a presentation whose $changed is another (400 invalid_request: $reason)"
  else bad "control: $changed changed: $(why "present-tamper-$mode.json"); $(tampered "$mode")"; fi
}
tamper nonce
refused nonce "KB-JWT nonce" "Verify Error: Invalid Nonce"
tamper aud
refused aud "KB-JWT aud" "The key binding JWT does not contain the expected audience"
# A disclosure whose digest the Issuer-signed JWT doesn't carry (RFC
# 9901 §7.1).
tamper disclosure
refused disclosure "disclosure" "Unreferenced disclosure(s) detected in SD-JWT"
# The Issuer-signed JWT signed again under a self-signed certificate:
# Credo checks the chain against its trust anchors.
tamper issuer
refused issuer "Issuer-signed JWT" "$CREDO_UNTRUSTED"

# Credo sends an unsigned request only by value, as a redirect_uri
# client: the wallet takes a request only signed, by reference
# (request_uri), and refuses it as it parses the link.
present unsigned pid-sd-jwt "$PID_QUERY" false -verifier-ca ca.pem
if jq -e '.stage == "request" and (.received | length == 1)
    and (.error | contains("wallet: parse authorization request link: request_uri is required"))' \
    present-unsigned.json >/dev/null && jq -e '.state != "ResponseVerified"' present-unsigned-session.json >/dev/null; then
  ok "control: an unsigned request (Credo's redirect_uri client) is refused"
else bad "control: an unsigned request: $(why present-unsigned.json)"; fi
present untrusted-verifier pid-sd-jwt "$PID_QUERY" true -verifier-ca other-ca.pem
if jq -e --arg want "$UNTRUSTED" '.stage == "request" and (.received | length == 1)
    and (.error | contains("parse authorization request: untrusted verifier: wallet: verifier certificate: " + $want))' \
    present-untrusted-verifier.json >/dev/null && jq -e '.state != "ResponseVerified"' present-untrusted-verifier-session.json >/dev/null; then
  ok "control: a Verifier whose Access Certificate the wallet doesn't trust is refused, for its chain"
else bad "control: an untrusted Verifier: $(why present-untrusted-verifier.json)"; fi

# The Wallet Attestations were the trusted provider's, and the other
# provider's was refused.
if grep -q ' served POST "/v1/wallet-attestation" 200' wallet-provider/wallet-provider.log \
    && grep -q ' served POST "/v1/wallet-attestation" 200' other-wallet-provider/wallet-provider.log; then
  ok "OID4VCgo's Wallet Providers issued the wallet's Wallet Attestations"
else bad "OID4VCgo's Wallet Providers issued the wallet's Wallet Attestations ($(grep ' served ' wallet-provider/wallet-provider.log | tail -3 | tr '\n' ';'))"; fi

if [[ $fail -ne 0 ]]; then echo "RESULT FAIL (logs in $WORK)"; else echo "RESULT ok"; fi
exit "$fail"
