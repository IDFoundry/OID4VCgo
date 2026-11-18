#!/usr/bin/env bash
# OID4VCgo against Credo (openwallet-foundation/credo-ts), from its
# published npm packages pinned by interop/credo/driver's
# package-lock.json, in four directions:
#
#   our wallet ← Credo's issuer     OpenID4VCI 1.0: an SD-JWT VC PID and an
#                                   mDL by pre-authorized code, DPoP and a
#                                   Wallet Attestation from OID4VCgo's
#                                   Wallet Provider required, each
#                                   credential checked as the wallet does;
#                                   and a PID whose jwt proof must carry
#                                   a Key Attestation
#   our wallet → Credo's verifier   OpenID4VP 1.0: DCQL, a signed
#                                   x509_hash request, the response
#                                   encrypted (direct_post.jwt)
#   Credo's holder ← our issuer     cmd/conformance-issuer (HAIP): SD-JWT
#                                   VC and mdoc PIDs by pre-authorized
#                                   code, a Wallet Attestation from
#                                   OID4VCgo's Wallet Provider, DPoP;
#                                   then its dpop-nonces, deferred and
#                                   key-attestation profiles
#   Credo's holder → our verifier   those PIDs, to cmd/conformance-verifier:
#                                   x509_hash, direct_post.jwt, DCQL, on
#                                   the default engine and through
#                                   verifier.Transactions under
#                                   production assurance, checking each
#                                   credential's status
#
# then controls that one side or the other must refuse, each by its
# reason. interop/credo/driver is Credo, one agent as Credential
# Issuer, Verifier and holder, driven over its control API; OID4VCgo's
# wallet is interop/waltid/scripts/wallet (walletflow). See README.md.
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
# under a CA Credo and OID4VCgo's issuer don't trust; the agents Credo's
# holder asks each of them through.
CREDO_PORT=$((BASE_PORT + 1)) CONTROL_PORT=$((BASE_PORT + 2))
WP_PORT=$((BASE_PORT + 3)) OTHER_WP_PORT=$((BASE_PORT + 5))
AGENT_PORT=$((BASE_PORT + 7)) OTHER_AGENT_PORT=$((BASE_PORT + 8))
# OID4VCgo's issuer, at https://localhost:$ISSUER_PORT through serve's
# tap, which logs what Credo's holder sends it (and the verifiers'
# status list fetches), listening behind it on ISSUER_INNER_PORT; its
# offers listener. Then OID4VCgo's five verifiers: the SD-JWT VC PID's on
# the default engine, then, through verifier.Transactions, the SD-JWT
# VC PID's, the mdoc PID's, and the two controls'.
ISSUER_PORT=$((BASE_PORT + 9)) OFFERS_PORT=$((BASE_PORT + 10)) ISSUER_INNER_PORT=$((BASE_PORT + 11))
VERIFIER_PORT=$((BASE_PORT + 12)) # and the next four
for p in $(seq "$CREDO_PORT" $((BASE_PORT + 16))); do
  if (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then
    echo "port $p is in use; set BASE_PORT" >&2
    exit 2
  fi
done
CREDO_URL="https://localhost:$CREDO_PORT"
CONTROL="http://127.0.0.1:$CONTROL_PORT"
OUR_ISSUER="https://localhost:$ISSUER_PORT"
CLIENT_ID=oid4vcgo-credo-interop-wallet

PIDS=()
ISSUER_PID=""
stop_issuer() {
  if [[ -n "$ISSUER_PID" ]]; then kill "$ISSUER_PID" 2>/dev/null || true; wait "$ISSUER_PID" 2>/dev/null || true; fi
  ISSUER_PID=""
}
# shellcheck disable=SC2329 # run by the EXIT trap
cleanup() {
  stop_issuer
  for pid in ${PIDS[@]+"${PIDS[@]}"}; do kill "$pid" 2>/dev/null || true; done
  for pid in ${PIDS[@]+"${PIDS[@]}"}; do wait "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT

echo "work dir  $WORK"
echo "oid4vcgo  $SRC, commit $(git -C "$SRC" rev-parse HEAD 2>/dev/null || echo unknown)"

# shellcheck source=../production.sh
. "$HERE/../production.sh"
# Built with the conformance_production tag: the Wallet Provider runs
# at all, and the verifiers on verifier.Transactions their production
# setup.
build_production "$WORK" "$SRC" walletprovider=./interop/walletprovider issuer=./cmd/conformance-issuer \
  verifier=./cmd/conformance-verifier
mkdir -p "$WORK/issuer-files"
(cd "$SRC" && go build -o "$WORK/wallet" ./interop/waltid/scripts/wallet \
  && go build -o "$WORK/serve" ./interop/waltid/scripts/serve \
  && go run ./interop/credo/scripts/setup -out "$WORK" -issuer-url "$CREDO_URL/oid4vci/credo" -our-issuer-url "$OUR_ISSUER" \
  && go run ./interop/eudi/scripts/setup-issuer -out "$WORK/issuer-files" -port "$ISSUER_INNER_PORT" -offers-port "$OFFERS_PORT")

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
# SQLite stores as a deployment runs it: the one Credo and OID4VCgo's
# issuer trust for Wallet Attestations and Key Attestations, and one
# under another CA, naming the same client and identifier (the attester
# OID4VCgo's issuer expects of its client). Then, for Credo's holder,
# the wallet's side of each, an agent with one registered instance.
ATTESTER="$(jq -r '.attester_issuer' issuer-files/driver.json)"
start_wallet_provider "$WORK/walletprovider" "$WORK/wallet-provider" "$WP_PORT" $((WP_PORT + 1)) "$CLIENT_ID" \
  -identifier "$ATTESTER" -ca-name "OID4VCgo Credo interop wallet provider CA"
PIDS+=($!)
start_wallet_provider "$WORK/walletprovider" "$WORK/other-wallet-provider" "$OTHER_WP_PORT" $((OTHER_WP_PORT + 1)) "$CLIENT_ID" \
  -identifier "$ATTESTER" -ca-name "OID4VCgo Credo interop untrusted wallet provider CA"
PIDS+=($!)
wait_ready "http://127.0.0.1:$((WP_PORT + 1))/ready" "http://127.0.0.1:$((OTHER_WP_PORT + 1))/ready"
start_provider_agent "$WORK/walletprovider" "$WORK/wallet-provider" "$WP_PORT" "$AGENT_PORT"
PIDS+=($!)
start_provider_agent "$WORK/walletprovider" "$WORK/other-wallet-provider" "$OTHER_WP_PORT" "$OTHER_AGENT_PORT"
PIDS+=($!)
wait_ready "http://127.0.0.1:$AGENT_PORT/ready" "http://127.0.0.1:$OTHER_AGENT_PORT/ready"

# Credo, trusting the first provider's CA for Wallet Attestations and
# Key Attestations; as holder, OID4VCgo's issuer's credentials by their
# chain to the run's CA (the SD-JWT VC signer) or to setup-issuer's
# IACA (the mdoc Document Signer), and OID4VCgo's verifiers' requests by
# their Access Certificate's chain to the run's CA. Every TLS server of
# the run has the run's CA's certificate, which Node trusts as well as
# its own roots (NODE_EXTRA_CA_CERTS).
jq --rawfile wp wallet-provider/ca.pem --rawfile ca ca.pem --arg iaca "$(jq -r '.iaca_pem' issuer-files/driver.json)" \
  --arg trusted "http://127.0.0.1:$AGENT_PORT" --arg other "http://127.0.0.1:$OTHER_AGENT_PORT" \
  '. + {attester_anchors: [$wp], holder_credential_anchors: [$ca, $iaca], holder_request_anchors: [$ca],
        wallet_providers: {trusted: $trusted, other: $other}}' credo.json > credo-run.json
NODE_EXTRA_CA_CERTS="$WORK/ca.pem" node driver/build/main.js --config credo-run.json --base-url "$CREDO_URL" --port "$CREDO_PORT" \
  --control-port "$CONTROL_PORT" --log-level "${CREDO_LOG_LEVEL:-info}" > credo.log 2>&1 &
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
# Why Credo's issuer refuses a Key Attestation of lower key storage than
# it requires.
CREDO_KA_LEVEL='Insufficient key_storage for key attestation'
# Why OID4VCgo's issuer refuses a wrong tx_code, and a Wallet
# Attestation from an attester it doesn't trust, as Credo's holder
# reports its Token Endpoint's error response, and a Key Attestation
# without the c_nonce; and why its verifier refuses a revoked
# credential.
OUR_WRONG_TX_CODE='{"error":"invalid_grant","error_description":"tx_code does not match"}'
OUR_UNTRUSTED_ATTESTER='{"error":"invalid_client","error_description":"no matching attester key"}'
OUR_KA_NONCE="proof 0: its key_attestation's nonce isn't the proof's c_nonce"
OUR_REVOKED="verifier: credential status: statuslist: the referenced token's status is INVALID (revoked)"
# What the transactions verifier answers Credo's holder's response with
# when it refuses it.
OUR_REFUSAL='{"error":"invalid_request","error_description":"the response was not accepted"}'

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

# Key attestations: pid-sd-jwt-ka's jwt proof requires one
# (key_attestations_required, key storage iso_18045_moderate), which the
# wallet gets from the Wallet Provider and sends in the proof's
# key_attestation header, naming the proof's key in its jwk header
# (-proof-key-by-jwk); Credo checks it by its chain to the provider's
# CA. The provider served it, in this case alone so far.
ka_before="$(grep -c ' served POST "/v1/key-attestation" 200' wallet-provider/wallet-provider.log || true)"
offer pid-sd-jwt-ka false offer-key-attestation.json
wallet receive-key-attestation -issuer-ca ca.pem -verifier-ca ca.pem "${TRUSTED_WP[@]}" -proof-key-by-jwk \
  -offer "$(jq -r .offer offer-key-attestation.json)"
state="$(issuance "$(jq -r .id offer-key-attestation.json)" | jq -r .state)"
ka_after="$(grep -c ' served POST "/v1/key-attestation" 200' wallet-provider/wallet-provider.log || true)"
if jq -e '.stage == "done" and (.received | length == 1)' receive-key-attestation.json >/dev/null \
    && [[ "$state" = Completed && "$ka_after" -gt "$ka_before" ]]; then
  ok "pid-sd-jwt-ka: issued, the jwt proof carrying a Key Attestation from OID4VCgo's Wallet Provider, which Credo checked"
else bad "pid-sd-jwt-ka: wallet $(why receive-key-attestation.json), Credo's session $state, Key Attestations served $ka_before → $ka_after"; fi
# The same, but pid-sd-jwt-ka-high requires key storage iso_18045_high,
# above the iso_18045_moderate the provider attests: Credo refuses the
# Credential Request, for the key storage level.
offer pid-sd-jwt-ka-high false offer-key-attestation-high.json
wallet receive-key-attestation-high -issuer-ca ca.pem -verifier-ca ca.pem "${TRUSTED_WP[@]}" -proof-key-by-jwk \
  -offer "$(jq -r .offer offer-key-attestation-high.json)"
if jq -e --arg why "$CREDO_KA_LEVEL" '.stage == "credential" and (.received | length == 0) and (.error | contains($why))' \
    receive-key-attestation-high.json >/dev/null; then
  ok "control: Credo refuses a Key Attestation below the key storage level it requires ($CREDO_KA_LEVEL)"
else bad "control: a Key Attestation below the required key storage level: $(why receive-key-attestation-high.json)"; fi
# README finding 7: the wallet's default names the proof's key by its
# index in the Key Attestation's attested_keys, as kid "0" (OpenID4VCI
# 1.0 Appendix F.1 allows kid, jwk or x5c; ETSI TS 119 472-3 requires
# the index), which Credo can't verify a proof by. The case differs from
# pid-sd-jwt-ka's in that alone. A known gap, so a note; the run fails if
# it changes.
offer pid-sd-jwt-ka false offer-key-attestation-index.json
wallet receive-key-attestation-index -issuer-ca ca.pem -verifier-ca ca.pem "${TRUSTED_WP[@]}" \
  -offer "$(jq -r .offer offer-key-attestation-index.json)"
if jq -e '.stage == "credential" and (.received | length == 0)
    and (.error | contains("invalid_proof: Error verifying credential request proof jwt. Unable to verify jws with unsupported jws signer method '"'custom'"'"))' \
    receive-key-attestation-index.json >/dev/null; then
  echo "  note  Credo refuses a key-attested jwt proof naming its key by its index (README finding 7): $(why receive-key-attestation-index.json)"
else bad "README finding 7 has changed: a key-attested jwt proof naming its key by index: $(why receive-key-attestation-index.json)"; fi

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

# OID4VCgo's issuer, cmd/conformance-issuer as interop/eudi/run-issuer.sh
# runs it (setup-issuer's config: HAIP, pre-authorized code offers from
# its offers listener), named localhost under the run's TLS certificate,
# on loopback behind serve's tap; its client is the one the Wallet
# Providers attest, its Wallet Attestations and Key Attestations
# trusted by their chain to the trusted provider's CA; its SD-JWT VCs
# signed by setup's our-issuer certificate, which names it (README
# finding 3); every credential with a Token Status List entry.
# shellcheck disable=SC2016 # jq's variables, not the shell's
jq --arg issuer "$OUR_ISSUER" --arg addr "127.0.0.1:$ISSUER_INNER_PORT" --arg client "$CLIENT_ID" \
  --rawfile cert tls-cert.pem --rawfile key tls-key.pem --rawfile wpca wallet-provider/ca.pem \
  --rawfile signer our-issuer-key.pem --rawfile signercert our-issuer-cert.pem \
  '.issuer = $issuer | .listen_addr = $addr | .tls_certificate_pem = $cert | .tls_private_key_pem = $key
    | .client.id = $client | .client.attester_trust_anchors_pem = $wpca | .key_attestation = {trust_anchor_pem: $wpca}
    | .credential_issuer_signing_key_pem = $signer | .credential_issuer_certificate_pem = $signercert
    | .status_lists = {}' issuer-files/issuer.json > our-issuer.json
./serve -dir . -tap "127.0.0.1:$ISSUER_PORT=https://127.0.0.1:$ISSUER_INNER_PORT" -tap-name localhost > serve.log 2>&1 &
PIDS+=($!)

# start_issuer (re)starts OID4VCgo's issuer in a profile of
# interop/eudi/run-issuer.sh's: our-issuer.json changed by the jq filter
# $2.
start_issuer() {  # $1 the profile's name, $2 a jq filter
  local name="$1" filter="$2"
  stop_issuer
  jq "$filter" our-issuer.json > "our-issuer-$name.json"
  ./issuer -config "our-issuer-$name.json" >> "our-issuer-$name.log" 2>&1 &
  ISSUER_PID=$!
  for _ in $(seq 1 50); do
    if curl -s -o /dev/null --max-time 1 --cacert ca.pem "$OUR_ISSUER/.well-known/openid-credential-issuer" \
      && curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$OFFERS_PORT/offers"; then return 0; fi
    sleep 0.2
  done
  echo "the issuer did not start in profile $name; see $WORK/our-issuer-$name.log" >&2
  exit 2
}
# our_offer is a pre-authorized code offer of OID4VCgo's issuer's
# configuration $1, by reference, with the tx_code $2 if given.
our_offer() {  # $1 configuration, $2 a tx_code
  local config="$1" tx="${2:-}"
  curl -sS --max-time 30 -X POST -H "$JSON" \
    --data "$(jq -cn --arg c "$config" --arg t "$tx" '{grant: "pre-authorized_code", credential_configuration_ids: [$c], by_reference: true}
      + (if $t == "" then {} else {tx_code: $t} end)')" "http://127.0.0.1:$OFFERS_PORT/offers" | jq -r '.uri'
}
# The Wallet Provider agents, by their names in credo-run.json.
AGENT=trusted OTHER_AGENT=other
# holder_receive has Credo's holder redeem the offer $2, attested through
# the Wallet Provider agent $3, with the tx_code $4 if given; $5 false
# has it look up the keys it signs with by kid alone, as Credo does
# (README finding 6); $6 false has its Key Attestations carry no c_nonce
# (holder.ts). Its outcome is in holder-$1.json, and what it sent
# OID4VCgo's issuer, as the tap saw it, in tap-$1.log.
holder_receive() {  # $1 name, $2 offer, $3 agent; then a tx_code, keys_by_thumbprint and key_attestation_nonce
  local name="$1" offer="$2" agent="$3" tx="${4:-}" thumbs="${5:-true}" nonce="${6:-true}" from
  from="$(wc -l < serve.log)"
  curl -sS --max-time 120 -X POST -H "$JSON" \
    --data "$(jq -cn --arg o "$offer" --arg a "$agent" --arg c "$CLIENT_ID" --arg t "$tx" --argjson k "$thumbs" --argjson n "$nonce" \
      '{offer: $o, wallet_provider: $a, client_id: $c, keys_by_thumbprint: $k, key_attestation_nonce: $n}
        + (if $t == "" then {} else {tx_code: $t} end)')" \
    "$CONTROL/holder/receive" > "holder-$name.json" || echo '{"stage": "control", "error": "the control API failed"}' > "holder-$name.json"
  tail -n +"$((from + 1))" serve.log | grep ' tap: ' | sed 's/.* tap: //' > "tap-$name.log" || true
}
held() {  # $1 name: Credo's holder's outcome, briefly
  local name="$1"
  jq -c '{stage, error, received: [.received[]? | .configuration_id]} | with_entries(select(.value != null))' "holder-$name.json" 2>/dev/null \
    | cut -c1-500 || head -c 500 "holder-$name.json"
}
OUR_SDJWT="$(jq -r '.sdjwt_configuration_id' issuer-files/driver.json)" OUR_MDOC="$(jq -r '.mdoc_configuration_id' issuer-files/driver.json)"

echo "### Credo's holder ← OID4VCgo's issuer"
start_issuer base .
for c in "pid $OUR_SDJWT dc+sd-jwt" "mdoc $OUR_MDOC mso_mdoc"; do
  read -r name config format <<< "$c"
  holder_receive "$name" "$(our_offer "$config")" "$AGENT"
  if jq -e --arg f "$format" '.stage == "done" and (.received | length == 1) and .received[0].format == $f
      and .token_type == "DPoP" and .proof_types == ["jwt"]' "holder-$name.json" >/dev/null \
      && grep -q '^POST "/token" 200 | pop ' "tap-$name.log" && grep -q '^POST "/credential" 200' "tap-$name.log"; then
    ok "$config: issued to Credo's holder (Wallet Attestation, DPoP), which checked it"
  else bad "$config: $(held "$name"); $(tr '\n' ';' < "tap-$name.log" | head -c 300)"; fi
done
holder_receive tx-code "$(our_offer "$OUR_SDJWT" 493817)" "$AGENT" 493817
if jq -e '.stage == "done" and (.received | length == 1)' holder-tx-code.json >/dev/null; then
  ok "$OUR_SDJWT with a tx_code: issued"
else bad "$OUR_SDJWT with a tx_code: $(held tx-code)"; fi
# The same, the tx_code's last digit another: the issuer refuses the
# Token Request, for its tx_code.
holder_receive wrong-tx-code "$(our_offer "$OUR_SDJWT" 493817)" "$AGENT" 493810
if jq -e --arg why "$OUR_WRONG_TX_CODE" '.stage == "token" and (.received | length == 0) and (.error | contains($why))' \
    holder-wrong-tx-code.json >/dev/null && grep -q '^POST "/token" 400' tap-wrong-tx-code.log; then
  ok "control: OID4VCgo's issuer refuses a wrong tx_code (400 $OUR_WRONG_TX_CODE)"
else bad "control: a wrong tx_code: $(held wrong-tx-code)"; fi
# A Wallet Attestation from the provider OID4VCgo's issuer doesn't trust.
# Credo reports the Token Endpoint's error and its description; the
# case differs from the first above in its provider alone, whose
# attestation the tap saw refused at the Token Endpoint.
holder_receive untrusted-attester "$(our_offer "$OUR_SDJWT")" "$OTHER_AGENT"
if jq -e --arg why "$OUR_UNTRUSTED_ATTESTER" '.stage == "token" and (.received | length == 0) and (.error | contains($why))' \
    holder-untrusted-attester.json >/dev/null && grep -q '^POST "/token" 401 | pop ' tap-untrusted-attester.log; then
  ok "control: OID4VCgo's issuer refuses a Wallet Attestation from a provider it doesn't trust (401 $OUR_UNTRUSTED_ATTESTER)"
else bad "control: an untrusted Wallet Provider: $(held untrusted-attester); $(tr '\n' ';' < tap-untrusted-attester.log | head -c 300)"; fi
# README finding 6: Credo signs only with a key whose JWK names its kid,
# which the Wallet Attestation's cnf.jwk needn't, and OID4VCgo's Wallet
# Provider's doesn't: without the driver's lookup by thumbprint, Credo
# can't sign the Client Attestation PoP, and sends no Token Request. A
# known gap, so a note; the run fails if it changes.
holder_receive by-kid "$(our_offer "$OUR_SDJWT")" "$AGENT" "" false
if jq -e '.stage == "token" and (.error | contains("Unable to determine keyId for jwk"))' holder-by-kid.json >/dev/null \
    && ! grep -q '"/token"' tap-by-kid.log; then
  echo "  note  Credo's holder can't sign with the key of a Wallet Attestation whose cnf.jwk has no kid (README finding 6): $(held by-kid)"
else bad "README finding 6 has changed: Credo's holder, looking keys up by kid alone: $(held by-kid)"; fi
# What Credo's holder sent the Token Endpoint, of what SPECIFICATIONS.md's
# "Known leniencies" concern: a Client Attestation PoP without iss
# (draft-07 §5.2 has one; later drafts don't), and DPoP proofs. Asserted
# as 0.7.4 sends them, so that a change is noticed.
SENT_TOKEN='"/token" 200 | pop iss=absent claims=aud,iat,jti | dpop typ="dpop+jwt" alg="ES256"'
echo "        observed: $(grep -hF '"/token" 200' tap-pid.log tap-mdoc.log | head -1)"
cat tap-pid.log tap-mdoc.log > tap-base.log
if [[ "$(grep -cF "$SENT_TOKEN" tap-base.log || true)" -ge 2 ]]; then
  ok "observed: Credo's holder sends a Client Attestation PoP without iss, and a DPoP proof"
else bad "observed: what Credo's holder sends the Token Endpoint changed: $(grep -hF '"/token"' tap-pid.log tap-mdoc.log | tr '\n' ';' | head -c 400)"; fi

echo "### Credo's holder → OID4VCgo's verifier"
# OID4VCgo's verifiers (cmd/conformance-verifier), each a signed
# x509_hash request under setup's our-verifier Access Certificate, the
# response encrypted (direct_post.jwt), checking each credential's
# chain and its Token Status List entry, fetched from the issuer
# through the tap: the SD-JWT VC PID's on the default engine at
# development assurance; the rest through verifier.Transactions under
# production assurance, its transactions in a sealed SQLite file: the
# SD-JWT VC PID's, the mdoc PID's, one whose Access Certificate is under
# the CA Credo doesn't trust, and one trusting another issuer CA.
# shellcheck disable=SC2016 # jq's variables, not the shell's
jq -n --rawfile cert tls-cert.pem --rawfile key tls-key.pem --rawfile access our-verifier-cert.pem \
  --rawfile accesskey our-verifier-key.pem --rawfile ca ca.pem --arg vct "$(jq -r '.vct' issuer-files/driver.json)" \
  '{tls_certificate_pem: $cert, tls_private_key_pem: $key, client_certificate_pem: $access, client_private_key_pem: $accesskey,
    vct: $vct, claims: ["family_name", "given_name"], credential_issuer_trust_anchors_pem: $ca,
    status_list_trust_anchors_pem: $ca, status_list_tls_trust_anchors_pem: $ca, status_list_allow_loopback: true}' > verifier-base.json
# shellcheck disable=SC2016 # jq's variables, not the shell's
TX_FILTER='.engine = "transactions" | .production = {database_path: $db, sealing_key: $key}'
# verifier_config writes verifier-$1.json, the base listening on port
# $2, changed by the jq filter $3 (and, unless $4 is "dev",
# TX_FILTER's), which reads $other (other-ca.pem), $iaca and the
# untrusted Access Certificate's $ucert and $ukey.
verifier_config() {  # $1 name, $2 port, $3 jq filter, $4 dev or tx
  local name="$1" port="$2" filter="$3" engine="$4"
  if [[ "$engine" = tx ]]; then filter="$filter | $TX_FILTER"; fi
  jq --arg addr "127.0.0.1:$port" --arg base "https://localhost:$port" --arg db "$WORK/verifier-$name.db" --arg key "$(sealing_key)" \
    --rawfile other other-ca.pem --arg iaca "$(jq -r '.iaca_pem' issuer-files/driver.json)" \
    --rawfile ucert untrusted-verifier-cert.pem --rawfile ukey untrusted-verifier-key.pem \
    --arg doctype "$(jq -r '.doctype' issuer-files/driver.json)" --arg ns "$(jq -r '.namespace' issuer-files/driver.json)" \
    ".listen_addr = \$addr | .base_url = \$base | $filter" verifier-base.json > "verifier-$name.json"
}
verifier_config sdjwt "$VERIFIER_PORT" . dev
verifier_config sdjwt-tx $((VERIFIER_PORT + 1)) . tx
# shellcheck disable=SC2016 # jq's variables, not the shell's
verifier_config mdoc-tx $((VERIFIER_PORT + 2)) 'del(.vct, .claims, .credential_issuer_trust_anchors_pem)
  | .credential_format = "mso_mdoc" | .doctype = $doctype | .namespace = $ns | .mdoc_claims = ["family_name", "given_name"]
  | .mdoc_trust_anchor_pem = $iaca | .status_list_trust_anchors_pem = $iaca' tx
# shellcheck disable=SC2016 # jq's variables, not the shell's
verifier_config untrusted-access $((VERIFIER_PORT + 3)) '.client_certificate_pem = $ucert | .client_private_key_pem = $ukey' tx
# shellcheck disable=SC2016 # jq's variables, not the shell's
verifier_config untrusted-issuer $((VERIFIER_PORT + 4)) '.credential_issuer_trust_anchors_pem = $other' tx
for v in sdjwt sdjwt-tx mdoc-tx untrusted-access untrusted-issuer; do
  ./verifier -config "verifier-$v.json" > "verifier-$v.log" 2>&1 &
  PIDS+=($!)
done
for port in $(seq "$VERIFIER_PORT" $((VERIFIER_PORT + 4))); do
  for _ in $(seq 1 50); do
    if curl -s -o /dev/null --max-time 1 --cacert ca.pem "https://localhost:$port/"; then continue 2; fi
    sleep 0.2
  done
  echo "the verifier on $port did not start; see $WORK/verifier-*.log" >&2
  exit 2
done

# authorize starts a request on the default-engine verifier at port $1,
# as a same-device page would, with request_uri_method $2, and prints
# the openid4vp:// launch; tx_authorize begins one on a transactions
# verifier, its browser binding kept in the cookie jar $2.
authorize() {
  local port="$1" method="$2"
  curl -sS --max-time 30 --cacert ca.pem -o /dev/null -w '%{redirect_url}' "https://localhost:$port/authorize?request_uri_method=$method"
}
tx_authorize() {
  local port="$1" jar="$2"
  curl -sS --max-time 30 --cacert ca.pem -c "$jar" -o /dev/null -w '%{redirect_url}' "https://localhost:$port/authorize"
}
# holder_present has Credo's holder answer the launch $2 with the stored
# credentials $3 ({query id: credential id}); its outcome is in
# answer-$1.json.
holder_present() {  # $1 name, $2 launch, $3 credentials
  local name="$1" launch="$2" credentials="$3"
  curl -sS --max-time 120 -X POST -H "$JSON" \
    --data "$(jq -cn --arg r "$launch" --argjson c "$credentials" '{request: $r, credentials: $c}')" \
    "$CONTROL/holder/present" > "answer-$name.json" || echo '{"stage": "control", "error": "the control API failed"}' > "answer-$name.json"
}
answered() {  # $1 name: Credo's holder's answer, briefly
  local name="$1"
  jq -c '{stage, status, error} | with_entries(select(.value != null))' "answer-$name.json" 2>/dev/null | cut -c1-500
}
# redeem follows the redirect_uri the default-engine verifier answered
# Credo's response with and redeems its response_code: the verifier's
# outcome is in result-$1.json.
redeem() {  # $1 name
  local name="$1" redirect
  redirect="$(jq -r '.body.redirect_uri // empty' "answer-$name.json" 2>/dev/null || true)"
  if [[ -z "$redirect" ]]; then echo '{"status": "no redirect_uri"}' > "result-$name.json"; return; fi
  curl -sS --max-time 30 --cacert ca.pem -o "result-$name.json" "${redirect/\?response_code=//redeem?response_code=}" || true
}
# tx_result saves the transactions verifier's page for the request the
# answer-$1.json answered: its redirect_uri, which redeems the
# response_code, or else the request's own page, /result/{id}, for the
# launch $2; both in the browser whose cookie jar is $3. Its HTML
# entities are decoded into result-$1.html.
tx_result() {  # $1 name, $2 launch, $3 cookie jar
  local name="$1" launch="$2" jar="$3" url
  url="$(jq -r '.body.redirect_uri // empty' "answer-$name.json" 2>/dev/null || true)"
  if [[ -z "$url" ]]; then
    url="$(sed -E 's/.*[?&]request_uri=([^&]*).*/\1/' <<< "$launch")"
    url="$(printf '%b' "${url//%/\\x}")"
    url="${url/\/request\///result/}"
  fi
  curl -sS --max-time 30 --cacert ca.pem -b "$jar" "$url" 2>/dev/null \
    | sed -e 's/&#34;/"/g' -e "s/&#39;/'/g" -e 's/&lt;/</g' -e 's/&gt;/>/g' -e 's/&amp;/\&/g' > "result-$name.html" || true
}
page() { local name="$1"; sed 's/<[^>]*>/ /g' "result-$name.html" | tr -s ' \n' ' ' | head -c 400; }
# refused_answer reports whether the verifier answered Credo's
# holder's response $1 as one it refused (400, OUR_REFUSAL).
refused_answer() {
  local name="$1"
  jq -e --argjson want "$OUR_REFUSAL" '.stage == "response" and .status == 400 and .body == $want' "answer-$name.json" >/dev/null 2>&1
}

PID_ID="$(jq -r '.received[0].id' holder-pid.json)" MDOC_ID="$(jq -r '.received[0].id' holder-mdoc.json)"
for method in get post; do
  holder_present "pid-$method" "$(authorize "$VERIFIER_PORT" "$method")" "{\"cred1\": \"$PID_ID\"}"
  redeem "pid-$method"
  if jq -e '.stage == "done"' "answer-pid-$method.json" >/dev/null \
      && jq -e '.status == "verified" and (.credentials.cred1 | has("family_name") and has("given_name") and (has("birth_date") | not))' \
        "result-pid-$method.json" >/dev/null; then
    ok "sd-jwt pid, request_uri_method $method: verified (issuer, holder binding, status, response encrypted), only the requested claims disclosed"
  else bad "sd-jwt pid, request_uri_method $method: Credo $(answered "pid-$method"), verifier $(jq -c . "result-pid-$method.json" | head -c 300)"; fi
done
# tx_present has Credo's holder answer a request begun on the
# transactions verifier at port $2 with the stored credential $3; the
# verifier's page is in result-$1.html.
tx_present() {  # $1 name, $2 port, $3 credential id
  local name="$1" port="$2" id="$3" launch
  launch="$(tx_authorize "$port" "tx-$name.cookies")"
  holder_present "$name" "$launch" "{\"cred1\": \"$id\"}"
  tx_result "$name" "$launch" "tx-$name.cookies"
}
# A PID OID4VCgo's issuer revokes after issuing it (POST /status, its
# status list entry INVALID): the verifier refuses it, for its status.
# The case differs from the sd-jwt pid's through the same verifier,
# next, in the credential's status alone; it comes first, as the
# verifier then caches the list for its ttl, as a Relying Party may.
holder_receive revoked "$(our_offer "$OUR_SDJWT")" "$AGENT"
REVOKED_ID="$(jq -r '.received[0].id // empty' holder-revoked.json)"
curl -sS --max-time 30 -X POST -H "$JSON" --data "$(jq -c '.received[0].status + {status: "INVALID"}' holder-revoked.json)" \
  "http://127.0.0.1:$OFFERS_PORT/status" > revoke.json || true
tx_present revoked $((VERIFIER_PORT + 1)) "$REVOKED_ID"
# The page names no verifier.Reason for a status refusal: its error
# says why.
if jq -e '.status == "INVALID"' revoke.json >/dev/null 2>&1 && refused_answer revoked \
    && grep -q '<h1>Verification failed</h1>' result-revoked.html && grep -qF "<pre>$OUR_REVOKED</pre>" result-revoked.html; then
  ok "control: the verifier refuses a PID its issuer revoked, for its status ($OUR_REVOKED)"
else bad "control: a revoked PID: revoke $(head -c 200 revoke.json), Credo $(answered revoked), verifier $(page revoked)"; fi
tx_present pid-tx $((VERIFIER_PORT + 1)) "$PID_ID"
if grep -q '<h1>Verification succeeded</h1>' result-pid-tx.html && grep -q '"family_name"' result-pid-tx.html \
    && grep -q '"given_name"' result-pid-tx.html; then
  ok "sd-jwt pid through verifier.Transactions under production assurance: verified, released to the browser that asked"
else bad "sd-jwt pid through verifier.Transactions: Credo $(answered pid-tx), verifier $(page pid-tx)"; fi
tx_present mdoc-tx $((VERIFIER_PORT + 2)) "$MDOC_ID"
if grep -q '<h1>Verification succeeded</h1>' result-mdoc-tx.html && grep -q '"family_name"' result-mdoc-tx.html \
    && grep -q '"given_name"' result-mdoc-tx.html && ! grep -qE '"(birth_date|issuing_country|issuing_authority)"' result-mdoc-tx.html; then
  ok "mdoc pid through verifier.Transactions under production assurance: verified, only the requested elements disclosed"
else bad "mdoc pid: Credo $(answered mdoc-tx), verifier $(page mdoc-tx)"; fi
# The verifier's Access Certificate under the CA Credo's holder doesn't
# trust: Credo refuses the request as it resolves it, and answers
# nothing.
tx_present untrusted-access $((VERIFIER_PORT + 3)) "$PID_ID"
if jq -e --arg why "$CREDO_UNTRUSTED" '.stage == "request" and (.error | contains($why)) and (.status | not)' \
    answer-untrusted-access.json >/dev/null && ! grep -q '<h1>Verification succeeded</h1>' result-untrusted-access.html; then
  ok "control: Credo's holder refuses a request whose Access Certificate it doesn't trust ($CREDO_UNTRUSTED)"
else bad "control: a Verifier whose Access Certificate Credo doesn't trust: Credo $(answered untrusted-access)"; fi
# The verifier trusting another issuer CA: it refuses the credential,
# for its issuer's chain (verifier.Reason untrusted_issuer).
tx_present untrusted-issuer $((VERIFIER_PORT + 4)) "$PID_ID"
if refused_answer untrusted-issuer && grep -q '<h1>Verification failed</h1>' result-untrusted-issuer.html \
    && grep -qF '<pre>reason: untrusted_issuer</pre>' result-untrusted-issuer.html \
    && grep -qF "verifier: resolve issuer key: $UNTRUSTED" result-untrusted-issuer.html; then
  ok "control: the verifier refuses a credential from an issuer it doesn't trust, for its chain (untrusted_issuer)"
else bad "control: a credential from an issuer the verifier doesn't trust: Credo $(answered untrusted-issuer), verifier $(page untrusted-issuer)"; fi
# The verifiers checked status by fetching the issuer's lists, through
# the tap; so did Credo's holder, as it received each credential
# (README, observation 9), which the tap tells by its User-Agent.
for path in /statuslists/1 /statuslists/1/cwt; do
  fetched="$(grep " tap: GET \"$path\" 200" serve.log | grep -v 'client="node"' | head -1 | sed 's/.* | //')"
  if [[ -n "$fetched" ]]; then ok "the verifiers fetched $path from OID4VCgo's issuer ($fetched)"
  else bad "the verifiers fetched $path from OID4VCgo's issuer ($(grep ' tap: GET "/statuslists' serve.log | head -3 | sed 's/.* tap: //' | tr '\n' ';'))"; fi
done
if grep ' tap: GET "/statuslists/1" 200' serve.log | grep -q 'client="node"' \
    && grep ' tap: GET "/statuslists/1/cwt" 200' serve.log | grep -q 'client="node"'; then
  ok "observed: Credo's holder fetches each credential's status list as it receives it"
else bad "observed: Credo's holder no longer fetches status lists as it receives credentials"; fi

echo "### Credo's holder ← OID4VCgo's issuer, its other profiles"
start_issuer dpop-nonces '.dpop_nonces = true'
holder_receive dpop-nonces "$(our_offer "$OUR_SDJWT")" "$AGENT"
# The issuer challenges at the Token Endpoint (400 use_dpop_nonce, with
# a DPoP-Nonce, RFC 9449 §8) and the Credential Endpoint (401, §9);
# Credo's holder retries each with the nonce. Its first Credential
# Request carries the Token Endpoint's nonce, which the Credential
# Issuer, with nonces of its own, challenges like none (README,
# observation 8).
if jq -e '.stage == "done" and (.received | length == 1)' holder-dpop-nonces.json >/dev/null \
    && grep -q '^POST "/token" 400 .*nonce=false.*dpop-nonce-sent' tap-dpop-nonces.log \
    && grep -q '^POST "/token" 200 .*nonce=true' tap-dpop-nonces.log \
    && grep -q '^POST "/credential" 401 .*nonce=true.*challenge=use_dpop_nonce' tap-dpop-nonces.log \
    && grep -q '^POST "/credential" 200 .*nonce=true' tap-dpop-nonces.log; then
  ok "dpop-nonces: issued; the Token and Credential Endpoints each asked for a DPoP nonce, and Credo's holder retried with it"
else bad "dpop-nonces: $(held dpop-nonces); $(tr '\n' ';' < tap-dpop-nonces.log | head -c 600)"; fi

start_issuer deferred '.deferred = true'
holder_receive deferred "$(our_offer "$OUR_SDJWT")" "$AGENT"
# Deferred (202, a transaction_id), then issued from the Deferred
# Credential Endpoint when Credo's holder polls it.
if jq -e '.stage == "done" and .deferred == 1 and (.received | length == 1)' holder-deferred.json >/dev/null \
    && grep -q '^POST "/credential" 202' tap-deferred.log && grep -q '^POST "/[a-z_-]*deferred[a-z_-]*" 200' tap-deferred.log; then
  ok "deferred: deferred (202), then issued from the Deferred Credential Endpoint when Credo's holder polled it"
else bad "deferred: $(held deferred); $(tr '\n' ';' < tap-deferred.log | head -c 400)"; fi

start_issuer key-attestation '.key_attestation.jwt_proof_requires_key_attestation = true'
# Every jwt proof must carry a Key Attestation, which Credo's holder
# gets from the Wallet Provider. The issuer takes the attestation proof
# type too, which Credo sends a Key Attestation carrying the c_nonce
# as (Appendix F.3), for each format.
for c in "ka-pid $OUR_SDJWT" "ka-mdoc $OUR_MDOC"; do
  read -r name config <<< "$c"
  holder_receive "$name" "$(our_offer "$config")" "$AGENT"
  if jq -e '.stage == "done" and (.received | length == 1) and .key_attestation and .proof_types == ["attestation"]' \
      "holder-$name.json" >/dev/null && grep -q '^POST "/credential" 200' "tap-$name.log"; then
    ok "key-attestation: $config issued, its Key Attestation from OID4VCgo's Wallet Provider sent as the attestation proof type"
  else bad "key-attestation, $config: $(held "$name"); proof types $(jq -c .proof_types "holder-$name.json" 2>/dev/null)"; fi
done
# Control: the Key Attestation without the c_nonce, which Credo then
# puts in a jwt proof's key_attestation header, the proof carrying the
# c_nonce. The issuer refuses it, for the attestation's nonce, as HAIP
# 1.0 §4.5.1 has a Key Attestation carry the c_nonce where the issuer
# has a Nonce Endpoint.
holder_receive ka-no-nonce "$(our_offer "$OUR_SDJWT")" "$AGENT" "" true false
if jq -e --arg why "$OUR_KA_NONCE" '.stage == "credential" and (.received | length == 0) and .proof_types == ["jwt+key_attestation"]
    and (.error | contains("\"error\": \"invalid_nonce\"") and contains($why))' holder-ka-no-nonce.json >/dev/null \
    && grep -q '^POST "/credential" 400' tap-ka-no-nonce.log; then
  ok "control: OID4VCgo's issuer refuses a key-attested jwt proof whose Key Attestation doesn't carry the c_nonce (400 invalid_nonce)"
else bad "control: a Key Attestation without the c_nonce: $(held ka-no-nonce)"; fi
stop_issuer

# The Wallet Attestations were the trusted provider's, and the other
# provider's was refused.
if grep -q ' served POST "/v1/wallet-attestation" 200' wallet-provider/wallet-provider.log \
    && grep -q ' served POST "/v1/wallet-attestation" 200' other-wallet-provider/wallet-provider.log; then
  ok "OID4VCgo's Wallet Providers issued the wallet's Wallet Attestations"
else bad "OID4VCgo's Wallet Providers issued the wallet's Wallet Attestations ($(grep ' served ' wallet-provider/wallet-provider.log | tail -3 | tr '\n' ';'))"; fi

if [[ $fail -ne 0 ]]; then echo "RESULT FAIL (logs in $WORK)"; else echo "RESULT ok"; fi
exit "$fail"
