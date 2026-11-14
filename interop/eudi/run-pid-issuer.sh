#!/usr/bin/env bash
# OID4VCgo's wallet obtains PIDs from the EUDI reference PID Issuer
# (eu-digital-identity-wallet/eudi-srv-pid-issuer), run as its own
# docker-compose stack (Keycloak with its attestation-based client
# authentication extension, the status list service, Postgres and
# HAProxy) from images pinned by digest: the authorization code flow
# with PAR, PKCE, DPoP and a Wallet Attestation, wallet-initiated and
# from the issuer's Credential Offer, both proof types, both formats,
# encrypted, in batches and deferred, each credential verified on the
# wallet's side and its status list checked; then controls that must
# be refused. See README.md.
#
#   interop/eudi/run-pid-issuer.sh
#   PID_ISSUER_IMAGE=ghcr.io/eu-digital-identity-wallet/eudi-srv-pid-issuer:latest interop/eudi/run-pid-issuer.sh
#
# Needs docker (with compose), go, jq, curl, openssl and keytool. Exits
# 0 only if every case behaves as expected.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="${OID4VCGO_SRC:-$(cd "$HERE/../.." && pwd)}"
EUDI=eu-digital-identity-wallet

# v0.11.2, read from ghcr.io on 2026-11-08, and the stack its tag's
# docker-compose/ runs. Move them only after reading the release's
# changes (README.md, "Moving the pins").
PID_ISSUER_IMAGE="${PID_ISSUER_IMAGE:-ghcr.io/$EUDI/eudi-srv-pid-issuer@sha256:fa864aa2deaf22845ca935fc4ccf2fb51ece57f2ea8691119c42f847dee883cb}"
PID_ISSUER_COMMIT=bdd5ea0bb9d6de685ecfb3c8ad8db06e6a168647 # v0.11.2
KEYCLOAK_IMAGE=quay.io/keycloak/keycloak@sha256:f9ba7b2af90db8dc749a57ca9aedca51e840cb9224441ab546a968da941da900 # 26.6.2-2
POSTGRES_IMAGE=postgres@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15 # 18.4-alpine3.24
HAPROXY_IMAGE=haproxy@sha256:fdd14bba61bed25638503b51a9d59ee31082d71a461ec28eddb29ad522156c67 # 2.8.3
# abca-keycloak-ext 0.2.0 (KEYCLOAK_ABCA_EXTENSION_VERSION), from Maven Central.
ABCA_URL=https://repo.maven.apache.org/maven2/eu/europa/ec/eudi/abca-keycloak-ext/0.2.0/abca-keycloak-ext-0.2.0.jar
ABCA_SHA256=4b10222577445f936ead647980b22e672ee9e38e0c1e5b8ac8dab60dd5ea8a86
# eudi-srv-statuslist-py v0.9.0 (STATUS_LIST_VERSION).
STATUS_LIST_URL=https://codeload.github.com/$EUDI/eudi-srv-statuslist-py/tar.gz/9a5079eaa064b714a8893e664e11b58144508ba5
STATUS_LIST_SHA256=cb963d95f353d8576d2b120878bbd2acbd5f12de0b3d6d3500f8a61841a0799f
# The PID Issuer's docker-compose/ files this run uses, by SHA-256.
PID_ISSUER_FILES=(
  "keycloak/realms/pid-issuer-realm-realm.json 1b84f8e7362e5090f24b2e39936876273f5fc5bdf6bcfdf74e7b2ee506c0ce2d"
  "keycloak/realms/pid-issuer-realm-users-0.json 8c30b65cdf407cfa85cfa1b38e83a84f7af0c5d58407afbc655030d0806d17df"
  "keycloak/conf/keycloak.conf 16e48754044ef32f18451f7f7b6db69e79980fd6f88a215665b074a030212f3c"
  "postgresql/schema/V1.sql cd7629f10dfabf421ea4ce0c8fec2fcf8df3adf6629ace2440dde91f9c08200f"
  "status-list/endpoints/get_status_list.py 7b8cf48b0cc4a2db12d4a40ec4d9f51730268df1105300132af1c8528c9b936b"
  "status-list/config/config_service.py 4e6cc79b86acab468d89214974f7d65e93069c593c6d6938bf093161e0c3e2d4"
  "haproxy/haproxy.conf c1f16710b5dbd8043463b8f85212b9cb11ee87d726ffbf6c861400c96f5f7263"
)

PORT="${PORT:-19443}"
SERVE_PORT="${SERVE_PORT:-19445}"
# The wallet publishes the CRLs of the CAs it trusts the issuer by (the
# IACA's and the signed metadata CA's) here, and checks every issuer
# certificate against them: see scripts/pidwallet's -crl-set.
CRL_PORT="${CRL_PORT:-19446}"
WORK="${WORK:-$(mktemp -d)}"
STACK="$WORK/stack"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-oid4vcgo-eudi-pid}"
ISSUER="https://localhost:$PORT/pid-issuer"
CLIENT_ID=eudiw-abca
# The wallet's redirect URI: the EUDI wallet app's, a private-use URI
# scheme with an authority, which the realm registers for the client.
REDIRECT_URI=eu.europa.ec.euidi://authorization

for p in "$PORT" "$SERVE_PORT" "$CRL_PORT"; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then
    echo "port $p is in use; set PORT / SERVE_PORT / CRL_PORT" >&2
    exit 2
  fi
done

# Keycloak and the issuer reach serve, on this host, as
# host.docker.internal: Docker Desktop resolves that name itself and
# reaches the host's loopback; on Linux the compose file maps it to the
# default bridge's gateway, which serve then listens on.
SERVE_BIND=127.0.0.1
if [[ "$(uname)" = Linux ]]; then
  SERVE_BIND="$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')"
fi
SERVE_URL="https://host.docker.internal:$SERVE_PORT"

compose() { docker compose -f "$HERE/pid-issuer/compose.yaml" "$@"; }

SERVE_PID=""
# shellcheck disable=SC2329 # run by the EXIT trap
cleanup() {
  if [[ -n "$SERVE_PID" ]]; then kill "$SERVE_PID" 2>/dev/null || true; fi
  if [[ -f "$STACK/compose.env" ]]; then
    set -a
    # shellcheck source=/dev/null
    . "$STACK/compose.env"
    set +a
    for s in pid-issuer keycloak status-list haproxy postgres; do
      compose logs --no-color "$s" > "$WORK/$s.log" 2>&1 || true
    done
    compose down -v --remove-orphans >/dev/null 2>&1 || true
    docker image rm "$COMPOSE_PROJECT_NAME-status-list" >/dev/null 2>&1 || true
    # The logs are uploaded: the status list service logs each
    # request's headers, its API key among them.
    local f s
    for f in "$WORK"/*.log; do
      for s in "$KEYSTORE_PASSWORD" "$DB_PASSWORD" "$KEYCLOAK_ADMIN_PASSWORD" "$INTROSPECTION_SECRET" "$STATUS_LIST_API_KEY"; do
        sed "s/$s/[redacted]/g" "$f" > "$f.tmp" && mv "$f.tmp" "$f"
      done
    done
  fi
}
trap cleanup EXIT

echo "work dir    $WORK"
echo "wallet      $SRC, commit $(git -C "$SRC" rev-parse HEAD 2>/dev/null || echo unknown)"
echo "pid issuer  $PID_ISSUER_IMAGE"

# fetch URL SHA256 FILE: downloads URL to FILE, refusing it unless its
# SHA-256 is the pinned one.
fetch() {
  local url="$1" sum="$2" out="$3"
  mkdir -p "$(dirname "$out")"
  curl -sSfL --max-time 120 -o "$out" "$url"
  if [[ "$(openssl dgst -sha256 -r "$out" | cut -d' ' -f1)" != "$sum" ]]; then
    echo "$url doesn't have the pinned SHA-256" >&2
    exit 2
  fi
}

mkdir -p "$STACK/eudi"
for entry in "${PID_ISSUER_FILES[@]}"; do
  read -r path sum <<< "$entry"
  fetch "https://raw.githubusercontent.com/$EUDI/eudi-srv-pid-issuer/$PID_ISSUER_COMMIT/docker-compose/$path" "$sum" "$STACK/eudi/$path"
done
fetch "$ABCA_URL" "$ABCA_SHA256" "$STACK/abca-keycloak-ext.jar"
fetch "$STATUS_LIST_URL" "$STATUS_LIST_SHA256" "$STACK/status-list.tar.gz"

(cd "$SRC" && go build -o "$WORK/serve" ./interop/eudi/scripts/serve \
  && go build -o "$WORK/pidwallet" ./interop/eudi/scripts/pidwallet \
  && go run ./interop/eudi/scripts/pidsetup -out "$WORK" -issuer-url "$ISSUER" -serve-url "$SERVE_URL" -crl-host "localhost:$CRL_PORT")
cd "$WORK"

# Per-run passwords: the stack's own are in its public repository.
KEYSTORE_PASSWORD="$(openssl rand -hex 16)"
DB_PASSWORD="$(openssl rand -hex 16)"
KEYCLOAK_ADMIN_PASSWORD="$(openssl rand -hex 16)"
INTROSPECTION_SECRET="$(openssl rand -hex 16)"
STATUS_LIST_API_KEY="$(openssl rand -hex 16)"

# Keycloak: the realm as the stack ships it, with the introspection
# client's secret replaced. The wallet's client and its redirect URI
# are the realm's own; the run refuses a realm that no longer registers
# that redirect URI for it.
mkdir -p "$STACK/realms" "$STACK/schema" "$STACK/keycloak-tls" "$STACK/haproxy-tls" "$STACK/status-list-certs" \
  "$STACK/bindings/tls-ca" "$STACK/status-list"
if ! jq -e --arg redirect "$REDIRECT_URI" --arg client "$CLIENT_ID" \
  'any(.clients[]; .clientId == $client and (.redirectUris | index($redirect)))' \
  "$STACK/eudi/keycloak/realms/pid-issuer-realm-realm.json" >/dev/null; then
  echo "the realm doesn't register $REDIRECT_URI for $CLIENT_ID" >&2
  exit 2
fi
jq --arg secret "$INTROSPECTION_SECRET" '
  .clients |= map(if .clientId == "pid-issuer-srv" then .secret = $secret else . end)' \
  "$STACK/eudi/keycloak/realms/pid-issuer-realm-realm.json" > "$STACK/realms/pid-issuer-realm-realm.json"
cp "$STACK/eudi/keycloak/realms/pid-issuer-realm-users-0.json" "$STACK/realms/"
cp "$STACK/eudi/keycloak/conf/keycloak.conf" "$STACK/keycloak.conf"
cp keycloak-cert.pem keycloak-key.pem tls-ca.pem "$STACK/keycloak-tls/"
cp "$STACK/eudi/postgresql/schema/V1.sql" "$STACK/schema/"

# The status list service: the release's app/ and the stack's
# get_status_list.py, its lists' URIs at this run's HAProxy, signing
# with the run's status list signer.
tar -xzf "$STACK/status-list.tar.gz" -C "$STACK/status-list" --strip-components 1
cp "$STACK/eudi/status-list/endpoints/get_status_list.py" "$STACK/status-list/"
cp "$HERE/pid-issuer/status-list.Dockerfile" "$STACK/status-list/Dockerfile"
cp "$HERE/pid-issuer/status-list-requirements.txt" "$STACK/status-list/requirements.txt"
sed "s|service_url = \"https://localhost/\"|service_url = \"https://localhost:$PORT/\"|" \
  "$STACK/eudi/status-list/config/config_service.py" > "$STACK/config_service.py"
grep -q "service_url = \"https://localhost:$PORT/\"" "$STACK/config_service.py" || { echo "config_service.py: no service_url to set" >&2; exit 2; }
cp statuslist-signer.key.pem "$STACK/status-list-certs/key.pem"
cp statuslist-signer.cert.der "$STACK/status-list-certs/cert.der"

# HAProxy: the stack's configuration, with its jwt-issuer metadata
# naming this run's issuer.
sed "s|https://localhost/pid-issuer|$ISSUER|g" "$STACK/eudi/haproxy/haproxy.conf" > "$STACK/haproxy.cfg"
cp haproxy.pem "$STACK/haproxy-tls/localhost.tls.pem"

# The issuer trusts the run's TLS CA through the image's
# ca-certificates buildpack, and reads its keys from one PKCS #12
# keystore, an entry per alias.
echo ca-certificates > "$STACK/bindings/tls-ca/type"
cp tls-ca.pem "$STACK/bindings/tls-ca/tls-ca.pem"
rm -f "$STACK/issuer-keys.p12"
for alias in pid-mdoc pid-sdjwt access-certificate request-encryption nonce-encryption; do
  openssl pkcs12 -export -inkey "$alias.key.pem" -in "$alias.chain.pem" -name "$alias" \
    -passout "pass:$KEYSTORE_PASSWORD" -out "$STACK/$alias.p12"
  keytool -importkeystore -noprompt -srckeystore "$STACK/$alias.p12" -srcstoretype PKCS12 \
    -srcstorepass "$KEYSTORE_PASSWORD" -destkeystore "$STACK/issuer-keys.p12" -deststoretype PKCS12 \
    -deststorepass "$KEYSTORE_PASSWORD" >/dev/null 2>&1
  rm -f "$STACK/$alias.p12"
done
chmod 644 "$STACK/issuer-keys.p12"

cat > "$STACK/compose.env" <<EOF
COMPOSE_PROJECT_NAME=$COMPOSE_PROJECT_NAME
STACK=$STACK
PORT=$PORT
PID_ISSUER_IMAGE=$PID_ISSUER_IMAGE
KEYCLOAK_IMAGE=$KEYCLOAK_IMAGE
POSTGRES_IMAGE=$POSTGRES_IMAGE
HAPROXY_IMAGE=$HAPROXY_IMAGE
KEYSTORE_PASSWORD=$KEYSTORE_PASSWORD
DB_PASSWORD=$DB_PASSWORD
KEYCLOAK_ADMIN_PASSWORD=$KEYCLOAK_ADMIN_PASSWORD
INTROSPECTION_SECRET=$INTROSPECTION_SECRET
STATUS_LIST_API_KEY=$STATUS_LIST_API_KEY
WRPRC=$(cat wrprc.jws)
EOF
chmod 600 "$STACK/compose.env"
set -a
# shellcheck source=/dev/null
. "$STACK/compose.env"
set +a

./serve -dir . -addr "$SERVE_BIND:$SERVE_PORT" > serve.log 2>&1 &
SERVE_PID=$!

echo "== starting the stack"
if ! compose up -d --build --quiet-pull > compose-up.log 2>&1; then
  tail -20 compose-up.log >&2
  echo "the stack did not start; see $WORK/compose-up.log" >&2
  exit 2
fi
for _ in $(seq 1 150); do
  if curl -sf --max-time 5 --cacert tls-ca.pem -H 'Accept: application/json' -o metadata.json \
    "https://localhost:$PORT/.well-known/openid-credential-issuer/pid-issuer"; then break; fi
  sleep 2
done
if [[ ! -s metadata.json ]]; then
  compose logs --no-color pid-issuer 2>&1 | grep -E 'APPLICATION FAILED|Caused by|Error' | head -5 >&2 || true
  echo "the issuer did not start; see $WORK/pid-issuer.log" >&2
  exit 2
fi
echo "  the issuer is up: $(jq -r '.credential_configurations_supported | keys | join(", ")' metadata.json)"

if [[ -n "${PID_STOP_AFTER_UP:-}" ]]; then
  # For developing the cases: the stack and serve (pid $SERVE_PID) are
  # left running, to stop by hand.
  echo "PID_STOP_AFTER_UP: leaving the stack and serve ($SERVE_PID) up"
  trap - EXIT
  exit 0
fi

fail=0
ok() { local what="$1"; echo "  ok    $what"; }
bad() { local what="$1"; echo "  FAIL  $what"; fail=1; }
note() { local what="$1"; echo "  note  $what"; }

# check NAME DESCRIPTION JQ: ok if result-NAME.json satisfies JQ.
check() {
  local name="$1" what="$2" filter="$3"
  if jq -e "$filter" "result-$name.json" >/dev/null 2>&1; then ok "$what"; else bad "$what"; fi
}

# wallet NAME ARGS...: runs the wallet, its result in result-NAME.json.
wallet() {
  local name="$1"; shift
  ./pidwallet -work . -out "result-$name.json" -client-id "$CLIENT_ID" -redirect-uri "$REDIRECT_URI" "$@" \
    >> pidwallet.log 2>&1 || true
  if [[ ! -s "result-$name.json" ]]; then echo '{"ok":false,"step":"run","error":"no result"}' > "result-$name.json"; fi
}

# why NAME: the step a run stopped at, and why.
why() { local name="$1"; jq -r '"\(.step // "-"): \(.error // "" | .[0:240])"' "result-$name.json"; }

# offer CONFIG: a Credential Offer from the issuer's own offer endpoint.
offer() {
  local config="$1"
  curl -sf --max-time 30 --cacert tls-ca.pem -X POST -H 'Content-Type: application/json' -H 'Accept: application/json' \
    -d "{\"credentialIds\":[\"$config\"]}" "$ISSUER/issuer/credentialsOffer/create" | jq -r '.credentialsOffer // empty'
}

# issued NAME COUNT STATUS: the checks every issuance must pass —
# completed; signed metadata verified; PAR, then the token request,
# each authenticated with a Wallet Attestation whose PoP carries a
# challenge; a DPoP-bound access token; the Credential Request and
# Response encrypted; the notification sent; COUNT credentials, each
# verified by the wallet, with status STATUS ("absent" for none).
issued() {
  local name="$1" count="$2" status="$3"
  if ! jq -e '.ok' "result-$name.json" >/dev/null; then bad "issued ($(why "$name"))"; return; fi
  ok "issued"
  check "$name" "signed metadata verified under the metadata CA" '.signed_metadata'
  check "$name" "PAR, then the token request, with a Wallet Attestation and a challenged PoP" \
    '([.exchanges[] | select((.path | endswith("/par/request")) and .status == 201 and .attestation)] | length == 1)
     and ([.exchanges[] | select((.path | endswith("/openid-connect/token")) and .status == 200 and .attestation and .dpop)] | length == 1)
     and .attestation_challenges >= 2'
  check "$name" "a DPoP-bound access token, the Credential Request DPoP-proved with the issuer's nonce" \
    '.token_type == "DPoP" and ([.exchanges[] | select((.path | endswith("/credentialEndpoint")) and .dpop)] | length >= 1) and .dpop_nonces >= 1'
  check "$name" "the Credential Request and Response encrypted" '.encrypted_request and .encrypted_response'
  check "$name" "the issuer notified of the credential_accepted" '.notified'
  check "$name" "$count credential(s), each verified by the wallet under the IACA" \
    "(.credentials | length == $count) and all(.credentials[]; .verified)"
  if [[ "$status" = cwt-der ]]; then
    # Not a pass: the wallet can't read the list (README.md, "Findings").
    # Most tokens fail on their DER signature; some aren't even
    # well-formed CBOR, and fail before that.
    check "$name" "the wallet refuses the mdoc's CWT Status List Token: a DER signature, or not well-formed CBOR" \
      'all(.credentials[]; .status_uri != null and (.status_error // "" | test("ecdsafixed: signature has length|cbor: [0-9]+ bytes of extraneous data")))'
    echo "        refused for: $(jq -r '[.credentials[].status_error // empty] | unique | join("; ")' "result-$name.json" | cut -c1-200)"
  else
    check "$name" "the wallet reads its status list entry: $status" "all(.credentials[]; .status == \"$status\")"
  fi
}

SDJWT=eu.europa.ec.eudi.pid_vc_sd_jwt
MDOC=eu.europa.ec.eudi.pid_mso_mdoc
# Each SD-JWT VC's JWT Status List Token is read and VALID; each mdoc's
# CWT one is refused, signed as v0.9.0 of the status list service signs
# it. If a later image fixes that, this fails: make it VALID.
SDJWT_STATUS=VALID
MDOC_STATUS=cwt-der

for proof in attestation jwt; do
  echo "== wallet-initiated, SD-JWT VC PID, $proof proof"
  wallet "sdjwt-$proof" -issuer "$ISSUER" -config "$SDJWT" -proof "$proof"
  issued "sdjwt-$proof" 1 "$SDJWT_STATUS"
  echo "== wallet-initiated, mdoc PID, $proof proof"
  wallet "mdoc-$proof" -issuer "$ISSUER" -config "$MDOC" -proof "$proof"
  issued "mdoc-$proof" 1 "$MDOC_STATUS"
done

# What the issuer sends that the wallet is lenient about
# (SPECIFICATIONS.md, "Known leniencies"): its
# credential_request_encryption keys, whose kid OpenID4VCI 1.0 §12.2.4
# requires and whose alg the wallet doesn't need. Asserted as v0.11.2
# sends them, so a change is noticed. (Keycloak's token_type, the other
# such value, is checked as DPoP for every issuance above.)
REQUEST_ENCRYPTION_KEYS='[{"alg":"ECDH-ES","kid":true}]'
echo "== observed: the issuer's credential_request_encryption keys"
observed_keys="$(jq -c '.request_encryption_keys // []' result-sdjwt-jwt.json)"
echo "        credential_request_encryption.jwks: $observed_keys"
if [[ "$observed_keys" == "$REQUEST_ENCRYPTION_KEYS" ]]; then ok "as v0.11.2 sends them"
else bad "as v0.11.2 sends them, $REQUEST_ENCRYPTION_KEYS: if a later image changed them, update README.md and this check"; fi

for c in "$SDJWT jwt sdjwt $SDJWT_STATUS" "$MDOC attestation mdoc $MDOC_STATUS"; do
  read -r config proof format status <<< "$c"
  echo "== the issuer's Credential Offer, $format PID, $proof proof"
  link="$(offer "$config")"
  if [[ -z "$link" ]]; then bad "the issuer made an offer"; continue; fi
  wallet "offer-$format" -offer "$link" -proof "$proof"
  issued "offer-$format" 1 "$status"
  check "offer-$format" "the offer's configuration requested" ".configuration == \"$config\""
  if jq -e '.offer_authorization_server != null and .authorization_servers == 1' "result-offer-$format.json" >/dev/null; then
    note "the offer names its authorization_server though the metadata lists one, as v0.11.2 does (README.md, \"Findings\")"
  fi
done

for c in "$SDJWT jwt sdjwt $SDJWT_STATUS" "$MDOC attestation mdoc $MDOC_STATUS"; do
  read -r config proof format status <<< "$c"
  echo "== batch: three $format PIDs for three keys in one Key Attestation, $proof proof"
  wallet "batch-$format" -issuer "$ISSUER" -config "$config" -proof "$proof" -batch 3
  issued "batch-$format" 3 "$status"
done

for c in "${SDJWT}_deferred attestation sdjwt $SDJWT_STATUS" "${MDOC}_deferred jwt mdoc $MDOC_STATUS"; do
  read -r config proof format status <<< "$c"
  echo "== deferred $format PID, $proof proof"
  wallet "deferred-$format" -issuer "$ISSUER" -config "$config" -proof "$proof"
  issued "deferred-$format" 1 "$status"
  check "deferred-$format" "deferred, then fetched from the Deferred Credential Endpoint" '.deferred and .deferred_polls >= 1'
done

# walletflow negotiates the proof itself; -proof jwt leaves its
# default, naming the jwt proof's key by index, as the issuer
# requires. Its result records no exchanges, so issued's protocol
# checks don't apply: walletflow's own tests make those.
for c in "1 walletflow-sdjwt" "3 walletflow-batch-sdjwt"; do
  read -r count name <<< "$c"
  echo "== walletflow, under ProfileHAIP, its default proof: $count SD-JWT VC PID(s)"
  wallet "$name" -engine walletflow -issuer "$ISSUER" -config "$SDJWT" -proof jwt -batch "$count"
  if ! jq -e '.ok' "result-$name.json" >/dev/null; then bad "issued ($(why "$name"))"; continue; fi
  ok "issued"
  check "$name" "$count credential(s), each verified by walletflow" "(.credentials | length == $count) and all(.credentials[]; .verified)"
  # walletflow names a status in lower case (statuslist.Status).
  check "$name" "walletflow reads its status list entry: $SDJWT_STATUS" \
    "all(.credentials[]; (.status // \"\" | ascii_upcase) == \"$SDJWT_STATUS\")"
done

echo "== an SD-JWT VC PID revoked at the status list service"
wallet revoked-sdjwt -issuer "$ISSUER" -config "$SDJWT" -proof attestation -revoke-api-key "$STATUS_LIST_API_KEY"
issued revoked-sdjwt 1 "$SDJWT_STATUS"
check revoked-sdjwt "the wallet reads it as INVALID once revoked" '.status_after_revoke == "INVALID"'

echo "== control: metadata signed under a CA the wallet doesn't trust"
wallet untrusted-metadata -issuer "$ISSUER" -config "$SDJWT" -metadata-roots other-ca.pem
check untrusted-metadata "the wallet refuses the metadata ($(why untrusted-metadata))" \
  '(.ok | not) and .step == "metadata"
   and (.error | contains("signed metadata: signer certificate: certchain: certificate chain does not verify against a trusted root: x509: certificate signed by unknown authority"))'

echo "== control: credentials whose IACA the wallet doesn't trust"
for c in "$SDJWT sdjwt" "$MDOC mdoc"; do
  read -r config format <<< "$c"
  wallet "untrusted-$format" -issuer "$ISSUER" -config "$config" -proof attestation -issuer-roots other-ca.pem
  check "untrusted-$format" "the wallet refuses the $format PID ($(why "untrusted-$format"))" \
    '(.ok | not) and .step == "verify" and (.credentials | length == 1) and (.credentials[0].verified | not)
     and (.error | contains("wallet: verify issued credential: issuer certificate: certchain: certificate chain does not verify against a trusted root: x509: certificate signed by unknown authority"))'
done

# The issuer's certificates' revocation: every run above checked the
# Document Signer, the SD-JWT VC signer, the status list signer and the
# metadata signer against their CA's current CRL, which the wallet
# fetched over https from the distribution point each names. Here the
# IACA's CRL revokes the credentials' signers, then the IACA publishes
# no current CRL (its list is past its nextUpdate): either way the
# wallet must refuse the credential, for that reason. The metadata CA's
# list stays current, so neither fails before the credential.
REVOCATION_REFUSAL='wallet: verify issued credential: issuer certificate: certchain: revocation: no verified path passes it: '
for c in "revoked certrevocation: certificate is revoked" \
  "expired certchain: revocation couldn't be decided: certrevocation: no current CRL from the certificate's issuer"; do
  read -r set why <<< "$c"
  case "$set" in
    revoked) echo "== control: credentials whose signer the IACA revoked" ;;
    expired) echo "== control: credentials whose IACA publishes no current CRL" ;;
  esac
  for f in "$SDJWT sdjwt" "$MDOC mdoc"; do
    read -r config format <<< "$f"
    wallet "crl-$set-$format" -issuer "$ISSUER" -config "$config" -proof attestation -crl-set "$set"
    check "crl-$set-$format" "the wallet refuses the $format PID ($(why "crl-$set-$format"))" \
      "(.ok | not) and .step == \"verify\" and (.credentials | length == 1) and (.credentials[0].verified | not)
       and (.error | contains(\"$REVOCATION_REFUSAL$why\"))"
  done
done

echo "== control: a Wallet Attestation whose client_status is revoked"
wallet revoked-wallet -issuer "$ISSUER" -config "$SDJWT" -proof attestation -wallet-status-idx 1
# Keycloak says no more than that authentication failed; the case differs
# from the ones above, which pass, only in the attestation's status.
check revoked-wallet "Keycloak refuses the PAR ($(why revoked-wallet))" \
  '(.ok | not) and .step == "par" and (.error | contains("invalid_response: Authentication failed."))'

echo "== control: a Key Attestation whose key_storage_status is revoked"
wallet revoked-keys -issuer "$ISSUER" -config "$SDJWT" -proof attestation -key-storage-status-idx 1
check revoked-keys "the issuer refuses the proof ($(why revoked-keys))" \
  '(.ok | not) and .step == "credential" and (.error | contains("invalid_proof: Key Storage Status is not valid"))'

# Both attestations' status lists are fetched from serve: a run in
# which nothing fetched them checked neither.
echo "== Keycloak and the issuer fetched the Wallet Provider's status list"
if grep -q 'served GET /statuslists/jwt$' serve.log; then ok "fetched /statuslists/jwt"; else bad "fetched /statuslists/jwt"; fi

# Not controls: what OpenID4VCI 1.0 allows a wallet, which this issuer
# refuses (README.md, "Findings"). Each says if a later image accepts,
# and fails if it's refused for anything but the finding: these differ
# from the cases above, which pass, only in what the finding is about.
# known_refusal NAME WHAT WHY: a note if result-NAME.json was accepted
# or refused at the Credential Endpoint for an error containing WHY.
known_refusal() {
  local name="$1" what="$2" want="$3"
  if jq -e '.ok' "result-$name.json" >/dev/null; then note "accepted: the issuer now takes $what; README.md's finding is fixed"
  elif jq -e --arg want "$want" '.step == "credential" and (.error | contains($want))' "result-$name.json" >/dev/null; then
    note "refused, as expected of v0.11.2 ($(why "$name"))"
  else bad "accepted, or refused for the finding ($want): $(why "$name")"; fi
}

echo "== a jwt proof naming its key in jwk, as GenerateProofWithKeyAttestation makes it"
wallet jwk-proof -issuer "$ISSUER" -config "$SDJWT" -proof jwk
JWK_PROOF_REFUSED='credential error response: invalid_proof: JWT Proof with `key_attestation` must contain header `kid` with value `0`'
known_refusal jwk-proof "a jwk-keyed proof" "$JWK_PROOF_REFUSED"

echo "== walletflow, under ProfileHAIP, naming the proof's key in jwk (Config.ProofKeyByJWK)"
wallet walletflow-jwk -engine walletflow -issuer "$ISSUER" -config "$SDJWT" -proof jwk
known_refusal walletflow-jwk "a jwk-keyed proof" "$JWK_PROOF_REFUSED"

echo "== a batch of one key proof per credential (OpenID4VCI 1.0 §8.2, §12.2.4)"
wallet proof-per-key -issuer "$ISSUER" -config "$SDJWT" -proof jwt-each -batch 2
known_refusal proof-per-key "several proofs" 'credential error response: invalid_proof: You can provide at most 1 proof'

if [[ "$fail" -eq 0 ]]; then echo "RESULT: every issuance succeeded and verified, and every control was refused"; else echo "RESULT: FAILED"; fi
exit "$fail"
