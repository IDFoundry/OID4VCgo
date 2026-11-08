#!/usr/bin/env bash
# The EUDI reference wallet library, eudi-lib-jvm-openid4vci-kt, obtains
# credentials from OID4VCgo's cmd/conformance-issuer: SD-JWT VC and
# mdoc PIDs, by the pre-authorized code and the authorization code
# flows, with every proof type, batches, encryption, signed metadata,
# deferral, notifications and DPoP nonces; EUDI's own SD-JWT VC verifier
# checks what's issued; then controls that must be refused. The issuer
# runs in four configurations in turn, its profiles. See README.md.
#
#   interop/eudi/run-issuer.sh
#   PROFILES="base deferred" interop/eudi/run-issuer.sh
#
# Needs go, a JDK (17 or later), curl and jq; the driver's dependencies
# come from Maven Central, pinned and checksum-verified. Exits 0 only if
# every case passes and every control is refused.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="${OID4VCGO_SRC:-$(cd "$HERE/../.." && pwd)}"
PORT="${PORT:-18446}"
OFFERS_PORT="${OFFERS_PORT:-18447}"
PROFILES="${PROFILES:-base key-attestation deferred dpop-nonces}"
WORK="${WORK:-$(mktemp -d)}"
ISSUER="https://localhost:$PORT"

for p in "$PORT" "$OFFERS_PORT"; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then
    echo "port $p is in use; set PORT / OFFERS_PORT" >&2
    exit 2
  fi
done

ISSUER_PID=""
stop_issuer() {
  if [[ -n "$ISSUER_PID" ]]; then
    kill "$ISSUER_PID" 2>/dev/null || true
    wait "$ISSUER_PID" 2>/dev/null || true
    ISSUER_PID=""
  fi
}
trap stop_issuer EXIT

echo "work dir  $WORK"
echo "issuer    $SRC, commit $(git -C "$SRC" rev-parse HEAD 2>/dev/null || echo unknown)"
echo "wallet    eu.europa.ec.eudi:eudi-lib-jvm-openid4vci-kt:$(sed -n 's/^openid4vci = "\(.*\)"/\1/p' "$HERE/issuance/gradle/libs.versions.toml")"

(cd "$SRC" && go build -o "$WORK/issuer" ./cmd/conformance-issuer \
  && go run ./interop/eudi/scripts/setup-issuer -out "$WORK" -port "$PORT" -offers-port "$OFFERS_PORT")
(cd "$HERE/issuance" && ./gradlew --quiet --no-configuration-cache installDist)
DRIVER="$HERE/issuance/build/install/eudi-issuance-interop/bin/eudi-issuance-interop"

# start_issuer runs the issuer with issuer.json changed by the jq filter
# $1, its profile.
start_issuer() {  # $1 the profile's name, $2 a jq filter
  local name="$1" filter="$2"
  stop_issuer
  jq "$filter" "$WORK/issuer.json" > "$WORK/issuer-$name.json"
  "$WORK/issuer" -config "$WORK/issuer-$name.json" >> "$WORK/issuer-$name.log" 2>&1 &
  ISSUER_PID=$!
  for _ in $(seq 1 50); do
    if curl -s -o /dev/null --max-time 1 --cacert "$WORK/tls-ca.pem" "$ISSUER/.well-known/openid-credential-issuer"; then return 0; fi
    sleep 0.2
  done
  echo "the issuer did not start; see $WORK/issuer-$name.log" >&2
  exit 2
}

fail=0
for profile in $PROFILES; do
  case "$profile" in
    base) filter='.' ;;
    key-attestation) filter='.key_attestation.jwt_proof_requires_key_attestation = true' ;;
    deferred) filter='.deferred = true' ;;
    dpop-nonces) filter='.dpop_nonces = true' ;;
    *) echo "unknown profile $profile" >&2; exit 2 ;;
  esac
  echo "### issuer profile: $profile"
  start_issuer "$profile" "$filter"
  # The driver prints the ok/FAIL lines; its stack traces and the
  # library's own logging go to the log.
  if ! "$DRIVER" "$WORK/driver.json" "$profile" 2>> "$WORK/driver-$profile.log"; then fail=1; fi
  stop_issuer
done

if [[ "$fail" -eq 0 ]]; then echo "RESULT: every credential issued and verified, and every control refused"; else echo "RESULT: FAILED"; fi
exit "$fail"
