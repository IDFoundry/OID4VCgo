#!/usr/bin/env bash
# Multipaz and OID4VCgo, each as mdoc reader and as holder: in person
# (ISO/IEC 18013-5: QR engagement, session encryption, reader
# authentication, device signature and deviceMac) and over the Digital
# Credentials API (ISO/IEC TS 18013-7 Annex C, org-iso-mdoc); each as
# OpenID4VP 1.0 wallet and Verifier, cross-device and over the DC API;
# and each as OpenID4VCI 1.0 wallet and issuer; then controls that
# OID4VCgo's side must refuse.
# interop/multipaz/driver, a JVM program on Multipaz's published
# library, runs every case against scripts/peer, OID4VCgo's walletflow
# holder and wallet and proximity and mdocdcapi readers, exchanging
# whole messages with it (no radio), and against cmd/conformance-verifier
# and cmd/conformance-issuer, which the peer starts. See README.md.
#
#   interop/multipaz/run.sh
#   MULTIPAZ_VERSION=latest interop/multipaz/run.sh
#
# MULTIPAZ_VERSION builds the driver against another Multipaz release
# (latest: Maven Central's newest) instead of the pinned one, without
# the locks and checksums, which are the pinned release's.
# walletflow's Wallet Attestations and Key Attestations, at Multipaz's
# issuer, are OID4VCgo's Wallet Provider's (interop/walletprovider), run
# here as a deployment runs it, on WP_PORT and the three ports after.
#
# Needs go and a JDK (21 or later), and curl for latest. Exits
# 0 only if every case behaves as expected.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="${OID4VCGO_SRC:-$(cd "$HERE/../.." && pwd)}"
WORK="${WORK:-$(mktemp -d)}"
LIB="$HERE/driver/build/install/multipaz-interop/lib"
# The Wallet Providers' ports: the trusted one's and its admin
# listener's, then those of one under a CA Multipaz's issuer doesn't
# trust.
WP_PORT="${WP_PORT:-22441}"
for p in $(seq "$WP_PORT" $((WP_PORT + 3))); do
  if (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then
    echo "port $p is in use; set WP_PORT" >&2
    exit 2
  fi
done

echo "work dir  $WORK"
echo "oid4vcgo  $SRC, commit $(git -C "$SRC" rev-parse HEAD 2>/dev/null || echo unknown)"

# shellcheck source=../production.sh
. "$HERE/../production.sh"
build_production "$WORK" "$SRC" walletprovider=./interop/walletprovider
(cd "$SRC" && go build -o "$WORK/peer" ./interop/multipaz/scripts/peer \
  && go build -o "$WORK/verifier" ./cmd/conformance-verifier \
  && go build -o "$WORK/issuer" ./cmd/conformance-issuer \
  && go build -o "$WORK/setup-issuer" ./interop/eudi/scripts/setup-issuer)
GRADLE_ARGS=()
if [[ -n "${MULTIPAZ_VERSION:-}" ]]; then
  if [[ "$MULTIPAZ_VERSION" == latest ]]; then
    MULTIPAZ_VERSION="$(curl -sSfL --proto '=https' --tlsv1.2 https://repo1.maven.org/maven2/org/multipaz/multipaz/maven-metadata.xml \
      | sed -nE 's|.*<release>([^<]+)</release>.*|\1|p')"
  fi
  [[ "$MULTIPAZ_VERSION" =~ ^[0-9A-Za-z.+-]+$ ]] || { echo "bad MULTIPAZ_VERSION: '$MULTIPAZ_VERSION'" >&2; exit 2; }
  GRADLE_ARGS=(-PmultipazVersion="$MULTIPAZ_VERSION" --dependency-verification off)
fi
(cd "$HERE/driver" && ./gradlew --quiet --no-daemon ${GRADLE_ARGS[@]+"${GRADLE_ARGS[@]}"} installDist)
echo "multipaz  $(find "$LIB" -name 'multipaz-*.jar' | sed -E 's|.*/||; s|\.jar$||' | sort | tr '\n' ' ')"

# walletflow's Wallet Providers, which the peer registers with (its
# environment names them): OID4VCgo's walletprovider.Provider over
# sealed SQLite stores, its CA named as Multipaz's issuer keys its
# trusted attesters, and one under a CA that issuer doesn't trust,
# naming the same identifier.
PROVIDER_PIDS=()
# shellcheck disable=SC2329 # run by the EXIT trap
stop_providers() {
  for pid in ${PROVIDER_PIDS[@]+"${PROVIDER_PIDS[@]}"}; do kill "$pid" 2>/dev/null || true; done
  for pid in ${PROVIDER_PIDS[@]+"${PROVIDER_PIDS[@]}"}; do wait "$pid" 2>/dev/null || true; done
}
trap stop_providers EXIT
start_wallet_provider "$WORK/walletprovider" "$WORK/wallet-provider" "$WP_PORT" $((WP_PORT + 1)) oid4vcgo-multipaz-interop-wallet \
  -ca-name "OID4VCgo interop wallet provider CA"
PROVIDER_PIDS+=($!)
start_wallet_provider "$WORK/walletprovider" "$WORK/other-wallet-provider" $((WP_PORT + 2)) $((WP_PORT + 3)) oid4vcgo-multipaz-interop-wallet \
  -ca-name "OID4VCgo interop untrusted wallet provider CA"
PROVIDER_PIDS+=($!)
wait_ready "http://127.0.0.1:$((WP_PORT + 1))/ready" "http://127.0.0.1:$((WP_PORT + 3))/ready"
export OID4VCGO_WALLET_PROVIDER="https://localhost:$WP_PORT" OID4VCGO_WALLET_PROVIDER_DIR="$WORK/wallet-provider"
export OID4VCGO_OTHER_WALLET_PROVIDER="https://localhost:$((WP_PORT + 2))" OID4VCGO_OTHER_WALLET_PROVIDER_DIR="$WORK/other-wallet-provider"

status=0
"$HERE/driver/build/install/multipaz-interop/bin/multipaz-interop" -peer "$WORK/peer" -verifier "$WORK/verifier" \
  -setup-issuer "$WORK/setup-issuer" -issuer "$WORK/issuer" -dir "$WORK" \
  > "$WORK/driver.log" 2>&1 || status=$?
# The driver's own lines; Multipaz's debug logging stays in driver.log.
grep -E '^(###|  ok|  FAIL|  known|RESULT)' "$WORK/driver.log" || true
# walletflow's attestations were the provider's: it attested the
# instance's keys and holder keys.
if grep -q ' served POST "/v1/wallet-attestation" 200' "$WORK/wallet-provider/wallet-provider.log" \
    && grep -q ' served POST "/v1/key-attestation" 200' "$WORK/wallet-provider/wallet-provider.log"; then
  echo "  ok    OID4VCgo's Wallet Provider issued walletflow's Wallet Attestations and Key Attestations"
else
  echo "  FAIL  OID4VCgo's Wallet Provider issued walletflow's attestations ($(grep ' served ' "$WORK/wallet-provider/wallet-provider.log" | tail -3 | tr '\n' ';'))"
  [[ $status -ne 0 ]] || status=1
fi
if [[ $status -ne 0 ]]; then
  grep -E '^RESULT' "$WORK/driver.log" >/dev/null || { echo "the driver failed; see $WORK/driver.log" >&2; tail -20 "$WORK/driver.log" >&2; }
fi
exit "$status"
