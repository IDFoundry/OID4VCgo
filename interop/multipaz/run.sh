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
# Needs go and a JDK (21 or later), and curl for latest. Exits 0 only
# if every case behaves as expected.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="${OID4VCGO_SRC:-$(cd "$HERE/../.." && pwd)}"
WORK="${WORK:-$(mktemp -d)}"
LIB="$HERE/driver/build/install/multipaz-interop/lib"

echo "work dir  $WORK"
echo "oid4vcgo  $SRC, commit $(git -C "$SRC" rev-parse HEAD 2>/dev/null || echo unknown)"

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

status=0
"$HERE/driver/build/install/multipaz-interop/bin/multipaz-interop" -peer "$WORK/peer" -verifier "$WORK/verifier" \
  -setup-issuer "$WORK/setup-issuer" -issuer "$WORK/issuer" -dir "$WORK" \
  > "$WORK/driver.log" 2>&1 || status=$?
# The driver's own lines; Multipaz's debug logging stays in driver.log.
grep -E '^(###|  ok|  FAIL|  known|RESULT)' "$WORK/driver.log" || true
if [[ $status -ne 0 ]]; then
  grep -E '^RESULT' "$WORK/driver.log" >/dev/null || { echo "the driver failed; see $WORK/driver.log" >&2; tail -20 "$WORK/driver.log" >&2; }
fi
exit "$status"
