#!/usr/bin/env bash
# Multipaz and OID4VCgo, each as mdoc reader and as holder: in person
# (ISO/IEC 18013-5: QR engagement, session encryption, reader
# authentication, device signature and deviceMac) and over the Digital
# Credentials API (ISO/IEC TS 18013-7 Annex C, org-iso-mdoc); then
# controls that OID4VCgo's side must refuse. interop/multipaz/driver, a
# JVM program on Multipaz's published library, runs every case against
# scripts/peer, OID4VCgo's walletflow holder and proximity and mdocdcapi
# readers, exchanging whole messages with it: no radio. See README.md.
#
#   interop/multipaz/run.sh
#
# Needs go and a JDK (21 or later). Exits 0 only if every case behaves
# as expected.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="${OID4VCGO_SRC:-$(cd "$HERE/../.." && pwd)}"
WORK="${WORK:-$(mktemp -d)}"
LIB="$HERE/driver/build/install/multipaz-interop/lib"

echo "work dir  $WORK"
echo "oid4vcgo  $SRC, commit $(git -C "$SRC" rev-parse HEAD 2>/dev/null || echo unknown)"

(cd "$SRC" && go build -o "$WORK/peer" ./interop/multipaz/scripts/peer)
(cd "$HERE/driver" && ./gradlew --quiet --no-daemon installDist)
echo "multipaz  $(find "$LIB" -name 'multipaz-*.jar' | sed -E 's|.*/||; s|\.jar$||' | sort | tr '\n' ' ')"

status=0
"$HERE/driver/build/install/multipaz-interop/bin/multipaz-interop" -peer "$WORK/peer" -dir "$WORK" \
  > "$WORK/driver.log" 2>&1 || status=$?
# The driver's own lines; Multipaz's debug logging stays in driver.log.
grep -E '^(###|  ok|  FAIL|RESULT)' "$WORK/driver.log" || true
if [[ $status -ne 0 ]]; then
  grep -E '^RESULT' "$WORK/driver.log" >/dev/null || { echo "the driver failed; see $WORK/driver.log" >&2; tail -20 "$WORK/driver.log" >&2; }
fi
exit "$status"
