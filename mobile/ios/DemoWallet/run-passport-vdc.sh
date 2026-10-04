#!/bin/sh
# Runs the demo wallet on an iOS Simulator against the passport-vdc demo
# (examples/passport-vdc: `go run ./cmd/demo` there first). Makes the
# Simulator trust the demo's TLS certificate, and launches the app with
# the demo's trust anchors and Wallet Provider. Then upload a passport on
# the issuer page, and open its offer link in the Simulator:
#
#   xcrun simctl openurl booted '<openid-credential-offer://… link>'
#
#   ./run-passport-vdc.sh [simulator-id-or-name]   (default: iPhone 16)
#
# Approve on the issuer's page with the confirmation code, or for a
# pre-authorized code offer enter its PIN in the app.
set -eu
cd "$(dirname "$0")"
DEVICE="${1:-iPhone 16}"
STATE="${STATE:-../../../examples/passport-vdc/.demo-state}"
for f in tls-cert.pem issuer-ca.pem verifier-ca.pem; do
	[ -s "$STATE/$f" ] || { echo "no $STATE/$f: run the passport-vdc demo first" >&2; exit 1; }
done

../../build-xcframework.sh
xcrun simctl boot "$DEVICE" 2>/dev/null || true
xcrun simctl bootstatus "$DEVICE" -b >/dev/null
xcrun simctl keychain "$DEVICE" add-root-cert "$STATE/tls-cert.pem"

case "$DEVICE" in
*-*-*-*-*) DEST="id=$DEVICE" ;;
*) DEST="platform=iOS Simulator,name=$DEVICE" ;;
esac
BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT
xcodebuild build -project DemoWallet.xcodeproj -scheme DemoWallet -destination "$DEST" -derivedDataPath "$BUILD" -quiet
xcrun simctl install "$DEVICE" "$BUILD/Build/Products/Debug-iphonesimulator/DemoWallet.app"

# The demo's registration of its wallet (examples/passport-vdc/cmd/demo).
CONFIG="$(python3 - "$STATE" <<'PY'
import json, pathlib, sys
state = pathlib.Path(sys.argv[1])
print(json.dumps({
    "wallet": {
        "client_id": "passport-vdc-wallet",
        "redirect_uri": "dev.idfoundry.oid4vcgo.demowallet:/callback",
        "issuer_roots": (state / "issuer-ca.pem").read_text(),
        "verifier_roots": (state / "verifier-ca.pem").read_text(),
        # The registrar of the verifier relying parties: the app shows
        # their registrations, and warns when one asks for more.
        "registrar_roots": (state / "registrar-ca.pem").read_text() if (state / "registrar-ca.pem").exists() else "",
        "development": True,
        # Credentials from a passport kept for refresh come with a
        # refresh token, so the app can fetch fresh copies.
        "request_refresh": True,
    },
    "provider_url": "https://127.0.0.1:6443",
}))
PY
)"
xcrun simctl terminate "$DEVICE" dev.idfoundry.oid4vcgo.demowallet 2>/dev/null || true
SIMCTL_CHILD_OID4VC_DEMO_CONFIG="$CONFIG" xcrun simctl launch "$DEVICE" dev.idfoundry.oid4vcgo.demowallet
