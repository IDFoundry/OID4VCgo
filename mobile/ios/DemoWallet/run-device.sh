#!/bin/sh
# Runs the demo wallet on a connected iPhone against the passport-vdc demo
# served on public URLs: start it with them, behind a tunnel (see
# cloudflared.yml.example), from examples/passport-vdc:
#
#   go run ./cmd/demo -state .demo-state-device \
#     -issuer-url https://issuer.example.com \
#     -verifier-url https://verifier.example.com \
#     -provider-url https://provider.example.com
#
# then, with your Apple developer team ID and that Wallet Provider URL:
#
#   TEAM_ID=ABCDE12345 PROVIDER_URL=https://provider.example.com \
#     STATE=../../../examples/passport-vdc/.demo-state-device ./run-device.sh [device-id]
#
# The device is the first connected iPhone unless named (xcrun devicectl
# list devices). It must be paired with this Mac, in Developer Mode, with
# a passcode set: the wallet's keys are in the Secure Enclave, and a
# presentation asks for Face ID. The app keeps its configuration, so
# later it opens from the Home Screen. BUNDLE_ID overrides the bundle
# identifier, for a team that can't register this one.
set -eu
cd "$(dirname "$0")"
: "${TEAM_ID:?set TEAM_ID to your Apple developer team ID}"
: "${PROVIDER_URL:?set PROVIDER_URL to the Wallet Provider public https URL, cmd/demo -provider-url}"
STATE="${STATE:-../../../examples/passport-vdc/.demo-state}"
BUNDLE_ID="${BUNDLE_ID:-dev.idfoundry.oid4vcgo.demowallet}"
for f in issuer-ca.pem verifier-ca.pem; do
	[ -s "$STATE/$f" ] || { echo "no $STATE/$f: run the passport-vdc demo first" >&2; exit 1; }
done

DEVICE="${1:-}"
if [ -z "$DEVICE" ]; then
	LIST="$(mktemp)"
	xcrun devicectl list devices --json-output "$LIST" >/dev/null
	DEVICE="$(python3 - "$LIST" <<'PY'
import json, sys
devices = json.load(open(sys.argv[1]))["result"]["devices"]
for d in devices:
    hw, conn = d.get("hardwareProperties", {}), d.get("connectionProperties", {})
    if hw.get("deviceType") == "iPhone" and conn.get("tunnelState") == "connected":
        print(d["identifier"]); break
PY
)"
	rm -f "$LIST"
	[ -n "$DEVICE" ] || { echo "no connected iPhone: connect one, or name it" >&2; exit 1; }
fi

../../build-xcframework.sh
BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT
xcodebuild build -project DemoWallet.xcodeproj -scheme DemoWallet -destination 'generic/platform=iOS' \
	-derivedDataPath "$BUILD" -allowProvisioningUpdates -quiet \
	DEVELOPMENT_TEAM="$TEAM_ID" CODE_SIGN_STYLE=Automatic PRODUCT_BUNDLE_IDENTIFIER="$BUNDLE_ID"
xcrun devicectl device install app --device "$DEVICE" "$BUILD/Build/Products/Debug-iphoneos/DemoWallet.app"

# The demo's registration of its wallet (examples/passport-vdc/cmd/demo),
# with the Wallet Provider at its public URL. The issuer and verifier
# are found from the offer and request links.
ENVIRONMENT="$(python3 - "$STATE" "$PROVIDER_URL" <<'PY'
import json, pathlib, sys
state, provider = pathlib.Path(sys.argv[1]), sys.argv[2]
config = {
    "wallet": {
        "client_id": "passport-vdc-wallet",
        "redirect_uri": "dev.idfoundry.oid4vcgo.demowallet:/callback",
        "issuer_roots": (state / "issuer-ca.pem").read_text(),
        "verifier_roots": (state / "verifier-ca.pem").read_text(),
        # The registrar of the verifier's relying parties: the app shows
        # their registrations, and warns when one asks for more.
        "registrar_roots": (state / "registrar-ca.pem").read_text() if (state / "registrar-ca.pem").exists() else "",
        "development": True,
        # Credentials from a passport kept for refresh come with a
        # refresh token, so the app can fetch fresh copies.
        "request_refresh": True,
    },
    "provider_url": provider,
}
print(json.dumps({"OID4VC_DEMO_CONFIG": json.dumps(config)}))
PY
)"
xcrun devicectl device process launch --device "$DEVICE" --terminate-existing -e "$ENVIRONMENT" "$BUNDLE_ID"
