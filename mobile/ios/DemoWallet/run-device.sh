#!/bin/sh
# Runs the demo wallet on a connected iPhone against the passport-vdc demo
# served on public URLs: start it with them, behind a tunnel (see
# cloudflared.yml.example), from examples/passport-vdc:
#
#   go run ./cmd/demo -state .demo-state-device \
#     -issuer-url https://issuer.example.com \
#     -verifier-url https://verifier.example.com \
#     -provider-url https://provider.example.com \
#     -ios-app ABCDE12345.dev.idfoundry.oid4vcgo.demowallet
#
# then, with your Apple developer team ID and that Wallet Provider URL:
#
#   TEAM_ID=ABCDE12345 PROVIDER_URL=https://provider.example.com \
#     STATE=../../../examples/passport-vdc/.demo-state-device ./run-device.sh [device-id]
#
# The app speaks the library's Wallet Provider protocol with App Attest
# (HttpWalletProvider): start the demo with -ios-app "$TEAM_ID.$BUNDLE_ID"
# too, and enable App Attest on the App ID in the Apple Developer portal.
# PROVIDER_PROTOCOL=demo uses the demo provider's own API instead, which
# attests any caller.
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
PROVIDER_PROTOCOL="${PROVIDER_PROTOCOL:-v1}"
case "$PROVIDER_PROTOCOL" in
v1) echo "the Wallet Provider must be started with -ios-app $TEAM_ID.$BUNDLE_ID" ;;
demo) ;;
*) echo "PROVIDER_PROTOCOL is v1 or demo, not $PROVIDER_PROTOCOL" >&2; exit 1 ;;
esac
for f in issuer-ca.pem verifier-ca.pem mdoc-reader-ca.pem; do
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
	DEVELOPMENT_TEAM="$TEAM_ID" CODE_SIGN_STYLE=Automatic DEMO_BUNDLE_ID="$BUNDLE_ID"
xcrun devicectl device install app --device "$DEVICE" "$BUILD/Build/Products/Debug-iphoneos/DemoWallet.app"

# The demo's registration of its wallet (examples/passport-vdc/cmd/demo),
# with the Wallet Provider at its public URL. The issuer and verifier
# are found from the offer and request links.
ENVIRONMENT="$(python3 - "$STATE" "$PROVIDER_URL" "$PROVIDER_PROTOCOL" <<'PY'
import json, pathlib, sys
state, provider, protocol = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
# The trust roles checked against the demo's CRLs: the issuer CA's
# (credentials and their status lists), the verifier CA's, the mdoc
# reader CA's and the registrar CA's.
REVOCATION = ["issuer", "status", "verifier", "mdoc_reader"]
if (state / "registrar-ca.pem").exists():
    REVOCATION.append("registrar")
config = {
    "wallet": {
        "client_id": "passport-vdc-wallet",
        "redirect_uri": "dev.idfoundry.oid4vcgo.demowallet:/callback",
        "issuer_roots": (state / "issuer-ca.pem").read_text(),
        "verifier_roots": (state / "verifier-ca.pem").read_text(),
        # The registrar of the verifier relying parties: the app shows
        # their registrations, and warns when one asks for more.
        "registrar_roots": (state / "registrar-ca.pem").read_text() if (state / "registrar-ca.pem").exists() else "",
        # The verifier relying parties sign their Digital Credentials
        # API requests (org-iso-mdoc) with mdoc reader authentication
        # certificates from the demo reader CA, which carry the ISO
        # reader authentication extended key usage: the extension names
        # the one asking, and recognizes no other certificate as a
        # reader.
        "mdoc_reader_roots": (state / "mdoc-reader-ca.pem").read_text(),
        "mdoc_reader_require_eku": True,
        "development": True,
        # Credentials from a passport kept for refresh come with a
        # refresh token, so the app can fetch fresh copies.
        "request_refresh": True,
        # The demo's CAs publish CRLs at the distribution points their
        # certificates name, on the public URLs: the app fetches them
        # (RefreshCRLs) and checks each role's certificates against them.
        "revocation": REVOCATION,
        "crl_distribution_points_from_roots": True,
        "crl_require_https": True,
    },
    "provider_url": provider,
    # v1: the library's protocol with App Attest; demo: the demo's own API.
    "provider_protocol": protocol,
}
# Reader mode identity: the in-person reader of the verifier, its key
# then its chain (a demo shortcut: a real reader keeps its key on the device).
reader_file = state / "mdoc-reader.pem"
if reader_file.exists():
    text = reader_file.read_text()
    end = "-----END PRIVATE KEY-----"
    key, chain = text.split(end, 1)
    config["reader"] = {
        "issuer_roots": (state / "issuer-ca.pem").read_text(),
        "reader_key": key + end + "\n",
        "reader_chain": chain.lstrip(),
        # Documents' signers, and their status lists', are checked
        # against the issuer CA's CRL.
        "revocation": ["issuer", "status"],
        "crl_distribution_points_from_roots": True,
        "crl_require_https": True,
    }
print(json.dumps({"OID4VC_DEMO_CONFIG": json.dumps(config)}))
PY
)"
xcrun devicectl device process launch --device "$DEVICE" --terminate-existing -e "$ENVIRONMENT" "$BUNDLE_ID"
