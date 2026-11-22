#!/bin/sh
# Builds a demo wallet APK to hand a tester: configured for the
# passport-vdc demo served on public URLs, with no adb. Start the demo
# with them, behind a tunnel (see mobile/ios/DemoWallet's
# cloudflared.yml.example), from examples/passport-vdc:
#
#   go run ./cmd/demo -state .demo-state-device \
#     -issuer-url https://issuer.example.com \
#     -verifier-url https://verifier.example.com \
#     -provider-url https://provider.example.com
#
# then, with that Wallet Provider URL:
#
#   PROVIDER_URL=https://provider.example.com \
#     STATE=../../../examples/passport-vdc/.demo-state-device ./build-shareable.sh [out-dir]
#
# It bundles the demo's registration of its wallet (-Pdemo.config), which
# the app applies at its first launch, and writes the debug-signed APK and
# its SHA-256 to out-dir (default build/shareable). The tester installs it
# by opening the file on the phone (allowing installs from that app).
#
# It also writes out-dir/android-app.txt, the app's package and signing
# certificate's SHA-256 as -android-app takes them. Restart the demo with
#
#   -android-app "$(cat build/shareable/android-app.txt)"
#
# added: its Wallet Provider refuses an app's Android key attestations
# unless the demo was started with that app. Every build signed with
# this machine's debug key has the same value.
#
# The configuration carries the demo verifier's in-person reader identity,
# its key included, so reader mode works: a demo shortcut (a real reader
# keeps its key on the device). Anyone holding the APK holds that key, which
# readers' certificates are trusted by in this demo only.
set -eu
cd "$(dirname "$0")"
: "${PROVIDER_URL:?set PROVIDER_URL to the Wallet Provider public https URL, cmd/demo -provider-url}"
STATE="${STATE:-../../../examples/passport-vdc/.demo-state}"
OUT="${1:-build/shareable}"
for f in issuer-ca.pem credential-issuers verifier-ca.pem mdoc-reader-ca.pem mdoc-reader.pem; do
	[ -s "$STATE/$f" ] || { echo "no $STATE/$f: run the passport-vdc demo first" >&2; exit 1; }
done
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# The demo's registration of its wallet (examples/passport-vdc/cmd/demo),
# as run-device.sh in mobile/ios/DemoWallet gives the iOS app, with the
# Wallet Provider at its public URL. The issuer and verifier are found
# from the offer and request links.
python3 - "$STATE" "$PROVIDER_URL" > "$WORK/demo-config.json" <<'PY'
import json, pathlib, sys
state, provider = pathlib.Path(sys.argv[1]), sys.argv[2]
if not provider.startswith("https://"):
    sys.exit("PROVIDER_URL must be an https URL")
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
        # The demo's issuer, the only one whose offers the app takes: an
        # offer naming another is refused before the holder is asked for
        # a PIN. cmd/demo writes it, with the issuer's public URL.
        "credential_issuers": (state / "credential-issuers").read_text().split(),
        "verifier_roots": (state / "verifier-ca.pem").read_text(),
        "registrar_roots": (state / "registrar-ca.pem").read_text() if (state / "registrar-ca.pem").exists() else "",
        # Readers are recognized by the mdoc reader CA of the demo.
        "mdoc_reader_roots": (state / "mdoc-reader-ca.pem").read_text(),
        "mdoc_reader_require_eku": True,
        "development": True,
        "request_refresh": True,
        # The demo's CAs publish CRLs at the distribution points their
        # certificates name, on the public URLs: the app fetches them
        # (RefreshCRLs) and checks each role's certificates against them.
        "revocation": REVOCATION,
        "crl_distribution_points_from_roots": True,
        "crl_require_https": True,
        # A status list signed over a day ago is refused, as production
        # requires a bound: the demo's issuer signs its lists every
        # minute.
        "status_max_age_seconds": 86400,
    },
    "provider_url": provider,
}
# Reader mode identity: the in-person reader of the verifier, its key
# then its chain.
text = (state / "mdoc-reader.pem").read_text()
end = "-----END PRIVATE KEY-----"
key, chain = text.split(end, 1)
config["reader"] = {
    "issuer_roots": (state / "issuer-ca.pem").read_text(),
    "reader_key": key + end + "\n",
    "reader_chain": chain.lstrip(),
    # Documents' signers, and their status lists', are checked against
    # the issuer CA's CRL.
    "revocation": ["issuer", "status"],
    "crl_distribution_points_from_roots": True,
    "crl_require_https": True,
}
print(json.dumps(config))
PY

../../build-aar.sh
(cd .. && ./gradlew -q :DemoWallet:assembleDebug -Pdemo.config="$WORK/demo-config.json")
mkdir -p "$OUT"
cp build/outputs/apk/debug/DemoWallet-debug.apk "$OUT/oid4vcgo-demowallet.apk"
(cd "$OUT" && shasum -a 256 oid4vcgo-demowallet.apk > oid4vcgo-demowallet.apk.sha256)

# The app as cmd/demo's -android-app names it: its package
# (build.gradle.kts's applicationId) and each of its signing
# certificates' SHA-256, in hex. The demo's Wallet Provider refuses the
# Android key attestations of an app it isn't started with.
BUILD_TOOLS="${ANDROID_HOME:-$HOME/Library/Android/sdk}/build-tools"
APKSIGNER="$BUILD_TOOLS/$(ls "$BUILD_TOOLS" 2>/dev/null | sort -t. -k1,1n -k2,2n -k3,3n | tail -1)/apksigner"
[ -x "$APKSIGNER" ] || { echo "no apksigner under $BUILD_TOOLS: install the Android SDK Build-Tools" >&2; exit 1; }
DIGESTS="$("$APKSIGNER" verify --print-certs "$OUT/oid4vcgo-demowallet.apk" |
	sed -n 's/^Signer #[0-9]* certificate SHA-256 digest: //p' | paste -s -d, -)"
[ -n "$DIGESTS" ] || { echo "apksigner printed no signing certificate's SHA-256" >&2; exit 1; }
echo "dev.idfoundry.oid4vcgo.demowallet:$DIGESTS" > "$OUT/android-app.txt"
echo "start the demo with -android-app $(cat "$OUT/android-app.txt")" >&2
echo "$OUT/oid4vcgo-demowallet.apk"
