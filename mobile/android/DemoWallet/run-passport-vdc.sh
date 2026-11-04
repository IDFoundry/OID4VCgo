#!/bin/sh
# Runs the demo wallet on an Android emulator or a USB-connected phone
# against the passport-vdc demo (examples/passport-vdc: `go run
# ./cmd/demo` there first): forwards the demo's ports into the device
# (adb reverse, so its loopback certificate holds), pushes the app's
# configuration — the demo's trust anchors, Wallet Provider and its
# in-person reader, for reader mode — and the demo's TLS certificate, and
# launches the app. Then upload a passport on https://127.0.0.1:8543 and
# open its offer link on the device:
#
#   adb shell am start -a android.intent.action.VIEW -d '"<openid-credential-offer://… link>"'
#
#   ./run-passport-vdc.sh            (ANDROID_SERIAL picks the device)
set -eu
cd "$(dirname "$0")"
STATE="${STATE:-../../../examples/passport-vdc/.demo-state}"
for f in tls-cert.pem issuer-ca.pem verifier-ca.pem mdoc-reader-ca.pem; do
	[ -s "$STATE/$f" ] || { echo "no $STATE/$f: run the passport-vdc demo first" >&2; exit 1; }
done
ADB="${ANDROID_HOME:-$HOME/Library/Android/sdk}/platform-tools/adb"
PKG=dev.idfoundry.oid4vcgo.demowallet
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

../../build-aar.sh
(cd .. && ./gradlew -q :DemoWallet:installDebug)
# The demo's wallet provider, issuer, verifier and web wallet: the
# issuer and verifier also serve their CAs' CRLs.
for p in 6443 8543 9443 7443; do "$ADB" reverse "tcp:$p" "tcp:$p" >/dev/null; done

# The demo's registration of its wallet (examples/passport-vdc/cmd/demo).
python3 - "$STATE" > "$WORK/config.json" <<'PY'
import json, pathlib, sys
state = pathlib.Path(sys.argv[1])
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
        "registrar_roots": (state / "registrar-ca.pem").read_text() if (state / "registrar-ca.pem").exists() else "",
        # Readers are recognized by the mdoc reader CA of the demo.
        "mdoc_reader_roots": (state / "mdoc-reader-ca.pem").read_text(),
        "mdoc_reader_require_eku": True,
        "development": True,
        "request_refresh": True,
        # The demo's CAs publish CRLs at the https distribution points
        # their certificates name, on the forwarded 127.0.0.1 ports. The
        # app fetches them (RefreshCRLs) trusting the demo's TLS
        # certificate, pushed below as dev-ca.pem, which the app passes
        # as development_roots (Go on Android trusts only the system's
        # CAs otherwise), and checks each role's certificates against
        # them.
        "revocation": REVOCATION,
        "crl_distribution_points_from_roots": True,
        "crl_require_https": True,
    },
    "provider_url": "https://127.0.0.1:6443",
}
# Reader mode identity: the in-person reader of the verifier, its key
# then its chain (a demo shortcut: a real reader keeps its key on the device).
reader_file = state / "mdoc-reader.pem"
if reader_file.exists():
    key, chain = reader_file.read_text().split("-----END PRIVATE KEY-----", 1)
    config["reader"] = {
        "issuer_roots": (state / "issuer-ca.pem").read_text(),
        "reader_key": key + "-----END PRIVATE KEY-----\n",
        "reader_chain": chain.lstrip(),
        # Documents' signers, and their status lists', are checked
        # against the issuer CA's CRL. A development reader, to fetch it
        # from 127.0.0.1 trusting the demo's TLS certificate as the
        # wallet does (the app passes it as the reader's
        # development_roots).
        "revocation": ["issuer", "status"],
        "crl_distribution_points_from_roots": True,
        "crl_require_https": True,
        "development": True,
    }
print(json.dumps(config))
PY

FILES=/sdcard/Android/data/$PKG/files
"$ADB" shell mkdir -p "$FILES"
"$ADB" push -q "$WORK/config.json" "$FILES/demo-config.json"
"$ADB" push -q "$STATE/tls-cert.pem" "$FILES/dev-ca.pem"
"$ADB" shell am force-stop "$PKG"
"$ADB" shell am start -n "$PKG/.MainActivity" >/dev/null
echo "the demo wallet is running against the passport-vdc demo"
