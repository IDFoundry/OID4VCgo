#!/bin/sh
# Runs the demo wallet on an Android emulator or device against
# mobile/cmd/testservices: builds the release Go library and the app,
# starts the services, forwards their ports into the device (adb
# reverse, so their loopback certificate holds), pushes the app's
# configuration and the services' CA, and launches it from an empty
# wallet. The services run until Ctrl-C; their control endpoint
# (https://127.0.0.1:8600) makes offers and requests:
#
#   curl -sk -X POST 'https://127.0.0.1:8600/offer?pin=493536'
#   curl -sk -X POST 'https://127.0.0.1:8600/request?format=dc%2Bsd-jwt'
#
# then open the link in the app: adb shell am start -a android.intent.action.VIEW -d '"<link>"'
set -eu
cd "$(dirname "$0")"
WORK="$(mktemp -d)"
SERVICES=""
trap 'if [ -n "$SERVICES" ]; then kill "$SERVICES" 2>/dev/null || true; fi; rm -rf "$WORK"' EXIT INT TERM
ADB="${ANDROID_HOME:-$HOME/Library/Android/sdk}/platform-tools/adb"
PKG=dev.idfoundry.oid4vcgo.demowallet

../../build-aar.sh
(cd .. && ./gradlew -q :DemoWallet:installDebug)
(cd ../.. && go build -o "$WORK/testservices" ./cmd/testservices)
"$WORK/testservices" -addr 127.0.0.1:8600 -cert "$WORK/services.pem" > "$WORK/services.log" 2>&1 &
SERVICES=$!
for _ in $(seq 100); do curl -sk https://127.0.0.1:8600/config > "$WORK/config.json" 2>/dev/null && [ -s "$WORK/config.json" ] && break; sleep 0.2; done

# Every service's port: the control endpoint's, those in the
# configuration and log, and the Verifier's, from a request.
REQUEST="$(curl -sk -X POST 'https://127.0.0.1:8600/request?format=dc%2Bsd-jwt')"
PORTS="$(printf '%s\n%s\n%s' "$(cat "$WORK/config.json" "$WORK/services.log")" "$(printf '%b' "$(echo "$REQUEST" | sed 's/%/\\x/g')")" "127.0.0.1:8600" \
	| grep -oE '127\.0\.0\.1:[0-9]+' | cut -d: -f2 | sort -u)"
for p in $PORTS; do "$ADB" reverse "tcp:$p" "tcp:$p" >/dev/null; done

FILES=/sdcard/Android/data/$PKG/files
"$ADB" shell mkdir -p "$FILES"
"$ADB" push -q "$WORK/config.json" "$FILES/demo-config.json"
"$ADB" push -q "$WORK/services.pem" "$FILES/dev-ca.pem"
"$ADB" shell am force-stop "$PKG"
"$ADB" shell am start -n "$PKG/.MainActivity" --ez reset true >/dev/null
echo "the demo wallet is running against the test services (ports $(echo $PORTS | tr '\n' ' ')); Ctrl-C to stop them"
wait "$SERVICES"
