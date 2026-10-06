#!/bin/sh
# Runs the demo wallet's UI tests (../DemoWalletUITests) on an emulator
# or device against mobile/cmd/testservices: builds the release Go
# library, starts the services, forwards their ports into the device
# (adb reverse, so their loopback certificate holds), pushes their CA to
# the app, and runs the tests, which reach the services' control
# endpoint over the same CA. The device needs a screen lock with PIN
# 1111, and unlocked (../unlock-emulator.sh sets one on an emulator).
#
#   ./run-ui-tests.sh [test]   (a test method, say present, to run only it)
set -eu
cd "$(dirname "$0")"
WORK="$(mktemp -d)"
SERVICES=""
trap 'if [ -n "$SERVICES" ]; then kill "$SERVICES" 2>/dev/null || true; fi; rm -rf "$WORK"' EXIT INT TERM
ADB="${ANDROID_HOME:-$HOME/Library/Android/sdk}/platform-tools/adb"
PKG=dev.idfoundry.oid4vcgo.demowallet

../../build-aar.sh
(cd ../.. && go build -o "$WORK/testservices" ./cmd/testservices)
"$WORK/testservices" -addr 127.0.0.1:8600 -cert "$WORK/services.pem" > "$WORK/services.log" 2>&1 &
SERVICES=$!
for _ in $(seq 100); do curl -sk https://127.0.0.1:8600/config > "$WORK/config.json" 2>/dev/null && [ -s "$WORK/config.json" ] && break; sleep 0.2; done

# Every service's port: the control endpoint's, those in the
# configuration and log, and the two Verifiers', from a request to each.
REQUEST="$(curl -sk -X POST 'https://127.0.0.1:8600/request?format=dc%2Bsd-jwt')$(curl -sk -X POST 'https://127.0.0.1:8600/request?format=dc%2Bsd-jwt&registered=1')"
PORTS="$(printf '%s\n%s\n%s' "$(cat "$WORK/config.json" "$WORK/services.log")" "$(printf '%b' "$(echo "$REQUEST" | sed 's/%/\\x/g')")" "127.0.0.1:8600" \
	| grep -oE '127\.0\.0\.1:[0-9]+' | cut -d: -f2 | sort -u)"
for p in $PORTS; do "$ADB" reverse "tcp:$p" "tcp:$p" >/dev/null; done

# The app takes the CA from its external files directory, which exists
# once it's installed.
(cd .. && ./gradlew -q :DemoWallet:installDebug)
FILES=/sdcard/Android/data/$PKG/files
"$ADB" shell mkdir -p "$FILES"
"$ADB" push -q "$WORK/services.pem" "$FILES/dev-ca.pem"

CA="$(base64 < "$WORK/services.pem" | tr -d '\n')"
ONLY=""
[ $# -gt 0 ] && ONLY="-Pandroid.testInstrumentationRunnerArguments.class=dev.idfoundry.oid4vcgo.demowallet.uitests.DemoWalletUITests#$1"
(cd .. && ./gradlew --console=plain :DemoWalletUITests:connectedDebugAndroidTest \
	-Pandroid.testInstrumentationRunnerArguments.controlCA="$CA" $ONLY)
