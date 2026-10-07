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
#
# UI_TEST_PORT sets the control endpoint's port (8600). The script stops
# if something already answers there: the tests would drive it.
set -eu
cd "$(dirname "$0")"
WORK="$(mktemp -d)"
SERVICES=""
ADB="${ANDROID_HOME:-$HOME/Library/Android/sdk}/platform-tools/adb"
CHROME_FLAGS=/data/local/tmp/chrome-command-line
cleanup() {
	if [ -n "$SERVICES" ]; then kill "$SERVICES" 2>/dev/null || true; fi
	"$ADB" shell rm -f "$CHROME_FLAGS" >/dev/null 2>&1 || true
	"$ADB" shell am clear-debug-app >/dev/null 2>&1 || true
	rm -rf "$WORK"
}
trap cleanup EXIT INT TERM
PKG=dev.idfoundry.oid4vcgo.demowallet

../../build-aar.sh
(cd ../.. && go build -o "$WORK/testservices" ./cmd/testservices)
PORT="${UI_TEST_PORT:-8600}"
if curl -sk -o /dev/null "https://127.0.0.1:$PORT/config"; then
	echo "something already answers on 127.0.0.1:$PORT; stop it, or set UI_TEST_PORT" >&2
	exit 1
fi
"$WORK/testservices" -addr 127.0.0.1:$PORT -cert "$WORK/services.pem" > "$WORK/services.log" 2>&1 &
SERVICES=$!
for _ in $(seq 100); do curl -sk https://127.0.0.1:$PORT/config > "$WORK/config.json" 2>/dev/null && [ -s "$WORK/config.json" ] && break; sleep 0.2; done

# Every service's port: the control endpoint's, those in the
# configuration and log, and the two Verifiers', from a request to each.
REQUEST="$(curl -sk -X POST "https://127.0.0.1:$PORT/request?format=dc%2Bsd-jwt")$(curl -sk -X POST "https://127.0.0.1:$PORT/request?format=dc%2Bsd-jwt&registered=1")"
PORTS="$(printf '%s\n%s\n%s' "$(cat "$WORK/config.json" "$WORK/services.log")" "$(printf '%b' "$(echo "$REQUEST" | sed 's/%/\\x/g')")" "127.0.0.1:$PORT" \
	| grep -oE '127\.0\.0\.1:[0-9]+' | cut -d: -f2 | sort -u)"
for p in $PORTS; do "$ADB" reverse "tcp:$p" "tcp:$p" >/dev/null; done

# The app takes the CA from its external files directory, which it
# creates when first run (from Android 11, adb can't create it).
(cd .. && ./gradlew -q :DemoWallet:installDebug)
FILES=/sdcard/Android/data/$PKG/files
"$ADB" shell am start -W -n "$PKG/.MainActivity" >/dev/null
"$ADB" shell am force-stop "$PKG"
"$ADB" shell mkdir -p "$FILES" 2>/dev/null || true
# Where adb can't write there (Android 11), the CA goes straight to
# where the app keeps it, through run-as (the debug build allows it).
if ! "$ADB" push -q "$WORK/services.pem" "$FILES/dev-ca.pem" 2>/dev/null; then
	"$ADB" push -q "$WORK/services.pem" /data/local/tmp/dev-ca.pem
	"$ADB" shell "run-as $PKG sh -c 'mkdir -p files && cp /data/local/tmp/dev-ca.pem files/dev-ca.pem'"
	"$ADB" shell rm -f /data/local/tmp/dev-ca.pem
fi

# The authorization code tests sign in at the issuer in Chrome, which
# accepts the services' self-signed certificate by its key (an SPKI
# pin, from a command line Chrome reads while it's the debug app),
# skipping its first-run screens.
SPKI="$(openssl x509 -in "$WORK/services.pem" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64)"
echo "chrome --ignore-certificate-errors-spki-list=$SPKI --disable-fre --no-first-run --no-default-browser-check" > "$WORK/chrome-command-line"
"$ADB" push -q "$WORK/chrome-command-line" "$CHROME_FLAGS"
"$ADB" shell am set-debug-app --persistent com.android.chrome
"$ADB" shell am force-stop com.android.chrome

CA="$(base64 < "$WORK/services.pem" | tr -d '\n')"
ONLY=""
[ $# -gt 0 ] && ONLY="-Pandroid.testInstrumentationRunnerArguments.class=dev.idfoundry.oid4vcgo.demowallet.uitests.DemoWalletUITests#$1"
(cd .. && ./gradlew --console=plain :DemoWalletUITests:connectedDebugAndroidTest \
	-Pandroid.testInstrumentationRunnerArguments.controlCA="$CA" \
	-Pandroid.testInstrumentationRunnerArguments.controlPort="$PORT" $ONLY)
