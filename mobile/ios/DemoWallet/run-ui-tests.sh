#!/bin/sh
# Runs the demo wallet's UI tests on an iOS Simulator against
# mobile/cmd/testservices: builds the XCFramework, starts the services,
# makes the Simulator trust their certificate, and runs the tests.
#
#   ./run-ui-tests.sh [simulator-id-or-name]   (default: iPhone 16)
set -eu
cd "$(dirname "$0")"
DEVICE="${1:-iPhone 16}"
WORK="$(mktemp -d)"
SERVICES=""
trap 'if [ -n "$SERVICES" ]; then kill "$SERVICES" 2>/dev/null || true; fi; rm -rf "$WORK"' EXIT

../../build-xcframework.sh
(cd ../.. && go build -o "$WORK/testservices" ./cmd/testservices)
"$WORK/testservices" -cert "$WORK/services.pem" &
SERVICES=$!
for _ in $(seq 50); do [ -s "$WORK/services.pem" ] && break; sleep 0.2; done

xcrun simctl boot "$DEVICE" 2>/dev/null || true
xcrun simctl bootstatus "$DEVICE" -b >/dev/null
xcrun simctl keychain "$DEVICE" add-root-cert "$WORK/services.pem"

case "$DEVICE" in
*-*-*-*-*) DEST="id=$DEVICE" ;;
*) DEST="platform=iOS Simulator,name=$DEVICE" ;;
esac
xcodebuild test -project DemoWallet.xcodeproj -scheme DemoWallet -destination "$DEST" ${ONLY:+-only-testing:"$ONLY"}
