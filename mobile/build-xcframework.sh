#!/bin/sh
# Builds the Go "mobile" package with gomobile bind into an XCFramework
# for iOS, the iOS Simulator and macOS (whose slice runs the Swift
# package's tests with `swift test`):
#
#   ./build-xcframework.sh                   → build/release/Mobile.xcframework
#   ./build-xcframework.sh -tags mobiletest  → build/test/Mobile.xcframework
#
# The test build carries an in-process test issuer and Verifier
# (TestEnv) that a shipped framework must not have; the Swift package
# links it only when OID4VC_TEST_FRAMEWORK=1 (see Package.swift), and
# OID4VC.isTestBuild tells an app which it has. gomobile and gobind are
# the versions go.mod pins (tool directives), built into build/bin.
# Needs Xcode. Other arguments go to gomobile bind.
set -eu
cd "$(dirname "$0")"
GOBIN="$PWD/build/bin" go install golang.org/x/mobile/cmd/gomobile golang.org/x/mobile/cmd/gobind
# gomobile sets the iOS minimum with -iosversion; the macOS slice's
# comes from the deployment target. Both match Package.swift.
OUT=build/release
case " $* " in *" -tags mobiletest "*) OUT=build/test ;; esac
rm -rf "$OUT/Mobile.xcframework"
mkdir -p "$OUT"
PATH="$PWD/build/bin:$PATH" MACOSX_DEPLOYMENT_TARGET=13.0 gomobile bind \
	-target=ios,iossimulator,macos -iosversion=16 \
	-trimpath -ldflags="-s -w" "$@" \
	-o "$OUT/Mobile.xcframework" .
echo "$OUT/Mobile.xcframework"
