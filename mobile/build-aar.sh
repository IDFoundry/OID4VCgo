#!/bin/sh
# Builds the Go "mobile" package with gomobile bind into an Android
# library (AAR) for every Android ABI: arm64-v8a and armeabi-v7a
# (devices), x86_64 and x86 (emulators). Play takes 32-bit libraries
# beside the 64-bit ones, for devices that run only 32-bit apps:
#
#   ./build-aar.sh                   → build/release/mobile.aar
#   ./build-aar.sh -tags mobiletest  → build/test/mobile.aar
#
# OID4VC_ABIS=64 builds arm64-v8a and x86_64 only, for an app that ships
# no 32-bit code: a smaller AAR.
#
# The test build carries an in-process test issuer and Verifier
# (TestEnv) that a shipped library must not have; the Kotlin library
# links it only with -Poid4vc.testFramework=true (see
# android/OID4VCWallet/build.gradle.kts), and OID4VC.isTestBuild tells
# an app which it has. The Java bindings are in package
# dev.idfoundry.oid4vcwallet.gomobile.mobile. gomobile and gobind are the
# versions go.mod pins (tool directives), built into build/bin.
# Needs the Android SDK (ANDROID_HOME) with an NDK. Other arguments go to
# gomobile bind.
set -eu
cd "$(dirname "$0")"
: "${ANDROID_HOME:=${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}"
export ANDROID_HOME
GOBIN="$PWD/build/bin" go install golang.org/x/mobile/cmd/gomobile golang.org/x/mobile/cmd/gobind
OUT=build/release
case " $* " in *" -tags mobiletest "*) OUT=build/test ;; esac
rm -f "$OUT/mobile.aar" "$OUT/mobile-sources.jar"
mkdir -p "$OUT"
# -androidapi matches the Kotlin library's minSdk (26).
case "${OID4VC_ABIS:-all}" in
all) TARGET=android/arm64,android/arm,android/amd64,android/386 ;;
64) TARGET=android/arm64,android/amd64 ;;
*) echo "OID4VC_ABIS is all or 64, not $OID4VC_ABIS" >&2; exit 2 ;;
esac
PATH="$PWD/build/bin:$PATH" gomobile bind \
	-target="$TARGET" -androidapi=26 \
	-javapkg=dev.idfoundry.oid4vcwallet.gomobile \
	-trimpath -ldflags="-s -w" "$@" \
	-o "$OUT/mobile.aar" .
echo "$OUT/mobile.aar"
