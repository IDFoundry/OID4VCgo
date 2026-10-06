#!/bin/sh
# Builds the Go "mobile" package with gomobile bind into an Android
# library (AAR) for arm64 and x86_64 (the emulator). 32-bit arm is left
# out: FAPIgo doesn't build where int is 32 bits, and Play requires
# 64-bit libraries anyway:
#
#   ./build-aar.sh                   → build/release/mobile.aar
#   ./build-aar.sh -tags mobiletest  → build/test/mobile.aar
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
# -androidapi matches the Kotlin library's minSdk.
PATH="$PWD/build/bin:$PATH" gomobile bind \
	-target=android/arm64,android/amd64 -androidapi=30 \
	-javapkg=dev.idfoundry.oid4vcwallet.gomobile \
	-trimpath -ldflags="-s -w" "$@" \
	-o "$OUT/mobile.aar" .
echo "$OUT/mobile.aar"
