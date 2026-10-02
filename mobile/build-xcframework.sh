#!/bin/sh
# Builds build/Mobile.xcframework — the Go "mobile" package for iOS, the
# iOS Simulator and macOS (whose slice runs the Swift package's tests
# with `swift test`) — with gomobile bind. gomobile and gobind are the
# versions go.mod pins (tool directives), built into build/bin. Needs
# Xcode.
set -eu
cd "$(dirname "$0")"
GOBIN="$PWD/build/bin" go install golang.org/x/mobile/cmd/gomobile golang.org/x/mobile/cmd/gobind
# gomobile sets the iOS minimum with -iosversion; the macOS slice's
# comes from the deployment target. Both match Package.swift.
PATH="$PWD/build/bin:$PATH" MACOSX_DEPLOYMENT_TARGET=13.0 gomobile bind \
	-target=ios,iossimulator,macos -iosversion=16 \
	-trimpath -ldflags="-s -w" \
	-o build/Mobile.xcframework .
