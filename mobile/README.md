# OID4VCgo mobile

The gomobile boundary of OID4VCgo's mobile wallet SDK — see
[MOBILE.md](../MOBILE.md) for the design and its phases. This is a
separate Go module (it needs `golang.org/x/mobile`).

- `mobile` (this directory): the Go package `gomobile bind` compiles.
- `ios/OID4VCWallet`: the Swift package wrapping the XCFramework, with
  its tests.
- `android/OID4VCWallet`: the Kotlin library wrapping the AAR, with its
  tests.

The API is described in [ABI.md](ABI.md).

Build the XCFramework (Xcode and Go needed; gomobile and gobind are the
versions `go.mod` pins). The Swift tests need the test build, which adds
an in-process test issuer and Verifier (`TestEnv`) a shipped framework
must not have:

```sh
./build-xcframework.sh -tags mobiletest   # → build/test/Mobile.xcframework
./build-xcframework.sh                    # → build/release/Mobile.xcframework, the one an app ships
cd ios/OID4VCWallet
OID4VC_TEST_FRAMEWORK=1 swift test        # macOS slice, against the test build
OID4VC_TEST_FRAMEWORK=1 xcodebuild test -scheme OID4VCWallet -destination 'platform=iOS Simulator,name=iPhone 16'
```

The package links the release build unless `OID4VC_TEST_FRAMEWORK=1`
is set, and `OID4VC.isTestBuild` says which one an app has.

## Android

Build the AAR (Go and the Android SDK with an NDK needed, `ANDROID_HOME`
set or the SDK in its default place), then the Kotlin library. Its tests
are instrumented: they need the test build, and an emulator or device
attached:

```sh
./build-aar.sh -tags mobiletest   # → build/test/mobile.aar
./build-aar.sh                    # → build/release/mobile.aar, the one an app ships
cd android
./gradlew :OID4VCWallet:connectedDebugAndroidTest -Poid4vc.testFramework=true
./gradlew :OID4VCWallet:assembleRelease   # against the release build
```

The library links the release build unless `-Poid4vc.testFramework=true`,
and `OID4VC.isTestBuild` says which one an app has.

## Publishing the Kotlin library

App developers add `dev.idfoundry:oid4vcwallet` from the Maven repository
[OID4VCgo-wallet-kotlin](https://github.com/IDFoundry/OID4VCgo-wallet-kotlin)'s
GitHub Pages serve:

```kotlin
repositories { maven("https://idfoundry.github.io/OID4VCgo-wallet-kotlin/maven") }
dependencies { implementation("dev.idfoundry:oid4vcwallet:0.7.0") }
```

To publish a version, run the `wallet-kotlin-release` workflow from the
commit to publish, with the version: the Swift package's, from the same
commit. It runs `android/package-kotlin-release.sh`, which:
1. builds the release AAR
2. publishes the library into a staging Maven repository, and builds an
   app depending on it from there
3. publishes it into the package repository's `maven/`, beside the
   earlier versions, and mirrors the sources and the README

The workflow then commits the result there and creates the tagged
release, carrying the AAR. It needs the `WALLET_KOTLIN_TOKEN` secret: a
fine-grained token with Contents read and write on OID4VCgo-wallet-kotlin
only; that repository's Pages serve its main branch. CI runs the same
script on every change, without publishing.

The library is compiled for Kotlin 2.2 (language and API version, and
its standard library), so an app on AGP 9's own Kotlin can use it.

## Publishing the Swift package

Integrators add the package from
[OID4VCgo-wallet-swift](https://github.com/IDFoundry/OID4VCgo-wallet-swift),
which SwiftPM can fetch:

```swift
.package(url: "https://github.com/IDFoundry/OID4VCgo-wallet-swift", from: "0.1.0")
```

To publish a version, run the `wallet-swift-release` workflow from
the commit to publish, with the version (`1.2.3`, versioned apart from
the Go module). It runs `ios/package-swift-release.sh`, which:
1. builds the release framework and zips it as the release asset
2. copies `ios/OID4VCWallet/Sources` across
3. writes a `Package.swift` naming the asset by URL and checksum
4. builds the package against the zipped framework, for macOS and the
   iOS Simulator

The workflow then commits the result there and creates the tagged
release. It needs the `WALLET_SWIFT_TOKEN` secret: a fine-grained token
with Contents read and write on OID4VCgo-wallet-swift only. CI runs the
same script on every change, without publishing.

## Go tests

The Go package's own tests run anywhere: `go test -tags mobiletest ./...`
for the end-to-end session tests too.
