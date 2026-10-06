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

App developers take `oid4vcwallet-<version>.aar` from a release of
[OID4VCgo-wallet-kotlin](https://github.com/IDFoundry/OID4VCgo-wallet-kotlin),
into their app module's `libs/`, with the libraries it uses, which that
repository's README lists:

```kotlin
dependencies {
    implementation(files("libs/oid4vcwallet-0.7.0.aar"))
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:…")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:…")
}
```

To publish a version, run the `wallet-kotlin-release` workflow from the
commit to publish, with the version: the Swift package's, from the same
commit. It runs `android/package-kotlin-release.sh`, which:
1. builds the release AAR, and the library's AAR and sources jar
2. builds an app on the AAR as the README says: the file, and the
   libraries the library's POM names
3. mirrors the sources into the package repository, and writes its
   README with those libraries

The workflow then commits the result there and creates the tagged
release, carrying the AAR and the sources jar. It needs the
`WALLET_KOTLIN_TOKEN` secret: a fine-grained token with Contents read and
write on OID4VCgo-wallet-kotlin only. CI runs the same script on every
change, without publishing.

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
