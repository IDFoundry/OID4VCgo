# OID4VCgo mobile

The gomobile boundary of OID4VCgo's mobile wallet SDK — see
[MOBILE.md](MOBILE.md) for the design and its phases. This is a
separate Go module (it needs `golang.org/x/mobile`).

- `mobile` (this directory): the Go package `gomobile bind` compiles.
- `ios/OID4VCWallet`: the Swift package wrapping the XCFramework, with
  its tests.
- `android/OID4VCWallet`: the Kotlin library wrapping the AAR, with its
  tests.

The API is described in [ABI.md](ABI.md). The HTTP protocol between a
wallet and a Wallet Provider built with `walletprovider` is described
in [WALLET_PROVIDER.md](WALLET_PROVIDER.md); the Kotlin and Swift
libraries' `HttpWalletProvider`s are clients of it.

The libraries' documentation, for app developers, is published with
each release:

- **Swift:** [the OID4VCWallet documentation](https://idfoundry.github.io/OID4VCgo-wallet-swift/latest/documentation/oid4vcwallet/) — getting started,
  an article for each task, and the API reference.
- **Kotlin:** [the guides](https://github.com/IDFoundry/OID4VCgo-wallet-kotlin/tree/main/docs) and [the API reference](https://idfoundry.github.io/OID4VCgo-wallet-kotlin/latest/).

## What each platform supports

| | Swift (iOS) | Kotlin (Android) |
|---|---|---|
| Issuance (`openid-credential-offer://` links) | ✓ | ✓ |
| Presentation (`openid4vp://` links) | ✓ | ✓ |
| OpenID4VP over the Digital Credentials API (`startDCAPIPresentation`, with `requireSignedDCAPIRequests`) | — Safari doesn't send it | ✓ Chrome, through Credential Manager |
| `org-iso-mdoc` over the Digital Credentials API (`startMdocPresentation`, `mdocCandidates`) | ✓ Safari, through a document provider extension | in the library, but Chrome sends OpenID4VP instead |
| In person, as the holder (`startProximityPresentation`) | ✓ | ✓ |
| In person, as the reader (`ProximityReader`) | ✓ | ✓ |
| In person by NFC tap, as the holder (`startNfcPresentation`, `startCombinedPresentation` for QR or NFC) | — | ✓ through an app's `NfcEngagementService` |
| In person by NFC tap, as the reader (`ProximityReader.startFromNfc`) | — | ✓ |
| Keys | `KeychainKeyStore` (Secure Enclave) | `AndroidKeystoreKeyStore` (StrongBox or TEE) |
| Credential store | `FileCredentialStore` | `FileCredentialStore` |
| Wallet Provider client (OID4VCgo's `walletprovider` protocol) | ✓ `HttpWalletProvider`, with App Attest | ✓ `HttpWalletProvider`, with Android Key Attestation |
| Certificate pinning for the SDK's requests (`tlsPins`) | ✓ | ✓ |
| Extra development CAs (`developmentRoots`) | ✓ | ✓ |
| Bluetooth permissions | asked by iOS on first use | `ProximityPermissions`, for the app to request |

The Swift library runs on iOS 15 and macOS 13 and later. Presenting to
Safari's Digital Credentials API needs iOS 26. `ProximityTimeouts`
takes its timeouts two ways:

| iOS | `ProximityTimeouts` |
|---|---|
| 15 and later | `TimeInterval` seconds: `ProximityTimeouts(connectSeconds:requestSeconds:idleSeconds:)`, and the `connectSeconds`, `requestSeconds` and `idleSeconds` properties |
| 16 and later | also `Duration`s: `ProximityTimeouts(connect:request:idle:)`, and the `connect`, `request` and `idle` properties |

The Kotlin library runs on Android 8 (API 26) and later. What its keys
guarantee depends on the API level:

| Android | Holder keys | Every key, and the credential store's | Where keys are made |
|---|---|---|---|
| 11 and later (API 30+) | can require biometrics or the screen lock for each use (`holderUserAuthentication`, the default) | work only while the device is unlocked | StrongBox where the device has it, else the TEE |
| 9 and 10 (API 28–29) | can't require the holder: set `holderUserAuthentication` false, which a key store with it true refuses, and authenticate the holder in the app before presenting | work only while the device is unlocked | StrongBox or the TEE |
| 8 (API 26–27) | as API 28–29 | work while the device is locked, once it was unlocked after boot (as `FileCredentialStore`'s `AFTER_FIRST_UNLOCK`) | the TEE; `StrongBox.REQUIRED` fails |

`BiometricPromptAuthenticator` is API 30's, like the per-use holder keys
it serves. Key attestation on API 26–27 can be software-backed on some
devices; the Wallet Provider decides whether to accept it.

The demo apps show each platform's integration with the browser: the
iOS document provider extension, and the Android Credential Manager
provider activity.

## In-person presentation

ISO/IEC 18013-5 device retrieval over BLE. The libraries carry the BLE
GATT transport: an app shows or scans a QR code and follows a session's
states; it never sees GATT.

On Android, an NFC tap can engage instead of the QR code, or alongside
it, with static or negotiated handover, and the data can then go over
BLE or stay on NFC. The holder answers taps through a subclass of the
library's `NfcEngagementService` that the app declares; the reader
passes the tag from Android's reader mode to `startFromNfc`. The
sessions have the same states as QR ones. [Presenting in person](android/docs/PresentingInPerson.md)
has the setup, the lifecycle and the routing rules.

- **The holder:** `wallet.startProximityPresentation()` returns a
  session whose `qrCode` the app shows. It offers both BLE modes by
  default (`modes`): it advertises (mdoc peripheral server mode) and
  scans for the reader (mdoc central client mode, checking the reader's
  Ident) until a reader connects either way. It then reports
  `requestReceived` with the reader's identity (`trusted` under
  `mdocReaderRoots`, `untrusted`, `unauthenticated` if unsigned, or
  `invalid`, with its certificate chain; in Swift also `certificates`,
  each certificate's fields, which iOS has no API to read) and the requested
  documents with the held mdocs that match, and, from a second-edition
  reader, `requestInfo`: its use cases, each with a mandatory flag,
  document sets and purpose hints, and `signed`, whether a verified
  whole-request signature covers them (null/nil when the reader sent
  none). `signed` isn't trust, which is the reader's status, and
  neither proves a purpose. The app asks the holder,
  then calls `respond(document:credentialID:elements:)` or `decline()`.
  `presented(linkable:)` says whether the copy shown had been seen by
  another Verifier. `requireTrustedMdocReader` ends a session from an
  unrecognized reader before anything is shown.
- **The reader:** `ProximityReader(configuration:keyStore:)`, with the
  IACAs whose mdocs it accepts and, to sign its requests, its key and
  certificate chain (with the reader authentication extended key
  usage, 1.0.18013.5.1.6). `start` takes the holder's QR code, the
  doctype and the elements to ask for, or several documents at once (a
  `DocumentRequest` each, at most eight), of which the holder may answer
  any. It connects in whichever mode
  the holder offers, preferring central client mode (`mode` says
  which), and ends in
  `verified` with the issuer-verified elements (each document's, for
  several), or another final state.
- **States** are an `AsyncStream` (`states`) in Swift and a `StateFlow`
  (`state`) in Kotlin; `isFinal` says when a session is over, and
  `cancel()` ends one.
- **Timeouts** (`ProximityTimeouts`): by default 60 s for the other
  device to connect, 30 s for the request, and 300 s for the holder to
  decide or the answer to arrive. In Swift, give them as `TimeInterval`
  seconds (iOS 15 and later) or `Duration`s (iOS 16 and later).
- **Bluetooth failures** are `ProximityError` (Swift) or
  `ProximityException` (Kotlin): Bluetooth off or not allowed, a
  timeout, or a lost connection, each with a sentence to show.
  Protocol failures are `WalletError`/`WalletException`.
- **iOS:** the app's Info.plist needs `NSBluetoothAlwaysUsageDescription`.
- **Android:** the library's manifest adds the Bluetooth permissions
  (up to Android 11, `BLUETOOTH`, `BLUETOOTH_ADMIN` and
  `ACCESS_FINE_LOCATION`, which a reader needs for scan results; from
  Android 12, `BLUETOOTH_ADVERTISE`, `BLUETOOTH_CONNECT` and
  `BLUETOOTH_SCAN` with `neverForLocation`). Request
  `ProximityPermissions.holder` (or `.holder(modes)`) or `.reader`
  before starting a session; without them it throws
  `ProximityException` (`PermissionMissing`). A holder in central
  client mode scans, so it needs `BLUETOOTH_SCAN` (location up to
  Android 11) as a reader does.
- **Keep the app in the foreground** during a session: neither library
  declares Bluetooth background modes or keeps a session through the
  app being suspended.
- **Not supported:** the L2CAP transport, NFC on iOS, and more than
  one request per session.

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

Both AAR builds explicitly link with 16 KB ELF page alignment, including
when using an older NDK. Apps must also package native libraries with
16 KB ZIP alignment (AGP 8.5.1 or later). Check the final APK with
`zipalign -c -P 16 4 app.apk` and inspect every arm64-v8a/x86_64 library's
LOAD segments with the NDK's `llvm-objdump -p`: alignment must be at least
`2**14`. See Android's [16 KB page-size guide](https://developer.android.com/guide/practices/page-sizes).
This preserves the gomobile ABI and the demo app's reader configuration
and trust policy.

## Publishing the Kotlin library

App developers take `oid4vcwallet-<version>.aar` from a release of
[OID4VCgo-wallet-kotlin](https://github.com/IDFoundry/OID4VCgo-wallet-kotlin),
into their app module's `libs/`, with the libraries it uses (its POM's
dependencies), at the versions that repository's README lists:

```kotlin
dependencies {
    implementation(files("libs/oid4vcwallet-<version>.aar"))
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:…")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:…")
    implementation("androidx.annotation:annotation:…")
    implementation("androidx.credentials:credentials:…")
    implementation("androidx.credentials.registry:registry-provider:…")
    implementation("androidx.credentials.registry:registry-provider-play-services:…")
    implementation("androidx.credentials.registry:registry-digitalcredentials-openid:…")
    implementation("androidx.credentials.registry:registry-digitalcredentials-mdoc:…")
    implementation("androidx.credentials.registry:registry-digitalcredentials-sdjwtvc:…")
}
```

To publish a version, run the `wallet-kotlin-release` workflow, with
the version: the Swift package's. The workflow runs only from `main`
and publishes `main`'s head, so a Kotlin release goes with a Swift
release from the same commit. It runs `android/package-kotlin-release.sh`, which:
1. builds the release AAR, and the library's AAR and sources jar
2. builds an app on the AAR as the README says: the file, and the
   libraries the library's POM names
3. mirrors the sources into the package repository, and writes its
   README with those libraries

The workflow then commits the result there and creates the tagged
release, carrying the AAR, the sources jar, their `SHA256SUMS` and a
build provenance attestation, and checks that the published files are
the ones it built. It needs the `WALLET_KOTLIN_TOKEN` secret: a
fine-grained token with Contents read and write on
OID4VCgo-wallet-kotlin only, which only the publishing steps see. CI
runs the same script on every change, without publishing.

The library's API reference is built with Dokka
(`./gradlew :OID4VCWallet:dokkaGenerate`, into
`OID4VCWallet/build/dokka/html`), from its KDoc and
`OID4VCWallet/Module.md`, its front page. The guides are Markdown in
`android/docs/`, which the release copies into the package repository's
`docs/`. `android/check-docs.sh` builds the reference, failing on any
Dokka warning (an undocumented public declaration included), and
compiles each guide's `kotlin` code blocks against the library; CI runs
it. The release workflow publishes the reference to the package
repository's `gh-pages` branch, under the version and `latest/`
(`android/docs-site.sh` lays it out), and the README links the
version's. GitHub Pages serves it once the package repository's
settings (Pages) deploy from that branch.

The library is compiled for Kotlin 2.2 (language and API version, and
its standard library), so an app on AGP 9's own Kotlin can use it.

Versions and compatibility: the wrapper's release version, not the
gomobile ABI number, says what it carries. Optional JSON members are
added within an ABI (ABI.md), so two wrappers on ABI 15 can differ:
`requestInfo` on `ProximityPresentation.Request` is one such addition.
It also changed that public data class's constructor and generated
methods, so Kotlin code compiled against a release before it must be
rebuilt, though calls passing `reader` and `documents` compile as they
are; each release's notes say when a rebuild is needed.

## Publishing the Swift package

Integrators add the package from
[OID4VCgo-wallet-swift](https://github.com/IDFoundry/OID4VCgo-wallet-swift),
which SwiftPM can fetch:

```swift
.package(url: "https://github.com/IDFoundry/OID4VCgo-wallet-swift", from: "<version>")
```

To publish a version, run the `wallet-swift-release` workflow, with the
version (`1.2.3`, versioned apart from the Go module). The workflow runs
only from `main` and publishes `main`'s head. It runs
`ios/package-swift-release.sh`, which:
1. builds the release framework and zips it as the release asset
2. copies `ios/OID4VCWallet/Sources` across
3. builds the package against the zipped framework, for macOS and the
   iOS Simulator, with `ios/ReadmeExample.swift` as a target of its own
4. writes a `Package.swift` naming the asset by URL and checksum, and
   the README, whose example is `ios/ReadmeExample.swift`: edit the
   README there, not in the package repository

The workflow then commits the result there and creates the tagged
release, carrying the framework, its `SHA256SUMS` and a build
provenance attestation, and checks that the published framework is the
one it built. It needs the `WALLET_SWIFT_TOKEN` secret: a fine-grained
token with Contents read and write on OID4VCgo-wallet-swift only, which
only the publishing steps see. CI runs the same script on every change,
without publishing.

The package's documentation is a DocC catalog,
`ios/OID4VCWallet/Sources/OID4VCWallet/OID4VCWallet.docc`, so it ships
with the sources. `ios/check-docs.sh` builds it, failing on any DocC
warning, and compiles each article's `swift` code blocks against the
package; CI runs it. The release workflow then publishes the
documentation to the package repository's `gh-pages` branch, under the
version and `latest/` (`ios/docs-site.sh` lays it out), and the
generated README links the version's. GitHub Pages serves it once the
package repository's settings (Pages) deploy from that branch.
If publishing the documentation fails after the release is made, run
the workflow again from `main` with the same version and
`documentation_only`: it builds and publishes only the latest
release's documentation, from the commit that release was built from.

Both release workflows run only from `main`, in the `mobile-release`
environment. In the repository's settings (Environments →
mobile-release), give it required reviewers, limit its deployment
branches to `main`, and keep `WALLET_SWIFT_TOKEN` and
`WALLET_KOTLIN_TOKEN` as its secrets rather than the repository's, so a
release waits for approval and no other workflow can read the tokens.

## Go tests

The Go package's own tests run anywhere: `go test -tags mobiletest ./...`
for the end-to-end session tests too.
