# OID4VCgo Mobile — design

Status: **iOS done; Android built, with checks on a device open
(Phase 8, [#461](https://github.com/IDFoundry/OID4VCgo/issues/461));
the DC API done on both (Phase 9); proximity in both SDKs, with the
demos and iPhone ↔ Android runs to come (Phase 10, [#482](https://github.com/IDFoundry/OID4VCgo/issues/482)).**
Phases 0 to 7 are done: the SDK is published as the OID4VCWallet Swift
package, and the demo app has issued and presented on a device, against
the passport-vdc demo through a tunnel, and presented to Safari as a
document provider. The Android library, the Android demo and the
Kotlin library's release are built; the Kotlin library has no release
yet. Later work is recorded after Phase 7. This is
the design for a mobile wallet SDK built on OID4VCgo, delivered in the
phases below. It records the decisions taken so far, what each phase
found, and the questions still open; update it as phases land.

## Goal

A cross-platform wallet SDK, compiled with `gomobile bind` into an iOS
XCFramework and an Android AAR, covering the wallet's side of the
credential lifecycle:

- **Issuance:** Credential Offer → OID4VCI 1.0 / HAIP 1.0 → Credential →
  wallet storage.
- **Presentation:** Authorization Request → OID4VP 1.0 / HAIP 1.0 → the
  holder's approval → Authorization Response.
- **Digital Credentials API:** a browser's request through the same
  presentation engine: `org-iso-mdoc` from Safari on iOS, OpenID4VP
  from Chrome through Credential Manager on Android.
- **In person:** ISO/IEC 18013-5 over BLE, as the holder or the
  reader.

One principle governs the split: **Go owns the protocols and the
wallet's orchestration; the native app owns platform capabilities and
user interaction.** Go decides what an issuer or verifier is asking for
and builds the protocol messages; the app decides whether the holder
agrees, and holds the keys.

## Layers

```
┌──────────────────────────────────────────────────────────────┐
│ iOS app (Swift)                                              │
│ UI, consent, Face ID / Touch ID, Secure Enclave, Keychain,   │
│ ASWebAuthenticationSession, Universal Links, app lifecycle   │
└──────────────────────────────┬───────────────────────────────┘
                gomobile ABI: primitives, []byte, JSON, small
                callback interfaces — versioned
┌──────────────────────────────▼───────────────────────────────┐
│ mobile/  (separate Go module)                                │
│ Thin façade: JSON in/out, callback adapters, error codes     │
└──────────────────────────────┬───────────────────────────────┘
                      native Go API
┌──────────────────────────────▼───────────────────────────────┐
│ walletflow  (new package in this module)                     │
│ Session-oriented wallet orchestration: issuance and          │
│ presentation sessions; interfaces for keys, credential       │
│ storage, the Wallet Provider and HTTP                        │
└──────────────────────────────┬───────────────────────────────┘
┌──────────────────────────────▼───────────────────────────────┐
│ OID4VCgo core (wallet, credential, dcql, oid4vpmdoc, …) and  │
│ FAPIgo (client: PAR, PKCE, DPoP, Wallet Attestation)         │
└──────────────────────────────────────────────────────────────┘
```

- **`walletflow`** is pure Go and fully testable end to end against
  this repo's own issuer and verifier. It starts as the orchestration
  `examples/passport-vdc/walletapp` already proves (offer resolution,
  PAR, the pre-authorized code with a PIN, deferred polling,
  notifications, received-credential checks, DCQL matching,
  presentation), generalised behind interfaces, and the demo wallets
  move onto it so it stays exercised.
- **`mobile/`** is its own Go module, like `examples/`, so
  `golang.org/x/mobile` never enters this module's `go.mod`, and its
  ABI is versioned separately. It translates between JSON/primitives and
  `walletflow`'s Go types and holds no protocol logic. It's excluded
  from this module's release-please package.
- **`mobile/ios`** holds the Swift package wrapping the XCFramework, and
  a demo app.
- **`mobile/android`** holds the Kotlin library wrapping the AAR, and
  a demo app.

## The gomobile boundary

The ABI is a public, versioned API of its own, deliberately narrow:

- **Types:** `string`, `bool`, integers, `[]byte`, a few exported
  objects, and small callback interfaces the app implements. No maps,
  slices of structs, generics, `context`, channels or Go-specific error
  types.
- **Rich data is JSON**, in a versioned envelope, so the boundary stays
  stable as `walletflow` evolves.
- **Errors** cross as a stable code plus a message (and, where useful,
  the protocol error code an issuer or verifier returned), never as Go
  error types.
- **Calls block.** Swift calls Go from background tasks, never the main
  thread. Go's callbacks into Swift (to sign, or to read the store) run
  on that same background thread, so a Face ID prompt during `Sign`
  simply blocks the goroutine waiting for it.
- **Cancellation** is explicit: each session has `Cancel()`, since no
  `context` crosses the boundary.

## Sessions

Flows are multi-step and wait on the holder, so both are sessions the
app advances:

```
Wallet
 ├── StartIssuance(offer) → IssuanceSession
 │      Offer()                 what's offered, by whom
 │      Next()                  NeedsAuthorization(url) | NeedsPIN(tx_code) | Done
 │      Authorized(callback) / SubmitPIN(pin)
 │      Result()                received credentials, and any deferred ones
 │      Cancel()
 └── StartPresentation(request) → PresentationSession
        Request()               verifier, purpose, what's asked
        Queries()               each query, its matching credentials, credential sets
        Preview(selection)      what the app's chosen selection would disclose
        Respond(selection) / Decline()
        Result()                sent, and where to send the browser
        Cancel()
```

- **Authorization** goes through the issuer's pages: the session hands
  the app an authorization URL, and the app returns the redirect it
  collects (`ASWebAuthenticationSession` or a Universal Link).
- **Suspension:** an authorization in progress is kept in the wallet's
  `AuthorizationStore`, which backs FAPIgo's client `SessionStore`, so
  the redirect can complete it after the app is killed
  (`ResumeIssuance`; see Phase 7 below).

Presentation is protocol-neutral inside `walletflow`: an adapter turns an
OID4VP request (`wallet.ParseAuthorizationRequest`) or a DC API request
(`wallet.ParseDCAPIRequestData`, which yields the same
`AuthorizationRequest` with `Origin` set) into one presentation request:
DCQL query, nonce, audience (client_id or origin) and response
encryption key.

## Platform keys

Every wallet-side signing operation in OID4VCgo already takes a
`crypto.Signer`, and passes it a SHA-256 digest expecting a DER ECDSA
signature back — exactly what the Secure Enclave's
`ecdsaSignatureDigestX962SHA256` returns. So a platform key is a Go
`crypto.Signer` whose `Sign` calls Swift: the private key never crosses
the boundary. FAPIgo's client signs DPoP proofs and Wallet Attestation
PoPs through `keys.KeyManager`; the mobile layer provides one backed by
the same bridge.

The bridge (conceptually):

```
PlatformKeys (implemented in Swift)
  NewKey(purpose, requireUserPresence) → key ID, public key (JWK)
  PublicKey(keyID)                     → JWK
  Sign(keyID, digest)                  → DER signature
  Delete(keyID)
```

### Key inventory

| Key | Lifetime | Owner | User authentication |
|---|---|---|---|
| Wallet instance key: the Wallet Attestation's `cnf`, signs PoPs at PAR and the token endpoint | per issuance | Secure Enclave | none |
| DPoP key | per issuance | Secure Enclave | none |
| Holder binding keys: a credential's `cnf` / mdoc `DeviceKey`, signing the Key Binding JWT or DeviceAuth when presenting | per credential copy | Secure Enclave | when presenting |
| Credential response decryption key | per request | Go, ephemeral | — |
| OID4VP response encryption (ECDH-ES to the verifier) | per response | Go, ephemeral | — |
| Verification, hashing, JOSE/COSE, DCQL, mdoc transcripts | — | Go | — |

The instance key, with its Wallet Attestation, and the DPoP key are new
for each issuance and deleted when it ends, so issuers can't link one
holder's issuances by them. The exception is a DPoP key that a pending
deferred credential polls with: it's kept until the last such credential
from its issuance is settled. Holder keys need biometrics only when presenting, never at
issuance: a batch of credentials means a batch of keys, and prompting
for each would be unusable.

### Attestations

HAIP needs two attestations from a **Wallet Provider** backend, neither
of which the wallet can produce itself:

- a **Wallet Attestation** over the instance key (§4.4.1), authenticating
  the wallet at PAR and the token endpoint;
- **Key Attestations** over holder keys (§4.5.1), proving at the
  Credential Endpoint that they live in secure hardware.

A real Wallet Provider attests only after checking platform evidence
(App Attest on iOS, Key Attestation on Android). During development the
SDK uses the passport-vdc demo's Wallet Provider service, which attests
any key; platform evidence is a later phase.

## Credential storage

A credential store the app implements, from the first release:

```
CredentialStore (implemented in Swift)
  Put(id, credential, metadataJSON)
  Get(id) / List() / Delete(id)
```

Credentials carry personal data, so on iOS they belong under Data
Protection or the Keychain, which only the app can apply. Each stored
credential records its holder key's ID; the key itself stays in the
Secure Enclave.

## Networking

Go makes the HTTPS calls (PAR, token, nonce, Credential and Deferred
Credential Endpoints, request URIs, responses), so protocol state stays
together. It sits behind `walletflow`'s HTTP interface, so a native
transport can replace it if iOS needs one. Go on iOS verifies TLS with
the platform's verifier, against the system trust store (confirmed in
the Phase 1 spike: expired, self-signed and untrusted-root certificates
are refused with Security framework errors). Still to check: behaviour
with proxies and VPNs. App Transport Security doesn't apply to Go's
networking.

## Phases

| # | Phase | Exit criteria |
|---|---|---|
| 0 ✓ | `walletflow` | Issuance and presentation sessions behind key, store, Wallet Provider and HTTP interfaces; the passport-vdc wallets run on it; their end-to-end tests pass |
| 1 ✓ | gomobile spike | An XCFramework; Swift calls Go and Go calls back into Swift; a JSON envelope; errors and cancellation across the boundary |
| 2 ✓ | Secure Enclave spike | A Swift-generated key signs an ES256 JWS through Go's `crypto.Signer`, verified by OID4VCgo; a platform `KeyManager` for FAPIgo |
| 3 ✓ | ABI foundation | Versioned JSON envelope, error codes and session lifecycle, documented |
| 4 ✓ | OID4VCI slice | HAIP issuance from the iOS demo app against the passport-vdc issuer, with Key Attestations from the Wallet Provider |
| 5 ✓ | Storage | The native credential store, with key references |
| 6 ✓ | OID4VP slice | Request parsing, candidates, consent and presentation from the iOS demo app |
| 7 ✓ | Hardening | Suspension and resumption (deferred credentials, an authorization in progress), cancellation, network failures, issuer and verifier errors, logging without personal data, the demo app's retry and cancel |
| 8 ✓ | Android | The same bridge over Android Keystore, packaged as an AAR, with the demo app and the DC API (below); checks on a device are open items |
| 9 ✓ | DC API | A DC API adapter over the presentation engine: `org-iso-mdoc` (MdocPresentation, iOS) and OpenID4VP (`StartDCAPIPresentation`, for Android's Credential Manager) |
| 10 | Proximity | ISO/IEC 18013-5 device retrieval over BLE in both SDKs: the holder shows a QR code and answers a reader; a reader mode in both demo apps; iPhone ↔ Android in both directions. The SDKs are done; the demos and the runs between devices aren't |

### Phase 1 findings

The spike is `mobile/` (the Go package) and `mobile/ios/OID4VCWallet`
(a Swift package wrapping the XCFramework, Swift 6 language mode), built
by `mobile/build-xcframework.sh` and tested by CI on Linux (Go) and
macOS (Swift, against the framework's macOS slice); the same Swift tests
pass on the iOS Simulator.

- **Build:** `gomobile bind -target=ios,iossimulator,macos` makes the
  XCFramework in under a minute; gomobile and gobind are pinned as
  `go.mod` tool directives. Stripped (`-ldflags=-s -w`), the iOS device
  slice is 8.4 MB. The macOS slice's minimum OS comes from
  `MACOSX_DEPLOYMENT_TARGET`, the iOS one from `-iosversion`.
- **Names:** package `mobile` becomes `Mobile…` in Swift. A Go interface
  becomes an Objective-C protocol and class of the same name, so Swift
  sees the protocol as `MobileSignerProtocol`; the Swift package wraps
  everything behind its own names (`OID4VC`, `WalletError`,
  `PlatformSigner`).
- **Calls into Go** return their error through an `NSError`
  out-parameter, which Swift sees as `throws`. Only the error's text
  crosses, so codes travel in it ("[code] message") and the wrapper
  parses them into `WalletError.Code`.
- **Callbacks into Swift:** a Swift class implementing a Go interface is
  called from the Go goroutine's thread; a Swift error it throws reaches
  Go as an `error` carrying the Swift message. A Security framework key
  signing with `.ecdsaSignatureDigestX962SHA256` returns the DER that
  Go's `crypto.Signer` contract expects, so `wallet.GenerateDPoPProof`
  signs with a Swift-held key unchanged; the same call works for a
  Secure Enclave key.
- **Threads:** the wrapper runs each Go call on a global dispatch queue,
  never the caller's; 64 concurrent calls, each calling back into Swift,
  work.
- **Cancellation:** an `Operation` made before the call and passed in;
  Swift Task cancellation calls its `cancel()` through
  `withTaskCancellationHandler`, and the blocked Go call returns a
  `cancelled` error. A timeout works the same way.

### Phase 2 findings

The app implements `KeyStore` (create a key for a purpose, return its
public key, sign a digest, delete it), which the `mobile` package turns
into a `walletflow.KeyStore`; the private keys stay in the app.
`KeychainKeyStore` is the Swift implementation, and `CheckKeyStore`
exercises any implementation as the wallet will: for each purpose, a
DPoP proof (`wallet.GenerateDPoPProof`) and a FAPIgo signing request
(`keys.NewKeyManagerFromSigners`, as walletflow's OAuth client signs),
each signature checked, then lookup and deletion.

- **Where it's proven:** Secure Enclave keys on the iOS Simulator (which
  simulates the enclave); Keychain-persisted keys, found again by a new
  store and deleted, on macOS. Neither environment does both: hostless
  Simulator tests have no Keychain (`-34018`, a missing entitlement),
  and a command-line macOS session can't create enclave keys. Persisted
  enclave keys, and the user-presence prompt for holder keys, need a
  signed app on a device: the Phase 4 demo app.
- **Access control:** enclave keys carry `.privateKeyUsage`, holder keys
  `.userPresence` too (`Options.holderUserPresence`), all
  `WhenUnlockedThisDeviceOnly`. On macOS an access control moves a key
  into the data protection keychain, so a key that needs none carries
  none.
- **gomobile and errors in callbacks:** a callback returning `[]byte`
  or only an `error` is a throwing Swift method; one returning a
  `string` is not — its Objective-C form returns a non-null `NSString`,
  which Swift won't import as `throws` — so the app reports failure
  through the `NSError` pointer (`KeychainKeyStore.createKey`). Prefer
  `[]byte` or no result for callbacks that can fail.
- **Naming:** a Go method named `New…` becomes an Objective-C `new…`
  selector, which ARC treats as returning an owned object; the key
  store's method is `CreateKey`.

### Phase 3 findings

The ABI is documented in [mobile/ABI.md](ABI.md) (version 1):
`NewWallet` with a JSON configuration and the app's `KeyStore`,
`CredentialStore` and `WalletProvider`; the issuance and presentation
sessions, each network step taking an `Operation`; eleven error codes.
The Swift package wraps it as `Wallet`, `Issuance` and `Presentation`
with Codable results, async calls and `WalletError`.

- **End to end through the boundary:** `walletflow/walletflowtest` (the
  in-process HAIP issuer, Wallet Provider and Verifier, now public) is
  in a framework built with `-tags mobiletest` as `TestEnv`, so the Swift
  tests run issuance (both grants, deferred approval and denial) and
  presentation (candidates, preview, respond, decline) against a real
  issuer and Verifier, with Go calling back into the Swift key store,
  credential store and Wallet Provider. On the iOS Simulator those runs
  use Secure Enclave keys. A shipped framework is built without the tag.
- **Which gomobile methods throw in Swift:** a method returning an
  object (`StartIssuance`), `[]byte` or nothing is a throwing Swift
  method; one returning a string takes an `NSError` out-parameter, and
  the wrapper turns that into a throw. The generated `MobileWallet`
  initializer drops the error, so the wrapper calls `MobileNewWallet`.
- **Swift 6 concurrency:** the generated session objects are declared
  `@unchecked Sendable`, which they are: gomobile references are
  thread-safe, and walletflow sessions serialize their own steps.
  Four concurrent issuances, each calling back into Swift, work.
- **Still open:** the app's `WalletProvider` callback runs on Go's
  thread, so it may block on its backend; an async provider would need
  the call split in two. Credential claims for display, and session
  persistence across app suspension, belong to Phases 5 and 7.

### Phase 4 findings

`mobile/ios/DemoWallet` is the demo wallet app: SwiftUI, its project
generated by XcodeGen. It opens `openid-credential-offer://` links, uses
Secure Enclave keys in the Keychain, gets Wallet and Key Attestations
from a Wallet Provider over HTTPS (the passport-vdc demo's API), and
keeps credentials in a data-protected file store.

- **Both grants, end to end in the app on the Simulator,** driven by a UI
  test against `mobile/cmd/testservices`. That command serves
  walletflowtest's issuer and Verifier and a Wallet Provider over HTTPS,
  and the Simulator is made to trust its certificate.
  - Authorization code: PAR, the issuer's page in an ephemeral
    `ASWebAuthenticationSession` (no "wants to sign in" prompt), the
    redirect back to the app, a DPoP-bound token, two credentials.
  - Pre-authorized code: the PIN typed in the app.

  `run-passport-vdc.sh` runs the app against the passport-vdc demo.
- **Native-app redirect URIs:** the app's redirect is a private-use
  scheme (RFC 8252 §7.1). fapigo/server accepted only `https`, and
  loopback `http` in development, though FAPI 2.0 forbids only
  non-loopback `http`. Raised with FAPIgo, which added
  `storage.ApplicationTypeNative`: a client registered as native may use
  private-use scheme and loopback redirects, in production too. The
  wallet registrations in walletflowtest and the passport-vdc demo are
  native.
- **Simulator limits:** it can't create a Secure Enclave key requiring
  user presence (OSStatus -25293), so the app requires it of holder keys
  only on a device. Persisted enclave keys work there, in an app.
- **On a device** (first run 2026-10-04, against the passport-vdc demo
  through a tunnel, `run-device.sh`): receiving and presenting work, with
  Secure Enclave holder keys requiring user presence. Face ID needs the
  app's `NSFaceIDUsageDescription`: without it, iOS asks for the
  passcode instead.
- **SwiftUI and XCUITest:** the offer sheet must not treat its dismissal
  as cancelling a receive in progress, because the authorization session
  presents over it. A `Section`'s accessibility identifier overrides its
  rows'.

### Phase 5 findings

- **The native store:** `FileCredentialStore` in the Swift package keeps
  one file per credential record, written with complete data protection
  (readable only while the device is unlocked). The store's directory is
  excluded from backups: a credential is useless without its holder key,
  which stays in this device's Secure Enclave. Both settings are
  options. Records are opaque JSON the app needn't read. IDs are checked
  before they name a file.
- **Key references:** each record names its holder key. A credential
  summary says whether the key store still holds it
  (`holder_key_present`), so an app can flag credentials it can no
  longer present, such as ones restored without their keys.
- **Claims for display:** walletflow keeps the claims it checked on
  receipt (`StoredCredential.Claims`), and `Wallet.Credential(id)`
  returns them. An mdoc's decoded CBOR is made JSON-safe: byte strings
  in base64, dates as their text. The demo app shows them.
- **Encryption at rest beyond data protection** isn't needed on iOS: the
  file protection class does it, keyed to the passcode. An Android store
  (Phase 8) needs its own answer.

### Phase 6 progress

The demo app presents. For an `openid4vp://` request it shows the
Verifier, the credentials that can answer each of its queries (the
first preselected), and exactly which claims sharing them discloses,
previewed as the holder changes the selection. Then it shares them, or
declines. When the Verifier returns a redirect, the app opens it.

- **On the Simulator, end to end:** the UI tests have a received SD-JWT
  VC shared in answer to the test Verifier's request, which then holds
  `family_name`, and an unanswerable request declined, which the
  Verifier records as `access_denied`. The holder key signs in the
  Secure Enclave.
- **Still on a device:** the Face ID or passcode prompt when holder keys
  sign. The Simulator can't make a holder key that requires it.
  Reaching the passport-vdc demo from a phone needs it served on a
  public URL: its services listen on loopback only, its certificate names
  loopback only, and the wallet's fetcher refuses private-network
  addresses.
- **Deferred credentials:** the app polls a deferred credential at the
  issuer's interval, with a Check again button. Since Phase 7 the wallet
  keeps it, so it survives the app quitting (below).
- **XCUITest:** opening a custom-scheme link from a test asks for
  confirmation, so the tests launch the app with the link instead.
- **QR codes and portraits:** the app scans QR codes live with
  VisionKit's `DataScannerViewController` where the device supports it,
  and from a photo or screenshot anywhere. It decodes those with Core
  Image's detector: Vision's barcode detector can't run on an Intel Mac's
  Simulator. Image claims (an SD-JWT VC's `picture` data URL, an mdoc's
  `portrait` bytes) show as images.

### Swift SDK shape (after the 2026-10-03 review)

- **Idiomatic callbacks:** an app implements the package's own
  `KeyStore`, `CredentialStore` and `WalletProvider` protocols: throwing,
  non-optional, with a `KeyPurpose` enum and nil for "none". Internal
  adapters bridge them to gomobile's Objective-C protocols, so the
  `NSError`-pointer special case for string results is gone from the
  app's view.
- **An async Wallet Provider:** `WalletProvider` is `async`. Go calls
  it on its own thread and waits, and the adapter bridges the two. That's
  safe because no Go call is made on the main thread.
- **Structured errors (ABI version 2):** errors carry the remote party's
  OAuth code, `[protocol:invalid_grant]` for a wrong PIN, checked to be a
  plain token. `WalletError` adds `protocolError`, `isRetryable` (network
  failures, a wrong PIN, `temporarily_unavailable`, `slow_down`) and a
  user-facing `localizedDescription`. A malformed result from Go is a
  `WalletError` too.
- **Separate test build:** `build/test/` (with `TestEnv`) and
  `build/release/` are built apart. The package links the test build
  only with `OID4VC_TEST_FRAMEWORK=1`, and `OID4VC.isTestBuild` lets an
  app refuse it.
- **Orphaned keys:** `KeychainKeyStore` labels each key with its purpose
  and can list and sweep the keys under its tag prefix.
  `Wallet.sweepOrphanedKeys(in:)`, at launch, keeps the keys the
  credentials are bound to (`HolderKeyIDs`) and deletes the rest. An
  `Issuance` dropped without `close()` closes itself.
- **Distribution:** the Swift module is `OID4VCWallet`, since it's
  the wallet side. The reader's side of in-person presentation
  (`ProximityReader`, Phase 10) later joined it, so an app can be
  either. SwiftPM fetches a package only from a `Package.swift` at the
  root of a git repository, so integrators get it from
  [OID4VCgo-wallet-swift](https://github.com/IDFoundry/OID4VCgo-wallet-swift).
  That repository is publish-only. Development, the tests (which need
  the test build of the same commit's Go code) and the demo app stay
  here. `wallet-swift-release.yml` publishes a version: it builds the
  release framework, attaches it to the release as
  `Mobile.xcframework.zip`, and commits the sources and a
  `Package.swift` naming that asset by URL and checksum
  (`binaryTarget(url:checksum:)`). The Swift package's versions are
  its own, apart from the Go module's.

## Decisions

Taken 2026-10-02:

1. **Layout:** `walletflow` in this module; `mobile/` a separate Go
   module; `mobile/ios` for the Swift package and demo app.
2. **DPoP key:** held in the Secure Enclave, like the instance key;
   both are per issuance.
3. **Storage:** the app's native credential store from the first
   release.
4. **Wallet Provider:** the passport-vdc demo service during
   development; platform-evidence attestation later.
5. **This document** lives in the repository, next to `ARCHITECTURE.md`.

### Phase 7: deferred credentials survive the app quitting

Polling a deferred credential needs the issuance's access token and the
DPoP key that token is bound to, and nothing else from the issuance. So
that state is what's persisted:

- **Format:** walletflow's `PendingDeferred`, with the ID, the
  credential issuer, the configuration, the transaction ID, the access
  token and its expiry when known, the DPoP and holder key IDs, the
  interval, and when it was deferred. A `DeferredStore` keeps them, and
  `walletflow.Dependencies.Deferred` defaults to one in memory.
- **Where:** on mobile, in the app's own `CredentialStore`, as a record
  marked `"kind": "deferred"` under the ID `deferred-<id>`. It's under
  the same data protection as the credentials (complete protection,
  excluded from backups, with `FileCredentialStore`), and an app
  implements no new protocol. The access token is bound to a DPoP key
  that never leaves the Secure Enclave, so a copy of the record alone
  can't poll.
- **Lifecycle:**
  - `RequestCredentials` stores each deferred credential.
  - `Issuance.Close` keeps the DPoP key while a pending credential
    polls with it.
  - `Wallet.Deferred` lists the pending ones after a relaunch, making
    no network calls. The first poll fetches the issuer's metadata
    again and makes fresh encryption keys.
  - A credential that's issued, denied, refused by the wallet's checks,
    or abandoned (`AbandonDeferred`) leaves the store, with its keys.
  - The launch key sweep keeps a pending credential's keys
    (`KeysInUse`).
- **Limits:**
  - An access token that has expired can't poll. The wallet reports
    the expiry when the issuer gave one, and the credential can then
    only be abandoned. Refresh tokens would lift this, if an issuer
    gives them.

### Phase 7: an authorization survives the app being killed

If iOS kills the app while the holder is at the issuer's pages, the
in-memory issuance goes with it. A redirect that reaches the relaunched
app could then complete nothing. This happens when the flow leaves the
authentication session, through an eID or banking app, say.

- **FAPIgo's extension point:** FAPIgo has no sealed sessions. Its
  client keeps an authorization's state (the PKCE verifier, nonce,
  issuer and redirect URI) in a `SessionStore` the caller provides,
  keyed by the `state` parameter. walletflow implements that store over
  its own `AuthorizationStore`. Each record also holds what rebuilding
  the issuance needs: the resolved offer, the authorization server, and
  the instance and DPoP key IDs.
- **Where:** on mobile, it's the app's `CredentialStore` again: a
  `"kind": "authorization"` record under `authorization-<SHA-256 of
  state>`. The PKCE verifier is no use without the DPoP key the code is
  bound to and the instance key the client authenticates with, both in
  the Secure Enclave.
- **Resuming:** `Wallet.ResumeIssuance(redirect)` finds the record by
  the redirect's `state`. It fetches the issuer's metadata again, loads
  the same keys, gets a fresh Wallet Attestation, and completes the
  authorization. A record is consumed once, under a lock, and expires
  with the session: 5 minutes, about what the issuer allows on its
  side. A redirect that matches nothing, is replayed or has expired is
  `not_found`. The launch key sweep keeps an
  unexpired authorization's keys and forgets expired ones.
- **No session handle needed:** the client a resumed issuance builds
  sets FAPIgo's `Config.CallbackBinding` to
  `CallbackBindingDeviceLocalStore`, so FAPIgo takes the session from
  the callback itself (from the verified signed response, under Message
  Signing). Resuming doesn't depend on the handle being the `state`.
  Every other issuance holds its handle and keeps the default binding.
  RFC 9700 §4.7's binding of the session to the user agent holds by
  construction: nothing else writes the app's store, so an attacker's
  session is never in it. walletflow finds its own record by the
  redirect's `state` query parameter, which is enough since it doesn't
  use Message Signing.
- **Production assurance:** FAPIgo's production checks need this store
  to be durable. walletflow at production assurance also needs a
  KeyStore that declares durable custody, and `crypto/rand.Reader`
  itself. Until this change, an issuance couldn't build its OAuth client
  without `development`. The app's stores declare durability
  (`isDurable`): `KeychainKeyStore` when persistent, and
  `FileCredentialStore`.
- **Not covered:** an app killed after the token response and before
  the credential request loses the access token.

### Phase 7: errors fit for logs

The wallet logs nothing itself: there's no logging in walletflow, the
wallet package, the mobile layer, the Swift package or FAPIgo's client.
What reaches an app's logs is the errors it gets. Every error crossing
the gomobile boundary is cleaned in one place, `classify`:

- **Remote text:** a remote party's own text (`error_description`, a
  FAPIgo error built from a whole error body) is replaced by fixed text
  naming who refused, with the HTTP status. The OAuth error code, checked
  to be a plain token, is the `detail`.
- **URLs:** network errors drop their URL, which can carry a
  `request_uri`, a pre-authorized code or a `response_code`. Any other
  URL in a message is cut to its scheme and host.
- **Control characters and length:** control characters become spaces,
  so a message can't forge log lines, and it's capped at 300
  characters.
- **Timeouts:** they're `network` (retryable), no longer `cancelled`.
  HTTP 5xx and 429 are `unavailable`, retryable later, and
  `invalid_nonce` is retryable too.
- **Swift:** a decoding failure names only the coding path, never the
  decoder's text, which can quote a value.

The credential's claims, the PIN, tokens and codes were never in an
error message.

### Phase 7: cancellation, failures and retries

Each step either can be retried safely, or says it can't:

- **Authorization:** the redirect is used up once its `state` matches,
  whatever fails after it, the token request say. The issuance then
  goes back to `BeginAuthorization`, with the same keys, rather than
  getting stuck.
- **Credentials:** one credential the issuer refuses for good (an HTTP
  4xx other than a stale nonce, token or DPoP proof), or that fails the
  wallet's checks, is reported in `failed` and doesn't block the rest. A
  retry requests only what's still outstanding.
- **Deferred credentials:** a credential the issuer has handed over is
  kept until the wallet has stored it. If storing fails, the next poll
  stores it without asking the issuer again, which wouldn't hand it over
  twice.
- **Presentation:**
  - A Respond that failed in transit, or got a Verifier's server error,
    may have arrived. It's `delivery_unknown` and isn't sent again,
    since a second response with the same nonce could present twice.
  - A Decline that failed in transit is sent again, as is.
- **Cancellation:**
  - It reaches every HTTP request, through the Operation's context. A
    Wallet Provider callback still waiting on the network no longer
    holds up a cancelled call.
  - Clean-up (deleting a key, settling a deferred credential) runs even
    when the call was cancelled.
  - A provider's `URLError` is a network failure, not a platform one.

The demo app shows the pattern:
- A failure `isRetryable` says may pass (the network, a wrong PIN)
  keeps the offer open with the error and a Try again button. A retry
  after the token only requests the credentials.
- Cancel cancels the receive in progress, then closes the issuance.
- Closing the issuer's page leaves the offer as it was.
- A deferred credential whose poll fails retryably keeps being polled,
  less often.
- Anything deferred before a failure is picked up at once.

The protocol can't make some steps idempotent. A lost token or
credential response leaves the issuer to decide whether a retry is
refused (`invalid_grant`) or issues again.

### After Phase 7: display, expiry and status

What a wallet's UI needs to show a credential, from the SDK:

- **Display metadata** (OpenID4VCI 1.0 §12.2.4):
  - **What:** the issuer's name and logo, and each credential's name,
    description, logo and colours.
  - **Where:** in offers, and kept with each credential when it's
    received.
  - **Language:** chosen by the holder's `locales`: an exact match, then
    the same language, then the issuer's entry without a locale.
  - **Logos:** only an https URL or a `data:` image is passed on, since
    an `http`, `javascript:` or custom-scheme logo would be the app's
    to refuse. The app loads logos itself (`AsyncImage`); Go fetches
    none.
- **Expiry:** an SD-JWT VC's `exp`, or an mdoc's
  `validityInfo.validUntil`, is kept as `valid_until`.
- **Revocation status:**
  - Each credential's Token Status List reference is kept.
  - `CheckStatus` fetches the list, checks it's signed by a certificate
    chaining to the issuer roots, and records the status with the time
    it was checked.
  - One list covers many credentials, so fetching it doesn't tell the
    issuer which credential, or whose, was checked.
  - The demo app checks every credential at launch, quietly, and on
    demand from a credential's page. Its cards show the issuer's colours
    and logo, the expiry, and a revocation.

### Batch issuance and unlinkability

A credential presented twice is the same signature and the same key,
so two Verifiers, or one Verifier twice, can link the presentations. An
issuer offering batches (OID4VCI 1.0 `batch_credential_issuance`) issues
several copies with the same claims, each bound to its own key.
SD-JWT copies also have their own salts, and mdoc copies their own
MSOs.

- **Requesting a batch:**
  - The wallet asks for `Config.BatchSize` copies (5 by default, capped
    at the issuer's `batch_size`).
  - It creates one holder key per copy, and has the Wallet Provider
    attest them all in one Key Attestation. The issuer binds one copy to
    each key.
  - The wallet checks every copy and matches it to its key. One copy
    failing the checks fails the batch.
- **Storing it:** as one credential with `Copies`. The claims are kept
  once, and the first copy also fills the existing single-copy fields,
  so code that reads one credential is unchanged.
- **Presenting:** each presentation uses a copy no Verifier has seen,
  and marks it presented once sent, or once its delivery is unknown.
  When every copy has been presented, one is reused. The app can tell
  from `copies_left`, and the demo warns then.
- **Keys:** a deferred batch keeps every copy's key, deleting a
  credential deletes them all, and the launch sweep keeps them.
- **Not yet:** asking the issuer for fresh copies once they run out,
  which needs a refresh grant.
- **Configuration:** the passport-vdc issuer and the demo's test
  services issue batches of three. The passport-vdc browser and CLI
  wallets ask for one copy, because their file store holds one key per
  credential.

## Phase 8: Android

Decisions taken 2026-10-06 (tracked in [#461](https://github.com/IDFoundry/OID4VCgo/issues/461)):

1. **Layout:** `mobile/android` here: the Kotlin library `OID4VCWallet`,
   the demo app and their tests. [OID4VCgo-wallet-kotlin](https://github.com/IDFoundry/OID4VCgo-wallet-kotlin)
   is publish-only, as the Swift repository is.
2. **Distribution:** release artifacts of that repository — one AAR
   holding the Kotlin API and the Go library, and its sources jar —
   versioned as the Swift package, published from the same commit. No
   Maven repository for now.
3. **Scope:** parity with the Swift SDK and demo, and the DC API in the
   first release: OpenID4VP requests through a new ABI session (Phase
   9's adapter) and `org-iso-mdoc` ones through `MdocPresentation`. The
   Credential Manager integration lives in the demo app, as the iOS
   document provider does. Superseded for `org-iso-mdoc`: it stays
   iOS's route, and Android answers OpenID4VP only (see "the Digital
   Credentials API on Android" below).
4. **Platform:** minSdk 30, the first level where a key can require
   biometrics *or* the screen lock for each use, as holder keys do on
   iOS. Since lowered to minSdk 26, for apps that authenticate the
   holder themselves: per-use holder authentication still needs API 30
   (below it, a key store asking for it refuses to be made), and keys
   need the device unlocked from API 28 (see mobile/README.md's table). Keys are P-256 in StrongBox, or else the TEE; credentials are
   files encrypted under a key that needs the device unlocked, kept out
   of backups.
5. **API:** the Swift API's names and shapes, in Kotlin: suspend
   functions, a cancelled coroutine cancelling the Go `Operation`.

### Phase 8 findings: the gomobile spike

`mobile/build-aar.sh` builds the Go package into `mobile.aar`;
`mobile/android/OID4VCWallet` wraps it, and its instrumented tests run
on an emulator, in CI too (`mobile-android`).

- **Build:** `gomobile bind -target=android/arm64,android/amd64
  -androidapi=30` with NDK 30. Stripped, the release arm64 library is
  8.4 MB, as the iOS device slice is. Both libraries' segments are 16 KB
  aligned, as Google Play requires, by the NDK's default.
- **No 32-bit arm:** FAPIgo didn't build where `int` is 32 bits
  (`math.MaxUint32` overflowed `int` in its `internal/jwe`) until
  v0.51.0, which fixed it. The AAR still leaves 32-bit arm out: Play
  requires the 64-bit libraries, and a 32-bit one would only add size.
  iOS never had a 32-bit target.
- **One library:** the AAR's Java bindings are in
  `dev.idfoundry.oid4vcwallet.gomobile` (`-javapkg`), but gomobile's own
  runtime (`go.Seq`, `libgojni.so`) isn't renamed, so an app can hold
  only one gomobile library. The Kotlin library unpacks the AAR into its
  own, so app developers get one artifact.
- **Errors:** every gomobile method and callback throws on the JVM, with
  the Go error's text, so the `NSError` special case Swift has for
  `CreateKey` doesn't arise. A callback's exception comes back as
  `platform`, carrying its message.
- **Cancellation:** the coroutine's cancellation cancels the
  `Operation`, and the blocked Go call returns at once; Go's
  `cancelled` answer becomes the coroutine's `CancellationException`.
- **Threads:** 32 concurrent calls, each calling back into Kotlin on
  Go's thread, work.
- **TLS:** Go verifies certificates itself, against CA files: on
  Android, only `/system/etc/security/cacerts`, which Android 14 no
  longer updates ([golang/go#71258](https://github.com/golang/go/issues/71258)),
  and not Network Security Config or user CAs. And Go loaded as an app's
  library starts with an empty environment — its runtime is given no
  envp (`rt0_android_*.s`) — so the app can't set `SSL_CERT_DIR` for it.
  The `mobile` package does, on Android (`certdirs_android.go`): the
  Conscrypt APEX store, then the system one, before anything verifies a
  certificate. On an API 37 emulator, public sites verify and an expired
  certificate is refused.
- **Tests:** Go builds for Android only, so the library's tests are
  instrumented, on an emulator: there's no host slice like the
  XCFramework's macOS one for `swift test`.

### Phase 8 findings: the Android Keystore key store

`AndroidKeystoreKeyStore` is `KeychainKeyStore`'s counterpart, and
`CheckKeyStore` passes with it.

- **Keys:** P-256 in StrongBox where the device has it (`Options.strongBox`,
  preferred by default; required or off), else the TEE. They sign Go's
  SHA-256 digests with `NONEwithECDSA`, which returns the DER `crypto.Signer`
  expects. Every key needs the device unlocked
  (`setUnlockedDeviceRequired`), as iOS's `WhenUnlockedThisDeviceOnly`.
- **Holder keys:** each signature needs the holder's strong biometric or
  screen lock (`setUserAuthenticationParameters(0, …)`, API 30), and a new
  fingerprint doesn't void them, as iOS's user presence. Keystore
  authorizes one `Signature` at a time, so the store hands it to the app's
  `HolderAuthenticator` before signing, on Go's thread, which waits.
  `BiometricPromptAuthenticator` is the framework prompt over the app's
  activity: from API 30 it takes the screen lock with a CryptoObject, so
  the SDK needs no AndroidX biometric library. A signature the
  authenticator didn't authorize is refused by Keystore itself.
- **Instance and DPoP keys** sign silently, as on iOS.
- **IDs:** a key's ID is its alias after a prefix; the store lists and
  sweeps only its own prefix's keys (`deleteKeys(except:)`).
- **Locked means locked:** with the screen locked, every key's signature
  fails ("Keystore operation failed"), as `setUnlockedDeviceRequired`
  says — so CI unlocks the emulator with its PIN before the tests.
- **The emulator:** its Keystore is software, with no StrongBox; holder
  keys still require authentication there, given a PIN (CI sets one).
  StrongBox, the TEE and the prompt itself are for the device run.

### Phase 8 findings: the Kotlin sessions

`Wallet`, `Issuance`, `Presentation` and `MdocPresentation` are the
Swift package's, in Kotlin: suspend functions, results as data classes
(kotlinx.serialization), times as `java.time.Instant`, claims as
`JsonElement`. The Swift session tests pass on the emulator against
`TestEnv`, with Android Keystore keys: both grants, presentation and its
selection rules, deferred credentials across a relaunch, resuming an
authorization after the app was killed, status, batches, registrations,
refresh, the per-Verifier copy policy, cancellation and four concurrent
issuances.

- **A dropped issuance:** Swift's `Issuance` closes itself in `deinit`;
  Kotlin has none, and `java.lang.ref.Cleaner` needs API 33. An issuance
  dropped without `close()` keeps its instance and DPoP keys until
  `sweepOrphanedKeys` at the next launch.
- **Host tests:** what doesn't load Go — error parsing, the provider
  bridge, origins — runs on the host JVM (`testDebugUnitTest`).

### Phase 8 findings: the credential store

Phase 5 left Android's encryption at rest open: Android has no per-file
protection class like iOS's complete protection, only file-based
encryption, readable from the first unlock after a boot. So
`FileCredentialStore` encrypts each record itself:

- **Encryption:** AES-256-GCM under an Android Keystore key, the
  record's ID as associated data, so a record copied under another ID,
  or altered, doesn't decrypt. Its file is a version byte, the IV and
  the ciphertext.
- **Protection:** by default the key works only while the device is
  unlocked (`setUnlockedDeviceRequired`). On the emulator, with the
  screen locked, a record neither reads nor writes; unlocked, it does —
  iOS's complete protection. `Protection.AFTER_FIRST_UNLOCK` drops the
  requirement, for an app that must read credentials while locked: file
  encryption alone, iOS's "until first user authentication".
- **Backups:** the standard store is in `noBackupFilesDir`, which neither
  backups nor device transfer copy, as iOS's store is excluded from
  backups. A restored record without its key wouldn't decrypt anyway,
  and its holder key doesn't move either.
- **Writes** go to a temporary file renamed over the record, so a
  reader never sees half of one.

### Phase 8 findings: the demo app

`mobile/android/DemoWallet` is the iOS demo's counterpart, in Jetpack
Compose: receiving (both grants, deferred credentials, resuming after
the app was killed), the credential list and pages, presenting with the
consent screen and its preview, QR codes, copies, status and refresh.
On the emulator, against `mobile/cmd/testservices`
(`run-test-services.sh`), it has received an SD-JWT VC (three copies,
the PIN refused once and then accepted), and shared it: the system
prompt asked for the screen lock before the holder key signed, and the
Verifier received `family_name`.

- **Go's environment:** Go loaded as an app's library starts with none,
  so neither `SSL_CERT_DIR` (see above) nor a development CA can be
  handed to it through the process environment. The wallet
  configuration's `development_roots`, only with `development`, are CAs
  its HTTPS requests trust besides the system's: the test services' own.
  The app's own requests (the Wallet Provider's) trust it through a
  trust manager of its own.
- **The services' ports** reach the device through `adb reverse`, so
  their loopback certificate holds there.
- **The authorization page** opens in an Auth Tab, else an ephemeral
  Custom Tab; closing it leaves the offer open, as on iOS. Beginning the
  authorization again then needed walletflow to allow it (#467), on iOS
  too.
- **Chrome** doesn't trust the test services' CA, unlike Go and the
  app: the issuer's page shows a certificate warning. The UI tests need
  the CA in the device's user store, which Chrome trusts.
- **Permissions:** the library declares `USE_BIOMETRIC`, for its
  prompt; the demo `INTERNET` and `CAMERA`, and backs nothing up.

### Phase 8 findings: the Digital Credentials API on Android

The demo is a Credential Manager provider for OpenID4VP over the DC API
(`StartDCAPIPresentation`, the OpenID4VP half of Phase 9). On the API 37
emulator with Google Play, end to end: a page served by the test
services asked with a signed request; Chrome asked whether to trust the
site; Credential Manager's chooser offered the registered SD-JWT VC and
the claim asked for; the app's consent screen opened on it; the holder
key signed after the screen lock; and the test Verifier verified the
answer, bound to the page's origin.

- **Registration:** each presentable credential, with its claims, in an
  `OpenId4VpRegistry` (androidx.credentials registry, alpha), whose
  default matcher is Google's: the app writes no matcher. Registering
  again replaces the set, after every change to the credentials.
- **The origin** is Chrome's, which Credential Manager hands over only
  for a browser on the app's privileged list (Chrome's entries from
  Google's published list); an app calling directly is named by its
  signing certificate.
- **The provider activity** opens the wallet without the app's launch
  work: the orphaned-key sweep would take the keys of an issuance the app
  has in progress.
- **`org-iso-mdoc` isn't planned on Android:** Chrome's requests are
  answered over OpenID4VP, mdocs included; `org-iso-mdoc` stays iOS's
  route (#476). passport-vdc's page offers both (#474).

### Phase 8 findings: publishing

`wallet-kotlin-release.yml` publishes the library as release artifacts
of OID4VCgo-wallet-kotlin — the AAR and its sources jar — as
`wallet-swift-release.yml` publishes the Swift package, from the same
commit and with the same version. No Maven repository for now: an app
adds the AAR as a file, with the two libraries it uses, which the
README lists.

- **One file:** the AAR holds the Kotlin API, the Go bindings (`libs/`)
  and the Go library for arm64 and x86_64. Only an app module can take a
  local AAR: an Android library can't.
- **Kotlin 2.2:** a library compiled with the newest Kotlin writes
  metadata only that compiler, or the next, can read: an app on AGP 9's
  own Kotlin (2.2) failed to compile against it. The library is built for
  Kotlin 2.2 — language and API version, and its standard library — so
  it can.
- **Checked as published:** the release script builds an app on the AAR
  exactly as the README says — the file, and the libraries the library's
  POM names — before it lays out anything. CI runs it on every change.

### Phase 8 findings: the demo's UI tests

`mobile/android/DemoWalletUITests` ports the iOS demo's XCUITests:
UiAutomator, from a self-instrumenting test app (`com.android.test`), so
a test can quit and relaunch the demo and answer the system's
screen-lock prompt — something an instrumented test inside the app
couldn't do. Compose's test tags are resource IDs
(`testTagsAsResourceId`), named as the iOS accessibility identifiers.
Thirteen tests pass on the emulator, against `testservices`.

- **What they found:** a deferred credential, once issued, didn't appear
  until the app was relaunched. The poll that found it cancelled its own
  job before refreshing the list, and Kotlin's cancellation is
  cooperative, so the refresh was cancelled too; Swift's tasks run on.
- **Two holder keys, two prompts:** sharing two credentials asks the
  holder twice, once per key: Keystore authorizes one signature at a
  time.
- **The authorization code grant,** whose issuer page is Chrome's, came
  later (#478): Chrome accepts the test services' certificate by an SPKI
  pin on its debug command line, which the script sets and removes.

### Open items

- The APEX store on golang/go#71258; drop `certdirs_android.go` once Go
  reads it.
- On a device: StrongBox, the unlocked-device key, BiometricPrompt with a
  fingerprint, and the DC API in Chrome.

## Phase 9 findings: `org-iso-mdoc` on iOS

The demo app is an Identity Document Provider (iOS 26): Safari's
`org-iso-mdoc` requests reach its `DocumentProvider` extension, which
answers through `StartMdocPresentation` (#447–#449). It worked on an
iPhone against the passport-vdc verifier. Safari on macOS has no
document providers, so a page there reports the API unsupported.

- **Registration:** the app registers each held mdoc's doctype with
  `IdentityDocumentServices` (`MobileDocumentRegistration`); iOS offers
  the app only for those. The doctype must be one Apple allows, which
  is why passport-vdc issues an ISO Photo ID (#444). The Digital
  Credentials API – Mobile Document Provider capability goes on both
  App IDs in the Developer portal.
- **The extension is another process:** the credential store and the
  configuration are in an App Group, and holder keys in a shared
  Keychain access group; instance and DPoP keys stay in the app's own,
  so the extension can present but not receive or refresh.
  `KeychainKeyStore`'s `holderAccessGroup` and
  `FileCredentialStore.inAppGroup` set this up.
- **What the holder is shown is what's released:** the extension checks
  that the request iOS releases is the one it showed (the document,
  the elements, the reader).
- **Reader trust** (#452): the reader is named only when its request
  is signed by a certificate under `mdoc_reader_roots`, with the reader
  authentication EKU when `mdoc_reader_require_eku`; otherwise only the
  website's origin is shown. `require_trusted_mdoc_reader` refuses the
  rest.
- **Linkability** (#459): `mdocCandidates` lists only mdocs that can be
  presented, each saying whether its every copy has been shown to
  another website, so the sheet can warn before the holder chooses.
- **Open:** the app and the extension each write a credential's record
  under a lock that only spans their own process, so a refresh in the
  app can overwrite the extension marking a copy presented. A lock
  across processes would get a suspended app terminated, so this needs
  writes that check the record's version.

## Phase 10: Proximity

Decisions taken 2026-10-06 (tracked in [#482](https://github.com/IDFoundry/OID4VCgo/issues/482)):

1. **One product:** the holder (`ProximityPresentation`) and the reader
   (`ProximityReader`) are two interfaces in the same SDK and Go
   library, so an app can use either, or both.
2. **BLE modes, as ISO/IEC 18013-5 requires:** the holder supports mdoc
   peripheral server mode (it shows the QR code, advertises and is the
   GATT server). The reader supports both modes (§8.3.3.1.1), choosing
   central client mode when the holder offers both.
3. **GATT first.** The L2CAP transmission profile (Annex A) is the next
   phase, behind the same transport.
4. **One request per session**, as `proximity` handles.
5. **Reader trust** reuses `mdoc_reader_roots`, `mdoc_reader_require_eku`
   and `require_trusted_mdoc_reader`, as the DC API's `org-iso-mdoc`
   does.
6. **The Go binding is bytes in, bytes out**: the native SDK moves
   whole messages over GATT, chunks them and handles State; Go does
   the rest. The additions are within ABI version 12.
7. **The native API** is a session with a state stream (`Flow`,
   `AsyncSequence`). Apps never see GATT. Every timeout is
   configurable: by default 60 s for a reader to connect, 30 s to its
   request, and 300 s idle (§8.2.3, §9.1.1.4).
8. **Demos:** "Share in person" with a consent screen naming the
   reader and its trust, a reader certificate page, and a reader mode
   behind settings (since moved to a Verify tab in the bottom bar). A presentation history is the app's job, not the
   SDK's.

### Phase 10 findings: the `proximity` gaps

- **Reader authentication** (§9.1.4) now works both ways. The holder's
  `VerifyReaderAuth` sorts a request into trusted, untrusted (it
  verifies by its own certificate, which doesn't chain), unauthenticated
  (no readerAuth) or invalid (it doesn't sign this session's request).
  Annex D's readerAuth verifies over its own transcript. The signing
  and verification are now shared with `mdocdcapi`, in
  `internal/readerauth`.
- **An mDL must release its mandatory elements to an unauthenticated
  reader** (§7.2.1). So `require_trusted_mdoc_reader` is a wallet's
  policy for other documents, or for optional elements, and stays off
  by default.
- **Status 12:** a DeviceRequest that decrypts but isn't valid is now
  `ErrCBORValidation` (or `ErrCBORDecoding` for bytes that aren't CBOR),
  which `ErrorResponse` answers with an encrypted DeviceResponse of
  status 12 (or 11), and the reader reports as
  `DeviceResponseStatusError`.
- **Map keys are matched case-sensitively.** The CBOR library fell
  back to a case-insensitive match, so `"DocType"` was read as
  `"docType"`.
- **The reader's key was already used as received:** the
  SessionTranscript embeds the EReaderKeyBytes the reader sent, not a
  re-encoding (the Annex D transcript test checks it byte for byte).

### Phase 10 findings: the holder binding

- **A walletflow session, as for the DC API:** `walletflow.ProximityPresentation`
  owns the state (waiting for the request, awaiting consent, ended),
  credential copies and linkability. `mobile.ProximityPresentation` turns
  it into JSON events for the native SDKs.
- **Readers are known by their certificate:** a reader whose signature
  verifies is recorded by its certificate's SHA-256, trusted or not,
  so a returning reader sees `shown_to_verifier`. A reader that didn't
  sign is a new one in every session.
- **Responding ends the session:** the DeviceResponse goes out with
  status 20 in the same message, as one request per session allows. A
  failed `Respond` (the holder cancels the biometric prompt) sends
  nothing, and the holder can try again.
- **The test issuer's certificates named no country.** A proximity
  reader requires the IACA's and the document signer's countryName to
  match (§9.3.3), so `walletflowtest` now names one.

### Phase 10 findings: the reader binding

- **Standalone:** `NewProximityReader(configJSON, keys)` needs no
  wallet: the IACAs it accepts, and optionally its key, in the app's
  KeyStore, and certificate chain for reader authentication. It checks
  the key against the chain when configured, not at the first holder.
- **Both BLE modes:** the reader uses whichever mode the holder offers,
  central client mode when it offers both. In that mode the reader is
  the GATT server and serves the Ident characteristic. The holder side
  offers peripheral server mode only.
- **Revocation isn't checked:** the result carries the MSO's status
  list reference for the app to check, as `proximity.Verify` leaves it.

### Phase 10 findings: the Android SDK

- **The BLE code sits behind a transport interface:** `GattServerTransport`
  (the holder, and a reader in central client mode) and
  `GattClientTransport` (a reader in peripheral server mode) carry whole
  messages, and the sessions never see GATT. The emulator tests pair a
  holder and a reader over an in-memory transport, so everything but
  the radio is tested in CI.
- **Android 13 changed the GATT calls:** writing and notifying take the
  value as an argument and return `BluetoothStatusCodes`, not GATT
  statuses. Both forms are used, by API level.
- **Multipaz's workarounds:** a scan that finds nothing for 10 s is
  restarted, and a connection is tried up to 10 times (GATT error 133
  among others). The MTU asked for is 517, so chunks of up to 512 bytes.
- **The holder lingers after responding:** up to 5 s, until the reader
  disconnects, so its last notification isn't lost to an early
  disconnect.
- **Permissions:** the library declares them, `ProximityPermissions`
  lists the runtime ones (advertise and connect for a holder; scan,
  connect and advertise for a reader; location up to Android 11, which
  delivers scan results only with it).

### Phase 10 findings: the iOS SDK

- **The same shape as Android's:** `ProximityPresentation` and
  `ProximityReader` sessions with an `AsyncStream` of states, over a
  `ProximityTransport`: `GattServerTransport` (CBPeripheralManager) and
  `GattClientTransport` (CBCentralManager), each on its own serial
  queue, in Swift 6 mode.
- **A peripheral isn't told of disconnections:** iOS reports only the
  central unsubscribing, which the holder takes as the reader leaving.
- **Back-pressure is the platform's:** `updateValue` returning false
  waits for `peripheralManagerIsReady`, and writes without response
  wait for `canSendWriteWithoutResponse`. Chunk sizes come from the
  central's `maximumUpdateValueLength` and the peripheral's
  `maximumWriteValueLength`.
- **Apps need `NSBluetoothAlwaysUsageDescription`** in Info.plist.

### Phase 10 findings: the demos

- **Two Android emulators can try BLE:** the emulator's own Bluetooth
  (netsim) carries a real GATT session between two of them on one Mac.
  The holder's debug build logs its QR code's text, and an `mdoc:` link
  hands it to the reader. A full presentation ran that way:
  - the holder saw the test reader as verified
  - it shared one element after the screen lock prompt
  - the reader verified it

  The iOS Simulator has no Bluetooth, so iOS needs devices.
- **A demo reader identity:** the test services and passport-vdc's demo
  give reader mode a key and certificate under a CA the wallets
  recognize (`mdoc_reader_roots`), so a holder sees it as verified. The
  key arrives in the configuration, a demo shortcut; a real reader makes
  its own in the Secure Enclave or Android Keystore.
- **Each side is a tab:** reader mode was at first a setting, which
  hid it, and sharing in person a button in the top bar. Both demos now
  have a bottom bar in each platform's own component (a Material
  `NavigationBar`, a SwiftUI `TabView`): Wallet, Present (its QR code
  at once, a new session after each, ended on leaving the tab) and
  Verify (the reader, which an `mdoc:` link opens).
- **iOS can't read a certificate's fields:** beyond a subject summary,
  Security has no public API. The request carries each reader
  certificate's fields from Go, for the certificate page.

## Open questions

- The Wallet Provider's production design, and whether it belongs in
  this repository. Before it attests, it should check platform evidence
  that it's talking to the genuine app — App Attest on iOS; on Android,
  Android Key Attestation of the wallet's keys (StrongBox or TEE, the
  app's signing certificate) or Play Integrity — and key attestation
  formats. Both demos attest any key with the passport-vdc demo's
  provider until then.
