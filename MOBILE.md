# OID4VCgo Mobile — design

Status: **iOS done; Android in progress (Phase 8, [#461](https://github.com/IDFoundry/OID4VCgo/issues/461)).**
Phases 0 to 7 are done: the SDK is published as the OID4VCWallet Swift
package, and the demo app has issued and presented on a device, against
the passport-vdc demo through a tunnel. Later work is recorded after
Phase 7. This is
the design for a mobile wallet SDK built on OID4VCgo, delivered in the
phases below. It records the decisions taken so far, what each phase
found, and the questions still open; update it as phases land.

## Goal

A cross-platform wallet SDK, compiled with `gomobile bind` into an iOS
XCFramework first and an Android AAR later, covering the wallet's side
of the credential lifecycle:

- **Issuance:** Credential Offer → OID4VCI 1.0 / HAIP 1.0 → Credential →
  wallet storage.
- **Presentation:** Authorization Request → OID4VP 1.0 / HAIP 1.0 → the
  holder's approval → Authorization Response.
- **Later:** a Digital Credentials API request through the same
  presentation engine.

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
  (from later in Phase 8) a demo app.

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
OID4VP request (`wallet.ParseAuthorizationRequest`) or, later, a DC API
request (`wallet.ParseDCAPIRequest`, which already yields the same
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
| 8 | Android | The same bridge over Android Keystore, packaged as an AAR, with the demo app and the DC API (below) |
| 9 | DC API | A DC API adapter over the presentation engine |

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

The ABI is documented in [mobile/ABI.md](mobile/ABI.md) (version 1):
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
  the wallet side only; a mobile Verifier would be a package of its
  own. SwiftPM fetches a package only from a `Package.swift` at the
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
2. **Distribution:** a Maven repository on that repository's GitHub
   Pages, `dev.idfoundry:oid4vcwallet`, one artifact holding the Kotlin
   API and the Go library, with the AAR also on a GitHub release. Its
   versions are the Swift package's, published from the same commit.
   Maven Central later.
3. **Scope:** parity with the Swift SDK and demo, and the DC API in the
   first release: OpenID4VP requests through a new ABI session (Phase
   9's adapter) and `org-iso-mdoc` ones through `MdocPresentation`. The
   Credential Manager integration lives in the demo app, as the iOS
   document provider does.
4. **Platform:** minSdk 30, the first level where a key can require
   biometrics *or* the screen lock for each use, as holder keys do on
   iOS. Keys are P-256 in StrongBox, or else the TEE; credentials are
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
- **No 32-bit arm:** FAPIgo doesn't build where `int` is 32 bits
  (`math.MaxUint32` overflows `int` in its `internal/jwe`). iOS never
  had a 32-bit target; Play requires the 64-bit ones anyway.
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

### Open items

- Publish to Maven Central.
- Whether `OpenId4VpRegistry`'s default matcher answers `org-iso-mdoc`
  requests; if not, Multipaz's matcher.
- FAPIgo on 32-bit platforms.
- The APEX store on golang/go#71258; drop `certdirs_android.go` once Go
  reads it.
- On a device: StrongBox, the unlocked-device key, BiometricPrompt, and
  the DC API in Chrome.

## Open questions

- The Wallet Provider's production design (App Attest verification, key
  attestation formats), and whether it belongs in this repository.
- iOS's integration point for the Digital Credentials API, when Phase 9
  starts.
