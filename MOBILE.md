# OID4VCgo Mobile — design

Status: **in progress** — Phases 0 to 5 are done, and Phase 6 is done on the Simulator (see Phases). This is
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
        Candidates()            matching credentials and what each would disclose
        Respond(choice) / Decline()
        Result()                sent, and where to send the browser
        Cancel()
```

- **Authorization** goes through the issuer's pages: the session hands
  the app an authorization URL, and the app returns the redirect it
  collects (`ASWebAuthenticationSession` or a Universal Link).
- **Suspension:** FAPIgo's client sessions persist as an opaque record
  (v0.43), so an in-flight authorization can be saved and resumed from
  the redirect after the app is suspended. Session persistence is a
  hardening-phase item.

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
holder's issuances by them; deferred credentials are polled within the
issuance. Holder keys need biometrics only when presenting, never at
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
| 6 ◐ | OID4VP slice | Request parsing, candidates, consent and presentation from the iOS demo app |
| 7 | Hardening | Suspension and resumption, cancellation, network failures, issuer and verifier errors, logging without personal data |
| 8 | Android | The same bridge over Android Keystore, packaged as an AAR |
| 9 | DC API | A DC API adapter over the presentation engine |

### Phase 1 findings

The spike is `mobile/` (the Go package) and `mobile/ios/OID4VCMobile`
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
- **Still to prove on a device:** the Face ID prompt when presenting
  (Phase 6), with a development team set in `project.yml`.
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
- **XCUITest:** opening a custom-scheme link from a test asks for
  confirmation, so the tests launch the app with the link instead.

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

## Open questions

- Session persistence format and where it's kept, for suspension.
- The Wallet Provider's production design (App Attest verification, key
  attestation formats), and whether it belongs in this repository.
- iOS's integration point for the Digital Credentials API, when Phase 9
  starts.
