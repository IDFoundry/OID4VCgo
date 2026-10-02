# OID4VCgo Mobile — design

Status: **planned**. This is the design for a mobile wallet SDK built on
OID4VCgo, to be delivered in the phases below. It records the decisions
taken so far and the questions still open; update it as phases land.

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
transport can replace it if iOS needs one. To confirm in the gomobile
spike: that Go on iOS verifies TLS against the system trust store, and
how it behaves with proxies and VPNs. App Transport Security doesn't
apply to Go's networking.

## Phases

| # | Phase | Exit criteria |
|---|---|---|
| 0 | `walletflow` | Issuance and presentation sessions behind key, store, Wallet Provider and HTTP interfaces; the passport-vdc wallets run on it; their end-to-end tests pass |
| 1 | gomobile spike | An XCFramework; Swift calls Go and Go calls back into Swift; a JSON envelope; errors and cancellation across the boundary |
| 2 | Secure Enclave spike | A Swift-generated key signs an ES256 JWS through Go's `crypto.Signer`, verified by OID4VCgo; a platform `KeyManager` for FAPIgo |
| 3 | ABI foundation | Versioned JSON envelope, error codes and session lifecycle, documented |
| 4 | OID4VCI slice | HAIP issuance from the iOS demo app against the passport-vdc issuer, with Key Attestations from the Wallet Provider |
| 5 | Storage | The native credential store, with key references |
| 6 | OID4VP slice | Request parsing, candidates, consent and presentation from the iOS demo app |
| 7 | Hardening | Suspension and resumption, cancellation, network failures, issuer and verifier errors, logging without personal data |
| 8 | Android | The same bridge over Android Keystore, packaged as an AAR |
| 9 | DC API | A DC API adapter over the presentation engine |

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
- Whether the app or Go owns the credential store's encryption at rest
  beyond iOS Data Protection.
- The Wallet Provider's production design (App Attest verification, key
  attestation formats), and whether it belongs in this repository.
- iOS's integration point for the Digital Credentials API, when Phase 9
  starts.
