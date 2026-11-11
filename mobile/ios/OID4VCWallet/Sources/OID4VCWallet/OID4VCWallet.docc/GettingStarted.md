# Getting started

Add the package, give the wallet its keys, its storage and a Wallet
Provider, and create it at launch.

## Overview

A ``Wallet`` needs four things from your app: its configuration, a
``KeyStore`` for its keys, a ``CredentialStore`` for what it holds, and a
``WalletProvider`` that attests it to issuers. The package has standard
stores for the first two; the Wallet Provider is your backend.

### Add the package

Add OID4VCWallet to your app with Swift Package Manager, from
`https://github.com/IDFoundry/OID4VCgo-wallet-swift`, at the release
whose documentation you're reading. In `Package.swift`:

```
.package(url: "https://github.com/IDFoundry/OID4VCgo-wallet-swift", from: "<version>")
```

The package links a binary framework, `Mobile`, which SwiftPM checks
against the checksum in the package's manifest.

### Register the wallet

Issuers' Authorization Servers know the wallet as an OAuth client: a
client ID, and a redirect URI the app opens when the holder returns from
the issuer's pages. Register a private-use URI scheme for it, in the
app's Info.plist (`CFBundleURLTypes`), and pass the URL the app receives
to the issuance.

The wallet trusts only what chains to the roots you give it, as PEM
certificates: `issuerRoots` for credentials, and `verifierRoots` for
the Verifiers it answers. A Credential Offer's issuer isn't trusted just
because it sent the offer.

### Provide the keys and the storage

``KeychainKeyStore`` keeps every key in the Secure Enclave. A holder
key — the one a credential copy is bound to — signs when presenting, and
the Credential Request's proof when receiving or refreshing. By default
it asks for Face ID, Touch ID or the passcode each time: add an
`NSFaceIDUsageDescription` to the app's Info.plist, or iOS asks for the
passcode instead. <doc:GoingToProduction> describes the trade-off.

``FileCredentialStore`` keeps each credential as a file with complete
data protection, out of backups: a credential is useless without its
holder key, which can't leave this device. An app with a document
provider extension keeps both in places the extension can read too; see
``FileCredentialStore/inAppGroup(_:options:)`` and
``KeychainKeyStore/Options/holderAccessGroup``. If the app may ever
present to Safari, use those from its first release: credentials it
received into ``FileCredentialStore/standard(options:)`` with the
default ``KeychainKeyStore`` can't be moved there, and its holders
would have to receive them again (<doc:PresentingToSafari>). The app and the
extension then share one store: a store of your own implements
``CredentialStore/compareAndSwap(id:expected:record:)`` atomically
across both processes, as ``FileCredentialStore`` does with a file
lock.

### Connect the Wallet Provider

Issuers following HAIP accept only a wallet its Wallet Provider has
attested: a Wallet Attestation for the wallet's instance key, and a Key
Attestation for the keys a credential will be bound to. Your backend
issues them, after checking App Attest evidence that it's talking to
your genuine app on a genuine device.

With a backend built on OID4VCgo's `walletprovider` package, the wallet
needs no provider code of your own: ``HttpWalletProvider`` speaks its
protocol, with App Attest evidence. Give it the URL the protocol is
mounted at and a registry that survives launches, and add the App
Attest capability to the app (<doc:GoingToProduction> has its
environments):

```swift
import Foundation
import OID4VCWallet

/// The Wallet Provider: OID4VCgo's `walletprovider`, mounted at /wp.
func makeWalletProvider() throws -> HttpWalletProvider {
    try HttpWalletProvider(baseURL: URL(string: "https://provider.example.com/wp")!,
                           instances: FileInstanceRegistry.standard())
}
```

It sends nothing but to that https URL, follows no redirect, times
each request out, and checks each answer is for what it asked before
the wallet uses it. Its failures reach the wallet as a retryable
``WalletError/Code/network`` when the network or the provider's
availability caused them, and as ``WalletError/Code/platform`` when the
provider refused.

#### If your backend isn't OID4VCgo's walletprovider

Implement ``WalletProvider`` yourself, and make the checks
``HttpWalletProvider`` makes:

- **Your backend** attests only after verifying App Attest: an
  attestation of the app's App Attest key once, then an assertion, with
  a counter that only rises, over each instance key and over each Key
  Attestation's keys. Without that, anything that can reach the backend
  gets attestations for keys it holds.
- **Transport:** send only to your backend's https URL, over a
  `URLSession` whose delegate refuses redirects (`URLSession.shared`
  follows them), with a timeout on each request, and read at most a
  bounded answer.
- **Answers:** before returning a Wallet Attestation, check its `sub`
  is `clientID` and its `cnf.jwk` is `instanceKey`; before returning a
  Key Attestation, check its `nonce` is `nonce` (absent when `nonce` is
  empty) and its `attested_keys` holds only keys you sent. The issuer
  verifies their signatures.
- **Errors:** throw a `URLError` for what's worth retrying — no
  connection, a timeout, HTTP 5xx or 429 — which reaches the wallet as
  a retryable ``WalletError/Code/network``. Any other error reaches it
  as ``WalletError/Code/platform``: throw a refusal as one.

### Create the wallet

Create one ``Wallet`` when the app starts, and keep it. Creating it
makes no network requests. At launch, before anything else, sweep the
Keychain of keys no credential uses: an issuance the app quit in the
middle of leaves its keys behind. Each trust role whose roots you set
needs a revocation choice: checked against the CRLs your app fetches
(``WalletConfiguration/revocation``), or declined
(``WalletConfiguration/noRevocationCheck``); see <doc:GoingToProduction>.

```swift
/// The app's wallet, created once at launch.
@MainActor
final class AppWallet {
    let wallet: Wallet
    private let keys: KeychainKeyStore
    private let provider: HttpWalletProvider

    init(clientID: String, redirectURI: String, issuerRoots: String, verifierRoots: String, crls: String) throws {
        let configuration = WalletConfiguration(
            clientID: clientID,
            redirectURI: redirectURI,
            issuerRoots: issuerRoots,
            verifierRoots: verifierRoots,
            crls: crls,
            revocation: [.issuer, .status, .verifier])
        keys = KeychainKeyStore()
        provider = try makeWalletProvider()
        wallet = try Wallet(
            configuration: configuration,
            keyStore: keys,
            credentialStore: try FileCredentialStore.standard(),
            provider: provider)
    }

    /// Run once at launch, before any issuance.
    func start() async throws {
        try await wallet.sweepOrphanedKeys(in: keys)
        try await provider.sweepOrphanedRegistrationKeys()
    }
}
```

### Ship the release build

The package links the release build of `Mobile`. OID4VCgo's own tests
use a test build with an in-process issuer and Verifier that a shipped
app must never have; ``OID4VC/isTestBuild`` says which one an app has,
so it can refuse to run on the test build.

### Next steps

- <doc:ReceivingCredentials>
- <doc:PresentingFromALink>
- <doc:PresentingToSafari>
- <doc:PresentingInPerson>
- <doc:HandlingErrors>
- <doc:GoingToProduction>
- <doc:IntegrationChecklist>
