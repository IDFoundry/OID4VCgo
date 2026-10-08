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
`https://github.com/IDFoundry/OID4VCgo-wallet-swift`. In `Package.swift`:

```
.package(url: "https://github.com/IDFoundry/OID4VCgo-wallet-swift", from: "0.8.0")
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
key — the one a credential is bound to — signs only when presenting, and
by default asks for Face ID, Touch ID or the passcode first: add an
`NSFaceIDUsageDescription` to the app's Info.plist, or iOS asks for the
passcode instead.

``FileCredentialStore`` keeps each credential as a file with complete
data protection, out of backups: a credential is useless without its
holder key, which can't leave this device. An app with a document
provider extension keeps both in places the extension can read too; see
``FileCredentialStore/inAppGroup(_:options:)`` and
``KeychainKeyStore/Options/holderAccessGroup``.

### Implement the Wallet Provider

Issuers following HAIP accept only a wallet its Wallet Provider has
attested: a Wallet Attestation for the wallet's instance key, and a Key
Attestation for the keys a credential will be bound to. Your backend
issues them; the app passes the keys and returns its answers. A real
Wallet Provider attests only after checking App Attest evidence that
it's talking to your genuine app.

```swift
import Foundation
import OID4VCWallet

/// Asks the app's backend for attestations. The keys are public JWKs,
/// as JSON; the answers are compact JWTs.
struct BackendWalletProvider: WalletProvider {
    let backend: URL

    func walletAttestation(clientID: String, instanceKey: Data) async throws -> String {
        try await post("wallet-attestation", [
            "client_id": clientID,
            "instance_key": try JSONSerialization.jsonObject(with: instanceKey),
        ])
    }

    func keyAttestation(keys: [Data], nonce: String) async throws -> String {
        try await post("key-attestation", [
            "keys": try keys.map { try JSONSerialization.jsonObject(with: $0) },
            "nonce": nonce,
        ])
    }

    private func post(_ path: String, _ body: [String: Any]) async throws -> String {
        var request = URLRequest(url: backend.appending(path: path))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await URLSession.shared.data(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw URLError(.badServerResponse) }
        return String(decoding: data, as: UTF8.self)
    }
}
```

A `URLError` the provider throws reaches the wallet as a retryable
``WalletError/Code/network`` error; any other is
``WalletError/Code/platform``.

### Create the wallet

Create one ``Wallet`` when the app starts, and keep it. Creating it
makes no network requests. At launch, before anything else, sweep the
Keychain of keys no credential uses: an issuance the app quit in the
middle of leaves its keys behind.

```swift
/// The app's wallet, created once at launch.
@MainActor
final class AppWallet {
    let wallet: Wallet
    private let keys: KeychainKeyStore

    init(clientID: String, redirectURI: String, issuerRoots: String, verifierRoots: String, provider: URL) throws {
        let configuration = WalletConfiguration(
            clientID: clientID,
            redirectURI: redirectURI,
            issuerRoots: issuerRoots,
            verifierRoots: verifierRoots)
        keys = KeychainKeyStore()
        wallet = try Wallet(
            configuration: configuration,
            keyStore: keys,
            credentialStore: try FileCredentialStore.standard(),
            provider: BackendWalletProvider(backend: provider))
    }

    /// Run once at launch, before any issuance.
    func start() async throws {
        try await wallet.sweepOrphanedKeys(in: keys)
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
