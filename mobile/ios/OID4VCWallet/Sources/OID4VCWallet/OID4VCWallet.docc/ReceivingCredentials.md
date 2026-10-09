# Receiving credentials

Receive the credentials a Credential Offer offers, with either grant,
and look after them once they're held.

## Overview

An issuer offers credentials with an `openid-credential-offer://` link,
as a QR code or a link the holder opens. Register the
`openid-credential-offer` URL scheme in the app's Info.plist so links
open the app, and hand the link to ``Wallet/startIssuance(offer:)``. It
resolves the offer and the issuer's metadata, and returns an
``Issuance`` whose ``Issuance/offer`` you show the holder: who is
offering what.

The offer names one of two grants:

- **Authorization code:** the holder signs in at the issuer's pages, in
  a browser, which redirects back to the wallet's redirect URI.
- **Pre-authorized code:** the issuer has already authenticated the
  holder, and may ask for a PIN it sent them separately
  (``Offer/txCode``).

Either way, ``Issuance/requestCredentials()`` then requests, checks and
stores the credentials, and ``Issuance/close()`` ends the issuance.

### Receive an offer

```swift
import AuthenticationServices
import Foundation
import OID4VCWallet

/// Receives the credentials an offer link offers. `askPIN` asks the
/// holder for the PIN the issuer sent, or returns nil if they cancel;
/// `signIn` opens the issuer's page and returns the redirect back.
func receive(offerLink: String, wallet: Wallet,
             askPIN: (Offer.TxCode?) async -> String?,
             signIn: (URL) async throws -> URL) async throws -> Issuance.Result? {
    let issuance = try await wallet.startIssuance(offer: offerLink)
    switch issuance.offer.grant {
    case .preAuthorizedCode:
        while true {
            guard let pin = await askPIN(issuance.offer.txCode) else {
                try await issuance.close()
                return nil
            }
            do {
                try await issuance.redeemPreAuthorizedCode(pin: pin)
                break
            } catch let error as WalletError where error.isRetryable {
                continue // A wrong PIN (invalid_grant): ask again.
            }
        }
    case .authorizationCode:
        let url = try await issuance.beginAuthorization()
        let redirect = try await signIn(url)
        try await issuance.completeAuthorization(redirect: redirect)
    }
    let result = try await issuance.requestCredentials()
    try await issuance.close()
    return result
}
```

``Issuance/Result`` lists what arrived, what the issuer deferred, and
what failed: one credential the issuer refused doesn't hold up the
rest.

### Open the issuer's page

Open the authorization URL in an `ASWebAuthenticationSession`, with the
redirect URI's scheme as its callback scheme. An ephemeral session
keeps the issuer's cookies out of Safari's.

```swift
/// Opens issuers' authorization pages over `window`.
@MainActor
final class IssuerSignIn: NSObject, ASWebAuthenticationPresentationContextProviding {
    private let window: ASPresentationAnchor
    private let callbackScheme: String

    init(window: ASPresentationAnchor, callbackScheme: String) {
        self.window = window
        self.callbackScheme = callbackScheme
    }

    nonisolated func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        MainActor.assumeIsolated { window }
    }

    /// The issuer's redirect back, or `ASWebAuthenticationSessionError`
    /// `.canceledLogin` when the holder closes the page.
    func open(_ url: URL) async throws -> URL {
        try await withCheckedThrowingContinuation { continuation in
            let session = ASWebAuthenticationSession(url: url, callbackURLScheme: callbackScheme) { redirect, error in
                if let redirect {
                    continuation.resume(returning: redirect)
                } else {
                    continuation.resume(throwing: error ?? URLError(.unknown))
                }
            }
            session.presentationContextProvider = self
            session.prefersEphemeralWebBrowserSession = true
            session.start()
        }
    }
}
```

If the holder closes the page, the offer stays open:
``Issuance/beginAuthorization()`` can begin again. A redirect is used
up by ``Issuance/completeAuthorization(redirect:)`` whatever happens,
so after a failure there, begin again rather than retrying it.

### Resume after the app is killed

iOS can terminate the app while the holder is at the issuer's pages.
The authorization in progress is kept in the credential store, so when
the redirect arrives at a relaunched app, ``Wallet/resumeIssuance(redirect:)``
completes it and returns an issuance ready for
``Issuance/requestCredentials()``. Handle every redirect this way: in
SwiftUI, from `onOpenURL`.

```swift
/// Completes an authorization the app was killed during, from the
/// redirect iOS delivers to the relaunched app.
func resume(redirect: URL, wallet: Wallet) async throws -> Issuance.Result {
    let issuance = try await wallet.resumeIssuance(redirect: redirect)
    let result = try await issuance.requestCredentials()
    try await issuance.close()
    return result
}
```

A redirect that matches no authorization in progress throws
``WalletError/Code/notFound``.

### Wait for a deferred credential

An issuer may issue a credential later, after a review, say. It's kept
in the credential store until it's issued, denied or abandoned, so it
survives the app quitting. ``Wallet/deferredCredentials()`` lists them
without network requests; poll each at the interval the issuer asks for.

```swift
/// Polls a deferred credential until the issuer settles it: the
/// credential, or a `.credentialDenied` error.
func waitFor(_ deferred: DeferredCredential, wallet: Wallet) async throws -> CredentialSummary {
    var interval = deferred.intervalSeconds
    while true {
        try await Task.sleep(for: .seconds(max(interval, 5)))
        switch try await wallet.pollDeferred(id: deferred.id) {
        case .issued(let credential): return credential
        case .pending(let next): interval = next
        }
    }
}
```

``Wallet/abandonDeferred(id:)`` gives one up, deleting its keys: once
its access token has expired, say (``DeferredCredential/accessTokenExpiresAt``).

### Look after held credentials

- ``Wallet/credentials()`` lists them, and ``Wallet/credential(id:)``
  returns one with its claims, for display. ``CredentialSummary/display``
  carries the issuer's names, logos and colours, in the holder's
  language (``WalletConfiguration/locales``).
- ``Wallet/checkStatus(id:)`` checks revocation against the issuer's
  status list, which covers many credentials, so the issuer can't tell
  which one is checked.
- Each credential arrives as a batch of copies, each bound to its own
  key (``WalletConfiguration/batchSize``), so presentations can't be
  linked by the credential. When ``CredentialSummary/copiesLeft``
  reaches zero, ``Wallet/refreshCredential(id:)`` replaces them without
  the holder, if the issuance kept a refresh token
  (``WalletConfiguration/requestRefresh``). Otherwise it throws
  ``WalletError/Code/reissueRequired``: receive the credential again.
- ``Wallet/deleteCredential(id:)`` deletes a credential and its keys,
  revoking its refresh token at the issuer.
