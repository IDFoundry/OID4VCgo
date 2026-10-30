# Presenting from a link

Answer a Verifier's OpenID4VP request: show who is asking and what,
let the holder choose, and present exactly that.

## Overview

A Verifier asks with an `openid4vp://` link, as a QR code or a link on
its page. Register the `openid4vp` URL scheme in the app's Info.plist so
links open the app, and hand the link to
``Wallet/startPresentation(request:)``. It fetches the Verifier's
signed request, checks its certificate against
``WalletConfiguration/verifierRoots``, and finds the credentials that
can answer it. A request from a Verifier the wallet doesn't trust
throws ``WalletError/Code/untrustedVerifier`` before anything is shown.

The ``Presentation`` it returns says:

- who is asking: ``Presentation/verifier``, its name, and its
  ``Presentation/Registration`` when a registrar the
  wallet trusts (``WalletConfiguration/registrarRoots``) registered it,
  with its purpose and the claims it's registered to ask for;
- what it asks for: ``Presentation/queries``, each with the held
  credentials that can answer it, and ``Presentation/credentialSets``,
  the request's alternatives.

### Present

```swift
import Foundation
import OID4VCWallet

/// Answers a request link: `confirm` shows the holder who is asking and
/// what sharing would disclose, and returns whether they agree. Returns
/// where to send the browser, when the Verifier asks.
func present(requestLink: String, wallet: Wallet,
             confirm: (Presentation, [Presentation.Disclosure]) async -> Bool) async throws -> URL? {
    let presentation: Presentation
    do {
        presentation = try await wallet.startPresentation(request: requestLink)
    } catch let error as WalletError where error.code == .requestRefused {
        // A refused request: the Verifier was told, and may say where to
        // take the holder next (OpenID4VP §8.2).
        return wallet.takeRefusalRedirect()
    }
    guard presentation.isAnswerable else {
        return try await presentation.decline().redirectURI
    }
    let selection: Presentation.Selection
    let disclosures: [Presentation.Disclosure]
    do {
        selection = try await presentation.defaultSelection()
        disclosures = try await presentation.preview(selection: selection)
    } catch {
        // Nothing can be shown: decline, so the Verifier isn't left waiting.
        _ = try? await presentation.decline()
        throw error
    }
    guard await confirm(presentation, disclosures) else {
        return try await presentation.decline().redirectURI
    }
    // The holder key signs now: Face ID, if the key store asks for it.
    return try await presentation.respond(selection: selection).redirectURI
}
```

``Presentation/defaultSelection()`` picks the first credential that
answers each query, and the first answerable option of each credential
set. To let the holder choose, build a ``Presentation/Selection`` from
each query's ``Presentation/Query/credentials`` instead: a query that
takes one credential gets exactly one. The wallet presents exactly the
selection, after checking it answers the request
(``WalletError/Code/invalidSelection`` otherwise), and
``Presentation/preview(selection:)`` says what it would disclose
without signing or sending anything: show that before the holder
agrees.

Open ``Presentation/Presented/redirectURI``, when the Verifier sends
one, in the browser the request came from: it's how a same-device
flow returns to the Verifier's page. The library refuses http and
schemes that run code or read local data, but lets through a scheme the
Verifier's own app may have registered: open an https URL in the
browser, any other only through `UIApplication.open`, never in a web
view, and never one in the wallet's own schemes (`openid4vp`,
`openid-credential-offer`, its redirect URI's), which would start
another flow in the wallet.

### When the wallet refuses a request

A request the wallet must not answer — one with `transaction_data` it
doesn't support, or a parameter OpenID4VP forbids — makes
``Wallet/startPresentation(request:)`` throw
``WalletError/Code/requestRefused``, its ``WalletError/protocolError``
the error code the wallet sent the Verifier, such as
`invalid_transaction_data`. Nothing is shown to the holder, and nothing
is presented. The Verifier may answer the refusal with a redirect:
``Wallet/takeRefusalRedirect()`` returns it, once, and you open it in
the browser the request came from, as a
``Presentation/Presented/redirectURI``, so the holder isn't left
stranded. Tell the holder the request wasn't answered.

### Show what's being asked beyond a registration

For a Verifier with a verified registration, each query's
``Presentation/Query/unregistered`` lists the claims it asks for beyond
what it's registered to request, and
``Presentation/Query/unregisteredAll`` whether it names no claims at
all. The library flags such a query in full, though OpenID4VP 1.0
§6.4.1 reads it as asking for no selectively disclosable claims, so a
presentation for it discloses only what the credential always shows.
Nothing is refused for them: show them, and let the holder decide.

### Keep presentations unlinkable

Each presentation uses a copy of the credential, bound to its own key,
so two Verifiers can't link the holder's presentations by the
credential. ``WalletConfiguration/copyPolicy`` chooses which copy:

- ``WalletConfiguration/CopyPolicy/perPresentation``, the default: a
  copy no Verifier has seen, every time.
- ``WalletConfiguration/CopyPolicy/perVerifier``: the copy a Verifier
  has seen before, so it can recognize a returning holder, and an unused
  one for a new Verifier.

Once every copy is used, one is reused. A candidate's
``CredentialSummary/linkableHere`` says whether presenting it now would
hand this Verifier a copy another has seen: warn the holder, and
refresh the credential (``Wallet/refreshCredential(id:)``) when its
``CredentialSummary/copiesLeft`` reaches zero.

### When delivery is uncertain

If sending the response fails in a way that leaves it unknown whether
the Verifier received it, ``Presentation/respond(selection:)`` throws
``WalletError/Code/deliveryUnknown`` and doesn't send it again: the
holder should check with the Verifier before sharing again.
