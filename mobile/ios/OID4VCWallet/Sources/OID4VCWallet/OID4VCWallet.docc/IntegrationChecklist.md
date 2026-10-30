# Integration checklist

Every step and rule for integrating OID4VCWallet, in order, each with
how to check it.

## Overview

This list is written to be followed literally: by a developer, or by a
coding assistant asked to integrate the package. The articles explain
the why; this list doesn't repeat them. When an item and an article
disagree, the article and the API reference are right: report the
difference.

For a coding assistant: read <doc:GettingStarted> and the article for
each feature you add before writing code. Use only the public API those
name; don't use the `Mobile` framework's generated types, and don't
reimplement a protocol or the Bluetooth transport the package already
carries. In person, the package engages by QR code only: don't add NFC
around it. The
[demo wallet](https://github.com/IDFoundry/OID4VCgo/tree/main/mobile/ios/DemoWallet)
is a complete, working app on this package to compare against.

### 1. Every app

- The package comes from
  `https://github.com/IDFoundry/OID4VCgo-wallet-swift`, at a released
  version, with the articles of that version. *Check:* the app builds;
  SwiftPM verifies the `Mobile` framework's checksum.
- The app refuses to run on a test build: ``OID4VC/isTestBuild`` is
  false in what you ship.
- Keys come from ``KeychainKeyStore``, with its defaults, and
  `NSFaceIDUsageDescription` is in the Info.plist. Credentials live in
  ``FileCredentialStore``. The app implements ``WalletProvider``, or
  passes nil for issuers that don't ask for attestations.
  (<doc:GettingStarted>)
- One ``Wallet``, created at launch and kept for the app's life, with
  ``Wallet/sweepOrphanedKeys(in:)`` run before any issuance.
- Trust roots are PEM in ``WalletConfiguration``, each in its own role:
  ``WalletConfiguration/issuerRoots``, ``WalletConfiguration/verifierRoots``,
  ``WalletConfiguration/mdocReaderRoots`` and the rest. Outside
  development, two roles whose roots may vouch for the same certificates
  (a shared anchor, or an intermediate in either) each need their own,
  distinct `RequireEKU`, or the wallet isn't made. *Check:* `Wallet(...)`
  succeeds with your production configuration. (<doc:GoingToProduction>)
- Errors are shown with `localizedDescription`, logged with
  ``WalletError/message``, and retried only when
  ``WalletError/isRetryable`` says so. (<doc:HandlingErrors>)
- Revocation, for every role whose roots you set: where your
  ecosystem's CAs publish CRLs, the role in
  ``WalletConfiguration/revocation``, its CAs' CRLs in
  ``WalletConfiguration/crls``, and, for a certificate pinned in the
  roots, its CA's certificate in ``WalletConfiguration/crlIssuers``;
  otherwise the role in ``WalletConfiguration/noRevocationCheck``, a
  deliberate decision. Fresh CRLs are fetched in the background and
  handed over with ``Wallet/setCRLs(_:)`` before the old ones expire.
  *Check:* `Wallet(...)` succeeds with your production configuration,
  and a certificate on a CRL is refused. (<doc:GoingToProduction>)

### 2. Receiving credentials

- The `openid-credential-offer` URL scheme is registered in the
  Info.plist, and each link goes to ``Wallet/startIssuance(offer:)``.
  Show ``Issuance/offer`` (who is offering what) before going on.
- ``WalletConfiguration/redirectURI`` uses the app's own scheme, a
  domain name in reverse order and a single slash, such as
  `com.example.wallet:/callback`, registered in `CFBundleURLTypes`. Not
  an https Universal Link, and not `myapp:/callback` or
  `com.example.wallet://callback`. *Check:* `Wallet(...)` succeeds with
  your production configuration.
- Pre-authorized code: ask for the PIN when ``Offer/txCode`` is set, and
  ask again when ``Issuance/redeemPreAuthorizedCode(pin:)`` throws a
  retryable error. Authorization code: open
  ``Issuance/beginAuthorization()``'s URL in an ephemeral
  `ASWebAuthenticationSession` with the redirect URI's scheme as its
  callback scheme, and pass the redirect to
  ``Issuance/completeAuthorization(redirect:)``.
- Every redirect the app is opened with (`onOpenURL`) goes to
  ``Wallet/resumeIssuance(redirect:)``: it completes an authorization
  the app was terminated during.
- ``Issuance/requestCredentials()``, then ``Issuance/close()`` the
  issuance whatever happens. Show ``Issuance/Result``'s received,
  deferred and failed credentials.
- Deferred credentials are polled (``Wallet/pollDeferred(id:)``) at the
  interval the issuer asks for, after relaunches too
  (``Wallet/deferredCredentials()``).
- ``Wallet/checkStatus(id:)`` before relying on a held credential; show
  ``CredentialStatus/Value/unknown`` as not checked, not as valid.
- *Check:* both grants against your issuer, including the app being
  terminated during sign-in; an offer from an issuer outside
  ``WalletConfiguration/issuerRoots`` is refused.
  (<doc:ReceivingCredentials>)

### 3. Presenting from a link

- The `openid4vp` URL scheme is registered in the Info.plist, and each
  link goes to ``Wallet/startPresentation(request:)``. An
  ``WalletError/Code/untrustedVerifier`` error is shown as such, with
  nothing presented.
- Show ``Presentation/verifier`` (and its registration when there is
  one), each query's claims and any
  ``Presentation/Query/unregistered`` ones, and what
  ``Presentation/preview(selection:)`` says would be disclosed, before
  the holder agrees. Then ``Presentation/respond(selection:)``, or
  ``Presentation/decline()``.
- Open ``Presentation/Presented/redirectURI``, when there is one, in the
  browser the request came from.
- ``WalletError/Code/deliveryUnknown`` isn't retried: tell the holder to
  check with the Verifier.
- *Check:* a Verifier outside ``WalletConfiguration/verifierRoots`` is
  refused before anything is shown; the Verifier receives exactly the
  claims the holder chose. (<doc:PresentingFromALink>)

### 4. Presenting to Safari

- A document provider extension target, with the extension point
  `com.apple.identity-document-services.document-provider-ui`, and the
  Mobile Document Provider capability and doctypes entitlement on both
  the app's and the extension's App IDs.
- Credentials in an App Group both list
  (``FileCredentialStore/inAppGroup(_:options:)``, whose
  ``CredentialStore/compareAndSwap(id:expected:record:)`` locks a file
  both processes see, so they never both use one copy), holder keys in a
  Keychain access group both list
  (``KeychainKeyStore/Options/holderAccessGroup``), and the
  configuration where the extension can read it. The extension opens
  its ``Wallet`` with no Wallet Provider: it presents, but doesn't
  receive.
- The app registers each presentable mdoc with iOS whenever the
  credentials change, and removes the rest.
- In the extension, the consent screen shows the website's origin and
  ``Wallet/mdocCandidates(origin:)``. In `sendResponse`'s closure,
  validate the raw request, parse it with
  ``Wallet/startMdocPresentation(requestData:origin:)``, refuse it if
  it differs from what the holder was shown, and answer with
  ``MdocPresentation/respond(document:credentialID:elements:)``.
- *Check:* on an iOS 26 device, Safari offers the app for a page's
  `org-iso-mdoc` request, and the page receives the elements the holder
  chose. (<doc:PresentingToSafari>)

### 5. In person, holder

- `NSBluetoothAlwaysUsageDescription` is in the Info.plist.
- ``Wallet/startProximityPresentation(timeouts:modes:)``, then show
  ``ProximityPresentation/qrCode`` and follow
  ``ProximityPresentation/states``. On `.requestReceived`, show
  ``ProximityPresentation/Request/reader`` (name, and whether trusted)
  and the requested elements, then respond or decline. On a final
  state, show the outcome.
- ``ProximityPresentation/cancel()`` when the holder leaves the screen;
  keep the app in the foreground during a session.
- *Check:* on two devices, a reader scanning the code gets the elements
  the holder chose, and nothing else. (<doc:PresentingInPerson>)

### 6. In person, reader

- ``ProximityReader`` with ``ProximityReaderConfiguration``'s
  `issuerRoots`, plus a reader key and chain with the
  reader-authentication extended key usage if holders should see who's
  asking.
- `development` not set, with each role (`issuer`, `status`) in
  `revocation` (with `crls`, refreshed by `setCRLs`) or
  `noRevocationCheck`, and `anyIssuerForAnyType` or
  `issuerRootsByDocType` deciding which IACAs issue which document type.
- ``ProximityReader/start(qrCode:docType:elements:timeouts:)`` with the
  scanned code, following the session's states.
- Call ``ProximityReaderSession/checkStatus()`` once the session is
  `.verified`, and rely on the document only on ``MdocStatus/valid`` or
  ``MdocStatus/noStatus``. Decide which issuers to accept on
  ``VerifiedMdoc/issuerChain``, not on its ``VerifiedMdoc/issuer`` name.
- *Check:* a holder verifies; an mdoc from an issuer outside the
  reader's `issuerRoots` is refused. (<doc:PresentingInPerson>)

### 7. Before shipping

- <doc:GoingToProduction> is done: ``WalletConfiguration/development``
  isn't set, nor ``ProximityReaderConfiguration/development``, and the
  Wallet Provider checks App Attest evidence.
- Interop beyond your own app: test your holder against at least one
  independent reader, and your reader against an independent holder.
