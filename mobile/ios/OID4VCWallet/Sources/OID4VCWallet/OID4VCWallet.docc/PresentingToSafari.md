# Presenting to Safari

Answer a web page's request for an mdoc over the Digital Credentials
API, as an iOS document provider.

## Overview

From iOS 26, a page in Safari can ask for an ISO mdoc with the W3C
Digital Credentials API, using the `org-iso-mdoc` protocol (ISO/IEC TS
18013-7 Annex C). iOS offers the apps that registered a matching
document, and shows the chosen app's document provider extension for
the holder's consent. The extension answers through
``Wallet/startMdocPresentation(requestData:origin:)`` and
``MdocPresentation/respond(document:credentialID:elements:)``; the
response goes back through Safari, encrypted to the page, with no
network request from the wallet.

Safari sends only `org-iso-mdoc`, not OpenID4VP, and on iOS only:
Safari on macOS has no document providers.

### Set up the app and its extension

- **The extension:** a target whose Info.plist names the extension
  point `com.apple.identity-document-services.document-provider-ui`
  (`EXAppExtensionAttributes`, `EXExtensionPointIdentifier`).
- **The capability:** Digital Credentials API – Mobile Document
  Provider, on both the app's and the extension's App IDs, with the
  doctypes the app presents in the
  `com.apple.developer.identity-document-services.document-provider.mobile-document-types`
  entitlement. Apple allows only certain doctypes, such as the ISO mDL
  and Photo ID.
- **Shared storage:** the extension is another process, so the app
  keeps its credentials in an App Group both list
  (``FileCredentialStore/inAppGroup(_:options:)``), and its holder keys in
  a Keychain access group both list
  (``KeychainKeyStore/Options/holderAccessGroup``). Instance and DPoP
  keys stay in the app's own group: the extension presents, but doesn't
  receive. The app saves its configuration where the extension can
  read it too.

```swift
import Foundation
import IdentityDocumentServices
import IdentityDocumentServicesUI
import OID4VCWallet
import SwiftUI

/// What the app and its document provider extension share.
enum SharedWallet {
    static let appGroup = "group.com.example.wallet"
    static let holderKeyGroup = "ABCDE12345.com.example.wallet.shared"

    /// The configuration the app saved in the group's defaults.
    static func configuration() throws -> WalletConfiguration {
        guard let data = UserDefaults(suiteName: appGroup)?.data(forKey: "configuration") else { throw CocoaError(.fileNoSuchFile) }
        return try JSONDecoder().decode(WalletConfiguration.self, from: data)
    }

    /// The wallet over the shared store and holder keys: the app passes
    /// its Wallet Provider; the extension, which only presents, nil.
    static func open(provider: (any WalletProvider)?) throws -> Wallet {
        try Wallet(
            configuration: try configuration(),
            keyStore: KeychainKeyStore(options: .init(holderAccessGroup: holderKeyGroup)),
            credentialStore: try FileCredentialStore.inAppGroup(appGroup),
            provider: provider)
    }
}
```

### Register the documents

iOS offers the app only for documents it registered. Whenever the
credentials change, register each presentable mdoc and remove the rest.
`supportedAuthorityKeyIdentifiers` names the reader CAs, by subject key
identifier, whose requests the document answers.

```swift
/// Registers the held mdocs of `doctypes` with iOS, so Safari offers the
/// app for them. The first registration asks the holder to allow it.
@available(iOS 26.0, *)
func registerDocuments(_ credentials: [CredentialSummary], doctypes: Set<String>, readerAuthorities: [Data]) async throws {
    let store = IdentityDocumentProviderRegistrationStore()
    for registration in try await store.registrations {
        try await store.removeRegistration(forDocumentIdentifier: registration.documentIdentifier)
    }
    for credential in credentials where credential.format == "mso_mdoc" && doctypes.contains(credential.doctype ?? "") {
        try await store.addRegistration(MobileDocumentRegistration(
            mobileDocumentType: credential.doctype ?? "",
            supportedAuthorityKeyIdentifiers: readerAuthorities,
            documentIdentifier: credential.id,
            invalidationDate: credential.validUntil))
    }
}
```

### Answer in the extension

iOS hands the extension the request in two stages. First,
`ISO18013MobileDocumentRequestContext.request` describes what's asked,
for the consent screen: show it with the website's origin, and the
candidates from ``Wallet/mdocCandidates(origin:)``. Only when the
holder shares does iOS release the request itself, to
`sendResponse`'s closure. Validate it there, parse it, check it's what
the holder was shown, and answer.

```swift
@available(iOS 26.0, *)
struct WalletDocumentProvider: IdentityDocumentProvider {
    var body: some IdentityDocumentRequestScene {
        ISO18013MobileDocumentRequestScene { context in
            ConsentView(context: context)
        }
    }

    func performRegistrationUpdates() async {}
}

struct RequestChanged: Error {}

@available(iOS 26.0, *)
struct ConsentView: View {
    let context: ISO18013MobileDocumentRequestContext

    var body: some View {
        Button("Share") { Task { try await share(credentialID: nil) } }
    }

    /// Shares the held mdoc `credentialID` (the first candidate when
    /// nil) for the request's first document.
    func share(credentialID: String?) async throws {
        guard let originURL = context.requestingWebsiteOrigin,
              let origin = MdocPresentation.origin(of: originURL) else { return }
        let wallet = try SharedWallet.open(provider: nil)
        try await context.sendResponse { raw in
            _ = try IdentityDocumentWebPresentmentRawRequestValidator()
                .validateISO18013MobileDocumentRequest(raw.requestData, origin: originURL)
            let presentation = try await wallet.startMdocPresentation(requestData: raw.requestData, origin: origin)
            guard let document = presentation.request.documents.first,
                  let chosen = credentialID ?? document.credentials.first?.id else { throw RequestChanged() }
            // The holder key signs now: Face ID, if the key store asks.
            let response = try await presentation.respond(document: 0, credentialID: chosen, elements: document.elements)
            return ISO18013MobileDocumentResponse(responseData: response.response)
        }
    }
}
```

A real consent screen compares the released request with what it
showed — the same document, elements and reader — and refuses one that
changed. The demo wallet's `DocumentProvider` target does this in full.

### Name the reader

A page's request may be signed by its reader's certificate (ISO/IEC
18013-5 reader authentication). When the certificate chains to
``WalletConfiguration/mdocReaderRoots``, ``MdocPresentation/Request/reader``
names it; otherwise show only the website's origin.
``WalletConfiguration/mdocReaderRequireEKU`` accepts only certificates
issued for readers, and ``WalletConfiguration/requireTrustedMdocReader``
refuses requests from any other reader before the holder sees them.

### Warn of linkable presentations

Each candidate's ``CredentialSummary/linkableHere`` says whether
presenting it would hand this website a copy another website has seen,
and ``MdocPresentation/Response/linkable`` whether it did. The
extension doesn't refresh used-up copies: have the app do it when it
next becomes active, after listing its credentials again.
