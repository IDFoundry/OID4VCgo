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
    @State private var problem: String?

    /// The request's first document as iOS parsed it: what the consent
    /// screen shows the holder.
    private var shown: (doctype: String, elements: [MdocPresentation.Element])? {
        guard let document = context.request.presentmentRequests.first?.documentRequestSets.first?.requests.first else {
            return nil
        }
        let elements = document.namespaces.flatMap { namespace, elements in
            elements.map { MdocPresentation.Element(namespace: namespace, identifier: $0.key, retain: $0.value.isRetaining) }
        }
        return (document.documentType, elements)
    }

    var body: some View {
        VStack {
            if let problem { Text(problem) }
            Button("Share") { Task { await share(credentialID: nil) } }
            Button("Cancel") { context.cancel() }
        }
    }

    /// Shares the held mdoc `credentialID` (the first candidate when
    /// nil), for exactly the document and elements the holder was shown.
    func share(credentialID: String?) async {
        guard let shown, let originURL = context.requestingWebsiteOrigin,
              let origin = MdocPresentation.origin(of: originURL) else { return }
        do {
            let wallet = try SharedWallet.open(provider: nil)
            try await context.sendResponse { raw in
                _ = try IdentityDocumentWebPresentmentRawRequestValidator()
                    .validateISO18013MobileDocumentRequest(raw.requestData, origin: originURL)
                let presentation = try await wallet.startMdocPresentation(requestData: raw.requestData, origin: origin)
                // Answer only what the holder was shown.
                guard let index = presentation.request.documents.firstIndex(where: { $0.doctype == shown.doctype }),
                      Set(presentation.request.documents[index].elements) == Set(shown.elements),
                      let chosen = credentialID ?? presentation.request.documents[index].credentials.first?.id else {
                    throw RequestChanged()
                }
                // The holder key signs now: Face ID, if the key store asks.
                let response = try await presentation.respond(document: index, credentialID: chosen, elements: shown.elements)
                return ISO18013MobileDocumentResponse(responseData: response.response)
            }
        } catch {
            // Nothing was shared: say so, and let the holder cancel.
            problem = "Not shared: \(error)"
        }
    }
}
```

The response answers the elements the holder was shown, not those the
released request names, and a request that changed in between is
refused. Where the consent screen names the reader (below), compare its
certificate with ``MdocPresentation/Request/readerCertificate`` there
too. The demo wallet's `DocumentProvider` target does all of this, with
a choice of credential and a linkability warning.

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
