import Foundation
import OID4VCWallet
#if canImport(IdentityDocumentServices)
import IdentityDocumentServices
#endif

/// Tells iOS which mdocs the wallet can present over the Digital
/// Credentials API, so Safari offers the app — through its document
/// provider extension — when a page asks for one of their doctypes.
enum DocumentRegistrations {
    /// The doctypes this build may register: its
    /// `com.apple.developer.identity-document-services.document-provider.mobile-document-types`
    /// entitlement's.
    static let doctypes: Set<String> = ["org.iso.23220.photoid.1"]

    /// Registers each presentable mdoc in `credentials` — one of
    /// `doctypes`, unexpired, with its holder key — for readers whose
    /// certificates the `readerRootsPEM` CAs issued, and removes every
    /// other registration. Before the holder has allowed the app to
    /// provide documents, the first registration asks them.
    static func sync(_ credentials: [CredentialSummary], readerRootsPEM: String) async {
        #if canImport(IdentityDocumentServices) && os(iOS)
        guard #available(iOS 26.0, *) else { return }
        let store = IdentityDocumentProviderRegistrationStore()
        let authorities = SharedWallet.subjectKeyIdentifiers(pem: readerRootsPEM)
        let now = Date()
        let wanted = credentials.filter { c in
            c.format == "mso_mdoc" && doctypes.contains(c.doctype ?? "") && !c.isExpired(at: now) && c.holderKeyPresent != false
        }
        let registered = (try? await store.registrations.map(\.documentIdentifier)) ?? []
        for id in registered where !wanted.contains(where: { $0.id == id }) {
            try? await store.removeRegistration(forDocumentIdentifier: id)
        }
        for c in wanted where !registered.contains(c.id) {
            let registration = MobileDocumentRegistration(mobileDocumentType: c.doctype ?? "", supportedAuthorityKeyIdentifiers: authorities,
                                                          documentIdentifier: c.id, invalidationDate: c.validUntil)
            do {
                try await store.addRegistration(registration)
            } catch {
                // Not authorized, or unsupported here: Safari won't offer
                // the app, and nothing else changes.
                return
            }
        }
        #endif
    }
}
