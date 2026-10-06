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
    /// `doctypes`, unexpired, not revoked or suspended as last checked,
    /// with its holder key — for readers whose
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
                && c.status?.value != .revoked && c.status?.value != .suspended
        }
        // A registration is current while its credential is wanted and
        // expires when it does: a refresh can change that.
        var registered: [String] = []
        for r in (try? await store.registrations) ?? [] {
            let current = wanted.first { $0.id == r.documentIdentifier }
            if let current, (r as? MobileDocumentRegistration)?.invalidationDate == current.validUntil {
                registered.append(r.documentIdentifier)
            } else {
                try? await store.removeRegistration(forDocumentIdentifier: r.documentIdentifier)
            }
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
