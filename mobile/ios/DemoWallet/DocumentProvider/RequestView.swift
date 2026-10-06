import IdentityDocumentServices
import IdentityDocumentServicesUI
import LocalAuthentication
import OID4VCWallet
import Security
import SwiftUI

/// The holder's consent to one org-iso-mdoc request. What it shows comes
/// from iOS's parsing of the request; only once the holder shares does
/// iOS release the request itself, which the wallet then parses, checks
/// against what was shown, and answers.
struct RequestView: View {
    let context: ISO18013MobileDocumentRequestContext

    @State private var held: [CredentialSummary] = []
    @State private var chosen: String?
    @State private var problem: String?
    @State private var sharing = false

    /// One requested document, as iOS parsed it.
    struct Asked: Identifiable, Sendable {
        let id: Int
        let doctype: String
        let elements: [MdocPresentation.Element]
    }

    private var origin: String? { context.requestingWebsiteOrigin.flatMap(MdocPresentation.origin(of:)) }

    private var asked: [Asked] {
        var out: [Asked] = []
        for request in context.request.presentmentRequests {
            for set in request.documentRequestSets {
                for document in set.requests {
                    let elements = document.namespaces.flatMap { ns, els in
                        els.map { MdocPresentation.Element(namespace: ns, identifier: $0.key, retain: $0.value.isRetaining) }
                    }.sorted { ($0.namespace, $0.identifier) < ($1.namespace, $1.identifier) }
                    out.append(Asked(id: out.count, doctype: document.documentType, elements: elements))
                }
            }
        }
        return out
    }

    /// The first requested document the wallet holds an mdoc for.
    private var answerable: Asked? { asked.first { a in held.contains { $0.doctype == a.doctype } } }

    /// The chosen credential, as last loaded.
    private var chosenCredential: CredentialSummary? { held.first { $0.id == chosen } }

    /// The reader's name, when the request is signed by a certificate
    /// under the configured mdoc reader roots: checked again, with the
    /// request's own signature, before anything is shared.
    private var recognizedReader: String? {
        guard let chain = context.request.requestAuthentications.first?.authenticationCertificateChain, let leaf = chain.first,
              let roots = DemoConfiguration.load()?.wallet.mdocReaderRoots, !roots.isEmpty else { return nil }
        let anchors = roots.components(separatedBy: "-----BEGIN CERTIFICATE-----").dropFirst().compactMap { block -> SecCertificate? in
            guard let body = block.components(separatedBy: "-----END CERTIFICATE-----").first,
                  let der = Data(base64Encoded: body, options: .ignoreUnknownCharacters) else { return nil }
            return SecCertificateCreateWithData(nil, der as CFData)
        }
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(chain as CFArray, SecPolicyCreateBasicX509(), &trust) == errSecSuccess, let trust,
              SecTrustSetAnchorCertificates(trust, anchors as CFArray) == errSecSuccess,
              SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess,
              SecTrustEvaluateWithError(trust, nil) else { return nil }
        var name: CFString?
        SecCertificateCopyCommonName(leaf, &name)
        return name as String?
    }

    var body: some View {
        NavigationStack {
            List {
                Section("Asking") {
                    if let reader = recognizedReader {
                        Label(reader, systemImage: "checkmark.seal")
                    }
                    Text(origin ?? "an unknown website").font(.headline)
                }
                if let a = answerable {
                    Section("Shares from your \(name(of: a.doctype))") {
                        ForEach(a.elements, id: \.self) { e in
                            HStack {
                                Text(e.identifier.replacingOccurrences(of: "_", with: " ").capitalized)
                                Spacer()
                                if e.retain { Text("kept").font(.caption).foregroundStyle(.secondary) }
                            }
                        }
                    }
                    let candidates = held.filter { $0.doctype == a.doctype }
                    if candidates.count > 1 {
                        Section("Which one") {
                            Picker("Credential", selection: $chosen) {
                                ForEach(candidates, id: \.id) { c in
                                    Text((c.display?.name ?? name(of: a.doctype)) + (c.linkableHere == true ? " (linkable)" : "")).tag(Optional(c.id))
                                }
                            }
                            .pickerStyle(.inline)
                            .labelsHidden()
                        }
                    }
                    if chosenCredential?.linkableHere == true {
                        Section {
                            Label("Every copy of this ID has been shown to another website, so this website and that one could tell it's you both times. Refresh it in the wallet app for new copies.",
                                  systemImage: "link")
                                .foregroundStyle(.orange)
                        }
                    }
                } else if problem == nil {
                    Section { Text("This wallet holds nothing this website asks for.") }
                }
                if let problem {
                    Section { Text(problem).foregroundStyle(.red) }
                }
            }
            .navigationTitle("Share your ID?")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { context.cancel() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Share") { share() }
                        .disabled(answerable == nil || chosen == nil || sharing || origin == nil)
                }
            }
            .task { await load() }
        }
    }

    private func name(of doctype: String) -> String {
        doctype == "org.iso.23220.photoid.1" ? "Photo ID" : doctype
    }

    private func wallet() throws -> Wallet {
        guard let config = DemoConfiguration.load() else { throw RequestError("Open the wallet app first.") }
        let presence = LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
        // The holder's own choices in the app, such as which copy a
        // presentation uses, apply here too.
        return try Wallet(configuration: SharedWallet.applyingHolderChoices(to: config.wallet), keyStore: SharedWallet.keyStore(presence: presence),
                          credentialStore: try SharedWallet.credentialStore(), provider: nil)
    }

    private func load() async {
        guard let origin else { return }
        do {
            // Each with whether presenting it to this origin would be
            // linkable, for the holder to see before agreeing.
            held = try await wallet().mdocCandidates(origin: origin).filter(Self.presentable)
            if let a = answerable {
                let candidates = held.filter { $0.doctype == a.doctype }
                chosen = (candidates.first { $0.linkableHere != true } ?? candidates.first)?.id
            }
        } catch {
            problem = describe(error)
        }
    }

    /// Whether c can be presented: its key is here, it hasn't expired, and
    /// its issuer hasn't revoked or suspended it, as last checked.
    static func presentable(_ c: CredentialSummary) -> Bool {
        guard c.holderKeyPresent != false, !c.isExpired() else { return false }
        switch c.status?.value {
        case .revoked, .suspended: return false
        default: return true
        }
    }

    private func share() {
        guard let shown = answerable, let credentialID = chosen, let origin, let originURL = context.requestingWebsiteOrigin else { return }
        let reader = recognizedReader
        let toldLinkable = chosenCredential?.linkableHere == true
        sharing = true
        problem = nil
        Task {
            do {
                let wallet = try wallet()
                try await context.sendResponse { raw in
                    // Apple's guidance: check the raw request against the
                    // origin before answering it.
                    _ = try IdentityDocumentWebPresentmentRawRequestValidator()
                        .validateISO18013MobileDocumentRequest(raw.requestData, origin: originURL)
                    let p = try await wallet.startMdocPresentation(requestData: raw.requestData, origin: origin)
                    // Answer only what the holder was shown.
                    guard let index = p.request.documents.firstIndex(where: { $0.doctype == shown.doctype }),
                          Set(p.request.documents[index].elements) == Set(shown.elements) else {
                        throw RequestError("The request changed after it was shown.")
                    }
                    if let reader, p.request.reader != reader {
                        throw RequestError("The request isn't signed by \(reader).")
                    }
                    // Nor a copy another website has seen, unless the
                    // holder was told.
                    if p.request.documents[index].credentials.first(where: { $0.id == credentialID })?.linkableHere == true, !toldLinkable {
                        throw RequestError("Sharing this ID now would be linkable to another website. Try again to see why.")
                    }
                    let response = try await p.respond(document: index, credentialID: credentialID, elements: shown.elements)
                    return ISO18013MobileDocumentResponse(responseData: response.response)
                }
            } catch {
                sharing = false
                problem = describe(error)
            }
        }
    }

    private func describe(_ error: Error) -> String {
        if let e = error as? RequestError { return e.message }
        if let e = error as? WalletError { return e.message }
        return error.localizedDescription
    }
}

struct RequestError: Error {
    let message: String
    init(_ message: String) { self.message = message }
}
