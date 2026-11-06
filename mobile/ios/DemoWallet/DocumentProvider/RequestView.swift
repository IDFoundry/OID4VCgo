import IdentityDocumentServices
import IdentityDocumentServicesUI
import OID4VCWallet
import Security
import SwiftUI

/// The holder's consent to one org-iso-mdoc request, which may ask for
/// several documents. What it shows comes from iOS's parsing of the
/// request; only once the holder shares does iOS release the request
/// itself, which the wallet then parses, checks against what was shown,
/// and answers with every document the holder chose, in one response.
struct RequestView: View {
    let context: ISO18013MobileDocumentRequestContext

    @State private var held: [CredentialSummary] = []
    /// The credential chosen for each shown document, by `Asked.id`.
    @State private var chosen: [Int: String] = [:]
    /// The shown documents the holder has left out, by `Asked.id`.
    @State private var leftOut: Set<Int> = []
    @State private var problem: String?
    @State private var sharing = false

    /// One requested document, as iOS parsed it.
    struct Asked: Identifiable, Sendable {
        let id: Int
        let doctype: String
        let elements: [MdocPresentation.Element]
    }

    private var origin: String? { context.requestingWebsiteOrigin.flatMap(MdocPresentation.origin(of:)) }

    /// Every requested document, each doctype once: a response answers
    /// a doctype once, as a document names only its doctype.
    private var asked: [Asked] {
        var out: [Asked] = []
        for request in context.request.presentmentRequests {
            for set in request.documentRequestSets {
                for document in set.requests where !out.contains(where: { $0.doctype == document.documentType }) {
                    let elements = document.namespaces.flatMap { ns, els in
                        els.map { MdocPresentation.Element(namespace: ns, identifier: $0.key, retain: $0.value.isRetaining) }
                    }.sorted { ($0.namespace, $0.identifier) < ($1.namespace, $1.identifier) }
                    out.append(Asked(id: out.count, doctype: document.documentType, elements: elements))
                }
            }
        }
        return out
    }

    /// The requested documents the wallet holds an mdoc for.
    private var answerable: [Asked] { asked.filter { a in held.contains { $0.doctype == a.doctype } } }

    /// The requested documents it doesn't.
    private var unheld: [Asked] { asked.filter { a in !held.contains { $0.doctype == a.doctype } } }

    /// The documents the holder would share: answerable, not left out,
    /// with a credential chosen.
    private var toShare: [Asked] { answerable.filter { !leftOut.contains($0.id) && chosen[$0.id] != nil } }

    private func candidates(_ a: Asked) -> [CredentialSummary] { held.filter { $0.doctype == a.doctype } }

    private func chosenCredential(_ a: Asked) -> CredentialSummary? { held.first { $0.id == chosen[a.id] } }

    /// The reader's name and certificate, when the request is signed by
    /// a certificate under the configured mdoc reader roots: checked
    /// again, with the request's own signature, before anything is
    /// shared.
    private var recognizedReader: (name: String, certificate: Data)? {
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
        guard let name = name as String? else { return nil }
        return (name, SecCertificateCopyData(leaf) as Data)
    }

    var body: some View {
        NavigationStack {
            List {
                Section("Asking") {
                    if let reader = recognizedReader {
                        Label(reader.name, systemImage: "checkmark.seal")
                    }
                    Text(origin ?? "an unknown website").font(.headline)
                }
                ForEach(answerable) { a in
                    documentSection(a)
                }
                if !unheld.isEmpty, !answerable.isEmpty {
                    Section {
                        LabeledContent("Also asked for, not in this wallet", value: unheld.map { name(of: $0.doctype) }.joined(separator: ", "))
                    }
                }
                if answerable.isEmpty, problem == nil {
                    Section { Text("This wallet holds nothing this website asks for.") }
                }
                if let problem {
                    Section { Text(problem).foregroundStyle(.red) }
                }
            }
            .navigationTitle(answerable.count > 1 ? "Share your IDs?" : "Share your ID?")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { context.cancel() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(toShare.count > 1 ? "Share \(toShare.count)" : "Share") { share() }
                        .disabled(toShare.isEmpty || sharing || origin == nil)
                }
            }
            .task { await load() }
        }
    }

    /// One requested document: what it shares, which credential, and,
    /// when several are asked for, whether to share it at all.
    @ViewBuilder
    private func documentSection(_ a: Asked) -> some View {
        let included = !leftOut.contains(a.id)
        Section("Shares from your \(name(of: a.doctype))") {
            if answerable.count > 1 {
                Toggle("Share this document", isOn: Binding(
                    get: { !leftOut.contains(a.id) },
                    set: { on in if on { leftOut.remove(a.id) } else { leftOut.insert(a.id) } }))
            }
            ForEach(a.elements, id: \.self) { e in
                HStack {
                    Text(e.identifier.replacingOccurrences(of: "_", with: " ").capitalized)
                    Spacer()
                    if e.retain { Text("kept").font(.caption).foregroundStyle(.secondary) }
                }
                .foregroundStyle(included ? .primary : .secondary)
            }
        }
        let options = candidates(a)
        if included, options.count > 1 {
            Section("Which \(name(of: a.doctype))") {
                Picker("Credential", selection: Binding(get: { chosen[a.id] }, set: { chosen[a.id] = $0 })) {
                    ForEach(options, id: \.id) { c in
                        Text((c.display?.name ?? name(of: a.doctype)) + (c.linkableHere == true ? " (linkable)" : "")).tag(Optional(c.id))
                    }
                }
                .pickerStyle(.inline)
                .labelsHidden()
            }
        }
        if included, chosenCredential(a)?.linkableHere == true {
            Section {
                Label("Every copy of this ID has been shown to another website, so this website and that one could tell it's you both times. Refresh it in the wallet app for new copies.",
                      systemImage: "link")
                    .foregroundStyle(.orange)
            }
        }
    }

    private func name(of doctype: String) -> String {
        doctype == "org.iso.23220.photoid.1" ? "Photo ID" : doctype
    }

    private func wallet() throws -> Wallet {
        guard let config = DemoConfiguration.load() else { throw RequestError("Open the wallet app first.") }
        // The holder's own choices in the app, such as which copy a
        // presentation uses, apply here too.
        return try Wallet(configuration: SharedWallet.applyingHolderChoices(to: config.wallet), keyStore: SharedWallet.keyStore(),
                          credentialStore: try SharedWallet.credentialStore(), provider: nil)
    }

    private func load() async {
        guard let origin else { return }
        do {
            // Each with whether presenting it to this origin would be
            // linkable, for the holder to see before agreeing.
            held = try await wallet().mdocCandidates(origin: origin).filter(Self.presentable)
            for a in answerable {
                let options = candidates(a)
                chosen[a.id] = (options.first { $0.linkableHere != true } ?? options.first)?.id
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

    /// What the holder agreed to for one document: shown before iOS
    /// released the request, checked against it after.
    private struct Agreed: Sendable {
        let doctype: String
        let elements: [MdocPresentation.Element]
        let credentialID: String
        let toldLinkable: Bool
    }

    private func share() {
        guard let origin, let originURL = context.requestingWebsiteOrigin else { return }
        let agreed = toShare.compactMap { a -> Agreed? in
            guard let id = chosen[a.id] else { return nil }
            return Agreed(doctype: a.doctype, elements: a.elements, credentialID: id, toldLinkable: chosenCredential(a)?.linkableHere == true)
        }
        guard !agreed.isEmpty else { return }
        let reader = recognizedReader
        sharing = true
        problem = nil
        Task {
            do {
                // One confirmation for the whole response, however many
                // documents it carries.
                try await SharedWallet.confirmHolder(reason: agreed.count > 1
                    ? "Share \(agreed.count) IDs with \(reader?.name ?? origin)."
                    : "Share your ID with \(reader?.name ?? origin).")
                let wallet = try wallet()
                try await context.sendResponse { raw in
                    // Apple's guidance: check the raw request against the
                    // origin before answering it.
                    _ = try IdentityDocumentWebPresentmentRawRequestValidator()
                        .validateISO18013MobileDocumentRequest(raw.requestData, origin: originURL)
                    let p = try await wallet.startMdocPresentation(requestData: raw.requestData, origin: origin)
                    // The certificate shown, not just its name: two can
                    // share one.
                    if let reader, p.request.readerCertificate != reader.certificate {
                        throw RequestError("The request isn't signed by \(reader.name).")
                    }
                    // Answer only what the holder was shown, document by
                    // document.
                    let answers = try agreed.map { a -> MdocPresentation.Answer in
                        guard let index = p.request.documents.firstIndex(where: { $0.doctype == a.doctype }),
                              Set(p.request.documents[index].elements) == Set(a.elements) else {
                            throw RequestError("The request changed after it was shown.")
                        }
                        // Nor a copy another website has seen, unless the
                        // holder was told.
                        if p.request.documents[index].credentials.first(where: { $0.id == a.credentialID })?.linkableHere == true, !a.toldLinkable {
                            throw RequestError("Sharing this ID now would be linkable to another website. Try again to see why.")
                        }
                        return MdocPresentation.Answer(document: index, credentialID: a.credentialID, elements: a.elements)
                    }
                    let response = try await p.respond(answers: answers)
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
