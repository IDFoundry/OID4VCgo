import CryptoKit
import Observation
import OID4VCWallet
import Security
import SwiftUI
import UIKit

// In person: ISO/IEC 18013-5 over BLE. The holder shows a QR code and
// answers a reader; reader mode, on in the settings, verifies another
// phone's mdoc.

/// The demo reader's key — a software P-256 key from the configuration
/// (DemoConfiguration.Reader) — as the KeyStore a ProximityReader signs
/// with. Demo only: a real reader keeps its key in the Secure Enclave.
struct DemoReaderKeys: KeyStore {
    static let id = "demo-reader"
    private let x963: Data

    init(_ reader: DemoConfiguration.Reader) throws {
        x963 = try P256.Signing.PrivateKey(pemRepresentation: reader.readerKey).x963Representation
    }

    func createKey(purpose _: KeyPurpose) throws -> String { throw DemoReaderKeysError() }

    func publicKey(id: String) throws -> Data? {
        guard id == Self.id else { return nil }
        return try P256.Signing.PrivateKey(x963Representation: x963).publicKey.x963Representation
    }

    func sign(id: String, digest: Data) throws -> Data {
        guard id == Self.id else { throw DemoReaderKeysError() }
        var error: Unmanaged<CFError>?
        let attributes = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPrivate] as CFDictionary
        guard let key = SecKeyCreateWithData(x963 as CFData, attributes, &error),
              let signature = SecKeyCreateSignature(key, .ecdsaSignatureDigestX962SHA256, digest as CFData, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return signature as Data
    }

    func deleteKey(id _: String) throws {
        // The demo reader's one key is fixed: there's nothing to delete.
    }
}

struct DemoReaderKeysError: Error {}

/// A request reader mode makes: one or more documents, each a type and
/// its elements.
struct ReaderPreset: Identifiable, Hashable {
    struct Document: Hashable {
        let docType: String
        let elements: [String: [String]]
    }

    let title: String
    let documents: [Document]
    var id: String { title }

    init(title: String, documents: [Document]) {
        self.title = title
        self.documents = documents
    }

    /// One document: `docType`'s `elements`.
    init(title: String, docType: String, elements: [String: [String]]) {
        self.init(title: title, documents: [Document(docType: docType, elements: elements)])
    }

    /// What this preset asks of documents of `docType`, by namespace.
    func elements(for docType: String) -> [String: [String]] {
        documents.first { $0.docType == docType }?.elements ?? [:]
    }

    /// The passport-vdc Photo ID, an mDL, and the test services' mdocs.
    /// The "and" ones ask for two documents in one request: the holder
    /// shares either or both.
    static let all: [ReaderPreset] = {
        let identity = ["family_name", "given_name", "portrait", "age_over_18"]
        let name = ["family_name", "given_name"]
        return [
            ReaderPreset(title: "Photo ID: over 18?", docType: "org.iso.23220.photoid.1", elements: ["org.iso.23220.1": ["age_over_18"]]),
            ReaderPreset(title: "Photo ID: name, photo and age", docType: "org.iso.23220.photoid.1", elements: ["org.iso.23220.1": identity]),
            ReaderPreset(title: "Driving licence: over 18?", docType: "org.iso.18013.5.1.mDL", elements: ["org.iso.18013.5.1": ["age_over_18"]]),
            ReaderPreset(title: "Driving licence: name, photo and age", docType: "org.iso.18013.5.1.mDL", elements: ["org.iso.18013.5.1": identity]),
            ReaderPreset(title: "Photo ID and driving licence: name", documents: [
                Document(docType: "org.iso.23220.photoid.1", elements: ["org.iso.23220.1": name]),
                Document(docType: "org.iso.18013.5.1.mDL", elements: ["org.iso.18013.5.1": name]),
            ]),
            ReaderPreset(title: "Test mdoc: name", docType: "org.example.test.1", elements: ["org.example.test.1": name]),
            ReaderPreset(title: "Test mdocs 1 and 2: name", documents: [
                Document(docType: "org.example.test.1", elements: ["org.example.test.1": name]),
                Document(docType: "org.example.test.2", elements: ["org.example.test.2": name]),
            ]),
        ]
    }()
}

/// An element identifier as a label: "age_over_18" → "Age over 18".
func elementLabel(_ identifier: String) -> String {
    let words = identifier.replacingOccurrences(of: "_", with: " ")
    return words.prefix(1).uppercased() + words.dropFirst()
}

/// The in-person sessions: the holder's, and reader mode's.
@MainActor @Observable
final class InPersonModel {
    private(set) var presentation: ProximityPresentation?
    private(set) var state: ProximityPresentation.State?
    private(set) var reading: ProximityReaderSession?
    private(set) var readingState: ProximityReaderSession.State?
    private(set) var readingPreset: ReaderPreset?
    var notice: String?
    private var watch: Task<Void, Never>?
    private var reader: ProximityReader?

    func share(_ model: WalletModel) {
        guard presentation == nil, let wallet = model.wallet else { return }
        notice = nil
        do {
            let p = try wallet.startProximityPresentation(modes: model.bleModes)
            presentation = p
            UIApplication.shared.isIdleTimerDisabled = true
            watch = Task { [weak self] in
                for await s in p.states {
                    self?.state = s
                    if s.isFinal { await model.refresh() }
                }
            }
        } catch {
            notice = WalletModel.describe(error)
        }
    }

    /// Shares `answers` with the reader in one response; the holder
    /// confirms once for them all.
    func respond(_ answers: [MdocPresentation.Answer]) {
        guard let p = presentation else { return }
        Task {
            do {
                let reason = answers.count > 1 ? "Share \(answers.count) documents with the reader." : "Share your credential with the reader."
                try await SharedWallet.confirmHolder(reason: reason)
                try await p.respond(answers: answers)
            } catch {
                // A cancelled prompt leaves the request standing.
                notice = WalletModel.describe(error)
            }
        }
    }

    func decline() {
        guard let p = presentation else { return }
        Task { await p.decline() }
    }

    func closeSharing() {
        presentation?.cancel()
        watch?.cancel()
        presentation = nil
        state = nil
        UIApplication.shared.isIdleTimerDisabled = false
    }

    /// The reader's last refresh of its revocation lists, this launch.
    private(set) var readerCRLs: WalletModel.CRLRefresh?
    private(set) var refreshingCRLs = false

    /// The demo reader, made on first use from the configuration's
    /// `reader`; nil without one.
    private func makeReader(_ model: WalletModel) throws -> ProximityReader? {
        if let reader { return reader }
        guard let r = model.config?.reader else { return nil }
        let saved = SharedWallet.defaults.string(forKey: SharedWallet.readerCRLsKey) ?? ""
        do {
            reader = try ProximityReader(configuration: Self.configuration(r, crls: saved), keyStore: try DemoReaderKeys(r))
        } catch let e as WalletError where e.code == .invalidInput && !saved.isEmpty {
            // Saved lists the reader refuses: start without them, and the
            // next refresh fetches them again.
            SharedWallet.defaults.removeObject(forKey: SharedWallet.readerCRLsKey)
            reader = try ProximityReader(configuration: Self.configuration(r, crls: ""), keyStore: try DemoReaderKeys(r))
        }
        return reader
    }

    /// A production reader's decisions: the demo's one IACA issues every
    /// type it reads. The roles the configuration names are checked
    /// against the IACA's Certificate Revocation List — the document
    /// signer's chain, and a status list signer's — with `crls` the lists
    /// last fetched, refreshed by refreshCRLs; the others decline it, as
    /// for services that publish no CRLs. A shipping reader checks both.
    private static func configuration(_ r: DemoConfiguration.Reader, crls: String) -> ProximityReaderConfiguration {
        let checked = r.revocation ?? []
        return ProximityReaderConfiguration(issuerRoots: r.issuerRoots, readerKeyID: DemoReaderKeys.id,
                                            readerChain: r.readerChain, maxClockSkewSeconds: 300,
                                            crls: crls, revocation: checked,
                                            noRevocationCheck: ProximityReaderConfiguration.RevocationRole.allCases.filter { !checked.contains($0) },
                                            anyIssuerForAnyType: true, statusCheck: .check, development: r.development ?? false,
                                            crlDistributionPoints: r.crlDistributionPoints ?? [],
                                            crlDistributionPointsFromRoots: r.crlDistributionPointsFromRoots ?? false,
                                            crlRequireHTTPS: r.crlRequireHTTPS ?? false)
    }

    /// Whether the configuration has the reader fetch revocation lists.
    func readerFetchesCRLs(_ model: WalletModel) -> Bool {
        guard let r = model.config?.reader else { return false }
        return r.crlDistributionPointsFromRoots == true || !(r.crlDistributionPoints ?? []).isEmpty
    }

    /// Whether the reader's lists are due again: the last refresh failed,
    /// or its nextRefresh has passed. The first, at launch, is the
    /// launch's.
    func readerCRLsDue(_ model: WalletModel) -> Bool {
        guard readerFetchesCRLs(model), let last = readerCRLs else { return false }
        guard let next = last.result?.nextRefresh, last.error == nil else { return true }
        return next <= .now
    }

    /// Fetches the reader's Certificate Revocation Lists and keeps them for
    /// the next launch, as WalletModel.refreshCRLs does the wallet's: at
    /// launch (making the reader), on returning to the foreground once
    /// they're due, and from the settings. Nothing schedules it in the
    /// background (BGTaskScheduler would, at the result's nextRefresh).
    func refreshReaderCRLs(_ model: WalletModel) async {
        guard readerFetchesCRLs(model), !refreshingCRLs else { return }
        refreshingCRLs = true
        defer { refreshingCRLs = false }
        do {
            guard let reader = try makeReader(model) else { return }
            let result = try await reader.refreshCRLs()
            SharedWallet.defaults.set(result.crls, forKey: SharedWallet.readerCRLsKey)
            readerCRLs = WalletModel.CRLRefresh(result: result, at: .now)
        } catch {
            readerCRLs = WalletModel.CRLRefresh(result: readerCRLs?.result, error: WalletModel.describe(error), at: .now)
        }
    }

    /// Reads the holder's `qrCode`, asking for `preset`.
    func read(_ qrCode: String, preset: ReaderPreset, model: WalletModel) {
        do {
            guard let reader = try makeReader(model) else { return }
            let session = try reader.start(qrCode: qrCode, documents: preset.documents.map {
                ProximityReader.DocumentRequest(docType: $0.docType, elements: $0.elements)
            })
            reading = session
            readingPreset = preset
            watch = Task { [weak self] in
                for await s in session.states { self?.readingState = s }
            }
        } catch {
            notice = WalletModel.describe(error)
        }
    }

    func closeReading() {
        reading?.cancel()
        watch?.cancel()
        reading = nil
        readingState = nil
        readingPreset = nil
    }
}

// MARK: The holder's side

/// The Present tab: the QR code, the reader's request, and the outcome;
/// with no session, why not, and Try again. RootView starts a session on
/// opening the tab and ends it on leaving; Done starts the next.
struct InPersonView: View {
    @Environment(WalletModel.self) private var model
    @Environment(InPersonModel.self) private var inPerson

    var body: some View {
        NavigationStack {
            Group {
                if inPerson.presentation == nil {
                    NoSessionView { inPerson.share(model) }
                } else {
                    switch inPerson.state {
                    case nil, .waitingForReader?:
                        QRCodeView(text: inPerson.presentation?.qrCode ?? "")
                    case .connected?:
                        ProgressView("Reader connected: waiting for its request…").accessibilityIdentifier("in-person-status")
                    case .requestReceived(let request)?:
                        ConsentView(request: request)
                    case .responding?:
                        ProgressView("Sharing…")
                    case let s?:
                        OutcomeView(text: outcome(s)) {
                            inPerson.closeSharing()
                            inPerson.share(model)
                        }
                    }
                }
            }
            .navigationTitle("Share in person")
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    private func outcome(_ s: ProximityPresentation.State) -> String {
        switch s {
        case .presented(let linkable):
            "Shared with the reader." + (linkable ? " That copy had been shown to another verifier before." : "")
        case .declined: "Declined: nothing was shared."
        case .readerEnded: "The reader ended the session."
        case .cancelled: "Cancelled."
        case .failed(let error as ProximityError): error.localizedDescription
        case .failed(let error): WalletModel.describe(error)
        default: ""
        }
    }
}

/// No session: Bluetooth off, nothing to share, or not configured.
private struct NoSessionView: View {
    @Environment(WalletModel.self) private var model
    @Environment(InPersonModel.self) private var inPerson
    let start: () -> Void

    var body: some View {
        VStack(spacing: 20) {
            Text(inPerson.notice ?? (model.credentials.contains { $0.format == "mso_mdoc" } ? "Not sharing." : "You hold no mdoc to share in person yet."))
                .multilineTextAlignment(.center)
                .accessibilityIdentifier("in-person-status")
            Button("Try again", action: start).disabled(!model.configured).accessibilityIdentifier("share-in-person")
        }
        .padding(24)
    }
}

private struct QRCodeView: View {
    let text: String

    var body: some View {
        VStack(spacing: 20) {
            if let image = QRCode.image(of: text) {
                Image(decorative: image, scale: 1)
                    .interpolation(.none)
                    .resizable()
                    .scaledToFit()
                    .padding(12)
                    .background(.white, in: RoundedRectangle(cornerRadius: 12))
                    .accessibilityLabel("QR code for the reader")
                    .accessibilityIdentifier("in-person-qr")
            }
        }
        .padding(24)
    }
}

/// Who is asking, what for, and the holder's choice: every requested
/// document the wallet holds, each with its elements to tick, shared in
/// one response; the ones it doesn't hold are named.
private struct ConsentView: View {
    @Environment(InPersonModel.self) private var inPerson
    let request: ProximityPresentation.Request
    @State private var unchosen: Set<String> = []

    /// A requested document the wallet can answer: its number in the
    /// request, and the held mdoc that answers it.
    private struct Answerable: Identifiable {
        let index: Int
        let document: MdocPresentation.Document
        let credential: CredentialSummary
        var id: Int { index }
    }

    private var answerable: [Answerable] {
        request.documents.enumerated().compactMap { i, d in d.credentials.first.map { Answerable(index: i, document: d, credential: $0) } }
    }

    private var missing: [MdocPresentation.Document] { request.documents.filter { $0.credentials.isEmpty } }

    private func key(_ index: Int, _ e: MdocPresentation.Element) -> String { "\(index)/\(e.namespace)/\(e.identifier)" }

    /// A document goes in the response when any of its elements is ticked.
    private var answers: [MdocPresentation.Answer] {
        answerable.compactMap { a in
            let chosen = a.document.elements.filter { !unchosen.contains(key(a.index, $0)) }
            return chosen.isEmpty ? nil : MdocPresentation.Answer(document: a.index, credentialID: a.credential.id, elements: chosen)
        }
    }

    var body: some View {
        List {
            Section { ReaderHeader(reader: request.reader) }
            if let notice = inPerson.notice {
                Section { Text(notice).foregroundStyle(.orange) }
            }
            ForEach(answerable) { a in
                Section("It asks for, from \(a.credential.display?.name ?? a.document.doctype)") {
                    ForEach(a.document.elements, id: \.self) { e in
                        let k = key(a.index, e)
                        Toggle(isOn: Binding(get: { !unchosen.contains(k) },
                                             set: { if $0 { unchosen.remove(k) } else { unchosen.insert(k) } })) {
                            VStack(alignment: .leading) {
                                Text(elementLabel(e.identifier))
                                if e.retain { Text("The reader says it will keep this").font(.caption).foregroundStyle(.orange) }
                            }
                        }
                        .accessibilityIdentifier("in-person-element")
                    }
                }
            }
            if answerable.isEmpty {
                Section {
                    Text("You have nothing this reader asks for (\(request.documents.map(\.doctype).joined(separator: ", "))).")
                        .accessibilityIdentifier("in-person-nothing")
                    Button("Decline", role: .destructive) { inPerson.decline() }
                        .accessibilityIdentifier("in-person-decline")
                }
            } else {
                if !missing.isEmpty {
                    Section {
                        Text("It also asks for what you don't have: \(missing.map(\.doctype).joined(separator: ", ")).")
                            .font(.caption).accessibilityIdentifier("in-person-missing")
                    }
                }
                Section {
                    let chosen = self.answers
                    Button(chosen.count > 1 ? "Share \(chosen.count) documents" : "Share") { inPerson.respond(chosen) }
                        .disabled(chosen.isEmpty)
                        .accessibilityIdentifier("in-person-share")
                    Button("Decline", role: .destructive) { inPerson.decline() }
                        .accessibilityIdentifier("in-person-decline")
                }
            }
        }
    }
}

/// The reader as the wallet knows it: its name and how far it's verified.
private struct ReaderHeader: View {
    let reader: ProximityReaderIdentity

    /// Green for a trusted reader, red for an invalid one, orange otherwise.
    private var trustColor: Color {
        switch reader.status {
        case .trusted: .green
        case .invalid: .red
        default: .orange
        }
    }

    var body: some View {
        let trusted = reader.status == .trusted
        VStack(alignment: .leading, spacing: 6) {
            let name = reader.name.isEmpty ? "A nearby reader" : reader.name
            Text(trusted ? name : "“\(name)”").font(.title2).accessibilityIdentifier("in-person-reader")
            Label(badge, systemImage: trusted ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                .foregroundStyle(trustColor)
                .accessibilityIdentifier("in-person-trust")
            if !reader.certificates.isEmpty {
                NavigationLink("Reader certificate") { CertificatesView(certificates: reader.certificates) }
                    .accessibilityIdentifier("in-person-certificates")
            }
        }
    }

    private var badge: String {
        switch reader.status {
        case .trusted: "Verified reader"
        case .untrusted: "Unverified: its certificate isn't from a reader authority you trust"
        case .unauthenticated: "Unknown reader: it didn't identify itself"
        case .invalid: "Its identity doesn't check out"
        }
    }
}

/// A reader's certificate chain, leaf first, each certificate in full.
struct CertificatesView: View {
    let certificates: [ProximityReaderIdentity.CertificateDetails]

    /// The certificate at index i: the reader's, the root, or between.
    private func role(_ i: Int) -> String {
        if i == 0 { return "Reader" }
        return i == certificates.count - 1 ? "Root" : "Intermediate"
    }

    var body: some View {
        List {
            ForEach(Array(certificates.enumerated()), id: \.offset) { i, c in
                Section(role(i)) {
                    LabeledContent("Subject", value: c.subject)
                    LabeledContent("Issuer", value: c.issuer)
                    LabeledContent("Valid", value: "\(c.notBefore.formatted(date: .abbreviated, time: .shortened)) to \(c.notAfter.formatted(date: .abbreviated, time: .shortened))")
                    LabeledContent("Serial number", value: c.serial)
                    if !c.subjectAltNames.isEmpty { LabeledContent("Alternative names", value: c.subjectAltNames.joined(separator: ", ")) }
                    if !c.extendedKeyUsages.isEmpty { LabeledContent("Extended key usage", value: c.extendedKeyUsages.joined(separator: ", ")) }
                    if !c.keyUsages.isEmpty { LabeledContent("Key usage", value: c.keyUsages.joined(separator: ", ")) }
                    if c.isCA { LabeledContent("Certificate authority", value: "yes") }
                    LabeledContent("Signature algorithm", value: c.signatureAlgorithm)
                    if !c.extensions.isEmpty { LabeledContent("Extensions", value: c.extensions.joined(separator: "\n")) }
                    Text("SHA-256 \(c.sha256)").font(.caption.monospaced())
                }
            }
        }
        .navigationTitle("Reader certificate")
    }
}

private struct OutcomeView: View {
    let text: String
    let done: () -> Void

    var body: some View {
        VStack(spacing: 24) {
            Text(text).multilineTextAlignment(.center).accessibilityIdentifier("in-person-outcome")
            Button("Done", action: done).buttonStyle(.borderedProminent).accessibilityIdentifier("in-person-done")
        }
        .padding(24)
    }
}

// MARK: Reader mode

/// The Verify tab: choose what to ask for, scan the holder's QR code,
/// see what verified.
struct ReaderView: View {
    @Environment(WalletModel.self) private var model
    @Environment(InPersonModel.self) private var inPerson
    @State private var preset: ReaderPreset?
    @State private var scanning = false

    var body: some View {
        NavigationStack {
            Group {
                switch inPerson.readingState {
                case nil where model.config?.reader == nil:
                    ContentUnavailableView("No reader", systemImage: "checkmark.shield",
                                           description: Text("Verifying needs a reader in the configuration: see mobile/ios/DemoWallet/README.md."))
                        .accessibilityIdentifier("reader-unavailable")
                case nil where inPerson.reading == nil:
                    presets
                case nil, .connecting?:
                    ProgressView("Connecting to the holder's phone…")
                case .waitingForResponse?:
                    ProgressView("Waiting for the holder to agree…")
                case let s?:
                    ReaderOutcomeView(state: s, documents: inPerson.reading?.documents ?? [], preset: inPerson.readingPreset,
                                      mode: inPerson.reading?.mode,
                                      checksIssuerRevocation: model.config?.reader?.revocation?.contains(.issuer) ?? false) {
                        inPerson.closeReading()
                        model.engagementToRead = nil
                    }
                }
            }
            .navigationTitle("Verify in person")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                if inPerson.reading != nil {
                    Button("Cancel") {
                        inPerson.closeReading()
                        model.engagementToRead = nil
                    }
                }
            }
            .sheet(isPresented: $scanning) {
                ScanView(accept: QRCode.isEngagement, what: "mdoc") { url in
                    if let preset { inPerson.read(url.absoluteString, preset: preset, model: model) }
                }
            }
        }
    }

    private var presets: some View {
        List {
            Section(model.engagementToRead != nil ? "Read the holder's phone: what to ask for" : "What to ask for") {
                ForEach(ReaderPreset.all) { p in
                    Button {
                        preset = p
                        // An engagement handed over by link needs no scan.
                        if let given = model.engagementToRead {
                            inPerson.read(given, preset: p, model: model)
                        } else {
                            scanning = true
                        }
                    } label: {
                        VStack(alignment: .leading) {
                            Text(p.title)
                            let asked = p.documents.flatMap { $0.elements.values.flatMap { $0 } }
                                .reduce(into: [String]()) { if !$0.contains($1) { $0.append($1) } }
                            Text(asked.map(elementLabel).joined(separator: ", ")).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    .accessibilityIdentifier("reader-preset")
                }
            }
            if let notice = inPerson.notice {
                Section { Text(notice).foregroundStyle(.orange) }
            }
        }
    }
}

private struct ReaderOutcomeView: View {
    let state: ProximityReaderSession.State
    /// Every verified document, in the response's order: the session's.
    let documents: [VerifiedMdoc]
    let preset: ReaderPreset?
    let mode: ProximityBLEMode?
    /// Whether the reader checks the document signer's chain against
    /// its CA's revocation list.
    let checksIssuerRevocation: Bool
    let done: () -> Void

    var body: some View {
        List {
            switch state {
            case .verified(let first):
                let verified = documents.isEmpty ? [first] : documents
                Section {
                    Label(verified.count > 1 ? "Verified \(verified.count) documents" : "Verified", systemImage: "checkmark.seal.fill")
                        .foregroundStyle(.green).font(.title2)
                        .accessibilityIdentifier("reader-outcome")
                }
                ForEach(Array(verified.enumerated()), id: \.offset) { n, v in
                    let asked = preset?.elements(for: v.doctype) ?? [:]
                    ForEach(v.claims.keys.sorted(), id: \.self) { namespace in
                        if case .object(let elements)? = v.claims[namespace] {
                            Section(verified.count > 1 ? v.doctype : "") {
                                ForEach(elements.keys.sorted(), id: \.self) { identifier in
                                    ClaimRow(identifier: identifier, value: elements[identifier]!)
                                }
                                let missing = (asked[namespace] ?? []).filter { elements[$0] == nil }
                                if !missing.isEmpty { LabeledContent("Not shared", value: missing.map(elementLabel).joined(separator: ", ")) }
                            }
                        }
                    }
                    Section {
                        LabeledContent("Document", value: v.doctype)
                        LabeledContent("Issued by", value: "\(v.issuer) (trusted via \(v.trustAnchor))")
                        LabeledContent("Valid", value: "\(v.validFrom.formatted(date: .abbreviated, time: .shortened)) to \(v.validUntil.formatted(date: .abbreviated, time: .shortened))")
                        LabeledContent("Holder's device", value: v.deviceAuth == "mac" ? "authenticated (MAC)" : "authenticated (signature)")
                        if n == 0, let mode {
                            LabeledContent("Bluetooth", value: mode == .centralClient
                                ? "Central client mode: the holder connected to this reader"
                                : "Peripheral server mode: this reader connected to the holder")
                                .accessibilityIdentifier("reader-ble-mode")
                        }
                        if let s = v.statusList {
                            LabeledContent("Status list", value: v.status == nil ? "not checked: \(s.uri) #\(s.index)" : "\(statusWord(v.status)): \(s.uri) #\(s.index)")
                        }
                        LabeledContent("Issuer certificate", value: issuerRevocation)
                            .accessibilityIdentifier("reader-issuer-revocation")
                    }
                }
                // Asked for and not shared at all: the holder may share some documents and not others.
                let absent = (preset?.documents ?? []).map(\.docType).filter { dt in !verified.contains { $0.doctype == dt } }
                if !absent.isEmpty {
                    Section { LabeledContent("Not shared", value: absent.joined(separator: ", ")).accessibilityIdentifier("reader-absent") }
                }
            case .declined:
                Text("The holder declined.").accessibilityIdentifier("reader-outcome")
            case .cancelled:
                Text("Cancelled.").accessibilityIdentifier("reader-outcome")
            case .failed(let error as ProximityError):
                Text(error.localizedDescription).foregroundStyle(.red).accessibilityIdentifier("reader-outcome")
            case .failed(let error):
                Section {
                    Label("Not verified", systemImage: "xmark.octagon.fill").foregroundStyle(.red).font(.title2)
                        .accessibilityIdentifier("reader-outcome")
                    // A revoked document signer, or no current list to
                    // tell, says so; anything else, the error.
                    Text(WalletModel.revocationReason(error) ?? WalletModel.describe(error))
                        .accessibilityIdentifier("reader-outcome-reason")
                }
            default:
                EmptyView()
            }
            Section { Button("Done", action: done).accessibilityIdentifier("reader-done") }
        }
    }

    /// Whether the document signer's certificate was checked for
    /// revocation: a document is verified only if it wasn't revoked.
    private var issuerRevocation: String {
        checksIssuerRevocation ? "not revoked (checked against its CA's revocation list)" : "revocation not checked"
    }

    private func statusWord(_ status: MdocStatus?) -> String {
        switch status {
        case .valid?: "valid"
        case .noStatus?: "none"
        case .revoked?: "revoked"
        case .suspended?: "suspended"
        case .other(let v)?: "status \(v)"
        case .unknown?, nil: "unknown"
        }
    }
}

private struct ClaimRow: View {
    let identifier: String
    let value: JSONValue

    var body: some View {
        if case .string(let text) = value, identifier == "portrait" || identifier.hasSuffix("_image"),
           let data = Data(base64Encoded: text), let image = UIImage(data: data) {
            LabeledContent(elementLabel(identifier)) {
                Image(uiImage: image).resizable().scaledToFit().frame(maxHeight: 120).clipShape(RoundedRectangle(cornerRadius: 8))
            }
        } else {
            LabeledContent(elementLabel(identifier), value: text(value)).accessibilityIdentifier("reader-claim")
        }
    }

    private func text(_ v: JSONValue) -> String {
        switch v {
        case .null: "—"
        case .bool(let b): b ? "Yes" : "No"
        case .number(let n): n.rounded() == n ? String(Int(n)) : String(n)
        case .string(let s): s
        case .array(let a): a.map(text).joined(separator: ", ")
        case .object(let o): o.keys.sorted().map { "\(elementLabel($0)): \(text(o[$0]!))" }.joined(separator: "; ")
        }
    }
}
