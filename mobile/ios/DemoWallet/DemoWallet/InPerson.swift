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

    func createKey(purpose: KeyPurpose) throws -> String { throw DemoReaderKeysError() }

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

    func deleteKey(id: String) throws {}
}

struct DemoReaderKeysError: Error {}

/// A request reader mode makes: a document type and its elements.
struct ReaderPreset: Identifiable, Hashable {
    let title: String
    let docType: String
    let elements: [String: [String]]
    var id: String { title }

    /// The passport-vdc Photo ID, an mDL, and the test services' mdoc.
    static let all: [ReaderPreset] = {
        let identity = ["family_name", "given_name", "portrait", "age_over_18"]
        return [
            ReaderPreset(title: "Photo ID: over 18?", docType: "org.iso.23220.photoid.1", elements: ["org.iso.23220.1": ["age_over_18"]]),
            ReaderPreset(title: "Photo ID: name, photo and age", docType: "org.iso.23220.photoid.1", elements: ["org.iso.23220.1": identity]),
            ReaderPreset(title: "Driving licence: over 18?", docType: "org.iso.18013.5.1.mDL", elements: ["org.iso.18013.5.1": ["age_over_18"]]),
            ReaderPreset(title: "Driving licence: name, photo and age", docType: "org.iso.18013.5.1.mDL", elements: ["org.iso.18013.5.1": identity]),
            ReaderPreset(title: "Test mdoc: name", docType: "org.example.test.1", elements: ["org.example.test.1": ["family_name", "given_name"]]),
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

    func respond(document: Int, credentialID: String, elements: [MdocPresentation.Element]) {
        guard let p = presentation else { return }
        Task {
            do {
                try await p.respond(document: document, credentialID: credentialID, elements: elements)
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

    /// Reads the holder's `qrCode`, asking for `preset`.
    func read(_ qrCode: String, preset: ReaderPreset, model: WalletModel) {
        do {
            if reader == nil {
                guard let r = model.config?.reader else { return }
                reader = try ProximityReader(
                    configuration: ProximityReaderConfiguration(issuerRoots: r.issuerRoots, readerKeyID: DemoReaderKeys.id,
                                                                readerChain: r.readerChain, maxClockSkewSeconds: 300),
                    keyStore: try DemoReaderKeys(r))
            }
            guard let reader else { return }
            let session = try reader.start(qrCode: qrCode, docType: preset.docType, elements: preset.elements)
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

/// Who is asking, what for, and the holder's choice of elements.
private struct ConsentView: View {
    @Environment(InPersonModel.self) private var inPerson
    let request: ProximityPresentation.Request
    @State private var unchosen: Set<String> = []

    private var documentIndex: Int { request.documents.firstIndex { !$0.credentials.isEmpty } ?? 0 }
    private var document: MdocPresentation.Document? { request.documents.indices.contains(documentIndex) ? request.documents[documentIndex] : nil }

    var body: some View {
        List {
            Section { ReaderHeader(reader: request.reader) }
            if let notice = inPerson.notice {
                Section { Text(notice).foregroundStyle(.orange) }
            }
            if let document, let credential = document.credentials.first {
                Section("It asks for, from \(credential.display?.name ?? document.doctype)") {
                    ForEach(document.elements, id: \.self) { e in
                        let key = e.namespace + "/" + e.identifier
                        Toggle(isOn: Binding(get: { !unchosen.contains(key) },
                                             set: { if $0 { unchosen.remove(key) } else { unchosen.insert(key) } })) {
                            VStack(alignment: .leading) {
                                Text(elementLabel(e.identifier))
                                if e.retain { Text("The reader says it will keep this").font(.caption).foregroundStyle(.orange) }
                            }
                        }
                        .accessibilityIdentifier("in-person-element")
                    }
                }
                Section {
                    let chosen = document.elements.filter { !unchosen.contains($0.namespace + "/" + $0.identifier) }
                    Button("Share") { inPerson.respond(document: documentIndex, credentialID: credential.id, elements: chosen) }
                        .disabled(chosen.isEmpty)
                        .accessibilityIdentifier("in-person-share")
                    Button("Decline", role: .destructive) { inPerson.decline() }
                        .accessibilityIdentifier("in-person-decline")
                }
            } else {
                Section {
                    Text("You have nothing this reader asks for\(document.map { " (\($0.doctype))" } ?? "").")
                        .accessibilityIdentifier("in-person-nothing")
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

    var body: some View {
        let trusted = reader.status == .trusted
        VStack(alignment: .leading, spacing: 6) {
            let name = reader.name.isEmpty ? "A nearby reader" : reader.name
            Text(trusted ? name : "“\(name)”").font(.title2).accessibilityIdentifier("in-person-reader")
            Label(badge, systemImage: trusted ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                .foregroundStyle(trusted ? .green : (reader.status == .invalid ? .red : .orange))
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

    var body: some View {
        List {
            ForEach(Array(certificates.enumerated()), id: \.offset) { i, c in
                Section(i == 0 ? "Reader" : (i == certificates.count - 1 ? "Root" : "Intermediate")) {
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
                    ReaderOutcomeView(state: s, preset: inPerson.readingPreset, mode: inPerson.reading?.mode) {
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
                            Text(p.elements.values.flatMap { $0 }.map(elementLabel).joined(separator: ", ")).font(.caption).foregroundStyle(.secondary)
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
    let preset: ReaderPreset?
    let mode: ProximityBLEMode?
    let done: () -> Void

    var body: some View {
        List {
            switch state {
            case .verified(let v):
                Section {
                    Label("Verified", systemImage: "checkmark.seal.fill").foregroundStyle(.green).font(.title2)
                        .accessibilityIdentifier("reader-outcome")
                }
                ForEach(v.claims.keys.sorted(), id: \.self) { namespace in
                    if case .object(let elements)? = v.claims[namespace] {
                        Section {
                            ForEach(elements.keys.sorted(), id: \.self) { identifier in
                                ClaimRow(identifier: identifier, value: elements[identifier]!)
                            }
                            let missing = (preset?.elements[namespace] ?? []).filter { elements[$0] == nil }
                            if !missing.isEmpty { LabeledContent("Not shared", value: missing.map(elementLabel).joined(separator: ", ")) }
                        }
                    }
                }
                Section {
                    LabeledContent("Document", value: v.doctype)
                    LabeledContent("Issued by", value: "\(v.issuer) (trusted via \(v.trustAnchor))")
                    LabeledContent("Valid", value: "\(v.validFrom.formatted(date: .abbreviated, time: .shortened)) to \(v.validUntil.formatted(date: .abbreviated, time: .shortened))")
                    LabeledContent("Holder's device", value: v.deviceAuth == "mac" ? "authenticated (MAC)" : "authenticated (signature)")
                    if let mode {
                        LabeledContent("Bluetooth", value: mode == .centralClient
                            ? "Central client mode: the holder connected to this reader"
                            : "Peripheral server mode: this reader connected to the holder")
                            .accessibilityIdentifier("reader-ble-mode")
                    }
                    if let s = v.statusList { LabeledContent("Revocation", value: "not checked: \(s.uri) #\(s.index)") }
                }
            case .declined:
                Text("The holder declined.").accessibilityIdentifier("reader-outcome")
            case .cancelled:
                Text("Cancelled.").accessibilityIdentifier("reader-outcome")
            case .failed(let error as ProximityError):
                Text(error.localizedDescription).foregroundStyle(.red).accessibilityIdentifier("reader-outcome")
            case .failed(let error):
                Text("Not verified: \(WalletModel.describe(error))").foregroundStyle(.red).accessibilityIdentifier("reader-outcome")
            default:
                EmptyView()
            }
            Section { Button("Done", action: done).accessibilityIdentifier("reader-done") }
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
