import AuthenticationServices
import OID4VCMobile
import SwiftUI

struct ContentView: View {
    @Environment(WalletModel.self) private var model
    @State private var scanning = false

    var body: some View {
        NavigationStack {
            List {
                if !model.configured {
                    Section {
                        Text("Not configured: launch with OID4VC_DEMO_CONFIG (see mobile/ios/DemoWallet/README.md).")
                    }
                }
                status
                Section("Credentials") {
                    if model.credentials.isEmpty {
                        Text("No credentials yet").foregroundStyle(.secondary)
                    }
                    ForEach(model.credentials, id: \.id) { c in
                        NavigationLink(value: c.id) {
                            VStack(alignment: .leading) {
                                Text(c.vct ?? c.doctype ?? c.configurationID).font(.headline)
                                Text("\(c.format) · \(c.credentialIssuer)").font(.caption).foregroundStyle(.secondary)
                                if c.holderKeyPresent == false {
                                    Text("Its key isn't on this device: it can't be presented").font(.caption).foregroundStyle(.red)
                                }
                            }
                        }
                        .accessibilityElement(children: .combine)
                        .accessibilityIdentifier("credential")
                        .swipeActions { Button("Delete", role: .destructive) { Task { await model.delete(c) } } }
                    }
                }
            }
            .navigationTitle("OID4VC Demo")
            .navigationDestination(for: String.self) { id in
                if let c = model.credentials.first(where: { $0.id == id }) { CredentialView(summary: c) }
            }
            .toolbar {
                ToolbarItemGroup {
                    Button("Paste") {
                        if let text = UIPasteboard.general.string, let url = URL(string: text) { model.open(url) }
                    }
                    Button {
                        scanning = true
                    } label: {
                        Label("Scan", systemImage: "qrcode.viewfinder")
                    }
                    .accessibilityIdentifier("scan")
                }
            }
            .sheet(isPresented: $scanning) { ScanView { model.open($0) } }
            .sheet(isPresented: offerShown) { OfferView() }
            .sheet(isPresented: requestShown) { RequestView() }
        }
    }

    @ViewBuilder private var status: some View {
        switch model.phase {
        case .done(let text):
            Section { Text(text).accessibilityIdentifier("status") }
        case .failed(let text):
            Section { Text(text).foregroundStyle(.red).accessibilityIdentifier("status") }
        default:
            EmptyView()
        }
    }

    private var requestShown: Binding<Bool> {
        Binding(get: { model.requestPhase != .idle },
                set: { if !$0 && model.requestPhase == .shown { Task { await model.decline() } } })
    }

    private var offerShown: Binding<Bool> {
        // Dismissing the sheet cancels the offer only while it's just
        // being shown: once receiving, the authorization session presents
        // over the sheet, and the receive carries on.
        Binding(get: { model.phase == .offered || model.phase == .receiving },
                set: { if !$0 && model.phase == .offered { Task { await model.cancelOffer() } } })
    }
}

struct OfferView: View {
    @Environment(WalletModel.self) private var model
    @Environment(\.webAuthenticationSession) private var webAuthenticationSession

    var body: some View {
        @Bindable var model = model
        NavigationStack {
            Form {
                if let offer = model.offer {
                    Section("From") { Text(offer.issuerName ?? offer.credentialIssuer) }
                    Section("Credentials") {
                        ForEach(offer.credentials, id: \.configurationID) { c in
                            Text(c.name ?? c.vct ?? c.doctype ?? c.configurationID)
                        }
                    }
                    if offer.grant == .preAuthorizedCode, let tx = offer.txCode {
                        Section(tx.description ?? "PIN") {
                            TextField("PIN", text: $model.pin)
                                .keyboardType(tx.inputMode == "text" ? .default : .numberPad)
                                .accessibilityIdentifier("pin")
                        }
                    }
                    Section {
                        Button(model.phase == .receiving ? "Receiving…" : "Receive") {
                            Task { await model.receive(authorize: authorize) }
                        }
                        .disabled(model.phase == .receiving)
                        .accessibilityIdentifier("receive")
                    }
                }
            }
            .navigationTitle("Credential offer")
            .toolbar { Button("Cancel") { Task { await model.cancelOffer() } } }
        }
    }

    /// Opens the issuer's authorization page in an ephemeral session (no
    /// cookies kept, no "wants to sign in" prompt) and returns the
    /// redirect back to the app.
    private func authorize(_ url: URL) async throws -> URL {
        try await webAuthenticationSession.authenticate(using: url, callbackURLScheme: model.callbackScheme,
                                                        preferredBrowserSession: .ephemeral)
    }
}

/// One credential's claims.
struct CredentialView: View {
    @Environment(WalletModel.self) private var model
    let summary: CredentialSummary
    @State private var detail: CredentialDetail?

    var body: some View {
        List {
            Section("Credential") {
                LabeledContent("Format", value: summary.format)
                LabeledContent("Issuer", value: summary.credentialIssuer)
                LabeledContent("Received", value: summary.receivedAt.formatted(date: .abbreviated, time: .shortened))
            }
            if let detail {
                Section("Claims") { ClaimRows(value: detail.claims, path: []) }
            }
        }
        .navigationTitle(summary.vct ?? summary.doctype ?? summary.configurationID)
        .task { detail = await model.detail(summary) }
    }
}

/// A claim tree as rows: nested objects flattened to dotted paths.
struct ClaimRows: View {
    let value: JSONValue
    let path: [String]

    var body: some View {
        if case .object(let o) = value {
            ForEach(o.keys.sorted().filter { !Self.hidden.contains($0) || !path.isEmpty }, id: \.self) { key in
                ClaimRows(value: o[key]!, path: path + [key])
            }
        } else if let image = Self.image(value, key: path.last ?? "") {
            LabeledContent(path.joined(separator: " · ")) {
                Image(uiImage: image).resizable().scaledToFit().frame(maxWidth: 120, maxHeight: 160)
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                    .accessibilityIdentifier("portrait")
            }
        } else {
            LabeledContent(path.joined(separator: " · "), value: Self.text(value))
                .accessibilityIdentifier("claim")
        }
    }

    /// An image claim: a data: URL (an SD-JWT VC's picture), or base64
    /// bytes under a name like an mdoc's portrait.
    static func image(_ v: JSONValue, key: String) -> UIImage? {
        guard case .string(let s) = v else { return nil }
        if s.hasPrefix("data:image/"), let comma = s.firstIndex(of: ","),
           let data = Data(base64Encoded: String(s[s.index(after: comma)...])) {
            return UIImage(data: data)
        }
        let named = ["portrait", "picture", "photo", "image"].contains { key.lowercased().contains($0) }
        guard named, let data = Data(base64Encoded: s) else { return nil }
        return UIImage(data: data)
    }

    /// The SD-JWT VC's own top-level claims, not about the holder.
    static let hidden: Set<String> = ["cnf", "iss", "iat", "exp", "nbf", "vct", "status", "_sd_alg"]

    static func text(_ v: JSONValue) -> String {
        switch v {
        case .null: "—"
        case .bool(let b): b ? "yes" : "no"
        case .number(let n): n.rounded() == n ? String(Int(n)) : String(n)
        case .string(let s): s.count > 80 ? String(s.prefix(77)) + "…" : s
        case .array(let a): a.map(text).joined(separator: ", ")
        case .object: "{…}"
        }
    }
}

/// A presentation request: who's asking, which credentials can answer,
/// and exactly what sharing them discloses.
struct RequestView: View {
    @Environment(WalletModel.self) private var model

    var body: some View {
        NavigationStack {
            Form {
                if let p = model.presentation {
                    Section("Requested by") {
                        Text(p.verifier.name).font(.headline)
                        Text(p.verifier.clientID).font(.caption).foregroundStyle(.secondary)
                    }
                    if p.candidates.isEmpty {
                        Section { Text("You have no credential this verifier accepts.") }
                    }
                    ForEach(p.candidates, id: \.queryID) { query in
                        Section("Answers “\(query.queryID)”") {
                            ForEach(query.credentials, id: \.id) { c in
                                Button {
                                    Task { await model.toggle(c.id) }
                                } label: {
                                    HStack {
                                        Image(systemName: model.selected.contains(c.id) ? "checkmark.circle.fill" : "circle")
                                        Text(c.vct ?? c.doctype ?? c.configurationID)
                                    }
                                }
                                .accessibilityIdentifier("candidate")
                            }
                        }
                    }
                    if !model.disclosures.isEmpty {
                        Section("Will share") {
                            ForEach(model.disclosures, id: \.credentialID) { d in
                                ForEach(d.claims.indices, id: \.self) { i in
                                    Text(Self.path(d.claims[i]))
                                }
                            }
                        }
                    }
                    Section {
                        Button(model.requestPhase == .sharing ? "Sharing…" : "Share") { Task { await model.share() } }
                            .disabled(model.selected.isEmpty || model.requestPhase == .sharing)
                            .accessibilityIdentifier("share")
                        Button("Decline", role: .destructive) { Task { await model.decline() } }
                            .disabled(model.requestPhase == .sharing)
                            .accessibilityIdentifier("decline")
                    }
                }
            }
            .navigationTitle("Presentation request")
        }
    }

    static func path(_ elements: [Presentation.PathElement]) -> String {
        elements.map {
            switch $0 {
            case .key(let k): k
            case .index(let i): String(i)
            case .all: "*"
            }
        }.joined(separator: " · ")
    }
}
