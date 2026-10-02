import AuthenticationServices
import OID4VCMobile
import SwiftUI

struct ContentView: View {
    @Environment(WalletModel.self) private var model

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
                        VStack(alignment: .leading) {
                            Text(c.vct ?? c.doctype ?? c.configurationID).font(.headline)
                            Text("\(c.format) · \(c.credentialIssuer)").font(.caption).foregroundStyle(.secondary)
                        }
                        .accessibilityElement(children: .combine)
                        .accessibilityIdentifier("credential")
                        .swipeActions { Button("Delete", role: .destructive) { Task { await model.delete(c) } } }
                    }
                }
            }
            .navigationTitle("OID4VC Demo")
            .toolbar {
                Button("Paste offer") {
                    if let text = UIPasteboard.general.string { Task { await model.start(offer: text) } }
                }
            }
            .sheet(isPresented: offerShown) { OfferView() }
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
