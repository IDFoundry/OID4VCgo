import AuthenticationServices
import OID4VCWallet
import SwiftUI

struct ContentView: View {
    @Environment(WalletModel.self) private var model
    @State private var scanning = false

    var body: some View {
        NavigationStack {
            List {
                if let reason = model.unavailable {
                    Section { Text(reason).foregroundStyle(.red).accessibilityIdentifier("unavailable") }
                } else if !model.configured {
                    Section {
                        Text("Not configured: launch with OID4VC_DEMO_CONFIG (see mobile/ios/DemoWallet/README.md).")
                    }
                }
                status
                if !model.pending.isEmpty {
                    Section("Waiting for the issuer") {
                        ForEach(model.pending) { p in PendingRow(pending: p) }
                    }
                }
                if model.credentials.isEmpty {
                    Section("Credentials") {
                        Text("No credentials yet").foregroundStyle(.secondary)
                    }
                }
                ForEach(Array(model.credentialsByHolder.enumerated()), id: \.offset) { _, group in
                    Section {
                        ForEach(group.credentials, id: \.id) { c in
                            NavigationLink(value: c.id) { CredentialRow(summary: c) }
                            .accessibilityElement(children: .combine)
                            .accessibilityIdentifier("credential")
                            .swipeActions { Button("Delete", role: .destructive) { Task { await model.delete(c) } } }
                        }
                    } header: {
                        HolderHeader(holder: group.holder)
                    }
                }
            }
            .navigationTitle("OID4VC Demo")
            .navigationDestination(for: String.self) { id in
                if let c = model.credentials.first(where: { $0.id == id }) { CredentialView(summary: c) }
            }
            .toolbar {
                ToolbarItemGroup(placement: .topBarLeading) {
                    Menu {
                        Picker("Copies", selection: Binding(get: { model.copyPolicy }, set: { model.setCopyPolicy($0) })) {
                            Text("New copy for every presentation").tag(WalletConfiguration.CopyPolicy.perPresentation)
                            Text("Same copy for the same verifier").tag(WalletConfiguration.CopyPolicy.perVerifier)
                        }
                        .accessibilityIdentifier("copy-policy")
                    } label: {
                        Label("Settings", systemImage: "gearshape")
                    }
                    .accessibilityIdentifier("settings")
                }
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
            .alert(linkTitle, isPresented: linkShown) {
                Button("Open") { model.confirmLink() }
                Button("Cancel", role: .cancel) { model.linkToConfirm = nil }
            } message: {
                Text("Another app opened this link. Opening it contacts the \(model.linkToConfirm?.scheme == "openid4vp" ? "verifier" : "issuer") it names; nothing is shared until you agree.")
            }
            .sheet(isPresented: requestShown) { RequestView() }
        }
    }

    @ViewBuilder private var status: some View {
        if let notice = model.notice {
            Section { Text(notice).foregroundStyle(.orange).accessibilityIdentifier("notice") }
        }
        switch model.phase {
        case .done(let text):
            Section { Text(text).accessibilityIdentifier("status") }
        case .failed(let text):
            Section { Text(text).foregroundStyle(.red).accessibilityIdentifier("status") }
        case .untrustedVerifier:
            UntrustedVerifierSection()
        default:
            EmptyView()
        }
    }

    private var linkTitle: String {
        model.linkToConfirm?.scheme == "openid4vp" ? "Open this presentation request?" : "Open this credential offer?"
    }

    private var linkShown: Binding<Bool> {
        Binding(get: { model.linkToConfirm != nil }, set: { if !$0 { model.linkToConfirm = nil } })
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
                    // Only the issuer's address is checked here (its TLS
                    // certificate): its name and logos are its own claim
                    // until the credential arrives and is checked against
                    // the issuers this wallet trusts. So the address
                    // leads, and no logo is fetched yet.
                    Section {
                        VStack(alignment: .leading) {
                            Text(Self.host(offer.credentialIssuer)).font(.headline).accessibilityIdentifier("offer-issuer")
                            if let name = offer.issuerName {
                                Text("Calls itself “\(name)”").font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    } header: {
                        Text("From")
                    } footer: {
                        Text("Not verified yet: an issuer names itself. The credential is checked against the issuers this wallet trusts when it arrives.")
                    }
                    Section("Credentials") {
                        ForEach(offer.credentials, id: \.configurationID) { c in
                            HStack {
                                VStack(alignment: .leading) {
                                    Text(c.name ?? c.vct ?? c.doctype ?? c.configurationID)
                                    if let description = c.description {
                                        Text(description).font(.caption).foregroundStyle(.secondary)
                                    }
                                }
                            }
                        }
                    }
                    if offer.grant == .preAuthorizedCode, let tx = offer.txCode {
                        Section(tx.description ?? "PIN") {
                            TextField("PIN", text: $model.pin)
                                .keyboardType(tx.inputMode == "text" ? .default : .numberPad)
                                .accessibilityIdentifier("pin")
                        }
                    }
                    if let error = model.offerError {
                        Section {
                            Text(error).foregroundStyle(.red).accessibilityIdentifier("offer-error")
                        }
                    }
                    Section {
                        Button(receiveLabel) {
                            model.startReceive(authorize: authorize)
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

    /// The host of an issuer identifier, an https URL.
    static func host(_ issuer: String) -> String {
        URL(string: issuer)?.host() ?? issuer
    }

    private var receiveLabel: String {
        if model.phase == .receiving { return "Receiving…" }
        return model.offerError == nil ? "Receive" : "Try again"
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
    @State private var checking = false
    @State private var checkError: String?
    @State private var justChecked = false
    @State private var refreshing = false
    @State private var refreshOutcome: WalletModel.RefreshOutcome?

    var body: some View {
        List {
            Section("Credential") {
                LabeledContent("Format", value: summary.format)
                LabeledContent("Issuer", value: summary.display?.issuerName ?? summary.credentialIssuer)
                LabeledContent("Received", value: summary.receivedAt.formatted(date: .abbreviated, time: .shortened))
                if let until = summary.validUntil {
                    LabeledContent(summary.isExpired() ? "Expired" : "Expires", value: until.formatted(date: .abbreviated, time: .omitted))
                }
            }
            Section("Status") {
                StatusRow(status: summary.status)
                Button {
                    check()
                } label: {
                    HStack {
                        Text(checking ? "Checking with the issuer…" : "Check status")
                        if checking {
                            Spacer()
                            ProgressView()
                        }
                    }
                }
                .disabled(checking)
                .accessibilityIdentifier("check-status")
                if let checkError {
                    Label("Couldn't check: \(checkError)", systemImage: "exclamationmark.triangle.fill")
                        .font(.caption).foregroundStyle(.red)
                        .accessibilityElement(children: .combine).accessibilityIdentifier("check-error")
                } else if justChecked {
                    Label("Checked with the issuer just now", systemImage: "checkmark.circle.fill")
                        .font(.caption).foregroundStyle(.green)
                        .accessibilityElement(children: .combine).accessibilityIdentifier("check-done")
                }
            }
            if summary.copies > 1 || summary.refreshable || refreshOutcome != nil {
                Section("Copies") {
                    Text(CredentialRow.copies(summary) ?? "\(summary.copiesLeft) of \(summary.copies) copies unused")
                        .accessibilityIdentifier("credential-copies")
                    if summary.refreshable {
                        Button {
                            refreshCopies()
                        } label: {
                            HStack {
                                Text(refreshing ? "Getting fresh copies from the issuer…" : "Refresh copies")
                                if refreshing {
                                    Spacer()
                                    ProgressView()
                                }
                            }
                        }
                        .disabled(refreshing)
                        .accessibilityIdentifier("refresh-copies")
                    }
                    if let refreshOutcome {
                        Self.outcomeLabel(refreshOutcome).font(.caption)
                            .accessibilityElement(children: .combine).accessibilityIdentifier("refresh-done")
                    }
                }
            }
            if let detail {
                Section("Claims") { ClaimRows(value: detail.claims, path: []) }
            }
        }
        .navigationTitle(CredentialRow.title(summary))
        .task { detail = await model.detail(summary) }
    }

    /// Checks the status, with feedback whatever the outcome: a spinner
    /// while it runs (for at least half a second, so a quick check is
    /// still seen), then "Checked just now" or why it couldn't, and a
    /// haptic.
    private func check() {
        checking = true
        checkError = nil
        justChecked = false
        Task {
            async let minimum: Void = Task.sleep(for: .milliseconds(500))
            let error = await model.checkStatus(summary.id)
            try? await minimum
            checking = false
            checkError = error
            justChecked = error == nil
            let revoked = summary.status.map { if case .valid = $0.value { false } else { true } } ?? false
            let feedback: UINotificationFeedbackGenerator.FeedbackType
            if error != nil {
                feedback = .error
            } else if revoked {
                feedback = .warning
            } else {
                feedback = .success
            }
            UINotificationFeedbackGenerator().notificationOccurred(feedback)
        }
    }
}

extension CredentialView {
    /// Refreshes the copies, with feedback whatever the outcome: a
    /// spinner while it runs (for at least half a second), then what
    /// happened, and a haptic.
    fileprivate func refreshCopies() {
        refreshing = true
        refreshOutcome = nil
        Task {
            async let minimum: Void = Task.sleep(for: .milliseconds(500))
            let outcome = await model.refreshCopies(summary.id)
            try? await minimum
            refreshing = false
            refreshOutcome = outcome
            let feedback: UINotificationFeedbackGenerator.FeedbackType = switch outcome {
            case .refreshed: .success
            case .deferred, .reissueRequired: .warning
            case .failed: .error
            }
            UINotificationFeedbackGenerator().notificationOccurred(feedback)
        }
    }

    @ViewBuilder fileprivate static func outcomeLabel(_ outcome: WalletModel.RefreshOutcome) -> some View {
        switch outcome {
        case .refreshed(let copies):
            Label("Got \(copies) fresh \(copies == 1 ? "copy" : "copies") just now", systemImage: "checkmark.circle.fill")
                .foregroundStyle(.green)
        case .deferred:
            Label("The issuer will send fresh copies later: they're waiting on the home screen", systemImage: "clock.fill")
                .foregroundStyle(.orange)
        case .reissueRequired:
            Label("This credential can't be refreshed any more: receive it again from the issuer", systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
        case .failed(let reason):
            Label("Couldn't refresh: \(reason)", systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.red)
        }
    }
}

/// A credential's status: what its issuer's status list said, and how
/// long ago that was checked, counting up.
struct StatusRow: View {
    let status: CredentialStatus?

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon).font(.title2).foregroundStyle(color)
            VStack(alignment: .leading) {
                Text(word).font(.headline)
                if let status {
                    (Text("Checked ") + Text(status.checkedAt, style: .relative) + Text(" ago"))
                        .font(.caption).foregroundStyle(.secondary)
                } else {
                    Text("Not checked yet").font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("credential-status")
    }

    private var word: String {
        switch status?.value {
        case nil: "Status unknown"
        case .valid: "Valid"
        case .revoked: "Revoked by the issuer"
        case .suspended: "Suspended by the issuer"
        case .other(let v): "Status \(v)"
        }
    }

    private var icon: String {
        switch status?.value {
        case nil: "questionmark.circle"
        case .valid: "checkmark.seal.fill"
        case .revoked: "xmark.octagon.fill"
        case .suspended: "pause.circle.fill"
        case .other: "exclamationmark.circle"
        }
    }

    private var color: Color {
        switch status?.value {
        case nil, .other: .secondary
        case .valid: .green
        case .revoked: .red
        case .suspended: .orange
        }
    }
}

/// A credential as a card in the issuer's colours: its logo, name,
/// issuer, and expiry or revocation.
/// Whose credentials a group holds: the holder's photo, name and date of
/// birth.
struct HolderHeader: View {
    let holder: Holder?

    var body: some View {
        if let holder {
            HStack(spacing: 12) {
                if let portrait = holder.portrait {
                    Image(uiImage: portrait).resizable().scaledToFill().frame(width: 40, height: 50)
                        .clipShape(RoundedRectangle(cornerRadius: 4))
                }
                VStack(alignment: .leading) {
                    Text(holder.name ?? "Unnamed holder").font(.headline).foregroundStyle(.primary)
                    if let born = holder.birthDate {
                        Text("Born \(born)").font(.caption)
                    }
                }
            }
            .textCase(nil)
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("holder")
        } else {
            Text("Credentials")
        }
    }
}

/// A refused presentation request from a verifier the wallet doesn't
/// trust: prominent, since that's the point, with what happened under
/// Details. Nothing about the request is shown — its contents, and the
/// name it claims, are only trustworthy if its signature is, which is
/// what failed.
struct UntrustedVerifierSection: View {
    var body: some View {
        Section {
            VStack(alignment: .leading, spacing: 10) {
                Label("Verifier not trusted", systemImage: "exclamationmark.shield.fill")
                    .font(.title3.bold()).foregroundStyle(.red)
                    .accessibilityIdentifier("untrusted-verifier")
                Text("The identity of this verifier couldn't be established, so your wallet didn't open its request.")
                Text("Nothing was shared.").bold()
                    .accessibilityIdentifier("nothing-shared")
            }
            .padding(.vertical, 4)
            DisclosureGroup("Details") {
                LabeledContent("Verifier authentication", value: "Failed")
                LabeledContent("Request signed by", value: "A certificate your wallet doesn't recognise")
                LabeledContent("Request opened", value: "No")
                LabeledContent("Credentials shared", value: "None")
            }
            .accessibilityIdentifier("untrusted-details")
        }
        .listRowBackground(Color.red.opacity(0.08))
    }
}

struct CredentialRow: View {
    let summary: CredentialSummary

    var body: some View {
        let d = summary.display
        let text = Color(css: d?.textColor) ?? .primary
        HStack {
            LogoView(logo: d?.logo ?? d?.issuerLogo)
            VStack(alignment: .leading) {
                Text(Self.title(summary)).font(.headline).foregroundStyle(text)
                Text(d?.issuerName ?? summary.credentialIssuer).font(.caption).foregroundStyle(text.opacity(0.8))
                if let problem = Self.problem(summary) {
                    Text(problem).font(.caption.bold()).foregroundStyle(.red)
                } else if let until = summary.validUntil {
                    Text("Expires \(until.formatted(date: .abbreviated, time: .omitted))").font(.caption).foregroundStyle(text.opacity(0.8))
                }
                if let copies = Self.copies(summary) {
                    Text(copies).font(.caption).foregroundStyle(summary.copiesLeft == 0 ? .orange : text.opacity(0.8))
                }
                Text("\(Self.format(summary)) · received \(summary.receivedAt.formatted(date: .abbreviated, time: .shortened))")
                    .font(.caption2).foregroundStyle(text.opacity(0.7))
            }
        }
        .listRowBackground(Color(css: d?.backgroundColor))
    }

    /// The credential's format, as a holder would name it.
    static func format(_ c: CredentialSummary) -> String {
        switch c.format {
        case "dc+sd-jwt": "SD-JWT VC"
        case "mso_mdoc": "mdoc"
        default: c.format
        }
    }

    static func title(_ c: CredentialSummary) -> String {
        c.display?.name ?? c.vct ?? c.doctype ?? c.configurationID
    }

    /// Why the credential can't be relied on, if it can't.
    static func problem(_ c: CredentialSummary) -> String? {
        if c.holderKeyPresent == false { return "Its key isn't on this device: it can't be presented" }
        if c.isExpired() { return "Expired" }
        switch c.status?.value {
        case .revoked: return "Revoked by the issuer"
        case .suspended: return "Suspended by the issuer"
        default: return nil
        }
    }

    /// How many fresh copies are left: each presentation uses one no
    /// Verifier has seen, so they can't be linked by the credential.
    static func copies(_ c: CredentialSummary) -> String? {
        if c.linkable { return "Copies have been shown to several verifiers: they could link these presentations" }
        if c.copiesLeft == 0 { return "Every copy has been shared: the next new verifier could link you with another" }
        guard c.copies > 1 else { return nil }
        return "\(c.copiesLeft) of \(c.copies) copies unused"
    }
}

/// An issuer's logo, loaded from its https or data: URL.
struct LogoView: View {
    let logo: Logo?

    var body: some View {
        if let url = logo?.url {
            AsyncImage(url: url) { image in
                image.resizable().scaledToFit()
            } placeholder: {
                Color.clear
            }
            .frame(width: 32, height: 32)
            .accessibilityLabel(logo?.altText ?? "")
        }
    }
}

extension Color {
    /// A CSS hex colour (#rgb or #rrggbb), as issuers' display metadata
    /// gives them; nil for anything else.
    init?(css: String?) {
        guard var hex = css?.trimmingCharacters(in: .whitespaces), hex.hasPrefix("#") else { return nil }
        hex.removeFirst()
        if hex.count == 3 { hex = hex.map { "\($0)\($0)" }.joined() }
        guard hex.count == 6, let v = UInt32(hex, radix: 16) else { return nil }
        self.init(red: Double((v >> 16) & 0xff) / 255, green: Double((v >> 8) & 0xff) / 255, blue: Double(v & 0xff) / 255)
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
        case .number(let n): Int(exactly: n).map(String.init) ?? String(n)
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
            List {
                if let p = model.presentation {
                    Section { VerifierHeader(verifier: p.verifier) }
                    if !p.isAnswerable {
                        Section { Text("You have no credential this verifier accepts.") }
                    }
                    ForEach(p.queries.filter { !$0.credentials.isEmpty }, id: \.queryID) { query in
                        querySection(query)
                    }
                    disclosureSections(p)
                    actions
                }
            }
            .navigationTitle("Share credentials")
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    /// One query: what it asks beyond the Verifier's registration, if
    /// anything, and the credentials that can answer it, as cards.
    private func querySection(_ query: Presentation.Query) -> some View {
        Section {
            if !query.unregistered.isEmpty || query.unregisteredAll {
                Label(Self.overAsking(query), systemImage: "exclamationmark.triangle.fill")
                    .font(.subheadline).foregroundStyle(.orange)
                    .accessibilityElement(children: .combine)
                    .accessibilityIdentifier("over-asking")
            }
            ForEach(query.credentials, id: \.id) { c in
                let selected = model.isSelected(c.id, for: query.queryID)
                Button {
                    Task { await model.toggle(c.id, for: query) }
                } label: {
                    CandidateCard(summary: c, holder: Holder(claims: model.candidateClaims[c.id]), selected: selected, multiple: query.multiple)
                }
                .listRowBackground(Color(css: c.display?.backgroundColor))
                .accessibilityIdentifier("candidate")
                .accessibilityAddTraits(selected ? .isSelected : [])
            }
        } header: {
            Text(query.multiple ? "Choose the credentials to share" : "Choose a credential to share")
        }
    }

    /// What sharing the selection discloses, by credential, with each
    /// claim's value.
    @ViewBuilder private func disclosureSections(_ p: Presentation) -> some View {
        if let error = model.previewError {
            Section { Text("Can't share this selection: \(error)").foregroundStyle(.red) }
        } else {
            ForEach(Array(model.disclosures.enumerated()), id: \.offset) { _, d in
                Section {
                    ForEach(d.claims.indices, id: \.self) { i in
                        DisclosedRow(path: d.claims[i], claims: model.candidateClaims[d.credentialID],
                                     unregistered: Self.isUnregistered(d.claims[i], query: d.queryID, in: p))
                    }
                } header: {
                    ShareHeader(holder: Holder(claims: model.candidateClaims[d.credentialID]),
                                title: p.queries.flatMap(\.credentials).first { $0.id == d.credentialID }.map(CredentialRow.title) ?? "credential")
                }
            }
        }
    }

    /// Share, prominent, and Decline under it.
    private var actions: some View {
        Section {
            VStack(spacing: 10) {
                Button {
                    Task { await model.share() }
                } label: {
                    Text(model.requestPhase == .sharing ? "Sharing…" : "Share").bold().frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent).controlSize(.large)
                .disabled(!model.canShare)
                .accessibilityIdentifier("share")
                Button(role: .destructive) {
                    Task { await model.decline() }
                } label: {
                    Text("Decline").frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered).controlSize(.large)
                .disabled(model.requestPhase == .sharing)
                .accessibilityIdentifier("decline")
            }
        }
        .listRowBackground(Color.clear)
        .listRowInsets(EdgeInsets())
    }

    /// A candidate's choice mark: a checkbox for a query taking several
    /// credentials, a radio button otherwise.
    static func choiceIcon(selected: Bool, multiple: Bool) -> String {
        guard selected else { return "circle" }
        return multiple ? "checkmark.circle.fill" : "largecircle.fill.circle"
    }

    /// What a query asks beyond the Verifier's registration, in words.
    static func overAsking(_ q: Presentation.Query) -> String {
        if q.unregisteredAll { return "Asks for every claim, beyond what it's registered for" }
        return "Asks for more than it's registered for: " + q.unregistered.map(path).joined(separator: ", ")
    }

    /// Whether disclosing path, for query, is beyond the Verifier's
    /// registration.
    static func isUnregistered(_ path: [Presentation.PathElement], query: String, in p: Presentation) -> Bool {
        guard let q = p.queries.first(where: { $0.queryID == query }) else { return false }
        return q.unregisteredAll || q.unregistered.contains(path)
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

/// Who's asking, at the top of the consent screen: the Verifier's name,
/// its registration, and its client_id under Details.
struct VerifierHeader: View {
    let verifier: Presentation.Verifier

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: "building.2.crop.circle.fill")
                .font(.system(size: 40)).foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 4) {
                Text(verifier.name).font(.title2.bold())
                Text("is asking for your credentials").font(.subheadline).foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 4)
        RegistrationRows(registration: verifier.registration)
        DisclosureGroup("Details") {
            LabeledContent("Client ID") {
                Text(verifier.clientID).font(.caption.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
            }
        }
        .font(.subheadline)
    }
}

/// A credential that can answer a query, as a card in its issuer's
/// colours like the home screen's: logo, name, whose it is, and the
/// selection mark.
struct CandidateCard: View {
    let summary: CredentialSummary
    let holder: Holder?
    let selected: Bool
    let multiple: Bool

    var body: some View {
        let d = summary.display
        let text = Color(css: d?.textColor) ?? .primary
        HStack(spacing: 12) {
            Image(systemName: RequestView.choiceIcon(selected: selected, multiple: multiple))
                .font(.title2).foregroundStyle(selected ? text : text.opacity(0.45))
            if let portrait = holder?.portrait {
                Image(uiImage: portrait).resizable().scaledToFill().frame(width: 44, height: 56)
                    .clipShape(RoundedRectangle(cornerRadius: 6))
            } else {
                LogoView(logo: d?.logo ?? d?.issuerLogo)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(CredentialRow.title(summary)).font(.headline).foregroundStyle(text)
                if let holder {
                    Text(holder.line).font(.subheadline).foregroundStyle(text)
                        .accessibilityIdentifier("candidate-holder")
                }
                Text("\(d?.issuerName ?? summary.credentialIssuer) · \(CredentialRow.format(summary)) · received \(summary.receivedAt.formatted(date: .abbreviated, time: .omitted))")
                    .font(.caption).foregroundStyle(text.opacity(0.8))
                hint
            }
        }
        .padding(.vertical, 4)
    }

    @ViewBuilder private var hint: some View {
        if summary.linkableHere == true {
            Label("Every copy has been shown elsewhere: this verifier and another could link you", systemImage: "link")
                .font(.caption).foregroundStyle(.orange)
                .accessibilityIdentifier("linkable-here")
        } else if summary.shownToVerifier == true {
            Label("This verifier has seen this credential before", systemImage: "eye")
                .font(.caption).foregroundStyle(Color(css: summary.display?.textColor)?.opacity(0.8) ?? .secondary)
                .accessibilityIdentifier("shown-before")
        }
    }
}

/// Whose credential a "Will share" section discloses from: the holder's
/// photo and name, and the credential.
struct ShareHeader: View {
    let holder: Holder?
    let title: String

    var body: some View {
        HStack(spacing: 10) {
            if let portrait = holder?.portrait {
                Image(uiImage: portrait).resizable().scaledToFill().frame(width: 28, height: 36)
                    .clipShape(RoundedRectangle(cornerRadius: 4))
            }
            VStack(alignment: .leading) {
                Text("Will share").font(.caption)
                Text(holder?.name.map { "\($0) · \(title)" } ?? title).font(.subheadline.bold()).foregroundStyle(.primary)
            }
        }
        .textCase(nil)
    }
}

/// One claim sharing discloses: its path and the value the verifier will
/// see, or the photo.
struct DisclosedRow: View {
    let path: [Presentation.PathElement]
    let claims: JSONValue?
    /// Beyond the Verifier's registration.
    var unregistered = false

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            row
            if unregistered {
                Text("Not in its registration").font(.caption2).foregroundStyle(.orange)
                    .accessibilityIdentifier("disclosed-unregistered")
            }
        }
    }

    @ViewBuilder private var row: some View {
        let label = RequestView.path(path)
        let value = claims.flatMap { Self.resolve(path, in: $0) }
        if let value, let image = ClaimRows.image(value, key: Self.lastKey(path)) {
            LabeledContent(label) {
                Image(uiImage: image).resizable().scaledToFit().frame(maxWidth: 60, maxHeight: 80)
                    .clipShape(RoundedRectangle(cornerRadius: 4))
            }
            .accessibilityIdentifier("disclosed")
        } else if let value {
            LabeledContent(label, value: ClaimRows.text(value)).accessibilityIdentifier("disclosed")
        } else {
            Text(label).accessibilityIdentifier("disclosed")
        }
    }

    /// The value at path in claims (an SD-JWT VC's claims, or an mdoc's
    /// namespace → element): null selects every element of an array.
    static func resolve(_ path: [Presentation.PathElement], in claims: JSONValue) -> JSONValue? {
        guard let first = path.first else { return claims }
        let rest = Array(path.dropFirst())
        switch (first, claims) {
        case (.key(let k), .object(let o)):
            return o[k].flatMap { resolve(rest, in: $0) }
        case (.index(let i), .array(let a)) where a.indices.contains(i):
            return resolve(rest, in: a[i])
        case (.all, .array(let a)):
            let values = a.compactMap { resolve(rest, in: $0) }
            return values.isEmpty ? nil : .array(values)
        default:
            return nil
        }
    }

    static func lastKey(_ path: [Presentation.PathElement]) -> String {
        for e in path.reversed() { if case .key(let k) = e { return k } }
        return ""
    }
}

/// A Verifier's registration, on the consent screen: who registered it
/// and for what, or that its registration didn't verify.
struct RegistrationRows: View {
    let registration: Presentation.Registration

    var body: some View {
        switch registration.status {
        case .verified:
            Label("Registered with \(Self.host(registration.registrar))", systemImage: "checkmark.seal.fill")
                .font(.subheadline).foregroundStyle(.green)
                .accessibilityElement(children: .combine).accessibilityIdentifier("registered")
            if let name = registration.name { LabeledContent("Registered as", value: name) }
            if let purpose = registration.purpose { LabeledContent("Purpose", value: purpose) }
            if !registration.claims.isEmpty {
                LabeledContent("Registered to ask for", value: registration.claims.map(RequestView.path).joined(separator: ", "))
            }
            if let policy = registration.privacyPolicy { Link("Privacy policy", destination: policy) }
        case .invalid:
            Label("Its registration couldn't be verified", systemImage: "exclamationmark.triangle.fill")
                .font(.subheadline).foregroundStyle(.orange)
                .accessibilityElement(children: .combine).accessibilityIdentifier("registration-invalid")
        case .none:
            Text("Not registered with a registrar this wallet knows").font(.caption).foregroundStyle(.secondary)
                .accessibilityIdentifier("not-registered")
        }
    }

    static func host(_ registrar: String?) -> String {
        guard let registrar else { return "a registrar" }
        return URL(string: registrar)?.host ?? registrar
    }
}

/// Whose credential this is, from its claims: the holder's name, date of
/// birth and photo, wherever the format keeps them (an SD-JWT VC's
/// top-level claims, an mdoc's namespaces).
struct Holder {
    let name: String?
    let birthDate: String?
    let portrait: UIImage?

    init?(claims: JSONValue?) {
        guard let claims else { return nil }
        let given = Self.find(["given_name", "given_names"], in: claims)
        let family = Self.find(["family_name"], in: claims)
        let names = [given, family].compactMap { v -> String? in
            if case .string(let s)? = v, !s.isEmpty { return s }
            return nil
        }
        name = names.isEmpty ? nil : names.joined(separator: " ")
        birthDate = Self.birthDate(Self.find(["birth_date", "birthdate"], in: claims))
        portrait = ["portrait", "picture"].lazy.compactMap { key in
            Self.find([key], in: claims).flatMap { ClaimRows.image($0, key: key) }
        }.first
        if name == nil && birthDate == nil && portrait == nil { return nil }
    }

    /// "Jane Citizen · born 1990-01-01".
    var line: String {
        [name, birthDate.map { "born \($0)" }].compactMap { $0 }.joined(separator: " · ")
    }

    /// A date of birth as text: an SD-JWT VC's string, or ISO/IEC TS
    /// 23220-2's birth_date structure ({birth_date, approximate_mask}),
    /// its masked digits shown as "x" — "xx14-06-01" when the century
    /// isn't known.
    static func birthDate(_ v: JSONValue?) -> String? {
        switch v {
        case .string(let s)?:
            return s
        case .object(let o)?:
            guard case .string(let date)? = o["birth_date"] else { return nil }
            guard case .string(let mask)? = o["approximate_mask"], mask.count == 8 else { return date }
            // The mask covers YYYYMMDD; the date is YYYY-MM-DD.
            var digits = Array(mask).makeIterator()
            return String(date.map { c in c == "-" ? c : (digits.next() == "1" ? "x" : c) })
        default:
            return nil
        }
    }

    /// The first value under any of keys, searching objects depth-first.
    static func find(_ keys: [String], in v: JSONValue) -> JSONValue? {
        guard case .object(let o) = v else { return nil }
        for k in keys { if let hit = o[k] { return hit } }
        for k in o.keys.sorted() { if let hit = find(keys, in: o[k]!) { return hit } }
        return nil
    }
}

/// A deferred credential: what it's waiting for, and a way to ask now.
struct PendingRow: View {
    @Environment(WalletModel.self) private var model
    let pending: WalletModel.PendingCredential

    var body: some View {
        HStack {
            VStack(alignment: .leading) {
                Text(pending.configurationID).font(.headline)
                    .accessibilityIdentifier("pending")
                Text(detail).font(.caption).foregroundStyle(pending.state == .denied ? .red : .secondary)
                    .accessibilityIdentifier("pending-state")
            }
            Spacer()
            if pending.state == .denied {
                Button("Dismiss") { Task { await model.dismiss(pending.id) } }
                    .buttonStyle(.bordered)
                    .accessibilityIdentifier("dismiss")
            } else {
                if case .failed = pending.state {
                    Button("Give up") { Task { await model.abandon(pending.id) } }
                        .buttonStyle(.bordered)
                        .accessibilityIdentifier("give-up")
                }
                Button("Check again") { Task { await model.checkAgain(pending.id) } }
                    .buttonStyle(.bordered)
                    .disabled(pending.state == .checking)
                    .accessibilityIdentifier("check-again")
            }
        }
    }

    private var detail: String {
        switch pending.state {
        case .waiting: "The issuer is reviewing it · checking every \(Int(max(pending.intervalSeconds, 1))) s"
        case .checking: "Checking…"
        case .denied: "Denied by the issuer"
        case .failed(let message): "Couldn't check: \(message)"
        }
    }
}
