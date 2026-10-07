import AuthenticationServices
import CryptoKit
import Foundation
import LocalAuthentication
import Observation
import UIKit
import OID4VCWallet

/// The demo wallet's state: the wallet, what it holds, and the issuance
/// in progress.
@MainActor @Observable
final class WalletModel {
    enum Phase: Equatable {
        case idle
        case offered
        case receiving
        case done(String)
        case failed(String)
        /// A presentation request from a verifier the wallet doesn't
        /// trust was refused unopened.
        case untrustedVerifier
    }

    private(set) var credentials: [CredentialSummary] = []
    /// Each held credential's claims, by ID: to group the credentials by
    /// whose they are.
    private(set) var claims: [String: JSONValue] = [:]
    private(set) var configured = false
    /// Why the wallet can't run on this device, when it can't.
    private(set) var unavailable: String?
    private(set) var offer: Offer?
    var phase: Phase = .idle
    var pin = ""

    private(set) var wallet: Wallet?
    private var keys: KeychainKeyStore?
    private(set) var config: DemoConfiguration?

    /// Which copy of a credential a presentation uses, as chosen in the
    /// app's settings; it overrides the configuration's.
    private(set) var copyPolicy: WalletConfiguration.CopyPolicy = .perPresentation
    private static let copyPolicyKey = SharedWallet.copyPolicyKey

    /// Not configured: there's no wallet to make.
    private struct NotConfigured: Error {}

    private func makeWallet() throws -> Wallet {
        guard let config, let keys else { throw NotConfigured() }
        var configuration = config.wallet
        configuration.copyPolicy = copyPolicy
        return try Wallet(configuration: configuration, keyStore: keys, credentialStore: try SharedWallet.credentialStore(),
                          provider: HTTPWalletProvider(baseURL: config.providerURL))
    }

    /// Switches the copy policy, rebuilding the wallet over the same keys
    /// and credentials.
    func setCopyPolicy(_ policy: WalletConfiguration.CopyPolicy) {
        guard policy != copyPolicy, presentation == nil else { return }
        copyPolicy = policy
        SharedWallet.defaults.set(policy.rawValue, forKey: Self.copyPolicyKey)
        do {
            wallet = try makeWallet()
        } catch {
            phase = .failed(Self.describe(error))
        }
    }
    private var issuance: Issuance?

    init() {
        guard let config = DemoConfiguration.load() else { return }
        do {
            // Secure Enclave keys, kept in the Keychain; holder keys need
            // Face ID or the passcode to present. The Simulator can't make
            // a Secure Enclave key requiring user presence (OSStatus
            // -25293), so there they don't.
            #if targetEnvironment(simulator)
            let presence = false
            #else
            // Without a passcode, holder keys would present with no one
            // there to agree: don't run.
            guard LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil) else {
                unavailable = "Set a device passcode to use this wallet: presenting a credential needs Face ID or the passcode."
                return
            }
            let presence = true
            #endif
            // Holder keys in the access group the document provider
            // extension shares, so it can present.
            let keys = SharedWallet.keyStore(presence: presence)
            self.keys = keys
            self.config = config
            // A reset (OID4VC_DEMO_RESET) starts from the configuration's
            // copy policy too.
            if ProcessInfo.processInfo.environment["OID4VC_DEMO_RESET"] == "1" {
                SharedWallet.defaults.removeObject(forKey: Self.copyPolicyKey)
            }
            if let saved = SharedWallet.defaults.string(forKey: Self.copyPolicyKey),
               let policy = WalletConfiguration.CopyPolicy(rawValue: saved) {
                copyPolicy = policy
            } else {
                copyPolicy = config.wallet.copyPolicy
            }
            wallet = try makeWallet()
            configured = true
            if let offer = ProcessInfo.processInfo.environment["OID4VC_DEMO_OFFER"], let url = URL(string: offer) {
                open(url)
            }
            if let request = ProcessInfo.processInfo.environment["OID4VC_DEMO_REQUEST"], let url = URL(string: request) {
                open(url)
            }
        } catch {
            phase = .failed(Self.describe(error))
        }
        if OID4VC.isTestBuild {
            notice = "This build links the test framework, with its in-process test issuer: never ship it."
        }
        let reset = ProcessInfo.processInfo.environment["OID4VC_DEMO_RESET"] == "1"
        Task {
            if reset { await deleteAll() }
            // At launch, before any issuance: delete keys left by one the
            // app quit in the middle of.
            if let wallet, let keys { _ = try? await wallet.sweepOrphanedKeys(in: keys) }
            await resumeDeferred()
            await refresh()
            await checkAllStatuses()
            await refreshUsedUp()
        }
    }

    /// Deletes every credential and pending deferred credential, with
    /// their keys: for UI tests, which launch with OID4VC_DEMO_RESET=1 to
    /// start from an empty wallet.
    private func deleteAll() async {
        guard let wallet else { return }
        for c in (try? await wallet.credentials()) ?? [] {
            try? await wallet.deleteCredential(id: c.id)
        }
        for d in (try? await wallet.deferredCredentials()) ?? [] {
            try? await wallet.abandonDeferred(id: d.id)
        }
    }

    /// The redirect URI's scheme, for the authorization session.
    var callbackScheme: String { config?.wallet.callbackScheme ?? "" }

    /// Something to tell the holder that isn't a receive's or
    /// presentation's outcome.
    var notice: String?

    /// Whether a receive or a presentation is in progress: a link that
    /// arrives then is refused rather than replacing it.
    private var busy: Bool {
        phase == .offered || phase == .receiving || requestPhase != .idle
    }

    /// A link another app opened the wallet with, held until the holder
    /// chooses to open it: opening it contacts the issuer or Verifier it
    /// names.
    var linkToConfirm: URL?

    /// Opens a link from another app: an issuer's redirect at once, an
    /// offer or a request once the holder confirms (linkToConfirm).
    /// A holder's engagement another app handed over (an mdoc: link), for
    /// reader mode to read.
    var engagementToRead: String?

    func openFromOutside(_ url: URL) {
        if QRCode.isEngagement(url) {
            if config?.reader != nil, InPersonModel.readerMode {
                engagementToRead = url.absoluteString
            } else {
                notice = "Turn on reader mode in the settings to verify in person."
            }
            return
        }
        guard url.scheme == "openid-credential-offer" || url.scheme == "openid4vp" else {
            open(url)
            return
        }
        linkToConfirm = url
    }

    func confirmLink() {
        guard let url = linkToConfirm else { return }
        linkToConfirm = nil
        open(url)
    }

    func open(_ url: URL) {
        // The issuer's redirect, arriving here rather than in the
        // authorization session — the app was killed while the holder was
        // at the issuer's pages — completes the issuance it began.
        if url.scheme == callbackScheme, !callbackScheme.isEmpty {
            if issuance == nil { Task { await resume(redirect: url) } }
            return
        }
        guard url.scheme == "openid-credential-offer" || url.scheme == "openid4vp" else { return }
        if busy {
            notice = "Finish or cancel the current request before opening another."
            return
        }
        notice = nil
        switch url.scheme {
        case "openid-credential-offer": Task { await start(offer: url.absoluteString) }
        case "openid4vp": Task { await startPresentation(request: url.absoluteString) }
        default: break
        }
    }

    // MARK: Presentation

    enum RequestPhase: Equatable { case idle, shown, sharing }

    private(set) var presentation: Presentation?
    private(set) var disclosures: [Presentation.Disclosure] = []
    var requestPhase: RequestPhase = .idle
    /// The holder's choice: for each query, the credentials to answer it.
    private(set) var selected: Presentation.Selection = [:]
    /// The selection `disclosures` was computed for: Share sends only a
    /// selection the holder has seen previewed.
    private(set) var previewed: Presentation.Selection?
    /// Why the selection couldn't be previewed, if it couldn't.
    private(set) var previewError: String?
    /// Each candidate credential's claims, by ID: to say whose it is,
    /// and show the values sharing it discloses.
    private(set) var candidateClaims: [String: JSONValue] = [:]

    /// Whether Share would send exactly what "Will share" shows.
    var canShare: Bool {
        !selected.isEmpty && previewed == selected && previewError == nil && requestPhase == .shown
    }

    /// Fetches and verifies a presentation request, and preselects what
    /// the wallet would choose itself.
    func startPresentation(request link: String) async {
        guard let wallet else { return }
        do {
            let p = try await wallet.startPresentation(request: link)
            var claims: [String: JSONValue] = [:]
            for c in p.queries.flatMap(\.credentials) where claims[c.id] == nil {
                claims[c.id] = try? await wallet.credential(id: c.id).claims
            }
            candidateClaims = claims
            presentation = p
            selected = (try? await p.defaultSelection()) ?? [:]
            requestPhase = .shown
            await updatePreview()
        } catch let e as WalletError where e.code == .untrustedVerifier {
            phase = .untrustedVerifier
        } catch {
            phase = .failed(Self.describe(error))
        }
    }

    /// Whether credential `id` is chosen to answer `queryID`.
    func isSelected(_ id: String, for queryID: String) -> Bool {
        selected[queryID]?.contains(id) ?? false
    }

    /// Chooses credential `id` to answer `query`, or unchooses it. A
    /// query takes one credential unless it asks for several (DCQL
    /// `multiple`, OpenID4VP 1.0 §6.1): then choosing one unchooses its
    /// others.
    func toggle(_ id: String, for query: Presentation.Query) async {
        var chosen = selected[query.queryID] ?? []
        if chosen.contains(id) {
            chosen.removeAll { $0 == id }
        } else {
            chosen = query.multiple ? chosen + [id] : [id]
        }
        selected[query.queryID] = chosen.isEmpty ? nil : chosen
        await updatePreview()
    }

    private func updatePreview() async {
        let selection = selected
        previewed = nil
        previewError = nil
        guard let presentation, !selection.isEmpty else {
            disclosures = []
            return
        }
        do {
            let result = try await presentation.preview(selection: selection)
            // A newer selection's preview supersedes this one.
            guard selection == selected else { return }
            disclosures = result
            previewed = selection
        } catch {
            guard selection == selected else { return }
            disclosures = []
            previewError = Self.describe(error)
        }
    }

    /// Shares the selected credentials: holder keys sign now, so Face ID
    /// or the passcode is asked for on a device.
    func share() async {
        guard let presentation, canShare, let selection = previewed else { return }
        requestPhase = .sharing
        do {
            let presented = try await presentation.respond(selection: selection)
            phase = .done("Shared with \(presentation.verifier.name)")
            endPresentation()
            // A copy of each shared credential is used up.
            await refresh()
            await refreshUsedUp()
            if let url = presented.redirectURI, url.scheme == "https" { await UIApplication.shared.open(url) }
        } catch {
            phase = .failed(Self.describe(error))
            endPresentation()
            await refresh()
        }
    }

    func decline() async {
        guard let presentation else { return }
        do {
            let presented = try await presentation.decline()
            phase = .done("Declined \(presentation.verifier.name)")
            endPresentation()
            if let url = presented.redirectURI, url.scheme == "https" { await UIApplication.shared.open(url) }
        } catch {
            phase = .failed(Self.describe(error))
            endPresentation()
        }
    }

    private func endPresentation() {
        presentation = nil
        disclosures = []
        selected = [:]
        previewed = nil
        previewError = nil
        candidateClaims = [:]
        requestPhase = .idle
    }

    func start(offer link: String) async {
        guard let wallet else { return }
        await closeIssuance()
        offerError = nil
        do {
            let s = try await wallet.startIssuance(offer: link)
            issuance = s
            offer = s.offer
            pin = ""
            phase = .offered
        } catch {
            phase = .failed(Self.describe(error))
        }
    }

    /// Why the last attempt to receive failed, when trying again may
    /// work: shown on the offer, which stays open.
    private(set) var offerError: String?
    /// Whether the issuance has its access token: a retry then only
    /// requests the credentials.
    private var authorized = false
    private var receiveTask: Task<Void, Never>?

    /// Starts receiving, as a task Cancel can stop.
    func startReceive(authorize: @escaping (URL) async throws -> URL) {
        receiveTask = Task { await receive(authorize: authorize) }
    }

    /// Receives the offered credentials; `authorize` opens the issuer's
    /// authorization page and returns the redirect. A failure that
    /// trying again may fix (the network, a wrong PIN) keeps the offer
    /// open to try again; any other ends it.
    func receive(authorize: (URL) async throws -> URL) async {
        guard let issuance, let offer else { return }
        phase = .receiving
        offerError = nil
        do {
            if !authorized {
                if offer.grant == .preAuthorizedCode {
                    try await issuance.redeemPreAuthorizedCode(pin: pin)
                } else {
                    // After a failed completeAuthorization this starts the
                    // authorization over, as it must.
                    let url = try await issuance.beginAuthorization()
                    try await issuance.completeAuthorization(redirect: try await authorize(url))
                }
                authorized = true
            }
            try await requestCredentials(issuance)
        } catch let e as WalletError where e.code == .cancelled {
            if phase == .receiving { phase = .offered }
        } catch let e as NSError where e.domain == ASWebAuthenticationSessionErrorDomain
            && e.code == ASWebAuthenticationSessionError.canceledLogin.rawValue {
            // The holder closed the issuer's page: the offer stays.
            phase = .offered
        } catch let e as WalletError where e.isRetryable {
            phase = .offered
            offerError = Self.describe(e)
            if e.protocolError == "invalid_grant" { pin = "" }
            // Anything deferred before the failure is pending already.
            await resumeDeferred()
        } catch {
            phase = .failed(Self.describe(error))
            // Don't leave the issuance's keys in the Keychain: the holder
            // starts again from the offer.
            await closeIssuance()
            await resumeDeferred()
        }
        await refresh()
    }

    /// Completes, after a relaunch, an issuance whose authorization was in
    /// progress when the app was killed.
    func resume(redirect: URL) async {
        guard let wallet, !busy else { return }
        phase = .receiving
        do {
            let s = try await wallet.resumeIssuance(redirect: redirect)
            issuance = s
            offer = s.offer
            try await requestCredentials(s)
        } catch let e as WalletError where e.code == .notFound {
            phase = .idle
            notice = "That sign-in has expired or was already used. Open the offer again."
        } catch {
            phase = .failed(Self.describe(error))
            await closeIssuance()
        }
        await refresh()
    }

    private func requestCredentials(_ issuance: Issuance) async throws {
        let result = try await issuance.requestCredentials()
        var summary = "Received \(result.credentials.count) credential(s)"
        if !result.deferred.isEmpty { summary += ", \(result.deferred.count) deferred" }
        if !result.failed.isEmpty {
            let reasons = result.failed.map { f in
                "\(f.configurationID): \(f.code.rawValue)" + (f.protocolError.map { " (\($0))" } ?? "")
            }
            summary += "; \(result.failed.count) couldn't be issued — \(reasons.joined(separator: "; "))"
        }
        phase = .done(summary)
        // Deferred credentials are kept in the credential store, with
        // what polling them needs: they outlive the issuance, and the
        // app quitting.
        await closeIssuance()
        for d in result.deferred { track(d) }
    }

    // MARK: Deferred credentials

    /// A credential the issuer will issue later (OpenID4VCI 1.0 §9),
    /// polled at the issuer's interval until it's issued or denied. The
    /// wallet keeps it in the credential store, so after a relaunch it's
    /// resumed (resumeDeferred).
    struct PendingCredential: Identifiable, Equatable {
        enum State: Equatable { case waiting, checking, denied, failed(String) }

        let id: String
        let configurationID: String
        var intervalSeconds: Double
        var state: State
    }

    private(set) var pending: [PendingCredential] = []
    private var pollTasks: [String: Task<Void, Never>] = [:]

    /// Picks up the deferred credentials the wallet holds — from before
    /// the app last quit — and polls them.
    private func resumeDeferred() async {
        guard let wallet, let held = try? await wallet.deferredCredentials() else { return }
        for d in held { track(d) }
    }

    private func track(_ d: DeferredCredential) {
        guard !pending.contains(where: { $0.id == d.id }) else { return }
        pending.append(PendingCredential(id: d.id, configurationID: d.configurationID, intervalSeconds: d.intervalSeconds, state: .waiting))
        schedule(d.id)
    }

    /// Polls `id` once its interval has passed (at least a second).
    private func schedule(_ id: String) {
        guard let p = pending.first(where: { $0.id == id }) else { return }
        pollTasks[id]?.cancel()
        let wait = max(p.intervalSeconds, 1)
        pollTasks[id] = Task { [weak self] in
            try? await Task.sleep(for: .seconds(wait))
            guard !Task.isCancelled else { return }
            await self?.poll(id)
        }
    }

    /// Asks the issuer about `id` now.
    func checkAgain(_ id: String) async {
        pollTasks[id]?.cancel()
        await poll(id)
    }

    private func poll(_ id: String) async {
        guard let wallet, let i = pending.firstIndex(where: { $0.id == id }) else { return }
        pending[i].state = .checking
        do {
            switch try await wallet.pollDeferred(id: id) {
            case .pending(let interval):
                update(id) { $0.state = .waiting; $0.intervalSeconds = interval }
                schedule(id)
            case .issued:
                forget(id)
                phase = .done("Received a deferred credential")
                await refresh()
            }
        } catch let e as WalletError where e.code == .credentialDenied {
            // The wallet has already forgotten it; the row stays until
            // it's dismissed.
            update(id) { $0.state = .denied }
        } catch {
            update(id) { $0.state = .failed(Self.describe(error)) }
            // A failure trying again may fix: keep polling, less often.
            if let e = error as? WalletError, e.isRetryable {
                update(id) { $0.intervalSeconds = min(max($0.intervalSeconds, 1) * 2, 60) }
                schedule(id)
            }
        }
    }

    /// Removes a denied credential's row.
    func dismiss(_ id: String) async {
        forget(id)
    }

    /// Gives up on a credential that can't be checked — its access token
    /// expired, say — deleting it and its keys.
    func abandon(_ id: String) async {
        try? await wallet?.abandonDeferred(id: id)
        forget(id)
    }

    private func update(_ id: String, _ change: (inout PendingCredential) -> Void) {
        if let i = pending.firstIndex(where: { $0.id == id }) { change(&pending[i]) }
    }

    private func forget(_ id: String) {
        pollTasks[id]?.cancel()
        pollTasks[id] = nil
        pending.removeAll { $0.id == id }
    }

    /// An error as the holder sees it: the wallet's own sentence, and —
    /// for the demo — its code.
    static func describe(_ error: Error) -> String {
        if let e = error as? WalletError { return "\(e.localizedDescription) (\(e.code.rawValue)\(e.protocolError.map { ": " + $0 } ?? ""))" }
        return error.localizedDescription
    }

    /// Stops receiving — the request in progress included — and ends the
    /// offer.
    func cancelOffer() async {
        receiveTask?.cancel()
        await receiveTask?.value
        receiveTask = nil
        await closeIssuance()
        phase = .idle
        offerError = nil
    }

    func detail(_ c: CredentialSummary) async -> CredentialDetail? {
        try? await wallet?.credential(id: c.id)
    }

    func delete(_ c: CredentialSummary) async {
        try? await wallet?.deleteCredential(id: c.id)
        await refresh()
    }

    /// The document provider extension presents from its own process,
    /// using copies in the shared store: on returning to the app, list
    /// them again, and refresh any it used up, as after presenting here.
    /// Not during an issuance or a presentation of the app's own.
    func becameActive() async {
        await refresh()
        if issuance == nil && presentation == nil { await refreshUsedUp() }
    }

    func refresh() async {
        guard let wallet else { return }
        do {
            credentials = try await wallet.credentials()
            await loadClaims(reload: [])
            // In the background: the list needn't wait for iOS.
            let held = credentials
            let roots = config?.wallet.mdocReaderRoots ?? ""
            Task.detached { await DocumentRegistrations.sync(held, readerRootsPEM: roots) }
        } catch {
            phase = .failed("Couldn't list credentials: " + Self.describe(error))
        }
    }

    /// Loads the claims of credentials not loaded yet, and of reload (a
    /// refresh can change them, such as an age claim), dropping those of
    /// credentials no longer held.
    private func loadClaims(reload: Set<String>) async {
        guard let wallet else { return }
        var loaded = claims.filter { id, _ in credentials.contains { $0.id == id } && !reload.contains(id) }
        for c in credentials where loaded[c.id] == nil {
            loaded[c.id] = try? await wallet.credential(id: c.id).claims
        }
        claims = loaded
    }

    /// The held credentials grouped by whose they are — the holder's name
    /// and date of birth from their claims — those of one holder oldest
    /// first, and those naming no holder last.
    var credentialsByHolder: [(holder: Holder?, credentials: [CredentialSummary])] {
        var groups: [String: (holder: Holder?, credentials: [CredentialSummary])] = [:]
        for c in credentials.sorted(by: { $0.receivedAt < $1.receivedAt }) {
            let holder = Holder(claims: claims[c.id])
            let key = holder.map { "\($0.name ?? "")|\($0.birthDate ?? "")" } ?? ""
            groups[key, default: (holder, [])].credentials.append(c)
            if groups[key]?.holder?.portrait == nil, holder?.portrait != nil { groups[key]?.holder = holder }
        }
        return groups.sorted { a, b in
            if a.key.isEmpty != b.key.isEmpty { return !a.key.isEmpty }
            return a.key < b.key
        }.map(\.value)
    }

    /// Checks a credential's revocation status in its issuer's status
    /// list, and shows it. Returns why it couldn't, if it couldn't.
    func checkStatus(_ id: String) async -> String? {
        guard let wallet else { return "The wallet isn't configured." }
        do {
            let checked = try await wallet.checkStatus(id: id)
            if let i = credentials.firstIndex(where: { $0.id == id }) { credentials[i] = checked }
            return nil
        } catch {
            return Self.describe(error)
        }
    }

    /// How refreshing a credential's copies ended.
    enum RefreshOutcome: Equatable {
        /// Fresh copies replaced the old ones.
        case refreshed(copies: Int)
        /// The issuer will issue them later: they're waiting for it.
        case deferred
        /// It can't be refreshed any more: receive it again.
        case reissueRequired
        /// It couldn't be refreshed now, for this reason.
        case failed(String)
    }

    /// Replaces a credential's copies with a fresh batch, without the
    /// holder, using the refresh token its issuance kept. One that can't
    /// be refreshed any more has to be received again.
    func refreshCopies(_ id: String) async -> RefreshOutcome {
        guard let wallet else { return .failed("The wallet isn't configured.") }
        do {
            let refreshed = try await wallet.refreshCredential(id: id)
            if let i = credentials.firstIndex(where: { $0.id == id }) { credentials[i] = refreshed.credential }
            await loadClaims(reload: [id])
            if let deferred = refreshed.deferred {
                track(deferred)
                return .deferred
            }
            return .refreshed(copies: refreshed.credential.copies)
        } catch let e as WalletError where e.code == .reissueRequired {
            await refresh()
            return .reissueRequired
        } catch {
            return .failed(Self.describe(error))
        }
    }

    /// Refreshes, without the holder, each credential that has a refresh
    /// token and no unused copy left — after a presentation, and at
    /// launch — so the next verifier gets a fresh copy rather than one
    /// another verifier has seen. Quietly: one that fails for now is
    /// tried again next time; one that can't be refreshed any more says
    /// so, and isn't refreshable after that.
    private func refreshUsedUp() async {
        guard let wallet else { return }
        for c in credentials where c.refreshable && c.copiesLeft == 0 {
            do {
                let refreshed = try await wallet.refreshCredential(id: c.id)
                if let i = credentials.firstIndex(where: { $0.id == c.id }) { credentials[i] = refreshed.credential }
                if let deferred = refreshed.deferred { track(deferred) }
            } catch let e as WalletError where e.code == .reissueRequired {
                notice = "Every copy of a credential has been shared, and it can't be refreshed any more: receive it again from the issuer."
                await refresh()
            } catch {
                continue
            }
        }
    }

    /// Checks every credential's status, at launch: one status list per
    /// issuer covers many credentials, so this tells no issuer which
    /// credentials the holder has.
    /// Quietly: a status list out of reach at launch isn't worth a
    /// notice, and the last status found stays shown.
    private func checkAllStatuses() async {
        guard let wallet else { return }
        for c in credentials {
            if let checked = try? await wallet.checkStatus(id: c.id), let i = credentials.firstIndex(where: { $0.id == c.id }) {
                credentials[i] = checked
            }
        }
    }

    private func closeIssuance() async {
        try? await issuance?.close()
        issuance = nil
        offer = nil
        authorized = false
    }
}
