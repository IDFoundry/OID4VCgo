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
    }

    private(set) var credentials: [CredentialSummary] = []
    private(set) var configured = false
    private(set) var offer: Offer?
    var phase: Phase = .idle
    var pin = ""

    private var wallet: Wallet?
    private var keys: KeychainKeyStore?
    private var config: DemoConfiguration?
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
            let presence = LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
            #endif
            let keys = KeychainKeyStore(options: .init(secureEnclave: SecureEnclave.isAvailable, persistent: true,
                                                       holderUserPresence: presence))
            wallet = try Wallet(configuration: config.wallet, keyStore: keys, credentialStore: try FileCredentialStore.standard(),
                                provider: HTTPWalletProvider(baseURL: config.providerURL))
            self.keys = keys
            self.config = config
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
    var selected: Set<String> = []
    /// The selection `disclosures` was computed for: Share sends only a
    /// selection the holder has seen previewed.
    private(set) var previewed: Set<String>?
    /// Why the selection couldn't be previewed, if it couldn't.
    private(set) var previewError: String?

    /// Whether Share would send exactly what "Will share" shows.
    var canShare: Bool {
        !selected.isEmpty && previewed == selected && previewError == nil && requestPhase == .shown
    }

    /// Fetches and verifies a presentation request, and preselects the
    /// first credential that can answer it.
    func startPresentation(request link: String) async {
        guard let wallet else { return }
        do {
            let p = try await wallet.startPresentation(request: link)
            presentation = p
            selected = p.candidates.first?.credentials.first.map { [$0.id] } ?? []
            requestPhase = .shown
            await updatePreview()
        } catch {
            phase = .failed(Self.describe(error))
        }
    }

    func toggle(_ id: String) async {
        if selected.contains(id) { selected.remove(id) } else { selected.insert(id) }
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
            let result = try await presentation.preview(credentialIDs: Array(selection))
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
            let presented = try await presentation.respond(credentialIDs: Array(selection))
            phase = .done("Shared with \(presentation.verifier.name)")
            endPresentation()
            if let url = presented.redirectURI, url.scheme == "https" { await UIApplication.shared.open(url) }
        } catch {
            phase = .failed(Self.describe(error))
            endPresentation()
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
        selected = []
        previewed = nil
        previewError = nil
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
        if !result.failed.isEmpty { summary += "; \(result.failed.count) couldn't be issued" }
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

    func refresh() async {
        guard let wallet else { return }
        do {
            credentials = try await wallet.credentials()
        } catch {
            phase = .failed("Couldn't list credentials: " + Self.describe(error))
        }
    }

    /// Checks a credential's revocation status in its issuer's status
    /// list, and shows it.
    func checkStatus(_ id: String) async {
        guard let wallet else { return }
        do {
            let checked = try await wallet.checkStatus(id: id)
            if let i = credentials.firstIndex(where: { $0.id == id }) { credentials[i] = checked }
        } catch {
            notice = "Couldn't check the status: " + Self.describe(error)
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
