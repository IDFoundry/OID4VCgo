import CryptoKit
import Foundation
import LocalAuthentication
import Observation
import UIKit
import OID4VCMobile

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
            await refresh()
        }
    }

    /// Deletes every credential and its holder key: for UI tests, which
    /// launch with OID4VC_DEMO_RESET=1 to start from an empty wallet.
    private func deleteAll() async {
        guard let wallet, let held = try? await wallet.credentials() else { return }
        for c in held {
            try? await wallet.deleteCredential(id: c.id)
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

    /// Receives the offered credentials; `authorize` opens the issuer's
    /// authorization page and returns the redirect.
    func receive(authorize: (URL) async throws -> URL) async {
        guard let issuance, let offer else { return }
        phase = .receiving
        do {
            if offer.grant == .preAuthorizedCode {
                try await issuance.redeemPreAuthorizedCode(pin: pin)
            } else {
                let url = try await issuance.beginAuthorization()
                try await issuance.completeAuthorization(redirect: try await authorize(url))
            }
            let result = try await issuance.requestCredentials()
            var summary = "Received \(result.credentials.count) credential(s)"
            if !result.deferred.isEmpty { summary += ", \(result.deferred.count) deferred" }
            phase = .done(summary)
            if result.deferred.isEmpty {
                await closeIssuance()
            } else {
                // The issuance stays open — its access token polls the
                // deferred credentials — until they're all settled.
                self.issuance = nil
                self.offer = nil
                for d in result.deferred { track(d, of: issuance) }
            }
        } catch {
            phase = .failed(Self.describe(error))
            // Don't leave the issuance's keys in the Keychain: the holder
            // starts again from the offer.
            await closeIssuance()
        }
        await refresh()
    }

    // MARK: Deferred credentials

    /// A credential the issuer will issue later (OpenID4VCI 1.0 §9),
    /// polled at the issuer's interval until it's issued or denied. It
    /// lives in memory: one still pending when the app quits is lost.
    struct PendingCredential: Identifiable, Equatable {
        enum State: Equatable { case waiting, checking, denied, failed(String) }

        let id: String
        let configurationID: String
        var intervalSeconds: Double
        var state: State

        static func == (a: Self, b: Self) -> Bool {
            a.id == b.id && a.state == b.state && a.intervalSeconds == b.intervalSeconds
        }
    }

    private(set) var pending: [PendingCredential] = []
    private var pendingIssuances: [String: Issuance] = [:]
    private var pollTasks: [String: Task<Void, Never>] = [:]

    private func track(_ d: Issuance.Deferred, of issuance: Issuance) {
        pending.append(PendingCredential(id: d.id, configurationID: d.configurationID, intervalSeconds: d.intervalSeconds, state: .waiting))
        pendingIssuances[d.id] = issuance
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
        guard let i = pending.firstIndex(where: { $0.id == id }), let issuance = pendingIssuances[id] else { return }
        pending[i].state = .checking
        do {
            switch try await issuance.pollDeferred(id: id) {
            case .pending(let interval):
                update(id) { $0.state = .waiting; $0.intervalSeconds = interval }
                schedule(id)
            case .issued:
                await settle(id)
                phase = .done("Received a deferred credential")
                await refresh()
            }
        } catch let e as WalletError where e.code == .credentialDenied {
            update(id) { $0.state = .denied }
            await release(id)
        } catch {
            update(id) { $0.state = .failed(Self.describe(error)) }
        }
    }

    /// Forgets a denied credential.
    func dismiss(_ id: String) async {
        await settle(id)
    }

    private func update(_ id: String, _ change: (inout PendingCredential) -> Void) {
        if let i = pending.firstIndex(where: { $0.id == id }) { change(&pending[i]) }
    }

    /// Removes `id`, and closes its issuance when nothing else waits on it.
    private func settle(_ id: String) async {
        pending.removeAll { $0.id == id }
        await release(id)
    }

    private func release(_ id: String) async {
        pollTasks[id]?.cancel()
        pollTasks[id] = nil
        guard let issuance = pendingIssuances.removeValue(forKey: id) else { return }
        if !pendingIssuances.values.contains(where: { $0 === issuance }) {
            try? await issuance.close()
        }
    }

    /// An error as the holder sees it: the wallet's own sentence, and —
    /// for the demo — its code.
    static func describe(_ error: Error) -> String {
        if let e = error as? WalletError { return "\(e.localizedDescription) (\(e.code.rawValue)\(e.protocolError.map { ": " + $0 } ?? ""))" }
        return error.localizedDescription
    }

    func cancelOffer() async {
        await closeIssuance()
        phase = .idle
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

    private func closeIssuance() async {
        try? await issuance?.close()
        issuance = nil
        offer = nil
    }
}
