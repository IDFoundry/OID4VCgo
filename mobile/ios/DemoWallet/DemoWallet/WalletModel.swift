import CryptoKit
import Foundation
import LocalAuthentication
import Observation
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
            self.config = config
            configured = true
            if let offer = ProcessInfo.processInfo.environment["OID4VC_DEMO_OFFER"], let url = URL(string: offer) {
                open(url)
            }
        } catch {
            phase = .failed("\(error)")
        }
        let reset = ProcessInfo.processInfo.environment["OID4VC_DEMO_RESET"] == "1"
        Task {
            if reset { await deleteAll() }
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
    var callbackScheme: String { config.flatMap { URL(string: $0.wallet.redirectURI)?.scheme } ?? "" }

    func open(_ url: URL) {
        guard url.scheme == "openid-credential-offer" else { return }
        Task { await start(offer: url.absoluteString) }
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
            phase = .failed("\(error)")
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
            await closeIssuance()
        } catch {
            phase = .failed("\(error)")
        }
        await refresh()
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
            phase = .failed("Couldn't list credentials: \(error)")
        }
    }

    private func closeIssuance() async {
        try? await issuance?.close()
        issuance = nil
        offer = nil
    }
}
