import CryptoKit
import DeviceCheck
import Foundation

/// Apple App Attest, as ``HttpWalletProvider`` uses it: the app's App
/// Attest key, made once at registration, attested by Apple, and
/// asserting over the client data of each later request.
/// ``DeviceAppAttestService`` is `DCAppAttestService`; a test supplies
/// its own.
public protocol AppAttestService: Sendable {
    /// Whether the device can make App Attest keys: false in the
    /// Simulator and on some older devices, where the app can't register
    /// with the Wallet Provider.
    var isSupported: Bool { get }
    /// Makes a new App Attest key and returns its key ID.
    func generateKey() async throws -> String
    /// Apple's attestation object for the key `keyID` over
    /// `clientDataHash`.
    func attestKey(_ keyID: String, clientDataHash: Data) async throws -> Data
    /// An assertion by the key `keyID` over `clientDataHash`.
    func generateAssertion(_ keyID: String, clientDataHash: Data) async throws -> Data
}

/// App Attest on this device: `DCAppAttestService.shared`. Its keys are
/// the environment's the app's
/// `com.apple.developer.devicecheck.appattest-environment` entitlement
/// names: `development` for a development build, `production` for a
/// distributed one, which only a provider accepting that environment
/// takes.
///
/// `DCError.serverUnavailable` is thrown as a
/// ``WalletProviderUnavailableError`` (a `.network` failure, which may be
/// retried); `DCError.invalidKey`, the App Attest key gone, as an
/// ``AppAttestKeyLostError``; any other error as it is.
public struct DeviceAppAttestService: AppAttestService {
    /// The device's App Attest.
    public init() {}

    public var isSupported: Bool { DCAppAttestService.shared.isSupported }

    public func generateKey() async throws -> String {
        try await mapped { try await service().generateKey() }
    }

    public func attestKey(_ keyID: String, clientDataHash: Data) async throws -> Data {
        try await mapped { try await service().attestKey(keyID, clientDataHash: clientDataHash) }
    }

    public func generateAssertion(_ keyID: String, clientDataHash: Data) async throws -> Data {
        try await mapped { try await service().generateAssertion(keyID, clientDataHash: clientDataHash) }
    }

    private func service() throws -> DCAppAttestService {
        let s = DCAppAttestService.shared
        guard s.isSupported else { throw StoreError(appAttestUnsupported) }
        return s
    }

    private func mapped<T>(_ body: () async throws -> T) async throws -> T {
        do {
            return try await body()
        } catch let e as DCError where e.code == .serverUnavailable {
            throw WalletProviderUnavailableError(status: nil, error: nil, message: "App Attest's server is unavailable")
        } catch let e as DCError where e.code == .invalidKey {
            throw AppAttestKeyLostError()
        }
    }
}

/// The App Attest key the registration names is gone — the app was
/// restored from a backup, or reinstalled — so it can't assert: the
/// installation must register again.
public struct AppAttestKeyLostError: LocalizedError, Sendable {
    /// The error.
    public init() {}
    /// The message.
    public var errorDescription: String? { "the App Attest key is gone: the app must register with the Wallet Provider again" }
}

let appAttestUnsupported = "App Attest isn't supported on this device (the Simulator, or an older device): it can't register with the Wallet Provider"

/// The client data an App Attest attestation or assertion is made over,
/// for the Wallet Provider protocol's `apple-app-attest` evidence
/// (WALLET_PROVIDER.md, Client data): LF-terminated lines of a fixed
/// prefix, the challenge's purpose, the challenge as the provider issued
/// it, and each key's RFC 7638 thumbprint, in the order the request
/// lists the keys.
enum AppAttestClientData {
    static let prefix = "OID4VCgo-WalletProvider-AppAttest/1"

    /// The client data for `purpose` and `challenge` over `keys`,
    /// uncompressed P-256 points.
    static func data(purpose: String, challenge: String, keys: [Data]) -> Data {
        var text = prefix + "\n" + purpose + "\n" + challenge + "\n"
        for k in keys { text += jwkThumbprint(point: k) + "\n" }
        return Data(text.utf8)
    }

    /// The SHA-256 of ``data(purpose:challenge:keys:)``: the
    /// `clientDataHash` App Attest is given.
    static func hash(purpose: String, challenge: String, keys: [Data]) -> Data {
        Data(SHA256.hash(data: data(purpose: purpose, challenge: challenge, keys: keys)))
    }
}
