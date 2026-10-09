import Foundation
import OID4VCWallet

/// What the demo wallet talks to: the wallet's configuration and the
/// Wallet Provider's URL — the JSON mobile/cmd/testservices serves at
/// /config, or mobile/ios/DemoWallet/run-passport-vdc.sh builds for the
/// passport-vdc demo. It comes from the OID4VC_DEMO_CONFIG environment
/// variable (simctl launch passes SIMCTL_CHILD_OID4VC_DEMO_CONFIG), and
/// is remembered for later launches, in the app group, where the document
/// provider extension reads it.
struct DemoConfiguration: Codable, Sendable {
    var wallet: WalletConfiguration
    /// The Wallet Provider, for issuers that ask for attestations; nil
    /// for a wallet that receives only from issuers that don't.
    var providerURL: URL?
    /// The reader mode's identity, when the services give one.
    var reader: Reader?

    /// A demo reader: the IACAs it accepts, and its key (PKCS #8 PEM) and
    /// certificate chain (PEM, leaf first). A demo shortcut: a real
    /// reader's key is made on its device and never leaves it.
    struct Reader: Codable, Sendable {
        var issuerRoots: String
        var readerChain: String
        var readerKey: String

        enum CodingKeys: String, CodingKey {
            case issuerRoots = "issuer_roots", readerChain = "reader_chain", readerKey = "reader_key"
        }
    }

    enum CodingKeys: String, CodingKey { case wallet, providerURL = "provider_url", reader }

    private static let defaultsKey = "demo-configuration"

    static func load() -> DemoConfiguration? {
        if let text = ProcessInfo.processInfo.environment["OID4VC_DEMO_CONFIG"], let data = text.data(using: .utf8),
           let config = try? JSONDecoder().decode(DemoConfiguration.self, from: data) {
            SharedWallet.defaults.set(data, forKey: defaultsKey)
            return config
        }
        guard let data = SharedWallet.defaults.data(forKey: defaultsKey) else { return nil }
        return try? JSONDecoder().decode(DemoConfiguration.self, from: data)
    }
}
