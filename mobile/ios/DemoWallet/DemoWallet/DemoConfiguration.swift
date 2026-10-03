import Foundation
import OID4VCMobile

/// What the demo wallet talks to: the wallet's configuration and the
/// Wallet Provider's URL — the JSON mobile/cmd/testservices serves at
/// /config, or mobile/ios/DemoWallet/run-passport-vdc.sh builds for the
/// passport-vdc demo. It comes from the OID4VC_DEMO_CONFIG environment
/// variable (simctl launch passes SIMCTL_CHILD_OID4VC_DEMO_CONFIG), and
/// is remembered for later launches.
struct DemoConfiguration: Codable, Sendable {
    var wallet: WalletConfiguration
    var providerURL: URL

    enum CodingKeys: String, CodingKey { case wallet, providerURL = "provider_url" }

    private static let defaultsKey = "demo-configuration"

    static func load() -> DemoConfiguration? {
        if let text = ProcessInfo.processInfo.environment["OID4VC_DEMO_CONFIG"], let data = text.data(using: .utf8),
           let config = try? JSONDecoder().decode(DemoConfiguration.self, from: data) {
            UserDefaults.standard.set(data, forKey: defaultsKey)
            return config
        }
        guard let data = UserDefaults.standard.data(forKey: defaultsKey) else { return nil }
        return try? JSONDecoder().decode(DemoConfiguration.self, from: data)
    }
}
