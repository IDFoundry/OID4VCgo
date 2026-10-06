import CryptoKit
import Foundation
import Security
import OID4VCWallet

/// What the app and its document provider extension share: the
/// configuration, the credential store in their app group's container,
/// and the holder keys in a shared Keychain access group. The extension
/// is a separate process with its own sandbox, so the app keeps there
/// what the extension reads.
enum SharedWallet {
    /// The app group both targets list in their entitlements.
    static let appGroup = "group.dev.idfoundry.oid4vcgo.demowallet"

    /// The Keychain access group holder keys are made in, from the
    /// Info.plist (`$(AppIdentifierPrefix)` expanded at build time). nil
    /// in a build without a team — the Simulator's — whose keys stay in
    /// the app's default group, unshared.
    static var holderAccessGroup: String? {
        guard let group = Bundle.main.object(forInfoDictionaryKey: "OID4VCHolderKeychainGroup") as? String,
              let dot = group.firstIndex(of: "."), group[..<dot].count == 10 else { return nil }
        return group
    }

    /// The defaults both targets read, in the app group; the app's own
    /// when the group is unavailable.
    static var defaults: UserDefaults { UserDefaults(suiteName: appGroup) ?? .standard }

    /// The credential store in the app group's container, or in the
    /// app's own Application Support when there's no container.
    static func credentialStore() throws -> FileCredentialStore {
        if FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup) != nil {
            return try FileCredentialStore.inAppGroup(appGroup)
        }
        return try FileCredentialStore.standard()
    }

    /// The wallet's keys: in the Secure Enclave, holder keys requiring
    /// user presence when `presence` is set, and in the shared access
    /// group.
    static func keyStore(presence: Bool) -> KeychainKeyStore {
        KeychainKeyStore(options: .init(secureEnclave: SecureEnclave.isAvailable, persistent: true, holderUserPresence: presence,
                                        holderAccessGroup: holderAccessGroup))
    }

    /// The Subject Key Identifiers of the certificates in `pem`, base64:
    /// what a reader certificate's Authority Key Identifier names when
    /// one of them issued it.
    static func subjectKeyIdentifiers(pem: String) -> [Data] {
        pem.components(separatedBy: "-----BEGIN CERTIFICATE-----").dropFirst().compactMap { block in
            guard let body = block.components(separatedBy: "-----END CERTIFICATE-----").first,
                  let der = Data(base64Encoded: body, options: .ignoreUnknownCharacters) else { return nil }
            return subjectKeyIdentifier(der: der)
        }
    }

    /// The certificate `der`'s Subject Key Identifier extension value
    /// (RFC 5280 §4.2.1.2): the extension's OID, an optional critical
    /// flag, then an OCTET STRING holding the KeyIdentifier OCTET STRING.
    static func subjectKeyIdentifier(der: Data) -> Data? {
        let oid: [UInt8] = [0x06, 0x03, 0x55, 0x1D, 0x0E]
        let bytes = [UInt8](der)
        guard let start = bytes.indices.first(where: { bytes[$0...].starts(with: oid) }) else { return nil }
        var i = start + oid.count
        if i + 2 < bytes.count, bytes[i] == 0x01, bytes[i + 1] == 0x01 { i += 3 } // BOOLEAN critical
        guard i + 3 < bytes.count, bytes[i] == 0x04, bytes[i + 2] == 0x04 else { return nil }
        let length = Int(bytes[i + 3])
        guard length < 0x80, i + 4 + length <= bytes.count, Int(bytes[i + 1]) == length + 2 else { return nil }
        return Data(bytes[(i + 4)..<(i + 4 + length)])
    }
}
