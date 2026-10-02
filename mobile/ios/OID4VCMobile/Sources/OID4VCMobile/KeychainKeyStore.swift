import Foundation
import Mobile
import Security

/// The wallet's keys, in the Secure Enclave and the Keychain: P-256 keys
/// whose private halves never leave the Security framework. Each key's
/// ID is its Keychain application tag (after `Options.tagPrefix`).
public final class KeychainKeyStore: NSObject, MobileKeyStoreProtocol, @unchecked Sendable {
    public struct Options: Sendable {
        /// Generate keys in the Secure Enclave. Off, keys are software
        /// keys — for development, and where there's no enclave.
        public var secureEnclave: Bool
        /// Keep keys in the Keychain, across launches. Off, they live
        /// only as long as this store (for tests: the Keychain needs a
        /// signed host app on iOS).
        public var persistent: Bool
        /// Require user presence (Face ID, Touch ID or the passcode) to
        /// sign with a holder key — that is, to present a credential.
        public var holderUserPresence: Bool
        /// Prefixes every key's Keychain application tag.
        public var tagPrefix: String

        public init(secureEnclave: Bool = true, persistent: Bool = true, holderUserPresence: Bool = true,
                    tagPrefix: String = "org.idfoundry.oid4vcgo.key.") {
            self.secureEnclave = secureEnclave
            self.persistent = persistent
            self.holderUserPresence = holderUserPresence
            self.tagPrefix = tagPrefix
        }
    }

    public let options: Options
    private let lock = NSLock()
    private var ephemeral: [String: SecKey] = [:]

    public init(options: Options = Options()) {
        self.options = options
    }

    /// Creates a key (see `PlatformKeyStore`). gomobile returns a Go
    /// string as a non-optional NSString, so this one callback reports
    /// failure through `error` rather than by throwing.
    public func createKey(_ purpose: String?, error: NSErrorPointer) -> String {
        do {
            return try create(purpose: purpose ?? "")
        } catch let failure {
            error?.pointee = failure as NSError
            return ""
        }
    }

    private func create(purpose: String) throws -> String {
        let id = UUID().uuidString
        var privateAttrs: [String: Any] = [
            kSecAttrIsPermanent as String: options.persistent,
            kSecAttrApplicationTag as String: tag(id),
        ]
        if let access = try accessControl(purpose: purpose) {
            privateAttrs[kSecAttrAccessControl as String] = access
        } else {
            #if os(iOS)
            privateAttrs[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            #endif
        }
        var attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: privateAttrs,
        ]
        if options.secureEnclave {
            attrs[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        }
        // Only holder keys can require user presence: instance and DPoP
        // keys sign protocol messages silently (a Client Attestation PoP
        // at PAR and the token endpoint, a DPoP proof on every protocol
        // request), so prompting for them would interrupt each issuance
        // several times. They're per issuance, this-device-only, and in
        // the Secure Enclave by default.
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        if !options.persistent {
            lock.withLock { ephemeral[id] = key }
        }
        return id
    }

    public func publicKey(_ id: String?) throws -> Data {
        guard let key = try privateKey(id ?? "") else { return Data() }
        guard let pub = SecKeyCopyPublicKey(key) else {
            throw KeyStoreError("key \(id ?? "") has no public key")
        }
        var error: Unmanaged<CFError>?
        guard let raw = SecKeyCopyExternalRepresentation(pub, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return raw as Data
    }

    public func sign(_ id: String?, digest: Data?) throws -> Data {
        guard let key = try privateKey(id ?? "") else {
            throw KeyStoreError("no key \(id ?? "")")
        }
        var error: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(key, .ecdsaSignatureDigestX962SHA256, (digest ?? Data()) as CFData, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return sig as Data
    }

    public func deleteKey(_ id: String?) throws {
        let id = id ?? ""
        if !options.persistent {
            _ = lock.withLock { ephemeral.removeValue(forKey: id) }
            return
        }
        let status = SecItemDelete(query(id) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeyStoreError("delete key \(id): OSStatus \(status)")
        }
    }

    private func privateKey(_ id: String) throws -> SecKey? {
        if !options.persistent {
            return lock.withLock { ephemeral[id] }
        }
        var q = query(id)
        q[kSecReturnRef as String] = true
        var item: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            return (item as! SecKey)
        case errSecItemNotFound:
            return nil
        default:
            throw KeyStoreError("key \(id): OSStatus \(status)")
        }
    }

    private func query(_ id: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrApplicationTag as String: tag(id),
        ]
    }

    private func tag(_ id: String) -> Data { Data((options.tagPrefix + id).utf8) }

    /// The key's access control, when it needs one: in the Secure Enclave,
    /// or — for a holder key, if asked — with user presence; always only
    /// on this device, only when unlocked. (A key without one is kept
    /// only on this device too, on iOS; on macOS, where this store serves
    /// tests, an access control would move it to the data protection
    /// keychain, which needs an entitlement.)
    private func accessControl(purpose: String) throws -> SecAccessControl? {
        var flags: SecAccessControlCreateFlags = []
        if options.secureEnclave {
            flags.insert(.privateKeyUsage)
        }
        if purpose == KeyPurpose.holder && options.holderUserPresence {
            flags.insert(.userPresence)
        }
        guard !flags.isEmpty else { return nil }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return access
    }
}

/// A KeychainKeyStore failure.
public struct KeyStoreError: LocalizedError {
    public let message: String
    init(_ message: String) { self.message = message }
    public var errorDescription: String? { message }
}
