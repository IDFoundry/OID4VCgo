import Foundation
import LocalAuthentication
import Security

/// The wallet's keys, in the Secure Enclave and the Keychain: P-256 keys
/// whose private halves never leave the Security framework. Each key's
/// ID is its Keychain application tag (after `Options.tagPrefix`), and
/// its label names its purpose. Holder keys also agree keys (ECDH), for
/// deviceMac in person: a P-256 key in the Secure Enclave or the Keychain
/// can, with nothing asked of it at creation.
public final class KeychainKeyStore: KeyStore, KeyAgreement, @unchecked Sendable {
    /// How the store makes and keeps keys.
    public struct Options: Sendable {
        /// Generate keys in the Secure Enclave. Off, keys are software
        /// keys — for development, and where there's no enclave.
        public var secureEnclave: Bool
        /// Keep keys in the Keychain, across launches. Off, they live
        /// only as long as this store (for tests: the Keychain needs a
        /// signed host app on iOS).
        public var persistent: Bool
        /// Require user presence (Face ID, Touch ID or the passcode) for
        /// every signature with a holder key: to present a credential,
        /// and to sign the Credential Request's jwt proofs, so receiving
        /// and refreshing credentials ask too — once per copy
        /// (``WalletConfiguration/batchSize``), or once per Credential
        /// Request when its jwt proof carries a key attestation, and
        /// again if the issuer refuses the nonce — and a refresh can't
        /// run without the holder. The Secure Enclave
        /// enforces it. Off, the app asks for it itself (with
        /// `LAContext.evaluatePolicy`) before every presentation — in
        /// the app, from a link, through a document provider extension,
        /// and in person — a check the app's own code keeps, not the
        /// key. For Face ID, the app's Info.plist must have an
        /// `NSFaceIDUsageDescription`; without one, iOS asks for the
        /// passcode instead. A presentation answering several documents
        /// at once (``ProximityPresentation/respond(answers:)``,
        /// ``MdocPresentation/respond(answers:)``) asks once: its holder
        /// keys share one authentication context for that call only.
        public var holderUserPresence: Bool
        /// Prefixes every key's Keychain application tag. Keys under
        /// another prefix are never touched, by a sweep or anything else.
        public var tagPrefix: String
        /// The Keychain access group holder keys are made in, when the
        /// app shares them with an extension — a document provider
        /// presenting credentials, say — that lists the group in its
        /// `keychain-access-groups` entitlement. Instance and DPoP keys
        /// stay in the app's default group: only the app issues. nil:
        /// every key is in the default group.
        public var holderAccessGroup: String?

        /// Options: by default, Secure Enclave keys kept in the Keychain, and
        /// holder keys asking for user presence.
        public init(secureEnclave: Bool = true, persistent: Bool = true, holderUserPresence: Bool = true,
                    tagPrefix: String = "org.idfoundry.oid4vcgo.key.", holderAccessGroup: String? = nil) {
            self.secureEnclave = secureEnclave
            self.persistent = persistent
            self.holderUserPresence = holderUserPresence
            self.tagPrefix = tagPrefix
            self.holderAccessGroup = holderAccessGroup
        }
    }

    /// How this store makes and keeps keys.
    public let options: Options
    private let lock = NSLock()
    private var ephemeral: [String: SecKey] = [:]
    private var ephemeralPurposes: [String: KeyPurpose] = [:]
    // The uses of keys in progress, by key ID, for cancelKeyUse.
    private let keyUses = CancellableWaits()

    /// A store making and keeping keys as `options` say.
    public init(options: Options = Options()) {
        self.options = options
    }

    /// Durable when the keys are kept in the Keychain (`Options.persistent`).
    public var isDurable: Bool { options.persistent }

    public func createKey(purpose: KeyPurpose) throws -> String {
        let id = UUID().uuidString
        var privateAttrs: [String: Any] = [
            kSecAttrIsPermanent as String: options.persistent,
            kSecAttrApplicationTag as String: tag(id),
            kSecAttrLabel as String: "oid4vcgo " + purpose.rawValue,
        ]
        let policy = Self.accessPolicy(purpose: purpose, options: options)
        if let group = policy.accessGroup {
            privateAttrs[kSecAttrAccessGroup as String] = group
        }
        if let access = try accessControl(policy) {
            privateAttrs[kSecAttrAccessControl as String] = access
        } else {
            #if os(iOS)
            privateAttrs[kSecAttrAccessible as String] = policy.accessible
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
            lock.withLock {
                ephemeral[id] = key
                ephemeralPurposes[id] = purpose
            }
        }
        return id
    }

    public func publicKey(id: String) throws -> Data? {
        guard let key = try privateKey(id, context: HolderPrompt.current) else { return nil }
        guard let pub = SecKeyCopyPublicKey(key) else {
            throw StoreError("key \(id) has no public key")
        }
        var error: Unmanaged<CFError>?
        guard let raw = SecKeyCopyExternalRepresentation(pub, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return raw as Data
    }

    public func sign(id: String, digest: Data) throws -> Data {
        try usingKey(id) { context in
            guard let key = try privateKey(id, context: context) else {
                throw StoreError("no key \(id)")
            }
            var error: Unmanaged<CFError>?
            guard let sig = SecKeyCreateSignature(key, .ecdsaSignatureDigestX962SHA256, digest as CFData, &error) else {
                throw error!.takeRetainedValue() as Error
            }
            return sig as Data
        }
    }

    /// Dismisses the Face ID or passcode sheet a ``sign(id:digest:)`` or
    /// ``agree(id:peerPublicKey:)`` with key `id` shows, because the call
    /// it's for was cancelled: it invalidates the use's authentication
    /// context, so the use throws. The wallet calls it; nothing waiting
    /// for `id` is fine. In a call whose holder keys share one
    /// authentication (``ProximityPresentation/respond(answers:)``), it
    /// ends that call's. A key kept only in memory
    /// (`Options.persistent` off) can't be cancelled.
    public func cancelKeyUse(id: String) {
        keyUses.cancel(id)
    }

    /// Runs `body`, a use of key `id` that may ask the holder, with the
    /// authentication context it asks in: this thread's ``HolderPrompt``
    /// one, inside ``oneHolderPrompt(_:)``, else one of its own,
    /// invalidated afterwards. ``cancelKeyUse(id:)`` invalidates it
    /// meanwhile. A key kept only in memory is used without one: its
    /// SecKey was made with none.
    private func usingKey<T>(_ id: String, _ body: (LAContext?) throws -> T) throws -> T {
        guard options.persistent else { return try body(nil) }
        let shared = HolderPrompt.current
        let context = ContextBox(shared ?? LAContext())
        defer {
            if shared == nil { context.context.invalidate() }
        }
        return try keyUses.run(id, cancel: { context.context.invalidate() }) { try body(context.context) }
    }

    /// ECDH between holder key `id` and `peerPublicKey` (an uncompressed
    /// X9.63 P-256 point): the 32-byte shared secret, its x-coordinate. A
    /// holder key asking for user presence asks here too, as for `sign`.
    /// Instance and DPoP keys never agree keys.
    public func agree(id: String, peerPublicKey: Data) throws -> Data {
        try usingKey(id) { context in try agree(id: id, peerPublicKey: peerPublicKey, context: context) }
    }

    private func agree(id: String, peerPublicKey: Data, context: LAContext?) throws -> Data {
        guard let key = try privateKey(id, context: context) else {
            throw StoreError("no key \(id)")
        }
        guard try purpose(of: id) == .holder else {
            throw KeyAgreementUnsupported("key \(id) isn't a holder key")
        }
        guard SecKeyIsAlgorithmSupported(key, .keyExchange, .ecdhKeyExchangeStandard) else {
            throw KeyAgreementUnsupported("key \(id) can't agree keys")
        }
        let peerAttrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256,
        ]
        var error: Unmanaged<CFError>?
        guard peerPublicKey.count == 65, peerPublicKey.first == 0x04,
              let peer = SecKeyCreateWithData(peerPublicKey as CFData, peerAttrs as CFDictionary, &error) else {
            throw StoreError("the peer's key isn't an uncompressed P-256 point")
        }
        guard let z = SecKeyCopyKeyExchangeResult(key, .ecdhKeyExchangeStandard, peer, [:] as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return z as Data
    }

    public func deleteKey(id: String) throws {
        if !options.persistent {
            lock.withLock {
                ephemeral[id] = nil
                ephemeralPurposes[id] = nil
            }
            return
        }
        let status = SecItemDelete(query(id) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw StoreError("delete key \(id): OSStatus \(status)")
        }
    }

    /// The IDs of every key this store holds (under its tag prefix).
    public func keyIDs() throws -> [String] {
        if !options.persistent {
            return lock.withLock { Array(ephemeral.keys) }
        }
        let q: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
        ]
        var items: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &items)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess, let all = items as? [[String: Any]] else {
            throw StoreError("list keys: OSStatus \(status)")
        }
        let prefix = Data(options.tagPrefix.utf8)
        return all.compactMap { attrs in
            guard let tag = attrs[kSecAttrApplicationTag as String] as? Data, tag.starts(with: prefix) else { return nil }
            return String(decoding: tag.dropFirst(prefix.count), as: UTF8.self)
        }
    }

    /// Deletes every key this store holds except `keep`, and returns how
    /// many it deleted. `Wallet.sweepOrphanedKeys(in:)` calls it with the
    /// keys the wallet's credentials are bound to.
    @discardableResult
    public func deleteKeys(except keep: Set<String>) throws -> Int {
        var deleted = 0
        for id in try keyIDs() where !keep.contains(id) {
            try deleteKey(id: id)
            deleted += 1
        }
        return deleted
    }

    /// Key `id`, asking the holder, if it does, in `context`: inside
    /// ``oneHolderPrompt(_:)``, this thread's ``HolderPrompt`` one, which
    /// one presentation's holder keys share — the first signature asks
    /// the holder, and the others don't again (it's this thread's: only
    /// that presentation's Go call signs on it); else the use's own.
    private func privateKey(_ id: String, context: LAContext?) throws -> SecKey? {
        if !options.persistent {
            return lock.withLock { ephemeral[id] }
        }
        var q = query(id)
        q[kSecReturnRef as String] = true
        if let context {
            q[kSecUseAuthenticationContext as String] = context
        }
        var item: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            return (item as! SecKey)
        case errSecItemNotFound:
            return nil
        default:
            throw StoreError("key \(id): OSStatus \(status)")
        }
    }

    /// The purpose a key was made for, from its label (`createKey`); nil
    /// for a key with none.
    private func purpose(of id: String) throws -> KeyPurpose? {
        if !options.persistent {
            return lock.withLock { ephemeralPurposes[id] }
        }
        var q = query(id)
        q[kSecReturnAttributes as String] = true
        var item: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &item)
        guard status == errSecSuccess, let attrs = item as? [String: Any],
              let label = attrs[kSecAttrLabel as String] as? String, label.hasPrefix("oid4vcgo ") else {
            return nil
        }
        return KeyPurpose(rawValue: String(label.dropFirst("oid4vcgo ".count)))
    }

    private func query(_ id: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrApplicationTag as String: tag(id),
        ]
    }

    private func tag(_ id: String) -> Data { Data((options.tagPrefix + id).utf8) }

    /// What guards a key: its access control's flags (none: it has no
    /// access control), when it's accessible, and its Keychain access
    /// group (nil: the app's default one).
    struct AccessPolicy {
        var flags: SecAccessControlCreateFlags
        var accessible: CFString
        var accessGroup: String?
    }

    /// The access policy of a key made for `purpose`: in the Secure
    /// Enclave, its private key's use is guarded; a holder key, if
    /// asked, needs user presence too — and so a passcode set; and
    /// always only on this device, only when unlocked. Only a holder key
    /// is made in `Options.holderAccessGroup`.
    static func accessPolicy(purpose: KeyPurpose, options: Options) -> AccessPolicy {
        var flags: SecAccessControlCreateFlags = []
        if options.secureEnclave {
            flags.insert(.privateKeyUsage)
        }
        if purpose == .holder && options.holderUserPresence {
            flags.insert(.userPresence)
        }
        // A key needing user presence needs a passcode too: it can't be
        // made without one, and goes if the passcode is removed.
        let accessible = flags.contains(.userPresence)
            ? kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly : kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let group = purpose == .holder ? options.holderAccessGroup : nil
        return AccessPolicy(flags: flags, accessible: accessible, accessGroup: group)
    }

    /// The key's access control, when its `policy` needs one: in the
    /// Secure Enclave, or with user presence. (A key without one is kept
    /// only on this device too, on iOS; on macOS, where this store serves
    /// tests, an access control would move it to the data protection
    /// keychain, which needs an entitlement.)
    private func accessControl(_ policy: AccessPolicy) throws -> SecAccessControl? {
        guard !policy.flags.isEmpty else { return nil }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, policy.accessible, policy.flags, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return access
    }
}

extension KeychainKeyStore {
    /// Runs `body` — one presentation's Go call, which signs with each
    /// holder key it answers with — with one authentication context
    /// shared by those signatures alone: with `Options.holderUserPresence`,
    /// the first asks the holder, and the holder keys after it in `body`
    /// reuse that, so answering several documents at once asks once. The
    /// context is invalidated when `body` returns: the next presentation
    /// asks again.
    ///
    /// The context is this thread's (`HolderPrompt`), not the process's:
    /// a C call into Go runs on the calling thread, which the goroutine
    /// keeps until it returns, so the key store's `sign`, called back by
    /// Go's own synchronous signing, runs on it too. A holder key used by
    /// any other call — another presentation at the same time, on another
    /// thread — asks the holder for itself. Were Go ever to sign on
    /// another goroutine, those signatures would ask again rather than
    /// share: it fails safe.
    static func oneHolderPrompt<T>(_ body: () throws -> T) rethrows -> T {
        try HolderPrompt.scoped(body)
    }
}

/// An authentication context, which `invalidate()` makes safe to end from
/// any thread.
final class ContextBox: @unchecked Sendable {
    let context: LAContext
    init(_ context: LAContext) { self.context = context }
}

/// The authentication context holder keys share inside
/// `KeychainKeyStore.oneHolderPrompt`, held in the calling thread's
/// dictionary; a nested call shares the outer one's.
enum HolderPrompt {
    private static let key = "dev.idfoundry.oid4vcwallet.holderPrompt"

    /// This thread's context, inside `oneHolderPrompt`; else nil.
    static var current: LAContext? { Thread.current.threadDictionary[key] as? LAContext }

    static func scoped<T>(_ body: () throws -> T) rethrows -> T {
        let dictionary = Thread.current.threadDictionary
        if dictionary[key] is LAContext {
            return try body()
        }
        let context = LAContext()
        dictionary[key] = context
        // A thread of a shared queue: cleared before it runs anything
        // else.
        defer {
            dictionary.removeObject(forKey: key)
            context.invalidate()
        }
        return try body()
    }
}
