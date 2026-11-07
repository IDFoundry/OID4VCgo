import Foundation

/// The wallet's registration with a Wallet Provider: its registration
/// key, its App Attest key and the instance ID the provider gave for
/// them (WALLET_PROVIDER.md, `POST /v1/instances`). One per installation.
public struct RegisteredInstance: Codable, Equatable, Sendable {
    /// The registration key's JWK SHA-256 thumbprint (RFC 7638),
    /// base64url: ``HttpWalletProvider`` checks the key store still holds
    /// that key under ``keyID``.
    public var keyThumbprint: String
    /// The registration key's ID in ``HttpWalletProvider``'s registration
    /// key store, which signs every request after registration.
    public var keyID: String
    /// The provider's instance ID.
    public var instanceID: String
    /// The App Attest key's ID, which makes every assertion after
    /// registration.
    public var appAttestKeyID: String

    /// A registration.
    public init(keyThumbprint: String, keyID: String, instanceID: String, appAttestKeyID: String) {
        self.keyThumbprint = keyThumbprint
        self.keyID = keyID
        self.instanceID = instanceID
        self.appAttestKeyID = appAttestKeyID
    }

    enum CodingKeys: String, CodingKey {
        case keyThumbprint = "key_thumbprint"
        case keyID = "key_id"
        case instanceID = "instance_id"
        case appAttestKeyID = "app_attest_key_id"
    }
}

/// Where ``HttpWalletProvider`` keeps the wallet's registration, so the
/// installation registers once, across launches. An instance ID isn't a
/// secret — every request naming it is signed with the registration key
/// — but losing it loses the instance: the wallet then registers again,
/// with a new registration key and App Attest key, and the instance keys
/// the lost instance recorded can't be attested again.
/// ``FileInstanceRegistry`` keeps it in a file;
/// ``InMemoryInstanceRegistry`` is for tests. Over either, every
/// ``HttpWalletProvider`` in the process registering or asserting for
/// the same registration takes turns; over a registry of another type,
/// a provider takes turns only with itself: keep one provider for it.
///
/// Called off the main thread; an error it throws fails the attestation
/// as a `.platform` WalletError.
public protocol InstanceRegistry: Sendable {
    /// The registration kept, or nil for none.
    func instance() throws -> RegisteredInstance?
    /// Keeps `instance`, replacing the one kept.
    func put(_ instance: RegisteredInstance) throws
    /// Forgets `instance` if it's the one kept; forgetting one that isn't
    /// isn't an error, and leaves the one kept.
    func remove(_ instance: RegisteredInstance) throws
}

/// An ``InstanceRegistry`` in memory, lost when the app quits: for tests.
/// Every ``HttpWalletProvider`` over the same registry shares its locks.
public final class InMemoryInstanceRegistry: InstanceRegistry, SharesWalletProviderState, @unchecked Sendable {
    private let lock = NSLock()
    private var kept: RegisteredInstance?
    let walletProviderState = WalletProviderState()

    /// An empty registry.
    public init() {}

    public func instance() throws -> RegisteredInstance? { lock.withLock { kept } }

    public func put(_ instance: RegisteredInstance) throws { lock.withLock { kept = instance } }

    public func remove(_ instance: RegisteredInstance) throws {
        lock.withLock { if kept == instance { kept = nil } }
    }
}

/// An ``InstanceRegistry`` in a JSON file (``url``), written whole and
/// atomically, so a reader never sees part of it, and kept out of
/// backups: a restored instance ID is useless without its registration
/// key and App Attest key, which never leave this device. Keep one
/// wallet process writing it. Every ``HttpWalletProvider`` over a
/// registry in the same file, in this process, shares its locks, so it
/// registers once and makes its assertions in order however many
/// providers the app makes.
public final class FileInstanceRegistry: InstanceRegistry, SharesWalletProviderState, @unchecked Sendable {
    /// The file the registration is kept in; its directory is made if
    /// missing.
    public let url: URL
    private let lock = NSLock()
    let walletProviderState: WalletProviderState

    /// The state of every registry file in this process, by its path.
    private static let states = Locked<[String: WalletProviderState]>(initialState: [:])

    /// A registry in `url`.
    public init(url: URL) {
        self.url = url
        let path = url.standardizedFileURL.path
        walletProviderState = Self.states.withLock { states in
            if let s = states[path] { return s }
            let s = WalletProviderState()
            states[path] = s
            return s
        }
    }

    /// A registry in `walletprovider/instance.json` under the app's
    /// Application Support directory, excluded from backups.
    public static func standard() throws -> FileInstanceRegistry {
        let support = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                                  appropriateFor: nil, create: true)
        return FileInstanceRegistry(url: support.appendingPathComponent("walletprovider", isDirectory: true)
            .appendingPathComponent("instance.json"))
    }

    public func instance() throws -> RegisteredInstance? {
        try lock.withLock { try read() }
    }

    public func put(_ instance: RegisteredInstance) throws {
        try lock.withLock {
            var dir = url.deletingLastPathComponent()
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            try dir.setResourceValues(values)
            var options: Data.WritingOptions = [.atomic]
            #if os(iOS)
            // Readable after the first unlock, in the background too.
            // The registration key it names signs only while the device
            // is unlocked (kSecAttrAccessibleWhenUnlockedThisDeviceOnly),
            // so a request to the provider needs the device unlocked
            // all the same.
            options.insert(.completeFileProtectionUntilFirstUserAuthentication)
            #endif
            try JSONEncoder().encode(Contents(instance: instance)).write(to: url, options: options)
        }
    }

    public func remove(_ instance: RegisteredInstance) throws {
        try lock.withLock {
            guard try read() == instance else { return }
            do {
                try FileManager.default.removeItem(at: url)
            } catch CocoaError.fileNoSuchFile {
                // Already gone.
            }
        }
    }

    private func read() throws -> RegisteredInstance? {
        let data: Data
        do {
            data = try Data(contentsOf: url)
        } catch CocoaError.fileReadNoSuchFile {
            return nil
        }
        do {
            return try JSONDecoder().decode(Contents.self, from: data).instance
        } catch {
            throw StoreError("the instance registry \(url.lastPathComponent) is malformed")
        }
    }

    private struct Contents: Codable {
        let instance: RegisteredInstance
    }
}
