import Foundation
import Security

/// The key authenticating the status lists a `statusCacheDir` keeps
/// (`status_cache_key` in ABI.md): 32 random bytes, made on first use and
/// kept in the Keychain on this device only, so that a list anyone else
/// wrote to the directory is dropped rather than used. A 304 from a
/// list's server confirms the `ETag` a kept list names, not the list
/// kept with it.
enum StatusCacheKey {
    static let service = "dev.idfoundry.oid4vcwallet.status-cache-key"
    static let bytes = 32

    /// The directory a nil `statusCacheDir` keeps lists in, in the app's
    /// Caches directory.
    static let defaultDirName = "oid4vcwallet-status-lists"

    /// Where the key comes from: the Keychain, unless a test replaced it.
    static let source = Locked<@Sendable () throws -> Data>(initialState: keychainKey)

    /// Where a nil `statusCacheDir` keeps lists, unless a test replaced
    /// it: `defaultDirName` in the app's Caches directory. None on macOS,
    /// where Caches is every app's of the user's.
    static let defaultDir = Locked<@Sendable () -> String?>(initialState: cachesDir)

    /// What makes `defaultDir` ready, unless a test replaced it:
    /// `protectedDir`.
    static let prepareDefault = Locked<@Sendable (String) throws -> Void>(initialState: protectedDir)

    /// `encoded`, a configuration's JSON, keeping lists in
    /// `statusCacheDir` with the `status_cache_key` that authenticates
    /// them. Empty keeps them in memory only. Nil keeps them in
    /// `defaultDir`, made with complete file protection, or in memory
    /// only when there's none, it can't be made, or its key can't be had
    /// (before the device is first unlocked, say): the default never
    /// stops a wallet being made.
    static func configuration(_ encoded: Data, statusCacheDir: String?) throws -> String {
        let unchanged = String(decoding: encoded, as: UTF8.self)
        let load = source.withLock { $0 }
        let dir: String
        let key: Data
        switch statusCacheDir {
        case ""?:
            return unchanged
        case let chosen?:
            dir = chosen
            key = try load()
        case nil:
            let prepare = prepareDefault.withLock { $0 }
            guard let fallback = defaultDir.withLock({ $0 })(), let loaded = try? load(),
                  (try? prepare(fallback)) != nil else { return unchanged }
            dir = fallback
            key = loaded
        }
        guard var object = try JSONSerialization.jsonObject(with: encoded) as? [String: Any] else {
            throw StoreError("the configuration isn't a JSON object")
        }
        object["status_cache_dir"] = dir
        object["status_cache_key"] = key.base64EncodedString()
        return String(decoding: try JSONSerialization.data(withJSONObject: object), as: UTF8.self)
    }

    @Sendable static func cachesDir() -> String? {
        #if os(macOS)
        return nil
        #else
        return FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first?
            .appendingPathComponent(defaultDirName, isDirectory: true).path
        #endif
    }

    /// Makes `path` if need be, with complete file protection, as the
    /// credentials have: what the lists there show (which lists the
    /// wallet checks, so its credentials' issuers, and when) is then
    /// readable only while the device is unlocked. Lists made in it
    /// inherit its protection; one an earlier version made, with the
    /// Caches directory's, is given it, the lists in it too. While the
    /// device is locked the lists can't be read or written, which costs
    /// a download, not a check. On macOS, which has no data protection
    /// (and no default directory), it only makes `path`.
    @Sendable static func protectedDir(_ path: String) throws {
        let fm = FileManager.default
        #if os(macOS)
        try fm.createDirectory(atPath: path, withIntermediateDirectories: true)
        #else
        let complete = [FileAttributeKey.protectionKey: FileProtectionType.complete]
        try fm.createDirectory(atPath: path, withIntermediateDirectories: true, attributes: complete)
        let protection = try fm.attributesOfItem(atPath: path)[.protectionKey] as? FileProtectionType
        guard protection != .complete else { return }
        try fm.setAttributes(complete, ofItemAtPath: path)
        for name in (try? fm.contentsOfDirectory(atPath: path)) ?? [] {
            try? fm.setAttributes(complete, ofItemAtPath: (path as NSString).appendingPathComponent(name))
        }
        #endif
    }

    /// The key the Keychain keeps, made and kept there on first use.
    static func keychainKey() throws -> Data {
        if let key = try read() { return key }
        var key = Data(count: bytes)
        let made = key.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, bytes, $0.baseAddress!) }
        guard made == errSecSuccess else { throw StoreError("can't make the status cache key (\(made))") }
        var add = query
        add[kSecValueData as String] = key
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        switch SecItemAdd(add as CFDictionary, nil) {
        case errSecSuccess:
            return key
        case errSecDuplicateItem:
            // Another thread or process made it first: theirs is the key.
            guard let theirs = try read() else { throw StoreError("the status cache key vanished") }
            return theirs
        case let status:
            throw StoreError("can't keep the status cache key in the Keychain (\(status))")
        }
    }

    private static var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: "v1"]
    }

    private static func read() throws -> Data? {
        var q = query
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        switch SecItemCopyMatching(q as CFDictionary, &item) {
        case errSecSuccess:
            guard let key = item as? Data, key.count >= bytes else { throw StoreError("the status cache key in the Keychain is malformed") }
            return key
        case errSecItemNotFound:
            return nil
        case let status:
            throw StoreError("can't read the status cache key from the Keychain (\(status))")
        }
    }
}
