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

    /// Where the key comes from: the Keychain, unless a test replaced it.
    static let source = Locked<@Sendable () throws -> Data>(initialState: keychainKey)

    /// `encoded`, a configuration's JSON, with `status_cache_key` added
    /// when the configuration keeps lists in `statusCacheDir`.
    static func configuration(_ encoded: Data, statusCacheDir: String) throws -> String {
        guard !statusCacheDir.isEmpty else { return String(decoding: encoded, as: UTF8.self) }
        guard var object = try JSONSerialization.jsonObject(with: encoded) as? [String: Any] else {
            throw StoreError("the configuration isn't a JSON object")
        }
        let load = source.withLock { $0 }
        object["status_cache_key"] = try load().base64EncodedString()
        return String(decoding: try JSONSerialization.data(withJSONObject: object), as: UTF8.self)
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
