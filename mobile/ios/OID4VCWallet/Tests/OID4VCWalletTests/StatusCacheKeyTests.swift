import Foundation
import XCTest
@testable import OID4VCWallet

/// A configuration keeping status lists in a directory carries the key
/// that authenticates them; one keeping them in memory doesn't.
final class StatusCacheKeyTests: XCTestCase {
    func testKeyAddedWithADirectory() throws {
        let key = Data(repeating: 5, count: StatusCacheKey.bytes)
        let original = StatusCacheKey.source.withLock { $0 }
        StatusCacheKey.source.withLock { $0 = { key } }
        defer { StatusCacheKey.source.withLock { $0 = original } }

        let encoded = Data(#"{"status_cache_dir":"/tmp/x","batch_size":3}"#.utf8)
        let json = try StatusCacheKey.configuration(encoded, statusCacheDir: "/tmp/x")
        let object = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
        XCTAssertEqual(object["status_cache_key"] as? String, key.base64EncodedString())
        XCTAssertEqual(object["status_cache_dir"] as? String, "/tmp/x")
        XCTAssertEqual(object["batch_size"] as? Int, 3)

        let inMemory = Data(#"{"batch_size":3}"#.utf8)
        XCTAssertEqual(try StatusCacheKey.configuration(inMemory, statusCacheDir: ""), String(decoding: inMemory, as: UTF8.self))
    }

    /// With no directory set, the lists are kept in the default one, with
    /// its key.
    func testDefaultDirectoryWhenUnset() throws {
        let key = Data(repeating: 6, count: StatusCacheKey.bytes)
        let source = StatusCacheKey.source.withLock { $0 }
        let dir = StatusCacheKey.defaultDir.withLock { $0 }
        StatusCacheKey.source.withLock { $0 = { key } }
        StatusCacheKey.defaultDir.withLock { $0 = { "/caches/oid4vcwallet-status-lists" } }
        defer {
            StatusCacheKey.source.withLock { $0 = source }
            StatusCacheKey.defaultDir.withLock { $0 = dir }
        }

        let encoded = try JSONEncoder().encode(WalletConfiguration(clientID: "c", redirectURI: "app:/cb"))
        XCTAssertNil(try XCTUnwrap(try JSONSerialization.jsonObject(with: encoded) as? [String: Any])["status_cache_dir"])
        let json = try StatusCacheKey.configuration(encoded, statusCacheDir: nil)
        let object = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
        XCTAssertEqual(object["status_cache_dir"] as? String, "/caches/oid4vcwallet-status-lists")
        XCTAssertEqual(object["status_cache_key"] as? String, key.base64EncodedString())
        XCTAssertEqual(object["client_id"] as? String, "c")
    }

    /// The default keeps lists in memory when its key can't be had, or
    /// there's no default directory, rather than fail.
    func testDefaultInMemoryWithoutItsKey() throws {
        let source = StatusCacheKey.source.withLock { $0 }
        let dir = StatusCacheKey.defaultDir.withLock { $0 }
        StatusCacheKey.source.withLock { $0 = { throw StoreError("locked") } }
        StatusCacheKey.defaultDir.withLock { $0 = { "/caches/oid4vcwallet-status-lists" } }
        defer {
            StatusCacheKey.source.withLock { $0 = source }
            StatusCacheKey.defaultDir.withLock { $0 = dir }
        }

        let encoded = Data(#"{"batch_size":3}"#.utf8)
        XCTAssertEqual(try StatusCacheKey.configuration(encoded, statusCacheDir: nil), String(decoding: encoded, as: UTF8.self))
        StatusCacheKey.defaultDir.withLock { $0 = { nil } }
        XCTAssertEqual(try StatusCacheKey.configuration(encoded, statusCacheDir: nil), String(decoding: encoded, as: UTF8.self))
    }

    /// A configuration decoded without the key leaves it unset, the default.
    func testDecodedWithoutItIsUnset() throws {
        let decoded = try JSONDecoder().decode(WalletConfiguration.self, from: Data(#"{"client_id":"c"}"#.utf8))
        XCTAssertNil(decoded.statusCacheDir)
        let empty = try JSONDecoder().decode(WalletConfiguration.self, from: Data(#"{"status_cache_dir":""}"#.utf8))
        XCTAssertEqual(empty.statusCacheDir, "")
    }

    /// A key that can't be had fails the configuration, rather than keep
    /// lists unauthenticated.
    func testKeyFailureFails() {
        let original = StatusCacheKey.source.withLock { $0 }
        StatusCacheKey.source.withLock { $0 = { throw StoreError("no keychain") } }
        defer { StatusCacheKey.source.withLock { $0 = original } }
        XCTAssertThrowsError(try StatusCacheKey.configuration(Data("{}".utf8), statusCacheDir: "/tmp/x"))
    }
}
