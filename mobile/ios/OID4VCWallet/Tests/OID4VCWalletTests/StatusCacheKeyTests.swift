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

    /// A key that can't be had fails the configuration, rather than keep
    /// lists unauthenticated.
    func testKeyFailureFails() {
        let original = StatusCacheKey.source.withLock { $0 }
        StatusCacheKey.source.withLock { $0 = { throw StoreError("no keychain") } }
        defer { StatusCacheKey.source.withLock { $0 = original } }
        XCTAssertThrowsError(try StatusCacheKey.configuration(Data("{}".utf8), statusCacheDir: "/tmp/x"))
    }
}
