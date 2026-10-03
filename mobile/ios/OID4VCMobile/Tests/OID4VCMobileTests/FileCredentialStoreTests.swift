import Foundation
import XCTest
@testable import OID4VCMobile

final class FileCredentialStoreTests: XCTestCase {
    func store() throws -> FileCredentialStore {
        let dir = FileManager.default.temporaryDirectory.appending(path: "store-\(UUID())", directoryHint: .isDirectory)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return try FileCredentialStore(directory: dir)
    }

    func testRecords() throws {
        let s = try store()
        XCTAssertEqual(try s.list(), Data("[]".utf8))
        XCTAssertEqual(try s.get("a"), Data())
        try s.put("a", record: Data(#"{"id":"a"}"#.utf8))
        try s.put("b-2_c", record: Data(#"{"id":"b"}"#.utf8))
        try s.put("a", record: Data(#"{"id":"a","v":2}"#.utf8))
        XCTAssertEqual(try s.get("a"), Data(#"{"id":"a","v":2}"#.utf8))
        let all = try JSONSerialization.jsonObject(with: try s.list()) as! [[String: Any]]
        XCTAssertEqual(all.count, 2)
        try s.delete("a")
        try s.delete("a")
        XCTAssertEqual(try s.get("a"), Data())
    }

    /// IDs name files: anything that could leave the directory is
    /// refused.
    func testRefusesMalformedIDs() throws {
        let s = try store()
        for id in ["", "../x", "a/b", "a.json", "é"] {
            XCTAssertThrowsError(try s.put(id, record: Data("{}".utf8)), id)
        }
    }

    func testExcludedFromBackup() throws {
        let s = try store()
        XCTAssertEqual(try s.directory.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup, true)
        let dir = FileManager.default.temporaryDirectory.appending(path: "store-\(UUID())", directoryHint: .isDirectory)
        defer { try? FileManager.default.removeItem(at: dir) }
        let kept = try FileCredentialStore(directory: dir, options: .init(excludedFromBackup: false))
        XCTAssertEqual(try kept.directory.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup, false)
    }
}
