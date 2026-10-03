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
        XCTAssertEqual(try s.records(), [])
        XCTAssertNil(try s.record(id: "a"))
        try s.put(id: "a", record: Data(#"{"id":"a"}"#.utf8))
        try s.put(id: "b-2_c", record: Data(#"{"id":"b"}"#.utf8))
        try s.put(id: "a", record: Data(#"{"id":"a","v":2}"#.utf8))
        XCTAssertEqual(try s.record(id: "a"), Data(#"{"id":"a","v":2}"#.utf8))
        XCTAssertEqual(try s.records().count, 2)
        try s.delete(id: "a")
        try s.delete(id: "a")
        XCTAssertNil(try s.record(id: "a"))
    }

    /// IDs name files: anything that could leave the directory is
    /// refused.
    func testRefusesMalformedIDs() throws {
        let s = try store()
        for id in ["", "../x", "a/b", "a.json", "é"] {
            XCTAssertThrowsError(try s.put(id: id, record: Data("{}".utf8)), id)
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
