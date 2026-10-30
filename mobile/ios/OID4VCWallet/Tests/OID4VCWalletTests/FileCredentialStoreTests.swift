import Foundation
import XCTest
@testable import OID4VCWallet

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

    func testCompareAndSwap() throws {
        let s = try store()
        let a = Data(#"{"id":"a"}"#.utf8), b = Data(#"{"id":"a","v":2}"#.utf8)
        XCTAssertNil(try s.compareAndSwap(id: "a", expected: a, record: b), "swapped into nothing")
        XCTAssertNil(try s.record(id: "a"))
        XCTAssertNil(try s.compareAndSwap(id: "a", expected: nil, record: a))
        XCTAssertEqual(try s.record(id: "a"), a)
        XCTAssertEqual(try s.compareAndSwap(id: "a", expected: b, record: Data("{}".utf8)), a, "swapped over another record")
        XCTAssertEqual(try s.record(id: "a"), a)
        XCTAssertEqual(try s.compareAndSwap(id: "a", expected: a, record: b), a)
        XCTAssertEqual(try s.record(id: "a"), b)
        XCTAssertEqual(try s.compareAndSwap(id: "a", expected: b, record: nil), b)
        XCTAssertNil(try s.record(id: "a"))
        XCTAssertEqual(try s.records(), [])
    }

    /// Stores open on one directory — as the app's and its extension's
    /// are on an App Group's — swap atomically between them: of
    /// concurrent read-and-swap loops, none loses another's write.
    func testCompareAndSwapAcrossStores() throws {
        let dir = FileManager.default.temporaryDirectory.appending(path: "store-\(UUID())", directoryHint: .isDirectory)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        let stores = try (0..<4).map { _ in try FileCredentialStore(directory: dir) }
        try stores[0].put(id: "counter", record: Data("0".utf8))
        let rounds = 50
        DispatchQueue.concurrentPerform(iterations: stores.count * 2) { i in
            let s = stores[i % stores.count]
            for _ in 0..<rounds {
                while true {
                    let current = try! s.record(id: "counter")!
                    let next = Data(String(Int(String(decoding: current, as: UTF8.self))! + 1).utf8)
                    if try! s.compareAndSwap(id: "counter", expected: current, record: next) == current { break }
                }
            }
        }
        XCTAssertEqual(try stores[1].record(id: "counter"), Data(String(stores.count * 2 * rounds).utf8))
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
