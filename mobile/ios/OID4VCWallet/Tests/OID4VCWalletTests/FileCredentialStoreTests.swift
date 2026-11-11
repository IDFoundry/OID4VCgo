import Foundation
import XCTest
@testable import OID4VCWallet

final class FileCredentialStoreTests: XCTestCase {
    func store() throws -> FileCredentialStore {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("store-\(UUID())", isDirectory: true)
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

    /// Listing by ID returns only the records it accepts, as the adapter
    /// asks for one kind at a time; a store without its own selection
    /// returns every record, which the wallet tells apart.
    func testRecordsWhere() throws {
        let s = try store()
        try s.put(id: "a", record: Data(#"{"id":"a"}"#.utf8))
        try s.put(id: "deferred-x", record: Data(#"{"kind":"deferred"}"#.utf8))
        try s.put(id: "grant-y", record: Data(#"{"kind":"grant"}"#.utf8))
        XCTAssertEqual(try s.records { $0.hasPrefix("deferred-") }, [Data(#"{"kind":"deferred"}"#.utf8)])
        let adapter = CredentialStoreAdapter(s)
        XCTAssertEqual(String(decoding: try adapter.listPrefixed("deferred-,authorization-,grant-", excluding: true), as: UTF8.self), #"[{"id":"a"}]"#)
        XCTAssertEqual(String(decoding: try adapter.listPrefixed("grant-", excluding: false), as: UTF8.self), #"[{"kind":"grant"}]"#)

        struct Unselective: CredentialStore {
            let inner: FileCredentialStore
            func put(id: String, record: Data) throws { try inner.put(id: id, record: record) }
            func record(id: String) throws -> Data? { try inner.record(id: id) }
            func records() throws -> [Data] { try inner.records() }
            func delete(id: String) throws { try inner.delete(id: id) }
            func compareAndSwap(id: String, expected: Data?, record: Data?) throws -> Data? {
                try inner.compareAndSwap(id: id, expected: expected, record: record)
            }
        }
        XCTAssertEqual(try Unselective(inner: s).records { $0.hasPrefix("deferred-") }.count, 3)
    }

    func testCompareAndSwap() throws {
        let s = try store()
        let a = Data(#"{"id":"a"}"#.utf8)
        let b = Data(#"{"id":"a","v":2}"#.utf8)
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
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("store-\(UUID())", isDirectory: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        let stores = try (0..<4).map { _ in try FileCredentialStore(directory: dir) }
        try stores[0].put(id: "counter", record: Data("0".utf8))
        let rounds = 50
        DispatchQueue.concurrentPerform(iterations: stores.count * 2) { i in
            let s = stores[i % stores.count]
            do {
                for _ in 0..<rounds {
                    while true {
                        guard let current = try s.record(id: "counter") else { return XCTFail("counter gone") }
                        let next = Data(String(Int(String(decoding: current, as: UTF8.self))! + 1).utf8)
                        if try s.compareAndSwap(id: "counter", expected: current, record: next) == current { break }
                    }
                }
            } catch {
                XCTFail("\(error)")
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

    func testWriteOptions() {
        let cases: [(FileProtectionType, Data.WritingOptions)] = [
            (.complete, [.atomic, .completeFileProtection]),
            (.completeUnlessOpen, [.atomic, .completeFileProtectionUnlessOpen]),
            (.completeUntilFirstUserAuthentication, [.atomic, .completeFileProtectionUntilFirstUserAuthentication]),
            (.none, [.atomic, .noFileProtection]),
            // A type this store doesn't know: the strictest, not none.
            (FileProtectionType(rawValue: "NSFileProtectionSomethingNew"), [.atomic, .completeFileProtection]),
        ]
        for (protection, want) in cases {
            XCTAssertEqual(FileCredentialStore.writeOptions(protection), want, protection.rawValue)
        }
    }

    func testExcludedFromBackup() throws {
        let s = try store()
        XCTAssertEqual(try s.directory.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup, true)
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("store-\(UUID())", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let kept = try FileCredentialStore(directory: dir, options: .init(excludedFromBackup: false))
        XCTAssertEqual(try kept.directory.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup, false)
    }
}
