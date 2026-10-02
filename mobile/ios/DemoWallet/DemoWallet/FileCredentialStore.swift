import Foundation
import OID4VCMobile

/// The demo's credential store: one file per credential record in
/// Application Support, written with complete file protection (readable
/// only while the device is unlocked). MOBILE.md Phase 5 replaces it with
/// the SDK's own native store.
final class FileCredentialStore: NSObject, PlatformCredentialStore {
    let directory: URL
    private let lock = NSLock()

    init(directory: URL) throws {
        self.directory = directory
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    static func standard() throws -> FileCredentialStore {
        let base = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        return try FileCredentialStore(directory: base.appending(path: "credentials", directoryHint: .isDirectory))
    }

    private func file(_ id: String?) throws -> URL {
        guard let id, !id.isEmpty, id.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" }) else {
            throw ProviderError("malformed credential ID")
        }
        return directory.appending(path: id + ".json")
    }

    func put(_ id: String?, record: Data?) throws {
        let url = try file(id)
        try lock.withLock { try (record ?? Data()).write(to: url, options: [.atomic, .completeFileProtection]) }
    }

    func get(_ id: String?) throws -> Data {
        let url = try file(id)
        return lock.withLock { (try? Data(contentsOf: url)) ?? Data() }
    }

    func list() throws -> Data {
        try lock.withLock {
            let files = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
                .filter { $0.pathExtension == "json" }
            let records = files.compactMap { try? Data(contentsOf: $0) }.map { String(decoding: $0, as: UTF8.self) }
            return Data(("[" + records.joined(separator: ",") + "]").utf8)
        }
    }

    func delete(_ id: String?) throws {
        let url = try file(id)
        lock.withLock { try? FileManager.default.removeItem(at: url) }
    }
}
