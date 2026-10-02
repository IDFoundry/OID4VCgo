import Foundation
import Mobile

/// A credential store of files: one per credential record, in a directory
/// of the app's (Application Support, by default). Records are written
/// with the given file protection — complete by default: readable only
/// while the device is unlocked — and kept out of backups by default,
/// since a credential is useless without its holder key, which is in
/// this device's Secure Enclave and can't be restored elsewhere.
public final class FileCredentialStore: NSObject, MobileCredentialStoreProtocol, @unchecked Sendable {
    public struct Options: Sendable {
        /// The data protection class of every record.
        public var protection: FileProtectionType
        /// Keeps the store's directory out of iCloud and device backups.
        public var excludedFromBackup: Bool

        public init(protection: FileProtectionType = .complete, excludedFromBackup: Bool = true) {
            self.protection = protection
            self.excludedFromBackup = excludedFromBackup
        }
    }

    public let directory: URL
    public let options: Options
    private let lock = NSLock()

    public init(directory: URL, options: Options = Options()) throws {
        self.directory = directory
        self.options = options
        super.init()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                attributes: [.protectionKey: options.protection])
        var dir = directory
        var values = URLResourceValues()
        values.isExcludedFromBackup = options.excludedFromBackup
        try dir.setResourceValues(values)
    }

    /// A store in Application Support/credentials.
    public static func standard(options: Options = Options()) throws -> FileCredentialStore {
        let base = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        return try FileCredentialStore(directory: base.appending(path: "credentials", directoryHint: .isDirectory), options: options)
    }

    private func file(_ id: String?) throws -> URL {
        guard let id, !id.isEmpty, id.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }) else {
            throw KeyStoreError("malformed credential ID")
        }
        return directory.appending(path: id + ".json")
    }

    private var writeOptions: Data.WritingOptions {
        switch options.protection {
        case .complete: [.atomic, .completeFileProtection]
        case .completeUnlessOpen: [.atomic, .completeFileProtectionUnlessOpen]
        case .completeUntilFirstUserAuthentication: [.atomic, .completeFileProtectionUntilFirstUserAuthentication]
        default: [.atomic, .noFileProtection]
        }
    }

    public func put(_ id: String?, record: Data?) throws {
        let url = try file(id)
        let options = writeOptions
        try lock.withLock { try (record ?? Data()).write(to: url, options: options) }
    }

    public func get(_ id: String?) throws -> Data {
        let url = try file(id)
        return try lock.withLock {
            do {
                return try Data(contentsOf: url)
            } catch CocoaError.fileReadNoSuchFile {
                return Data()
            }
        }
    }

    public func list() throws -> Data {
        try lock.withLock {
            let files = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
                .filter { $0.pathExtension == "json" }
                .sorted { $0.lastPathComponent < $1.lastPathComponent }
            let records = try files.map { String(decoding: try Data(contentsOf: $0), as: UTF8.self) }
            return Data(("[" + records.joined(separator: ",") + "]").utf8)
        }
    }

    public func delete(_ id: String?) throws {
        let url = try file(id)
        try lock.withLock {
            do {
                try FileManager.default.removeItem(at: url)
            } catch CocoaError.fileNoSuchFile {
                // Already gone.
            }
        }
    }
}
