import Foundation

/// A credential store of files: one per credential record, in a directory
/// of the app's (Application Support, by default). Records are written
/// with the given file protection — complete by default: readable only
/// while the device is unlocked — and kept out of backups by default,
/// since a credential is useless without its holder key, which is in
/// this device's Secure Enclave and can't be restored elsewhere.
public final class FileCredentialStore: CredentialStore, @unchecked Sendable {
    /// How the store keeps its files.
    public struct Options: Sendable {
        /// The data protection class of every record.
        public var protection: FileProtectionType
        /// Keeps the store's directory out of iCloud and device backups.
        public var excludedFromBackup: Bool

        /// Options: by default, complete file protection, out of backups.
        public init(protection: FileProtectionType = .complete, excludedFromBackup: Bool = true) {
            self.protection = protection
            self.excludedFromBackup = excludedFromBackup
        }
    }

    /// The directory the records are kept in.
    public let directory: URL
    /// How the records are kept.
    public let options: Options
    private let lock = NSLock()

    /// A store in `directory`, created if need be, with `options`' file
    /// protection, and out of backups unless `options` says otherwise.
    public init(directory: URL, options: Options = Options()) throws {
        self.directory = directory
        self.options = options
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

    /// A store in the app group `identifier`'s container
    /// (Library/Application Support/credentials there), which the app and
    /// its extensions listing the group in their
    /// `com.apple.security.application-groups` entitlement share.
    public static func inAppGroup(_ identifier: String, options: Options = Options()) throws -> FileCredentialStore {
        guard let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: identifier) else {
            throw StoreError("no container for app group \(identifier): is it in the target's entitlements?")
        }
        let dir = container.appending(path: "Library/Application Support/credentials", directoryHint: .isDirectory)
        return try FileCredentialStore(directory: dir, options: options)
    }

    private func file(_ id: String) throws -> URL {
        guard !id.isEmpty, id.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }) else {
            throw StoreError("malformed credential ID")
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

    /// Records are files: they survive the app quitting.
    public var isDurable: Bool { true }

    public func put(id: String, record: Data) throws {
        let url = try file(id)
        let options = writeOptions
        try lock.withLock { try record.write(to: url, options: options) }
    }

    public func record(id: String) throws -> Data? {
        let url = try file(id)
        return try lock.withLock {
            do {
                return try Data(contentsOf: url)
            } catch CocoaError.fileReadNoSuchFile {
                return nil
            }
        }
    }

    public func records() throws -> [Data] {
        try lock.withLock {
            try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
                .filter { $0.pathExtension == "json" }
                .sorted { $0.lastPathComponent < $1.lastPathComponent }
                .map { try Data(contentsOf: $0) }
        }
    }

    public func delete(id: String) throws {
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
