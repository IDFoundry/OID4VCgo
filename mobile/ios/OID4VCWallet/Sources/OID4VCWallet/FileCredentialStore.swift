import Foundation

/// A credential store of files: one per credential record, in a directory
/// of the app's (Application Support, by default). Records are written
/// with the given file protection — complete by default: readable only
/// while the device is unlocked — and kept out of backups by default,
/// since a credential is useless without its holder key, which is in
/// this device's Secure Enclave and can't be restored elsewhere.
///
/// Every write takes an exclusive `flock` on a lock file in the
/// directory, so ``compareAndSwap(id:expected:record:)`` is atomic
/// across every process using it — an app and its extensions sharing an
/// App Group's (``inAppGroup(_:options:)``) — and across stores open on
/// it in one process. The lock is held only across one record's read,
/// compare and write: iOS terminates a suspended process holding a lock
/// in a shared container. Reads take none: each record is written whole
/// and moved into place, so a reader never sees part of one.
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
    /// The file every write locks: not a record (no `.json`).
    private var lockFile: URL { directory.appending(path: "store.lock") }

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
        try withFileLock { try record.write(to: url, options: options) }
    }

    public func record(id: String) throws -> Data? {
        try Self.read(try file(id))
    }

    public func records() throws -> [Data] {
        try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "json" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
            .compactMap { try Self.read($0) } // one deleted meanwhile isn't listed
    }

    public func delete(id: String) throws {
        let url = try file(id)
        try withFileLock { try Self.remove(url) }
    }

    public func compareAndSwap(id: String, expected: Data?, record: Data?) throws -> Data? {
        let url = try file(id)
        let options = writeOptions
        return try withFileLock {
            let current = try Self.read(url)
            guard current == expected else { return current }
            if let record {
                try record.write(to: url, options: options)
            } else {
                try Self.remove(url)
            }
            return current
        }
    }

    /// Runs `body` holding the store's exclusive lock: a `flock` on its
    /// lock file, through a descriptor of its own, so it excludes other
    /// processes and other stores on the directory in this one alike.
    /// Closing the descriptor releases it.
    private func withFileLock<T>(_ body: () throws -> T) throws -> T {
        let fd = open(lockFile.path, O_RDWR | O_CREAT | O_CLOEXEC, S_IRUSR | S_IWUSR)
        guard fd >= 0 else { throw StoreError("can't open the store's lock file (errno \(errno))") }
        defer { close(fd) }
        while flock(fd, LOCK_EX) != 0 {
            guard errno == EINTR else { throw StoreError("can't lock the store (errno \(errno))") }
        }
        return try body()
    }

    /// The file's contents, or nil when there's no such file.
    private static func read(_ url: URL) throws -> Data? {
        do {
            return try Data(contentsOf: url)
        } catch CocoaError.fileReadNoSuchFile {
            return nil
        }
    }

    private static func remove(_ url: URL) throws {
        do {
            try FileManager.default.removeItem(at: url)
        } catch CocoaError.fileNoSuchFile {
            // Already gone.
        }
    }
}
