import Foundation

/// Waits on Go's thread that another thread can end by a key: a key's
/// use by its ID (its authentication context invalidated, which dismisses
/// the system's Face ID or passcode sheet), a Wallet Provider call by the
/// issuance's instance key (its Task cancelled). Go calls back on its own
/// thread, which waits; when the call waiting on it is cancelled, Go
/// tells the wallet's CallbackCanceller, which ends the wait here.
final class CancellableWaits: @unchecked Sendable {
    private let lock = NSLock()
    private var waits: [String: [UUID: @Sendable () -> Void]] = [:]

    /// Runs `body` as a wait for `key`: until it returns, ``cancel(_:)``
    /// with `key` calls `cancel`, which ends it.
    func run<T>(_ key: String, cancel: @escaping @Sendable () -> Void, _ body: () throws -> T) rethrows -> T {
        let token = UUID()
        lock.withLock { waits[key, default: [:]][token] = cancel }
        defer {
            lock.withLock {
                waits[key]?[token] = nil
                if waits[key]?.isEmpty == true { waits[key] = nil }
            }
        }
        return try body()
    }

    /// Ends every wait for `key` in progress; none is fine.
    func cancel(_ key: String) {
        let cancels = lock.withLock { waits[key].map { Array($0.values) } ?? [] }
        for cancel in cancels { cancel() }
    }

    /// How many waits are in progress, for tests.
    var count: Int { lock.withLock { waits.values.reduce(0) { $0 + $1.count } } }
}
