import Foundation

/// A value guarded by a lock: what `OSAllocatedUnfairLock` is, which
/// needs iOS 16, so that the package runs on iOS 15.
final class Locked<State>: @unchecked Sendable {
    private let lock = NSLock()
    private var state: State

    init(initialState: State) { state = initialState }

    func withLock<R>(_ body: (inout State) throws -> R) rethrows -> R {
        lock.lock()
        defer { lock.unlock() }
        return try body(&state)
    }
}
