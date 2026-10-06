import CoreBluetooth
import Foundation

/// ISO/IEC 18013-5 §8.3.3.1.1.6's message chunking over GATT: each
/// characteristic value is one prefix byte — 0x01 when more chunks
/// follow, 0x00 for the last — and up to (size − 1) message bytes.
enum BleChunks {
    /// The most a GATT attribute value holds, and what Multipaz uses.
    static let maxCharacteristicSize = 512
    /// The largest message accepted: the Go side's MaxMessageBytes.
    static let maxMessageBytes = 2 << 20

    /// Splits `message` into chunks of at most `size` bytes, prefix
    /// included.
    static func split(_ message: Data, size: Int) -> [Data] {
        precondition(size >= 2, "a chunk needs room for its prefix and a byte")
        let payload = size - 1
        let bytes = [UInt8](message)
        if bytes.isEmpty { return [Data([0x00])] }
        var chunks: [Data] = []
        var offset = 0
        while offset < bytes.count {
            let end = min(bytes.count, offset + payload)
            chunks.append(Data([end < bytes.count ? 0x01 : 0x00] + bytes[offset..<end]))
            offset = end
        }
        return chunks
    }

    /// Reassembles chunks into whole messages. Not thread-safe.
    struct Reassembler {
        private var buffer = Data()

        /// Adds `chunk` and returns the whole message when it was the last,
        /// else nil. A chunk with another prefix, or a message over
        /// `maxMessageBytes`, is a protocol error.
        mutating func add(_ chunk: Data) throws -> Data? {
            guard let prefix = chunk.first else { throw ProximityTransportError("an empty chunk") }
            if buffer.count + chunk.count - 1 > maxMessageBytes {
                buffer = Data()
                throw ProximityTransportError("a message over \(maxMessageBytes) bytes")
            }
            buffer.append(chunk.dropFirst())
            switch prefix {
            case 0x01:
                return nil
            case 0x00:
                defer { buffer = Data() }
                return buffer
            default:
                buffer = Data()
                throw ProximityTransportError("a chunk with prefix \(prefix)")
            }
        }
    }
}

/// Carries one ISO/IEC 18013-5 session's whole messages between the
/// holder and the reader: over BLE GATT (`GattServerTransport`,
/// `GattClientTransport`), or in memory in tests.
protocol ProximityTransport: AnyObject, Sendable {
    /// Advertises or scans, connects, and returns once the session has
    /// started: the GATT client has subscribed and written 0x01 to State.
    func connect() async throws
    /// Sends one whole message.
    func send(_ message: Data) async throws
    /// The next whole message. It throws a `ProximityTransportError` with
    /// `peerEnded` once the other side ends the session (State 0x02) or
    /// disconnects.
    func receive() async throws -> Data
    /// Ends the session: 0x02 to State if it started, disconnects, stops
    /// advertising or scanning. Calling it again does nothing.
    func close()
}

/// The transport failed, or the other side ended the session.
struct ProximityTransportError: Error, CustomStringConvertible {
    let message: String
    var peerEnded = false
    var bluetoothUnavailable = false

    init(_ message: String, peerEnded: Bool = false, bluetoothUnavailable: Bool = false) {
        self.message = message
        self.peerEnded = peerEnded
        self.bluetoothUnavailable = bluetoothUnavailable
    }

    var description: String { message }
}

/// The GATT characteristics of one BLE mode (§8.3.3.1.1.4 Table 11).
// CBUUID is immutable, though not marked Sendable.
struct GattCharacteristics: @unchecked Sendable {
    let state: CBUUID
    let client2Server: CBUUID
    let server2Client: CBUUID
    let ident: CBUUID?

    private static func uuid(_ n: Int) -> CBUUID { CBUUID(string: String(format: "%08X-A123-48CE-896B-4C76973373E6", n)) }

    /// mdoc peripheral server mode: the mdoc is the GATT server.
    static let peripheralServer = GattCharacteristics(state: uuid(1), client2Server: uuid(2), server2Client: uuid(3), ident: nil)
    /// mdoc central client mode: the reader is the GATT server, with Ident.
    static let centralClient = GattCharacteristics(state: uuid(5), client2Server: uuid(6), server2Client: uuid(7), ident: uuid(8))

    /// State's values (§8.3.3.1.1.5 Table 13).
    static let start = Data([0x01])
    static let end = Data([0x02])
}

/// Whole messages waiting for `receive`, and the error that ended them.
final class MessageQueue: @unchecked Sendable {
    private let lock = NSLock()
    private var messages: [Data] = []
    private var waiter: CheckedContinuation<Data, any Error>?
    private var ended: (any Error)?

    func push(_ message: Data) {
        lock.lock()
        if ended != nil { lock.unlock(); return }
        if let w = waiter {
            waiter = nil
            lock.unlock()
            w.resume(returning: message)
            return
        }
        messages.append(message)
        lock.unlock()
    }

    /// Ends the queue: `receive` throws `error` once the messages run out.
    func end(_ error: any Error) {
        lock.lock()
        if ended == nil { ended = error }
        let w = messages.isEmpty ? waiter : nil
        if w != nil { waiter = nil }
        lock.unlock()
        w?.resume(throwing: error)
    }

    func receive() async throws -> Data {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (c: CheckedContinuation<Data, any Error>) in
                lock.lock()
                if !messages.isEmpty {
                    let m = messages.removeFirst()
                    lock.unlock()
                    c.resume(returning: m)
                } else if let e = ended {
                    lock.unlock()
                    c.resume(throwing: e)
                } else if Task.isCancelled {
                    lock.unlock()
                    c.resume(throwing: CancellationError())
                } else {
                    waiter = c
                    lock.unlock()
                }
            }
        } onCancel: {
            lock.lock()
            let w = waiter
            waiter = nil
            lock.unlock()
            w?.resume(throwing: CancellationError())
        }
    }
}

/// A one-shot signal: `wait` returns once `signal` was called, or throws
/// what `fail` was given. A cancelled `wait` throws CancellationError.
final class Signal: @unchecked Sendable {
    private let lock = NSLock()
    private var result: Result<Void, any Error>?
    private var waiters: [UUID: CheckedContinuation<Void, any Error>] = [:]

    var isSet: Bool {
        lock.lock(); defer { lock.unlock() }
        if case .success = result { return true }
        return false
    }

    func signal() { finish(.success(())) }
    func fail(_ error: any Error) { finish(.failure(error)) }

    private func finish(_ r: Result<Void, any Error>) {
        lock.lock()
        if result != nil { lock.unlock(); return }
        result = r
        let ws = waiters.values
        waiters = [:]
        lock.unlock()
        for w in ws { w.resume(with: r) }
    }

    func wait() async throws {
        let id = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, any Error>) in
                lock.lock()
                if let r = result {
                    lock.unlock()
                    c.resume(with: r)
                } else if Task.isCancelled {
                    lock.unlock()
                    c.resume(throwing: CancellationError())
                } else {
                    waiters[id] = c
                    lock.unlock()
                }
            }
        } onCancel: {
            lock.lock()
            let w = waiters.removeValue(forKey: id)
            lock.unlock()
            w?.resume(throwing: CancellationError())
        }
    }
}

/// A value an operation's callback delivers once: `wait` returns it.
/// A cancelled `wait` throws CancellationError.
final class Pending<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var result: Result<T, any Error>?
    private var waiter: CheckedContinuation<T, any Error>?

    func resolve(_ r: Result<T, any Error>) {
        lock.lock()
        if result != nil { lock.unlock(); return }
        if let w = waiter {
            waiter = nil
            result = r
            lock.unlock()
            w.resume(with: r)
            return
        }
        result = r
        lock.unlock()
    }

    func wait() async throws -> T {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (c: CheckedContinuation<T, any Error>) in
                lock.lock()
                if let r = result {
                    lock.unlock()
                    c.resume(with: r)
                } else if Task.isCancelled {
                    lock.unlock()
                    c.resume(throwing: CancellationError())
                } else {
                    waiter = c
                    lock.unlock()
                }
            }
        } onCancel: {
            lock.lock()
            let w = waiter
            waiter = nil
            lock.unlock()
            w?.resume(throwing: CancellationError())
        }
    }
}

/// The time passed before `body` finished.
struct ProximityTimeout: Error {}

/// Runs `body`, throwing `ProximityTimeout` if it takes longer than
/// `timeout`; `body` is cancelled then.
func withTimeout<T: Sendable>(_ timeout: Duration, _ body: @escaping @Sendable () async throws -> T) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask { try await body() }
        group.addTask {
            try await Task.sleep(for: timeout)
            throw ProximityTimeout()
        }
        defer { group.cancelAll() }
        return try await group.next()!
    }
}
