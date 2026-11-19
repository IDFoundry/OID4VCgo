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

        /// The bytes of the message so far.
        var buffered: Int { buffer.count }

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
    /// `connect`, for a reader that has passed over a device (`reject`):
    /// a GATT client gives up, throwing `ProximityTransportError`, when a
    /// scan finds no device advertising the service within `findWithin`
    /// seconds. Connecting to a device found takes the caller's own time.
    /// Other transports connect as `connect` does.
    func connect(findWithin: TimeInterval) async throws
    /// Sends one whole message.
    func send(_ message: Data) async throws
    /// The next whole message. It throws a `ProximityTransportError` with
    /// `peerEnded` once the other side ends the session (State 0x02) or
    /// disconnects.
    func receive() async throws -> Data
    /// Ends the session: 0x02 to State if it started, disconnects, stops
    /// advertising or scanning. Calling it again does nothing.
    func close()
    /// The device whose message `receive` returned last isn't this
    /// session's peer (Go rejected it): drop it, and have `receive`
    /// return the next first message, from any other device. A GATT
    /// client disconnects, passes over the device, and connects to the
    /// next one advertising the service: at the next `connect`, or
    /// `receive`. A transport with one peer keeps it.
    func reject()
    /// The device whose message `receive` returned last is this
    /// session's reader (Go accepted it): stop looking for others, and
    /// from now on send to it and receive only from it. Before `send`,
    /// a GATT server whose `receive` returned nothing yet commits to the
    /// first device that started the session. Calling it again does
    /// nothing.
    func commit()
}

extension ProximityTransport {
    func connect(findWithin: TimeInterval) async throws {
        try await connect()
    }

    func reject() {
        // One peer: nothing else to wait for.
    }

    func commit() {
        // One peer: already committed.
    }
}

/// Several transports at once, for a holder offering both BLE modes: it
/// advertises and scans until a reader connects either way, and keeps
/// every way open until Go accepts a first message (`commit`): that
/// transport is kept and the others closed. A device that only starts a
/// session, or sends a first message Go rejects, closes nothing. It
/// fails only once every transport has.
final class EitherTransport: ProximityTransport, @unchecked Sendable {
    /// A transport's first message, before one is chosen.
    private struct Arrival: Sendable {
        let index: Int
        let message: Data
    }

    private let transports: [any ProximityTransport]
    private let lock = NSLock()
    // Under `lock`.
    private var chosen: (any ProximityTransport)?
    /// The transport whose message `receive` returned last.
    private var pending: Int?
    /// Each transport's wait for Go's verdict on its message: true when
    /// it was chosen.
    private var verdicts: [Int: Pending<Bool>] = [:]
    private var failures: [any Error] = []
    private var pumps: [Task<Void, Never>] = []

    private let started = Signal()
    private let arrivals = BoundedQueue<Arrival>()

    init(_ transports: [any ProximityTransport]) { self.transports = transports }

    /// The one chosen.
    var connected: (any ProximityTransport)? { lock.withLock { chosen } }

    /// Starts every transport and returns once one has connected.
    func connect() async throws {
        lock.withLock {
            guard pumps.isEmpty else { return }
            pumps = startPumps()
        }
        try await started.wait()
    }

    /// One pump per transport, each started.
    private func startPumps() -> [Task<Void, Never>] {
        transports.indices.map { i in Task { [self] in await pump(i) } }
    }

    /// Connects transport `i`, then hands each first message it receives
    /// to `receive`, waiting for Go's verdict before the next: until it
    /// is chosen, when its messages go to `receive` directly.
    private func pump(_ i: Int) async {
        let t = transports[i]
        do {
            try await t.connect()
            started.signal()
            while true {
                let message = try await t.receive()
                let verdict = Pending<Bool>()
                lock.withLock { verdicts[i] = verdict }
                guard arrivals.push(Arrival(index: i, message: message)) else {
                    throw ProximityTransportError("too many unread messages")
                }
                if try await verdict.wait() { return }
            }
        } catch {
            failed(error)
        }
    }

    /// A transport failed: the whole fails once every one has, unless
    /// one was chosen.
    private func failed(_ error: any Error) {
        let all: (any Error)? = lock.withLock {
            failures.append(error)
            return failures.count == transports.count && chosen == nil ? failures[0] : nil
        }
        guard let all else { return }
        started.fail(all)
        arrivals.end(all)
    }

    func send(_ message: Data) async throws {
        guard let t = connected else { throw ProximityTransportError("the session hasn't started") }
        try await t.send(message)
    }

    func receive() async throws -> Data {
        if let t = connected { return try await t.receive() }
        let arrival = try await arrivals.receive()
        lock.withLock { pending = arrival.index }
        return arrival.message
    }

    func reject() {
        let rejected: (Int, Pending<Bool>?)? = lock.withLock {
            guard chosen == nil, let i = pending else { return nil }
            pending = nil
            return (i, verdicts.removeValue(forKey: i))
        }
        guard let (i, verdict) = rejected else { return }
        transports[i].reject()
        verdict?.resolve(.success(false))
    }

    func commit() {
        let won: (Int, Pending<Bool>?)? = lock.withLock {
            guard chosen == nil, let i = pending else { return nil }
            chosen = transports[i]
            return (i, verdicts.removeValue(forKey: i))
        }
        guard let (i, verdict) = won else { return }
        transports[i].commit()
        verdict?.resolve(.success(true))
        for (j, t) in transports.enumerated() where j != i { t.close() }
    }

    func close() {
        let tasks = lock.withLock { pumps }
        for t in transports { t.close() }
        for task in tasks { task.cancel() }
        let ended = ProximityTransportError("the session ended", peerEnded: true)
        started.fail(ended)
        arrivals.end(ended)
    }
}

/// The transport failed, or the other side ended the session.
struct ProximityTransportError: Error, CustomStringConvertible {
    let message: String
    var peerEnded = false
    var bluetoothUnavailable = false
    /// The device found isn't this session's reader: its Ident differs.
    var wrongReader = false

    init(_ message: String, peerEnded: Bool = false, bluetoothUnavailable: Bool = false, wrongReader: Bool = false) {
        self.message = message
        self.peerEnded = peerEnded
        self.bluetoothUnavailable = bluetoothUnavailable
        self.wrongReader = wrongReader
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
typealias MessageQueue = BoundedQueue<Data>

/// Values waiting for `receive`, oldest first, and the error that ended them.
final class BoundedQueue<Element: Sendable>: @unchecked Sendable {
    /// How many unread messages it keeps. A session reads each message
    /// before the next is due, so more is a misbehaving peer, not one to
    /// buffer for.
    static var capacity: Int { 4 }

    /// How many unread values this one keeps: `capacity` unless given.
    private let limit: Int

    init(capacity: Int = BoundedQueue.capacity) { limit = capacity }

    private let lock = NSLock()
    private var messages: [Element] = []
    /// The `receive`s waiting, oldest first: each message goes to the
    /// oldest. Each is kept, never overwritten by a later one, so each
    /// is resumed (a dropped continuation never is, and its task waits
    /// forever), and a cancelled one resumes only its own.
    private var waiters: [(id: UUID, continuation: CheckedContinuation<Element, any Error>)] = []
    private var ended: (any Error)?

    /// Queues message for `receive`. False when its limit of messages are
    /// already unread: they're dropped, and the transport should end the
    /// session.
    func push(_ message: Element) -> Bool {
        lock.lock()
        if ended != nil { lock.unlock(); return true }
        if !waiters.isEmpty {
            let w = waiters.removeFirst().continuation
            lock.unlock()
            w.resume(returning: message)
            return true
        }
        guard messages.count < limit else {
            messages.removeAll()
            lock.unlock()
            return false
        }
        messages.append(message)
        lock.unlock()
        return true
    }

    /// Queues value for `receive`, as `push` does, except that when its
    /// limit of values are already unread, only value is refused: false,
    /// with the others kept.
    func offer(_ value: Element) -> Bool {
        lock.lock()
        if ended != nil { lock.unlock(); return true }
        if !waiters.isEmpty {
            let w = waiters.removeFirst().continuation
            lock.unlock()
            w.resume(returning: value)
            return true
        }
        guard messages.count < limit else { lock.unlock(); return false }
        messages.append(value)
        lock.unlock()
        return true
    }

    /// Ends the queue: `receive` throws `error` once the messages run out.
    func end(_ error: any Error) {
        lock.lock()
        if ended == nil { ended = error }
        // A waiter means no message is queued: push gives it any.
        let ws = waiters.map(\.continuation)
        waiters = []
        let e = ended!
        lock.unlock()
        for w in ws { w.resume(throwing: e) }
    }

    func receive() async throws -> Element {
        let id = UUID()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (c: CheckedContinuation<Element, any Error>) in
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
                    waiters.append((id, c))
                    lock.unlock()
                }
            }
        } onCancel: {
            lock.lock()
            let i = waiters.firstIndex { $0.id == id }
            let w = i.map { waiters.remove(at: $0).continuation }
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

/// `seconds` as nanoseconds to sleep: none for a negative one or NaN,
/// and nil, never, for an infinite one or one past `Int64.max`
/// nanoseconds (about 292 years). `Task.sleep(nanoseconds:)` takes the
/// count as an `Int64`: a larger one wraps, and returns at once.
func nanoseconds(_ seconds: TimeInterval) -> UInt64? {
    guard seconds > 0 else { return 0 }
    let ns = seconds * 1_000_000_000
    return ns < Double(Int64.max) ? UInt64(ns) : nil
}

/// Runs `body`, throwing `ProximityTimeout` if it takes longer than
/// `timeout` seconds; `body` is cancelled then. An infinite timeout (see
/// `nanoseconds`) waits for `body`, however long it takes.
func withTimeout<T: Sendable>(_ timeout: TimeInterval, _ body: @escaping @Sendable () async throws -> T) async throws -> T {
    guard let ns = nanoseconds(timeout) else { return try await body() }
    return try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask { try await body() }
        group.addTask {
            try await Task.sleep(nanoseconds: ns)
            throw ProximityTimeout()
        }
        defer { group.cancelAll() }
        return try await group.next()!
    }
}
