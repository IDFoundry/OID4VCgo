import Foundation

/// The devices that started a session (State 0x01) on a GATT server
/// before one was committed to, any of which may be the reader, and
/// their first messages' chunks. Not thread-safe: `GattServerTransport`
/// keeps it on its queue.
///
/// A device that starts a session is listed, whenever it comes: with
/// `maxCandidates` listed, it displaces the one heard from least
/// recently (its State 0x01 or its last chunk), never one whose message
/// was handed on. A chunk that takes the partial messages past
/// `maxBufferedBytes` displaces others the same way, so memory stays
/// bounded. However many identities devices that never saw the QR code
/// use, they can't keep the reader out: displacing it partway through
/// its message takes `maxCandidates` writes from other devices, each
/// listed or listing itself, between two of its own. Each device can be
/// listed `maxStarts` times at most, and one whose message was handed on
/// isn't listed again until Go has judged it, so Go sees one message per
/// device at a time.
struct BleCandidates<ID: Hashable> {
    /// How many devices may be listed at once.
    static var maxCandidates: Int { 64 }
    /// How many bytes the listed devices' partial messages may hold in
    /// all: room for a whole message of `BleChunks.maxMessageBytes` and as
    /// much again.
    static var maxBufferedBytes: Int { 2 * BleChunks.maxMessageBytes }
    /// How many times one device may be listed.
    static var maxStarts: Int { 3 }
    /// How many first messages may wait for Go: more is a refused device.
    static var maxFirstMessages: Int { 16 }

    private struct Candidate {
        let id: ID
        /// When it last wrote: its State 0x01 or a chunk.
        var heard: TimeInterval
        var reassembler = BleChunks.Reassembler()
        /// Whether its first message was handed on: it sends no more
        /// before a reply, so later chunks are dropped.
        var delivered = false
    }

    private let now: () -> TimeInterval
    /// Oldest first.
    private var candidates: [Candidate] = []
    /// Devices dropped for good: Go rejected their message, or they sent
    /// a malformed chunk.
    private var refused = Set<ID>()
    /// Devices whose first message was handed on and not yet judged.
    private var judging = Set<ID>()
    private var starts: [ID: Int] = [:]

    init(now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) {
        self.now = now
    }

    /// The listed devices, oldest first.
    var ids: [ID] { candidates.map(\.id) }

    /// How many devices are listed.
    var count: Int { candidates.count }

    func isRefused(_ id: ID) -> Bool { refused.contains(id) }

    func contains(_ id: ID) -> Bool { candidates.contains { $0.id == id } }

    /// `id` wrote State 0x01. True when it is listed.
    @discardableResult
    mutating func start(_ id: ID) -> Bool {
        if contains(id) { return true }
        guard !refused.contains(id), !judging.contains(id), starts[id, default: 0] < Self.maxStarts else { return false }
        if candidates.count >= Self.maxCandidates {
            guard let i = leastRecentlyHeard(except: id) else { return false }
            candidates.remove(at: i)
        }
        starts[id, default: 0] += 1
        candidates.append(Candidate(id: id, heard: now()))
        return true
    }

    /// The candidate to displace, other than `id`: the one heard from
    /// least recently whose message wasn't handed on.
    private func leastRecentlyHeard(except id: ID) -> Int? {
        var found: Int?
        for (i, c) in candidates.enumerated() where !c.delivered && c.id != id {
            if let f = found, candidates[f].heard <= c.heard { continue }
            found = i
        }
        return found
    }

    /// `id` wrote State 0x02, unsubscribed or disconnected: it is no
    /// longer listed. A message of its already handed on stays judged.
    mutating func end(_ id: ID) {
        candidates.removeAll { $0.id == id }
    }

    /// Adds a chunk from `id`, returning its first whole message. It
    /// throws for a malformed chunk: refuse the device.
    mutating func chunk(_ value: Data, from id: ID) throws -> Data? {
        guard let i = candidates.firstIndex(where: { $0.id == id }), !candidates[i].delivered else { return nil }
        let message = try candidates[i].reassembler.add(value)
        candidates[i].heard = now()
        guard let message else {
            makeRoom(keeping: id)
            return nil
        }
        candidates[i].delivered = true
        judging.insert(id)
        return message
    }

    /// Adds a chunk from `id`, as `chunk` does, and queues its first
    /// whole message on `firsts`. A malformed chunk refuses `id`, and so
    /// does a message the full queue can't take: only it, never the
    /// messages already queued.
    mutating func chunk<Message>(_ value: Data, from id: ID, queueingOn firsts: BoundedQueue<Message>, _ wrap: (Data) -> Message) {
        do {
            guard let message = try chunk(value, from: id) else { return }
            if !firsts.offer(wrap(message)) { refuse(id) }
        } catch {
            refuse(id)
        }
    }

    /// Displaces others, least recently heard first, until the partial
    /// messages fit `maxBufferedBytes`. `id`'s own is at most
    /// `BleChunks.maxMessageBytes`, so it always fits.
    private mutating func makeRoom(keeping id: ID) {
        var buffered = candidates.reduce(0) { $0 + $1.reassembler.buffered }
        while buffered > Self.maxBufferedBytes, let i = leastRecentlyHeard(except: id) {
            buffered -= candidates[i].reassembler.buffered
            candidates.remove(at: i)
        }
    }

    /// Forgets `id` and ignores it from now on.
    mutating func refuse(_ id: ID) {
        end(id)
        judging.remove(id)
        refused.insert(id)
    }

    /// The device to commit to: `pending`, the one whose message Go
    /// accepted, if still listed; before any message, the first listed.
    func chosen(pending: ID?) -> ID? {
        guard let pending else { return candidates.first?.id }
        return contains(pending) ? pending : nil
    }

    /// Forgets every candidate, once one is committed to.
    mutating func removeAll() {
        candidates = []
        judging = []
    }
}
