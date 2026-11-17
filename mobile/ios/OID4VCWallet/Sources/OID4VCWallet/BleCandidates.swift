import Foundation

/// The devices that started a session (State 0x01) on a GATT server
/// before one was committed to, any of which may be the reader, and
/// their first messages' chunks. Not thread-safe: `GattServerTransport`
/// keeps it on its queue.
///
/// At most `maxCandidates` are listed. A device that starts a session
/// when the list is full displaces the oldest candidate past its
/// `deadline` without a whole message, else the oldest that hasn't sent a
/// chunk; never one partway through its message within its deadline, nor
/// one whose message was handed on. With none to displace, it isn't
/// listed. Each device can be listed `maxStarts` times at most, so
/// devices that only write State can't keep displacing others; one whose
/// message was handed on isn't listed again until Go has judged it.
struct BleCandidates<ID: Hashable> {
    /// How many devices may start a session at once.
    static var maxCandidates: Int { 8 }
    /// How long, from its State 0x01, a candidate keeps its place while
    /// its first message arrives. Past it, a newcomer may displace it.
    static var deadline: TimeInterval { 10 }
    /// How many times one device may be listed.
    static var maxStarts: Int { 3 }

    private struct Candidate {
        let id: ID
        let started: TimeInterval
        var reassembler = BleChunks.Reassembler()
        /// Whether a chunk of its first message has arrived.
        var receiving = false
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

    func isRefused(_ id: ID) -> Bool { refused.contains(id) }

    func contains(_ id: ID) -> Bool { candidates.contains { $0.id == id } }

    /// `id` wrote State 0x01. True when it is listed.
    @discardableResult
    mutating func start(_ id: ID) -> Bool {
        if contains(id) { return true }
        guard !refused.contains(id), !judging.contains(id), starts[id, default: 0] < Self.maxStarts else { return false }
        if candidates.count >= Self.maxCandidates {
            guard let i = displaceable() else { return false }
            candidates.remove(at: i)
        }
        starts[id, default: 0] += 1
        candidates.append(Candidate(id: id, started: now()))
        return true
    }

    /// The candidate a newcomer displaces, if any.
    private func displaceable() -> Int? {
        let t = now()
        return candidates.firstIndex { !$0.delivered && t - $0.started > Self.deadline }
            ?? candidates.firstIndex { !$0.delivered && !$0.receiving }
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
        candidates[i].receiving = true
        guard let message = try candidates[i].reassembler.add(value) else { return nil }
        candidates[i].delivered = true
        judging.insert(id)
        return message
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
