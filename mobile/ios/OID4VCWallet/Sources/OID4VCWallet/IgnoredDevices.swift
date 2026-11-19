import Foundation

/// The devices a GATT client passes over while it looks for this
/// session's peer: in mdoc central client mode, one whose Ident was read
/// and differs (another session's reader), or that has no mdoc service,
/// characteristic or Ident to read; in either mode, one whose first
/// message Go rejected (`reject`), or, for a reader, whose link was lost
/// before it answered. Each is passed over for `duration`,
/// not for the session: devices are known by an identifier derived from
/// their address, which another device can claim, so one that claims the
/// reader's address and shows another Ident keeps the reader passed over
/// only that long. A failure while connecting that says nothing about
/// which device it is — a dropped link, a GATT error, an Ident read that
/// fails or isn't answered — ignores nothing: it is one failed
/// connection attempt. Not
/// thread-safe: `GattClientTransport` keeps it on its queue.
struct IgnoredDevices<Key: Hashable> {
    /// How long a device is passed over.
    static var duration: TimeInterval { 10 }

    private let now: () -> TimeInterval
    /// When each device is no longer ignored.
    private var until: [Key: TimeInterval] = [:]

    init(now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) {
        self.now = now
    }

    /// Passes over `key` for `duration`.
    mutating func ignore(_ key: Key) {
        let t = now()
        until = until.filter { $0.value > t }
        until[key] = t + Self.duration
    }

    /// Whether `key` is passed over now.
    func contains(_ key: Key) -> Bool {
        guard let u = until[key] else { return false }
        return now() < u
    }
}

/// Checks the Ident a device showed, `read`, against this session's
/// reader's, `want`. A read that failed (nil) is a failed attempt; an
/// Ident that differs is another session's reader (`wrongReader`).
func checkReaderIdent(_ read: Data?, want: Data) throws {
    guard let read else { throw ProximityTransportError("couldn't read the reader's Ident") }
    guard read == want else {
        throw ProximityTransportError("the device found isn't this session's reader (its Ident differs)", wrongReader: true)
    }
}
