import Foundation
import XCTest
@testable import OID4VCWallet

/// The GATT server's candidate list (`BleCandidates`): devices that never
/// saw the QR code, writing State and chunks, can't push the reader out
/// or keep it out.
final class BleCandidatesTests: XCTestCase {
    private final class Clock: @unchecked Sendable {
        var t: TimeInterval = 0
    }

    private typealias List = BleCandidates<Int>
    private let reader = -1
    /// A first chunk, more to come.
    private let partial = Data([0x01, 0xa2])

    /// A full list of devices that only wrote State, displacing each
    /// other between the reader's chunks, doesn't displace it partway
    /// through its message.
    func testReaderPartwayThroughItsMessageIsNotDisplaced() throws {
        let clock = Clock()
        var list = List(now: { clock.t })
        for o in 0..<List.maxCandidates { list.start(o) }
        clock.t = 1
        XCTAssertTrue(list.start(reader), "a full list makes way for the reader")
        XCTAssertFalse(list.contains(0), "the one heard from least recently made way")
        clock.t = 2
        XCTAssertNil(try list.chunk(Data([0x01, 0xa2]), from: reader))
        clock.t = 3
        for o in 1000..<(1000 + List.maxCandidates - 1) { XCTAssertTrue(list.start(o)) }
        XCTAssertTrue(list.contains(reader))
        clock.t = 3.5
        XCTAssertNil(try list.chunk(Data([0x01, 0x01]), from: reader))
        clock.t = 4
        for o in 2000..<(2000 + List.maxCandidates - 1) { XCTAssertTrue(list.start(o)) }
        XCTAssertEqual(try list.chunk(Data([0x00, 0x02]), from: reader), Data([0xa2, 0x01, 0x02]))
    }

    /// Displacing the reader takes a write from every other listed device,
    /// and one more, between two of its own.
    func testDisplacingTheReaderTakesAFullListOfNewerWrites() throws {
        let clock = Clock()
        var list = List(now: { clock.t })
        for o in 0..<(List.maxCandidates - 1) { list.start(o) }
        clock.t = 1
        list.start(reader)
        XCTAssertNil(try list.chunk(partial, from: reader))
        clock.t = 2
        for o in 0..<(List.maxCandidates - 2) { XCTAssertNil(try list.chunk(partial, from: o)) }
        XCTAssertTrue(list.start(100), "the one other heard before the reader made way")
        XCTAssertTrue(list.contains(reader))
        XCTAssertTrue(list.start(101))
        XCTAssertFalse(list.contains(reader), "every other was heard after the reader")
        XCTAssertNil(try list.chunk(Data([0x00, 0x02]), from: reader), "its last chunk is dropped")
    }

    /// A newcomer displaces the candidate heard from least recently, even
    /// partway through its message.
    func testNewcomerDisplacesTheLeastRecentlyHeard() throws {
        let clock = Clock()
        var list = List(now: { clock.t })
        for o in 0..<List.maxCandidates {
            clock.t = TimeInterval(o)
            list.start(o)
            XCTAssertNil(try list.chunk(partial, from: o))
        }
        clock.t += 1
        XCTAssertNil(try list.chunk(Data([0x01, 0x00]), from: 0))
        XCTAssertTrue(list.start(reader))
        XCTAssertTrue(list.contains(0), "it wrote last but one")
        XCTAssertFalse(list.contains(1), "the one heard from least recently made way")
    }

    /// The partial messages' bytes are bounded: a chunk past the bound
    /// displaces the one heard from least recently.
    func testBufferedBytesAreBounded() throws {
        let clock = Clock()
        var list = List(now: { clock.t })
        let big = Data([0x01]) + Data(count: BleChunks.maxMessageBytes - 1)
        for o in 1...2 {
            clock.t = TimeInterval(o)
            list.start(o)
            XCTAssertNil(try list.chunk(big, from: o))
        }
        clock.t = 3
        list.start(3)
        XCTAssertNil(try list.chunk(Data([0x01, 0x00, 0x00, 0x00]), from: 3))
        XCTAssertEqual(list.ids, [2, 3])
    }

    /// Re-adds are limited per device: one displaced again and again
    /// stops coming back, and the slots it churned go to others.
    func testStartsAreLimitedPerDevice() {
        var list = List()
        for _ in 0..<List.maxStarts {
            XCTAssertTrue(list.start(1))
            list.end(1)
        }
        XCTAssertFalse(list.start(1))
        XCTAssertTrue(list.start(2))
    }

    /// A candidate whose message was handed on is never displaced, and a
    /// device whose message is queued or being judged can't start again
    /// after leaving, so one device can't queue several.
    func testDeviceIsNotListedAgainWhileItsMessageIsJudged() throws {
        var list = List()
        list.start(1)
        XCTAssertEqual(try list.chunk(Data([0x00, 0x01]), from: 1), Data([0x01]))
        list.end(1) // State 0x02
        XCTAssertFalse(list.start(1))
        XCTAssertNil(try list.chunk(Data([0x00, 0x01]), from: 1))

        list.start(2)
        XCTAssertNotNil(try list.chunk(Data([0x00, 0x02]), from: 2))
        for o in 10..<(10 + 3 * List.maxCandidates) { list.start(o) }
        XCTAssertTrue(list.contains(2), "a candidate whose message was handed on was displaced")

        list.refuse(1) // Go rejected it
        XCTAssertTrue(list.isRefused(1))
        XCTAssertFalse(list.start(1))
    }

    func testChosen() throws {
        var list = List()
        XCTAssertNil(list.chosen(pending: nil))
        list.start(1)
        list.start(2)
        XCTAssertEqual(list.chosen(pending: nil), 1)
        _ = try list.chunk(Data([0x00, 0x01]), from: 2)
        XCTAssertEqual(list.chosen(pending: 2), 2)
        list.end(2)
        XCTAssertNil(list.chosen(pending: 2), "the accepted device left")
    }

    /// A malformed chunk throws, for the transport to refuse the device.
    func testMalformedChunk() {
        var list = List()
        list.start(1)
        XCTAssertThrowsError(try list.chunk(Data([0x07, 0x00]), from: 1))
    }

    /// An overflowing first-message queue refuses only the newcomer.
    func testOfferRefusesOnlyTheNewcomer() async throws {
        let q = BoundedQueue<Int>(capacity: 2)
        XCTAssertTrue(q.offer(1))
        XCTAssertTrue(q.offer(2))
        XCTAssertFalse(q.offer(3))
        // A queue that dropped what it held fails here rather than hangs.
        let first = try await withTimeout(5) { try await q.receive() }
        let second = try await withTimeout(5) { try await q.receive() }
        XCTAssertEqual([first, second], [1, 2])
    }

    /// The GATT server queues first messages through the list: with the
    /// queue full, the newest message's device is refused, and the
    /// messages already queued are kept; a malformed chunk refuses its
    /// device.
    func testAFullFirstMessageQueueRefusesOnlyTheNewestDevice() async throws {
        var list = List()
        let q = BoundedQueue<Int>(capacity: 2)
        for o in 1...3 {
            list.start(o)
            list.chunk(Data([0x00, UInt8(o)]), from: o, queueingOn: q) { Int($0[0]) }
        }
        XCTAssertFalse(list.isRefused(1))
        XCTAssertFalse(list.isRefused(2))
        XCTAssertTrue(list.isRefused(3))
        let first = try await withTimeout(5) { try await q.receive() }
        let second = try await withTimeout(5) { try await q.receive() }
        XCTAssertEqual([first, second], [1, 2])

        list.start(4)
        list.chunk(Data([0x07]), from: 4, queueingOn: q) { Int($0[0]) }
        XCTAssertTrue(list.isRefused(4))
    }

    // MARK: Devices that never saw the QR code, in simulated time

    /// Devices that never saw the QR code, using a new identity for each
    /// State 0x01 (no limit on identities), list one more each
    /// millisecond, each with the first chunk of a message it never
    /// finishes. The reader writes State 0x01 once at `readerAt`, then a
    /// three-chunk message 10 ms apart. Returns when its message was
    /// handed on, or nil if it wasn't within the 30 s request timeout,
    /// which the devices' first State write started.
    private func reader(at readerAt: TimeInterval, firstInTick: Bool) throws -> TimeInterval? {
        let clock = Clock()
        var list = List(now: { clock.t })
        var next = 0
        var started = false
        var chunks = 0
        func attacker() throws {
            if list.start(next) { XCTAssertNil(try list.chunk(partial, from: next)) }
            next += 1
        }
        func readerStep() throws -> Bool {
            if !started {
                guard clock.t >= readerAt else { return false }
                started = true
                list.start(reader)
                return false
            }
            guard chunks < 3, clock.t >= readerAt + Double(chunks + 1) * 0.010 else { return false }
            chunks += 1
            return try list.chunk(chunks < 3 ? partial : Data([0x00, 0x02]), from: reader) != nil
        }
        for tick in 0..<30_000 {
            clock.t = Double(tick) / 1000
            if firstInTick {
                if try readerStep() { return clock.t }
                try attacker()
            } else {
                try attacker()
                if try readerStep() { return clock.t }
            }
        }
        return nil
    }

    /// The reader gets its message to Go wherever it arrives in the
    /// request window, however the writes in a millisecond are ordered.
    func testDevicesWithoutTheQRCodeCantKeepTheReaderOut() throws {
        for readerAt in [0.05, 0.5, 2.0, 10.0] {
            for firstInTick in [false, true] {
                let delivered = try reader(at: readerAt, firstInTick: firstInTick)
                XCTAssertNotNil(delivered, "reader at \(readerAt) s (first in its tick: \(firstInTick)) was kept out")
                if let delivered { XCTAssertEqual(delivered, readerAt + 0.030, accuracy: 0.0015) }
            }
        }
    }

    /// A reader whose message takes longer than 10 s (a small MTU, a
    /// congested radio) keeps its place while it sends, as devices that
    /// never saw the QR code list a new identity each millisecond.
    func testASlowReaderKeepsItsPlaceWhileItSends() throws {
        let clock = Clock()
        var list = List(now: { clock.t })
        XCTAssertTrue(list.start(reader))
        var next = 0
        for tick in 1...12_000 {
            clock.t = Double(tick) / 1000
            if list.start(next) { XCTAssertNil(try list.chunk(partial, from: next)) }
            next += 1
            if tick % 20 == 0, tick < 12_000 {
                XCTAssertNil(try list.chunk(partial, from: reader), "at \(clock.t) s")
            }
            XCTAssertTrue(list.contains(reader), "displaced at \(clock.t) s")
        }
        XCTAssertNotNil(try list.chunk(Data([0x00, 0x02]), from: reader))
    }
}
