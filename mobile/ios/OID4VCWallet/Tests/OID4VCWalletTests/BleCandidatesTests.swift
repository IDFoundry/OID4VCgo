import Foundation
import XCTest
@testable import OID4VCWallet

/// The GATT server's candidate list (`BleCandidates`): devices that never
/// saw the QR code, writing State and chunks, can't push the reader out.
final class BleCandidatesTests: XCTestCase {
    private final class Clock: @unchecked Sendable {
        var t: TimeInterval = 0
    }

    private typealias List = BleCandidates<Int>
    private let reader = 100

    /// Eight State-only devices, re-adding themselves between the
    /// reader's chunks, don't displace it partway through its message.
    func testReaderPartwayThroughItsMessageIsNotDisplaced() throws {
        var list = List()
        let others = Array(0..<List.maxCandidates)
        for o in others { list.start(o) }
        XCTAssertTrue(list.start(reader), "a silent candidate makes way for the reader")
        XCTAssertNil(try list.chunk(Data([0x01, 0xa2]), from: reader))
        for _ in 0..<100 {
            for o in others where !list.contains(o) { list.start(o) }
        }
        XCTAssertTrue(list.contains(reader))
        XCTAssertNil(try list.chunk(Data([0x01, 0x01]), from: reader))
        XCTAssertEqual(try list.chunk(Data([0x00, 0x02]), from: reader), Data([0xa2, 0x01, 0x02]))
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

    /// A candidate past its deadline without a whole message may be
    /// displaced, even partway through one; within it, it may not.
    func testDeadline() throws {
        let clock = Clock()
        var list = List(now: { clock.t })
        for o in 0..<List.maxCandidates {
            list.start(o)
            XCTAssertNil(try list.chunk(Data([0x01, 0x00]), from: o))
        }
        XCTAssertFalse(list.start(reader), "every candidate is partway through, within its deadline")
        clock.t += List.deadline + 1
        XCTAssertTrue(list.start(reader))
        XCTAssertFalse(list.contains(0), "the oldest past its deadline made way")
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
        let first = try await q.receive()
        let second = try await q.receive()
        XCTAssertEqual([first, second], [1, 2])
    }
}
