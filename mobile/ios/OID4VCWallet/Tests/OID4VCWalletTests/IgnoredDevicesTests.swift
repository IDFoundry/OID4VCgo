import Foundation
import XCTest
@testable import OID4VCWallet

/// The devices a GATT client in central client mode passes over
/// (`IgnoredDevices`, `checkReaderIdent`): only one that showed another
/// Ident, and only for a while, since another device can claim its
/// address.
final class IgnoredDevicesTests: XCTestCase {
    private final class Clock: @unchecked Sendable {
        var t: TimeInterval = 0
    }

    func testADeviceIsPassedOverForAWhileOnly() {
        let clock = Clock()
        var ignored = IgnoredDevices<String>(now: { clock.t })
        ignored.ignore("reader")
        XCTAssertTrue(ignored.contains("reader"))
        XCTAssertFalse(ignored.contains("other"))
        clock.t = IgnoredDevices<String>.duration - 0.001
        XCTAssertTrue(ignored.contains("reader"))
        clock.t = IgnoredDevices<String>.duration
        XCTAssertFalse(ignored.contains("reader"), "a device claiming the reader's address kept it passed over past the limit")
    }

    func testIgnoringAgainRestartsTheLimit() {
        let clock = Clock()
        var ignored = IgnoredDevices<String>(now: { clock.t })
        ignored.ignore("a")
        clock.t = IgnoredDevices<String>.duration - 1
        ignored.ignore("a")
        clock.t = IgnoredDevices<String>.duration + 1
        XCTAssertTrue(ignored.contains("a"))
    }

    /// Only an Ident that was read and differs is another session's
    /// reader: a failed read is a failed attempt.
    func testOnlyAnIdentReadAndDifferentIsAnotherReader() throws {
        let want = Data([1, 2, 3])
        try checkReaderIdent(Data([1, 2, 3]), want: want)
        XCTAssertThrowsError(try checkReaderIdent(Data([1, 2, 4]), want: want)) {
            XCTAssertTrue(($0 as? ProximityTransportError)?.wrongReader == true)
        }
        XCTAssertThrowsError(try checkReaderIdent(nil, want: want)) {
            XCTAssertEqual(($0 as? ProximityTransportError)?.wrongReader, false, "a failed read passed over the device")
        }
    }
}
