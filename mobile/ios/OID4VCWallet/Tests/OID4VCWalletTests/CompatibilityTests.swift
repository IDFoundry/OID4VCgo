import Foundation
import XCTest
@testable import OID4VCWallet

/// What the package does in place of iOS 16 API, so that it runs on
/// iOS 15: run on an iOS 15 device, these take the iOS 15 paths.
final class CompatibilityTests: XCTestCase {
    func testProximityTimeoutsInSeconds() {
        let d = ProximityTimeouts()
        XCTAssertEqual(d.connectSeconds, 60)
        XCTAssertEqual(d.requestSeconds, 30)
        XCTAssertEqual(d.idleSeconds, 300)
        let t = ProximityTimeouts(requestSeconds: 1.5)
        XCTAssertEqual(t.connectSeconds, 60)
        XCTAssertEqual(t.requestSeconds, 1.5)
        XCTAssertEqual(t.idleSeconds, 300)
    }

    func testProximityTimeoutsAsDurations() throws {
        guard #available(iOS 16.0, macOS 13.0, *) else { throw XCTSkip("Duration is iOS 16 and later") }
        let t = ProximityTimeouts(connect: .milliseconds(1500), request: .seconds(2))
        XCTAssertEqual(t.connectSeconds, 1.5)
        XCTAssertEqual(t.requestSeconds, 2)
        XCTAssertEqual(t.idleSeconds, 300)
        var u = ProximityTimeouts()
        u.idle = .seconds(7)
        XCTAssertEqual(u.idleSeconds, 7)
        XCTAssertEqual(u.idle, .seconds(7))
        XCTAssertEqual(u.connect, .seconds(60))
    }

    func testLocked() async {
        let counter = Locked(initialState: 0)
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<100 { group.addTask { counter.withLock { $0 += 1 } } }
        }
        XCTAssertEqual(counter.withLock { $0 }, 100)
    }

    func testWithTimeoutReturnsInTime() async throws {
        let got = try await withTimeout(5) { 42 }
        XCTAssertEqual(got, 42)
    }

    func testWithTimeoutTimesOutAndCancels() async {
        let cancelled = Locked(initialState: false)
        let start = Date()
        do {
            _ = try await withTimeout(0.2) {
                do { try await Task.sleep(nanoseconds: 10_000_000_000) } catch { cancelled.withLock { $0 = true }; throw error }
            }
            XCTFail("no timeout")
        } catch {
            XCTAssertTrue(error is ProximityTimeout, "\(error)")
        }
        let elapsed = Date().timeIntervalSince(start)
        XCTAssertGreaterThanOrEqual(elapsed, 0.2)
        XCTAssertLessThan(elapsed, 5)
        XCTAssertTrue(cancelled.withLock { $0 }, "the body is cancelled")
    }

    /// A timeout in seconds of any value converts without trapping:
    /// infinite or too long for a `UInt64` waits as long as it can.
    func testNanoseconds() {
        XCTAssertEqual(nanoseconds(1.5), 1_500_000_000)
        XCTAssertEqual(nanoseconds(0), 0)
        XCTAssertEqual(nanoseconds(-1), 0)
        XCTAssertEqual(nanoseconds(.nan), 0)
        XCTAssertEqual(nanoseconds(.infinity), .max)
        XCTAssertEqual(nanoseconds(1e300), .max)
        XCTAssertEqual(nanoseconds(Double(UInt64.max) / 1e9), .max)
    }

    /// An infinite timeout is no timeout: `body` finishes.
    func testWithTimeoutInfinite() async throws {
        let got = try await withTimeout(.infinity) { 7 }
        XCTAssertEqual(got, 7)
    }

    func testOrigin() {
        let cases: [(String, String?)] = [
            ("https://verifier.example", "https://verifier.example"),
            ("https://verifier.example/", "https://verifier.example"),
            ("https://verifier.example/path?q=1#f", "https://verifier.example"),
            ("HTTPS://verifier.example", "https://verifier.example"),
            ("https://verifier.example:443/", "https://verifier.example"),
            ("https://verifier.example:8443/", "https://verifier.example:8443"),
            ("http://localhost:80", "http://localhost"),
            ("http://localhost:8080/x", "http://localhost:8080"),
            ("https://[::1]:8443/", "https://[::1]:8443"),
            // A browser serializes an IDN host in its ASCII (punycode) form.
            ("https://xn--bcher-kva.example/", "https://xn--bcher-kva.example"),
            ("file:///tmp/x", nil),
        ]
        for (input, want) in cases {
            XCTAssertEqual(MdocPresentation.origin(of: URL(string: input)!), want, input)
        }
    }
}
