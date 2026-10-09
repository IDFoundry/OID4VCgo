import Foundation
import Mobile
import XCTest
@testable import OID4VCWallet

/// One end of an in-memory transport: what BLE carries, without the radio.
final class PipeTransport: ProximityTransport, @unchecked Sendable {
    private let inbox = MessageQueue()
    private let connected = Signal()
    weak var peer: PipeTransport?
    /// Whether the other end connects at all: false for a reader that never comes.
    var peerConnects = true

    static func pair() -> (PipeTransport, PipeTransport) {
        let a = PipeTransport()
        let b = PipeTransport()
        a.peer = b
        b.peer = a
        return (a, b)
    }

    func connect() async throws {
        connected.signal()
        if !peerConnects { try await Signal().wait() }
        try await peer?.connected.wait()
    }

    func send(_ message: Data) async throws {
        guard let peer else { throw ProximityTransportError("the other end is gone", peerEnded: true) }
        peer.inbox.push(message)
    }

    func receive() async throws -> Data { try await inbox.receive() }

    func close() {
        let ended = ProximityTransportError("the other end closed", peerEnded: true)
        inbox.end(ended)
        peer?.inbox.end(ended)
    }
}

/// In-person presentation through the Swift API, holder and reader in one
/// process over an in-memory transport: the Go sessions, the key store and
/// both state machines, without BLE.
final class ProximityTests: XCTestCase {
    static let docType = "org.example.test.1"
    static let namespace = "org.example.test.1"

    struct Setup {
        let env: TestEnv
        let wallet: Wallet
        let reader: ProximityReader
        let mdocID: String
        // Pipes are weakly paired: the test keeps both ends.
        var pipes: [PipeTransport] = []
    }

    func keyStore() -> KeychainKeyStore {
        #if targetEnvironment(simulator)
        KeychainKeyStore(options: .init(secureEnclave: true, persistent: false, holderUserPresence: false))
        #else
        KeychainKeyStore(options: .init(secureEnclave: false, persistent: false))
        #endif
    }

    func setup(signed: Bool = true, requireTrusted: Bool = false) async throws -> Setup {
        struct ReaderSetup: Decodable {
            let readerConfig: String
            let mdocReaderRoots: String
            enum CodingKeys: String, CodingKey { case readerConfig = "reader_config", mdocReaderRoots = "mdoc_reader_roots" }
        }
        let env = try TestEnv()
        let keys = keyStore()
        let adapter = KeyStoreAdapter(keys)
        let readerSetup = try JSONDecoder().decode(ReaderSetup.self, from: Data(try OID4VC.call { env.env.proximityReader(adapter, error: $0) }.utf8))
        var config = try env.configuration
        config.mdocReaderRoots = readerSetup.mdocReaderRoots
        config.mdocReaderRequireEKU = true
        config.requireTrustedMdocReader = requireTrusted
        let wallet = try Wallet(configuration: config, keys: adapter, credentials: CredentialStoreAdapter(InMemoryCredentialStore()),
                                provider: env.env.provider())
        let result = try await SessionTests.receive(env, wallet)
        let mdocID = try XCTUnwrap(result.credentials.first { $0.format == "mso_mdoc" }?.id)
        let readerConfig = try JSONDecoder().decode(ProximityReaderConfiguration.self, from: Data(readerSetup.readerConfig.utf8))
        let reader = signed
            ? try ProximityReader(configuration: readerConfig, keys: adapter)
            : try ProximityReader(configuration: ProximityReaderConfiguration(issuerRoots: readerConfig.issuerRoots), keys: nil)
        return Setup(env: env, wallet: wallet, reader: reader, mdocID: mdocID)
    }

    let timeouts = ProximityTimeouts(connect: .seconds(10), request: .seconds(10), idle: .seconds(30))

    func start(_ s: inout Setup, modes: Set<ProximityBLEMode> = [.peripheralServer]) throws -> (ProximityPresentation, ProximityReaderSession) {
        let (holderEnd, readerEnd) = PipeTransport.pair()
        s.pipes = [holderEnd, readerEnd]
        let holder = try s.wallet.startProximityPresentation(timeouts: timeouts, modes: modes) { _ in holderEnd }
        let reader = try s.reader.start(qrCode: holder.qrCode, docType: Self.docType,
                                        elements: [Self.namespace: ["family_name", "given_name"]], timeouts: timeouts) { _ in readerEnd }
        return (holder, reader)
    }

    func final<S: Sendable>(_ states: AsyncStream<S>, _ isFinal: (S) -> Bool) async throws -> S {
        for await s in states where isFinal(s) { return s }
        throw XCTSkip("the stream ended")
    }

    func request(_ holder: ProximityPresentation) async throws -> ProximityPresentation.Request {
        for await s in holder.states {
            if case .requestReceived(let r) = s { return r }
            if s.isFinal { XCTFail("no request: \(s)"); break }
        }
        throw WalletError(code: .internalError, message: "no request")
    }

    func testPresentAndVerify() async throws {
        var s = try await setup()
        defer { s.env.close() }
        let (holder, reader) = try start(&s)
        XCTAssertTrue(holder.qrCode.hasPrefix("mdoc:"))
        XCTAssertTrue(reader.signed)

        let r = try await request(holder)
        XCTAssertEqual(r.reader.status, .trusted)
        XCTAssertEqual(r.reader.name, "Test Reader")
        XCTAssertEqual(r.reader.chain.count, 2)
        XCTAssertEqual(r.reader.certificates.map(\.subject), ["CN=Test Reader,C=US", "CN=Test Reader CA,C=US"])
        XCTAssertEqual(r.reader.certificates.map(\.isCA), [false, true])
        XCTAssertTrue(r.reader.certificates[0].extendedKeyUsages.contains { $0.hasPrefix("mdoc reader authentication") })
        let document = try XCTUnwrap(r.documents.first)
        XCTAssertEqual(document.doctype, Self.docType)
        // In the request's order: the reader encodes them sorted.
        XCTAssertEqual(document.elements.map(\.identifier), ["given_name", "family_name"])
        XCTAssertEqual(document.credentials.map(\.id), [s.mdocID])

        let linkable = try await holder.respond(document: 0, credentialID: s.mdocID,
                                                elements: [.init(namespace: Self.namespace, identifier: "family_name", retain: false)])
        XCTAssertFalse(linkable)
        let result = try await final(reader.states) { $0.isFinal }
        guard case .verified(let v) = result else { return XCTFail("reader: \(result)") }
        XCTAssertEqual(v.doctype, Self.docType)
        XCTAssertEqual(v.claims[Self.namespace]?["family_name"], .string("Doe"))
        XCTAssertNil(v.claims[Self.namespace]?["given_name"])
        XCTAssertEqual(v.deviceAuth, "signature")
        XCTAssertNotNil(v.statusList)
        let held = try await final(holder.states) { $0.isFinal }
        guard case .presented(linkable: false) = held else { return XCTFail("holder: \(held)") }
    }

    func testDeclined() async throws {
        var s = try await setup()
        defer { s.env.close() }
        let (holder, reader) = try start(&s)
        _ = try await request(holder)
        await holder.decline()
        guard case .declined = holder.state else { return XCTFail("holder: \(holder.state)") }
        let result = try await final(reader.states) { $0.isFinal }
        guard case .declined = result else { return XCTFail("reader: \(result)") }
    }

    func testUnrequestedElementRefused() async throws {
        var s = try await setup()
        defer { s.env.close() }
        let (holder, reader) = try start(&s)
        _ = try await request(holder)
        do {
            try await holder.respond(document: 0, credentialID: s.mdocID, elements: [.init(namespace: Self.namespace, identifier: "portrait", retain: false)])
            XCTFail("an unrequested element was presented")
        } catch let e as WalletError {
            XCTAssertEqual(e.code, .invalidSelection)
        }
        guard case .requestReceived = holder.state else { return XCTFail("the request doesn't stand: \(holder.state)") }
        try await holder.respond(document: 0, credentialID: s.mdocID, elements: [.init(namespace: Self.namespace, identifier: "given_name", retain: false)])
        let result = try await final(reader.states) { $0.isFinal }
        guard case .verified = result else { return XCTFail("reader: \(result)") }
    }

    /// Offered both modes, a reader chooses central client mode; offered
    /// one, that one.
    func testBLEModes() async throws {
        var s = try await setup()
        defer { s.env.close() }
        let cases: [(Set<ProximityBLEMode>, ProximityBLEMode)] = [
            (Set(ProximityBLEMode.allCases), .centralClient), ([.centralClient], .centralClient), ([.peripheralServer], .peripheralServer),
        ]
        for (modes, chosen) in cases {
            let (holder, reader) = try start(&s, modes: modes)
            XCTAssertEqual(reader.mode, chosen, "offered \(modes)")
            _ = try await request(holder)
            holder.cancel()
            let h = try await final(holder.states) { $0.isFinal }
            guard case .cancelled = h else { return XCTFail("holder: \(h)") }
        }
        do {
            _ = try s.wallet.startProximityPresentation(timeouts: timeouts, modes: []) { _ in PipeTransport() }
            XCTFail("started with no mode")
        } catch let e as WalletError {
            XCTAssertEqual(e.code, .invalidInput)
        }
    }

    func testReaderCancels() async throws {
        var s = try await setup()
        defer { s.env.close() }
        let (holder, reader) = try start(&s)
        _ = try await request(holder)
        reader.cancel()
        let r = try await final(reader.states) { $0.isFinal }
        guard case .cancelled = r else { return XCTFail("reader: \(r)") }
        let h = try await final(holder.states) { $0.isFinal }
        guard case .readerEnded = h else { return XCTFail("holder: \(h)") }
    }

    func testUnsignedReader() async throws {
        var s = try await setup(signed: false)
        defer { s.env.close() }
        let (holder, reader) = try start(&s)
        XCTAssertFalse(reader.signed)
        let r = try await request(holder)
        XCTAssertEqual(r.reader.status, .unauthenticated)
        XCTAssertEqual(r.reader.name, "")
        holder.cancel()
        let h = try await final(holder.states) { $0.isFinal }
        guard case .cancelled = h else { return XCTFail("holder: \(h)") }
    }

    func testUntrustedReaderRefusedWhenRequired() async throws {
        var s = try await setup(signed: false, requireTrusted: true)
        defer { s.env.close() }
        let (holder, reader) = try start(&s)
        let h = try await final(holder.states) { $0.isFinal }
        guard case .failed(let error) = h, let e = error as? WalletError else { return XCTFail("holder: \(h)") }
        XCTAssertEqual(e.code, .untrustedVerifier)
        let r = try await final(reader.states) { $0.isFinal }
        guard case .declined = r else { return XCTFail("reader: \(r)") }
    }

    func testNoReaderTimesOut() async throws {
        let s = try await setup()
        defer { s.env.close() }
        let (holderEnd, readerEnd) = PipeTransport.pair()
        holderEnd.peerConnects = false
        let holder = try s.wallet.startProximityPresentation(timeouts: ProximityTimeouts(connect: .seconds(1))) { _ in holderEnd }
        let h = try await final(holder.states) { $0.isFinal }
        guard case .failed(let error) = h, let e = error as? ProximityError else { return XCTFail("holder: \(h)") }
        XCTAssertEqual(e.reason, .timedOut)
        _ = readerEnd
    }

    func testChunks() throws {
        for size in [0, 1, 18, 19, 20, 512, 10_000] {
            let message = Data((0..<size).map { UInt8(truncatingIfNeeded: $0 &* 7) })
            let chunks = BleChunks.split(message, size: 20)
            for (i, c) in chunks.enumerated() {
                XCTAssertLessThanOrEqual(c.count, 20)
                XCTAssertEqual(c.first, i == chunks.count - 1 ? 0x00 : 0x01)
            }
            var r = BleChunks.Reassembler()
            for c in chunks.dropLast() { XCTAssertNil(try r.add(c)) }
            XCTAssertEqual(try r.add(chunks.last!), message)
        }
        var r = BleChunks.Reassembler()
        XCTAssertThrowsError(try r.add(Data()))
        XCTAssertThrowsError(try r.add(Data([0x02, 0x41])))
        XCTAssertEqual(try r.add(Data([0x00, 0x42])), Data([0x42]))
    }
}

/// A holder offering both BLE modes: the first transport to connect is
/// kept, the others closed.
final class EitherTransportTests: XCTestCase {
    final class Fake: ProximityTransport, @unchecked Sendable {
        let connects: @Sendable (Fake) async throws -> Void
        private let lock = NSLock()
        private var isClosed = false
        var closed: Bool { lock.withLock { isClosed } }
        let stop = Signal()

        init(_ connects: @escaping @Sendable (Fake) async throws -> Void) { self.connects = connects }

        /// Connects never: until closed.
        static func never() -> Fake { Fake { try await $0.stop.wait() } }

        func connect() async throws { try await connects(self) }
        func send(_: Data) async throws {
            // These tests send nothing.
        }
        func receive() async throws -> Data { Data([7]) }
        func close() {
            lock.withLock { isClosed = true }
            stop.fail(ProximityTransportError("closed"))
        }
    }

    func testFirstToConnectWins() async throws {
        let waiting = Fake.never()
        let connecting = Fake { _ in
            // Connects at once.
        }
        let either = EitherTransport([waiting, connecting])
        try await either.connect()
        XCTAssertTrue(either.connected === connecting)
        XCTAssertTrue(waiting.closed, "the other wasn't stopped")
        XCTAssertFalse(connecting.closed)
        let got = try await either.receive()
        XCTAssertEqual(got, Data([7]))
        either.close()
        XCTAssertTrue(connecting.closed)
    }

    /// One way failing (no advertising, say) leaves the other to connect.
    func testOneFailingLeavesTheOther() async throws {
        let failing = Fake { _ in throw ProximityTransportError("can't advertise") }
        let connecting = Fake { _ in try await Task.sleep(for: .milliseconds(50)) }
        let either = EitherTransport([failing, connecting])
        try await either.connect()
        XCTAssertTrue(either.connected === connecting)
    }

    func testFailsOnceEveryOneHas() async throws {
        let either = EitherTransport([Fake { _ in throw ProximityTransportError("first") }, Fake { _ in throw ProximityTransportError("second") }])
        do {
            try await either.connect()
            XCTFail("connected")
        } catch let e as ProximityTransportError {
            XCTAssertTrue(["first", "second"].contains(e.message), e.message)
        }
        do {
            try await either.send(Data([1]))
            XCTFail("sent without a connection")
        } catch is ProximityTransportError {
            // Expected: nothing connected.
        }
    }
}
