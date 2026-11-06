import Foundation
import Mobile
import XCTest
@testable import OID4VCWallet

/// Answering a reader's request for several documents in one response,
/// holder and reader in one process over an in-memory transport.
final class MultiDocumentTests: XCTestCase {
    static let docType1 = "org.example.test.1"
    static let docType2 = "org.example.test.2"

    struct Setup {
        let env: TestEnv
        let wallet: Wallet
        let reader: ProximityReader
        let ids: [String: String]
        var pipes: [PipeTransport] = []
    }

    let timeouts = ProximityTimeouts(connectSeconds: 10, requestSeconds: 10, idleSeconds: 30)
    func keyStore() -> KeychainKeyStore {
        #if targetEnvironment(simulator)
        KeychainKeyStore(options: .init(secureEnclave: true, persistent: false, holderUserPresence: false))
        #else
        KeychainKeyStore(options: .init(secureEnclave: false, persistent: false))
        #endif
    }

    func final<S: Sendable>(_ states: AsyncStream<S>, _ isFinal: (S) -> Bool) async throws -> S {
        for await s in states where isFinal(s) { return s }
        throw XCTSkip("the stream ended")
    }

    func request(_ holder: ProximityPresentation) async throws -> ProximityPresentation.Request {
        for await s in holder.states {
            if case .requestReceived(let r) = s { return r }
            if s.isFinal { XCTFail("no request: (s)"); break }
        }
        throw WalletError(code: .internalError, message: "no request")
    }

    /// A wallet holding mdocs of two types, recognizing the test reader,
    /// and that reader.
    func setup() async throws -> Setup {
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
        let wallet = try Wallet(configuration: config, keys: adapter, credentials: CredentialStoreAdapter(InMemoryCredentialStore()),
                                provider: env.env.provider(), agreement: KeyAgreementAdapter(keys))
        let offer = try OID4VC.call { env.env.multiDocumentOffer($0) }
        let s = try await wallet.startIssuance(offer: offer)
        let url = try await s.beginAuthorization()
        try await s.completeAuthorization(redirect: env.approve(url))
        let result = try await s.requestCredentials()
        try await s.close()
        var ids: [String: String] = [:]
        for c in result.credentials { if let d = c.doctype { ids[d] = c.id } }
        var readerConfig = try JSONDecoder().decode(ProximityReaderConfiguration.self, from: Data(readerSetup.readerConfig.utf8))
        readerConfig.statusCheck = .check
        return Setup(env: env, wallet: wallet, reader: try ProximityReader(configuration: readerConfig, keys: adapter), ids: ids)
    }

    func start(_ s: inout Setup) throws -> (ProximityPresentation, ProximityReaderSession) {
        let (holderEnd, readerEnd) = PipeTransport.pair()
        s.pipes = [holderEnd, readerEnd]
        let holder = try s.wallet.startProximityPresentation(timeouts: timeouts, modes: [.peripheralServer]) { _ in holderEnd }
        let reader = try s.reader.start(qrCode: holder.qrCode, documents: [
            .init(docType: Self.docType1, elements: [Self.docType1: ["family_name"]]),
            .init(docType: Self.docType2, elements: [Self.docType2: ["family_name", "given_name"]]),
        ], timeouts: timeouts) { _ in readerEnd }
        return (holder, reader)
    }

    /// Two answers in one response: the reader verifies both.
    func testRespondWithTwoDocuments() async throws {
        var s = try await setup()
        defer { s.env.close() }
        let (holder, reader) = try start(&s)
        let asked = try await self.request(holder)
        XCTAssertEqual(asked.documents.map(\.doctype), [Self.docType1, Self.docType2])

        let responded = try await holder.respond(answers: [
            .init(document: 1, credentialID: try XCTUnwrap(s.ids[Self.docType2]), elements: [.init(namespace: Self.docType2, identifier: "given_name", retain: false)]),
            .init(document: 0, credentialID: try XCTUnwrap(s.ids[Self.docType1]), elements: [.init(namespace: Self.docType1, identifier: "family_name", retain: false)]),
        ])
        XCTAssertFalse(responded.linkable)
        XCTAssertEqual(responded.linkableCredentials, [])
        let result = try await final(reader.states) { $0.isFinal }
        guard case .verified = result else { return XCTFail("reader: \(result)") }
        XCTAssertEqual(reader.documents.map(\.doctype), [Self.docType1, Self.docType2])
        XCTAssertTrue(reader.documents.allSatisfy { $0.status == .valid })
    }

    /// A refused answer sends nothing: the request stands, and a good
    /// answer then goes through.
    func testRefusedAnswersLeaveTheRequest() async throws {
        var s = try await setup()
        defer { s.env.close() }
        let (holder, reader) = try start(&s)
        _ = try await self.request(holder)
        let one = MdocPresentation.Answer(document: 0, credentialID: try XCTUnwrap(s.ids[Self.docType1]),
                                          elements: [.init(namespace: Self.docType1, identifier: "family_name", retain: false)])
        for answers in [[], [one, one]] as [[MdocPresentation.Answer]] {
            do {
                try await holder.respond(answers: answers)
                XCTFail("respond(\(answers)) succeeded")
            } catch let e as WalletError {
                XCTAssertEqual(e.code, .invalidSelection)
            }
            guard case .requestReceived = holder.state else { return XCTFail("holder: \(holder.state)") }
        }
        try await holder.respond(answers: [one])
        let result = try await final(reader.states) { $0.isFinal }
        guard case .verified(let v) = result else { return XCTFail("reader: \(result)") }
        XCTAssertEqual(v.doctype, Self.docType1)
        XCTAssertEqual(reader.documents.count, 1)
    }

    /// The one-document respond still answers a request for several,
    /// with that one.
    func testOneDocumentRespondStillWorks() async throws {
        var s = try await setup()
        defer { s.env.close() }
        let (holder, reader) = try start(&s)
        _ = try await self.request(holder)
        let linkable = try await holder.respond(document: 1, credentialID: try XCTUnwrap(s.ids[Self.docType2]),
                                                elements: [.init(namespace: Self.docType2, identifier: "family_name", retain: false)])
        XCTAssertFalse(linkable)
        let result = try await final(reader.states) { $0.isFinal }
        guard case .verified(let v) = result else { return XCTFail("reader: \(result)") }
        XCTAssertEqual(v.doctype, Self.docType2)
    }

    /// The shared authentication context is the calling thread's, for
    /// that call alone: none outside it, one inside (a nested call shares
    /// it), none on another thread meanwhile — another presentation's
    /// holder keys ask for themselves — and none once the call returns.
    func testHolderPromptIsScopedToTheCall() throws {
        XCTAssertNil(HolderPrompt.current)
        let elsewhere = expectation(description: "another thread")
        try KeychainKeyStore.oneHolderPrompt {
            let outer = try XCTUnwrap(HolderPrompt.current)
            KeychainKeyStore.oneHolderPrompt {
                XCTAssertTrue(HolderPrompt.current === outer, "a nested call shares the outer context")
            }
            XCTAssertTrue(HolderPrompt.current === outer)
            Thread.detachNewThread {
                XCTAssertNil(HolderPrompt.current, "another thread shares no context")
                elsewhere.fulfill()
            }
            wait(for: [elsewhere], timeout: 5)
        }
        XCTAssertNil(HolderPrompt.current)
    }
}
