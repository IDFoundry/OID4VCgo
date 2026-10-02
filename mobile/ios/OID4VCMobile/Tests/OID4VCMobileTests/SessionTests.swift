import Foundation
import Mobile
import XCTest
@testable import OID4VCMobile

extension MobileTestEnv: @retroactive @unchecked Sendable {}

/// The in-process test issuer, Wallet Provider and Verifier (Go's
/// TestEnv, in a framework built with -tags mobiletest).
final class TestEnv: Sendable {
    let env: MobileTestEnv

    init(deferIssuance: Bool = false) throws {
        env = try OID4VC.call { MobileStartTestEnv(deferIssuance, $0) }!
    }

    func close() { env.close() }

    var configuration: WalletConfiguration {
        get throws { try JSONDecoder().decode(WalletConfiguration.self, from: Data(env.configJSON().utf8)) }
    }

    func approve(_ url: URL) throws -> URL { URL(string: try OID4VC.call { env.approve(url.absoluteString, error: $0) })! }

    func request(format: String = "") throws -> (id: String, link: String) {
        let json = try OID4VC.call { env.request(format, error: $0) }
        let d = try JSONSerialization.jsonObject(with: Data(json.utf8)) as! [String: String]
        return (d["id"]!, d["link"]!)
    }

    func result(_ id: String) throws -> [String: Any] {
        let json = try OID4VC.call { env.requestResult(id, error: $0) }
        return try JSONSerialization.jsonObject(with: Data(json.utf8)) as! [String: Any]
    }
}

extension WalletConfiguration: Decodable {
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.init(clientID: try c.decode(String.self, forKey: .clientID), redirectURI: try c.decode(String.self, forKey: .redirectURI),
                  issuerRoots: try c.decode(String.self, forKey: .issuerRoots), verifierRoots: try c.decode(String.self, forKey: .verifierRoots),
                  development: try c.decode(Bool.self, forKey: .development))
    }
}

final class SessionTests: XCTestCase {
    /// A key store as the platform allows here: Secure Enclave keys on the
    /// Simulator, software keys on macOS; in memory either way.
    func keyStore() -> KeychainKeyStore {
        #if targetEnvironment(simulator)
        KeychainKeyStore(options: .init(secureEnclave: true, persistent: false, holderUserPresence: false))
        #else
        KeychainKeyStore(options: .init(secureEnclave: false, persistent: false))
        #endif
    }

    func wallet(_ env: TestEnv, keys: KeychainKeyStore? = nil, store: InMemoryCredentialStore = InMemoryCredentialStore()) throws -> Wallet {
        try Wallet(configuration: try env.configuration, keyStore: keys ?? keyStore(), credentialStore: store,
                   provider: env.env.provider())
    }

    static func receive(_ env: TestEnv, _ w: Wallet) async throws -> Issuance.Result {
        let offer = try OID4VC.call { env.env.authorizationCodeOffer($0) }
        let s = try await w.startIssuance(offer: offer)
        XCTAssertEqual(s.offer.grant, .authorizationCode)
        XCTAssertEqual(s.offer.credentials.map(\.format).sorted(), ["dc+sd-jwt", "mso_mdoc"])
        let url = try await s.beginAuthorization()
        try await s.completeAuthorization(redirect: env.approve(url))
        let result = try await s.requestCredentials()
        try await s.close()
        return result
    }

    /// The whole lifecycle across the boundary: Go drives the protocols,
    /// calling back into the Swift key store, credential store and
    /// Wallet Provider.
    func testIssueThenPresent() async throws {
        let env = try TestEnv()
        defer { env.close() }
        let store = InMemoryCredentialStore()
        let w = try wallet(env, store: store)

        let received = try await Self.receive(env, w)
        XCTAssertEqual(received.credentials.count, 2)
        XCTAssertTrue(received.deferred.isEmpty)
        let held = try await w.credentials()
        XCTAssertEqual(Set(held.map(\.id)), Set(received.credentials.map(\.id)))

        let req = try env.request()
        let p = try await w.startPresentation(request: req.link)
        XCTAssertFalse(p.verifier.name.isEmpty)
        XCTAssertEqual(p.candidates.map(\.queryID), ["mdl", "pid"])
        let sdjwt = held.first { $0.format == "dc+sd-jwt" }!.id
        let disclosed = try await p.preview(credentialIDs: [sdjwt])
        XCTAssertEqual(disclosed.first?.claims, [[.key("family_name")]])
        let presented = try await p.respond(credentialIDs: [sdjwt])
        XCTAssertEqual(presented.queryIDs, ["pid"])
        let result = try env.result(req.id)
        XCTAssertEqual(result["status"] as? String, "done")
        XCTAssertEqual((result["claims"] as? [String: Any])?["family_name"] as? String, "Doe")

        do {
            _ = try await p.respond(credentialIDs: [sdjwt])
            XCTFail("a second answer")
        } catch let e as WalletError {
            XCTAssertEqual(e.code, .wrongStep)
        }

        try await w.deleteCredential(id: sdjwt)
        let remaining = try await w.credentials()
        XCTAssertEqual(remaining.count, 1)
    }

    func testPreAuthorizedCodeWithPIN() async throws {
        let env = try TestEnv()
        defer { env.close() }
        let w = try wallet(env)
        let offer = try OID4VC.call { env.env.preAuthorizedOffer("493536", error: $0) }
        let s = try await w.startIssuance(offer: offer)
        XCTAssertEqual(s.offer.grant, .preAuthorizedCode)
        XCTAssertEqual(s.offer.txCode?.length, 6)
        do {
            try await s.redeemPreAuthorizedCode(pin: "000000")
            XCTFail("a wrong PIN was accepted")
        } catch let e as WalletError {
            XCTAssertEqual(e.code, .protocolError)
        }
        try await s.redeemPreAuthorizedCode(pin: "493536")
        let result = try await s.requestCredentials()
        XCTAssertEqual(result.credentials.count, 1)
        try await s.close()
    }

    func testDeferred() async throws {
        let env = try TestEnv(deferIssuance: true)
        defer { env.close() }
        let w = try wallet(env)
        let offer = try OID4VC.call { env.env.authorizationCodeOffer($0) }
        let s = try await w.startIssuance(offer: offer)
        try await s.completeAuthorization(redirect: env.approve(try await s.beginAuthorization()))
        let result = try await s.requestCredentials()
        XCTAssertEqual(result.deferred.count, 2)
        guard case .pending = try await s.pollDeferred(id: result.deferred[0].id) else { return XCTFail("issued before a decision") }
        env.env.decide(true)
        guard case .issued(let c) = try await s.pollDeferred(id: result.deferred[0].id) else { return XCTFail("still pending") }
        XCTAssertFalse(c.id.isEmpty)
        env.env.decide(false)
        do {
            _ = try await s.pollDeferred(id: result.deferred[1].id)
            XCTFail("a denied credential")
        } catch let e as WalletError {
            XCTAssertEqual(e.code, .credentialDenied)
        }
        try await s.close()
    }

    func testDeclineWithNothingToPresent() async throws {
        let env = try TestEnv()
        defer { env.close() }
        let w = try wallet(env)
        let req = try env.request(format: "mso_mdoc")
        let p = try await w.startPresentation(request: req.link)
        XCTAssertTrue(p.candidates.isEmpty)
        do {
            _ = try await p.respond()
            XCTFail("responded with nothing held")
        } catch let e as WalletError {
            XCTAssertEqual(e.code, .noMatchingCredential)
        }
        _ = try await p.decline()
        XCTAssertTrue((try env.result(req.id)["last_error"] as? String ?? "").contains("access_denied"))
    }

    /// Cancelling the Swift Task cancels the Go call waiting on the
    /// network.
    func testCancellation() async throws {
        let env = try TestEnv()
        defer { env.close() }
        let w = try wallet(env)
        let server = try SilentServer()
        defer { server.stop() }
        let offer = "openid-credential-offer://?credential_offer_uri=" +
            "https://127.0.0.1:\(server.port)/offer".addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
        let task = Task { try await w.startIssuance(offer: offer) }
        try await Task.sleep(for: .milliseconds(300))
        task.cancel()
        do {
            _ = try await task.value
            XCTFail("a cancelled StartIssuance returned")
        } catch let e as WalletError {
            XCTAssertEqual(e.code, .cancelled)
        }
    }

    /// Several issuances at once, each calling back into Swift.
    func testConcurrentIssuances() async throws {
        let env = try TestEnv()
        defer { env.close() }
        let store = InMemoryCredentialStore()
        let w = try wallet(env, store: store)
        try await withThrowingTaskGroup(of: Int.self) { group in
            for _ in 0..<4 {
                group.addTask { try await Self.receive(env, w).credentials.count }
            }
            var total = 0
            for try await n in group { total += n }
            XCTAssertEqual(total, 8)
        }
        let held = try await w.credentials()
        XCTAssertEqual(held.count, 8)
    }
}
