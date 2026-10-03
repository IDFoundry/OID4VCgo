import Foundation
import Mobile
import XCTest
@testable import OID4VCWallet

extension MobileTestEnv: @retroactive @unchecked Sendable {}

/// The in-process test issuer, Wallet Provider and Verifier (Go's
/// TestEnv, in a framework built with -tags mobiletest).
final class TestEnv: Sendable {
    let env: MobileTestEnv

    init(deferIssuance: Bool = false, batchSize: Int = 0) throws {
        env = try OID4VC.call { MobileStartBatchTestEnv(deferIssuance, batchSize, $0) }!
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
        try Wallet(configuration: try env.configuration, keys: KeyStoreAdapter(keys ?? keyStore()),
                   credentials: CredentialStoreAdapter(store), provider: env.env.provider())
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

        // Claims for display, and whether the holder key is still there.
        let detail = try await w.credential(id: sdjwt)
        XCTAssertEqual(detail.summary.id, sdjwt)
        XCTAssertEqual(detail.summary.holderKeyPresent, true)
        XCTAssertEqual(detail.claims["family_name"], .string("Doe"))
        let mdoc = held.first { $0.format == "mso_mdoc" }!.id
        let mdocDetail = try await w.credential(id: mdoc)
        XCTAssertEqual(mdocDetail.claims["org.example.test.1"]?["given_name"], .string("Jane"))

        try await w.deleteCredential(id: sdjwt)
        let remaining = try await w.credentials()
        XCTAssertEqual(remaining.count, 1)
        do {
            _ = try await w.credential(id: sdjwt)
            XCTFail("a deleted credential's detail")
        } catch let e as WalletError {
            XCTAssertEqual(e.code, .notFound)
        }
    }

    /// The SDK's file store, end to end: credentials survive a new Wallet
    /// over the same directory, and one whose holder key is gone is
    /// listed as such.
    func testFileStoreAcrossWallets() async throws {
        let env = try TestEnv()
        defer { env.close() }
        let dir = FileManager.default.temporaryDirectory.appending(path: "creds-\(UUID())", directoryHint: .isDirectory)
        defer { try? FileManager.default.removeItem(at: dir) }
        let keys = keyStore()
        let first = try Wallet(configuration: try env.configuration, keys: KeyStoreAdapter(keys),
                               credentials: CredentialStoreAdapter(try FileCredentialStore(directory: dir)), provider: env.env.provider())
        let received = try await Self.receive(env, first)
        let second = try Wallet(configuration: try env.configuration, keyStore: keys,
                                credentialStore: try FileCredentialStore(directory: dir), provider: nil)
        let held = try await second.credentials()
        XCTAssertEqual(Set(held.map(\.id)), Set(received.credentials.map(\.id)))
        XCTAssertTrue(held.allSatisfy { $0.holderKeyPresent == true })

        let other = try Wallet(configuration: try env.configuration, keyStore: keyStore(),
                               credentialStore: try FileCredentialStore(directory: dir), provider: nil)
        let orphaned = try await other.credentials()
        XCTAssertTrue(orphaned.allSatisfy { $0.holderKeyPresent == false }, "another key store holds none of the keys")
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

    /// Deferred credentials survive the issuance closing and the app
    /// relaunching: a new Wallet over the same stores lists and polls
    /// them.
    func testDeferredSurvivesARelaunch() async throws {
        let env = try TestEnv(deferIssuance: true)
        defer { env.close() }
        let keys = keyStore()
        let store = InMemoryCredentialStore()
        let w = try wallet(env, keys: keys, store: store)
        let offer = try OID4VC.call { env.env.authorizationCodeOffer($0) }
        let s = try await w.startIssuance(offer: offer)
        try await s.completeAuthorization(redirect: env.approve(try await s.beginAuthorization()))
        let result = try await s.requestCredentials()
        XCTAssertEqual(result.deferred.count, 2)
        try await s.close()

        let relaunched = try wallet(env, keys: keys, store: store)
        let pending = try await relaunched.deferredCredentials()
        XCTAssertEqual(pending.map(\.id), result.deferred.map(\.id))
        XCTAssertEqual(pending.first?.configurationID, result.deferred.first?.configurationID)
        let held = try await relaunched.credentials()
        XCTAssertTrue(held.isEmpty, "pending ones listed as credentials")
        let swept = try await relaunched.sweepOrphanedKeys(in: keys)
        XCTAssertEqual(swept, 0, "the sweep deleted a pending credential's key")

        guard case .pending = try await relaunched.pollDeferred(id: pending[0].id) else { return XCTFail("issued before a decision") }
        env.env.decide(true)
        guard case .issued(let c) = try await relaunched.pollDeferred(id: pending[0].id) else { return XCTFail("still pending") }
        XCTAssertFalse(c.id.isEmpty)
        env.env.decide(false)
        do {
            _ = try await relaunched.pollDeferred(id: pending[1].id)
            XCTFail("a denied credential")
        } catch let e as WalletError {
            XCTAssertEqual(e.code, .credentialDenied)
        }
        let left = try await relaunched.deferredCredentials()
        XCTAssertTrue(left.isEmpty)
        XCTAssertEqual(try keys.keyIDs().count, 1, "only the issued credential's key is left")
    }

    /// The redirect completes an authorization begun before the app
    /// quit: a relaunched wallet over the same stores resumes it, and the
    /// launch sweep keeps its keys.
    func testResumeIssuanceAfterARelaunch() async throws {
        let env = try TestEnv()
        defer { env.close() }
        let keys = keyStore()
        let store = InMemoryCredentialStore()
        let w = try wallet(env, keys: keys, store: store)
        let offer = try OID4VC.call { env.env.authorizationCodeOffer($0) }
        let quit = try await w.startIssuance(offer: offer)
        let redirect = try env.approve(try await quit.beginAuthorization())
        // The app is killed: no close(), and no deinit either (which would
        // close it), so `quit` is kept alive to the end.
        defer { withExtendedLifetime(quit) { XCTAssertFalse($0.offer.credentials.isEmpty) } }
        let relaunched = try wallet(env, keys: keys, store: store)
        let swept = try await relaunched.sweepOrphanedKeys(in: keys)
        XCTAssertEqual(swept, 0, "the sweep deleted the authorization's keys")
        let s = try await relaunched.resumeIssuance(redirect: redirect)
        let result = try await s.requestCredentials()
        XCTAssertEqual(result.credentials.count, 2)
        try await s.close()
        do {
            _ = try await relaunched.resumeIssuance(redirect: redirect)
            XCTFail("the redirect completed twice")
        } catch let e as WalletError {
            XCTAssertEqual(e.code, .notFound)
        }
    }

    /// A received credential shows the issuer's display metadata and its
    /// expiry; checkStatus reads its revocation status, and sees a
    /// revocation.
    func testDisplayAndStatus() async throws {
        let env = try TestEnv()
        defer { env.close() }
        let w = try wallet(env)
        let received = try await Self.receive(env, w)
        let held = try await w.credentials()
        XCTAssertEqual(held.count, received.credentials.count)
        for c in held {
            XCTAssertEqual(c.display?.issuerName, "Test Issuer")
            XCTAssertNotNil(c.display?.name)
            XCTAssertNotNil(c.display?.logo?.url)
            XCTAssertEqual(c.display?.backgroundColor, "#12107c")
            XCTAssertFalse(c.isExpired())
            XCTAssertNil(c.status, "status before any check")
        }
        let checked = try await w.checkStatus(id: held[0].id)
        XCTAssertEqual(checked.status?.value, .valid)
        env.env.revoke()
        let revoked = try await w.checkStatus(id: held[0].id)
        XCTAssertEqual(revoked.status?.value, .revoked)
        let listed = try await w.credentials()
        XCTAssertEqual(listed.first { $0.id == held[0].id }?.status?.value, .revoked, "the status isn't kept")
    }

    /// From an issuer offering batches, each credential arrives as
    /// copies, and a presentation uses up one.
    func testBatch() async throws {
        let env = try TestEnv(batchSize: 3)
        defer { env.close() }
        let w = try wallet(env)
        _ = try await Self.receive(env, w)
        let held = try await w.credentials()
        XCTAssertTrue(held.allSatisfy { $0.copies == 3 && $0.copiesLeft == 3 }, "\(held.map { ($0.copies, $0.copiesLeft) })")
        let req = try env.request(format: "dc+sd-jwt")
        let p = try await w.startPresentation(request: req.link)
        _ = try await p.respond()
        let after = try await w.credentials()
        XCTAssertEqual(after.map(\.copiesLeft).sorted(), [2, 3])
    }

    func testAbandonDeferred() async throws {
        let env = try TestEnv(deferIssuance: true)
        defer { env.close() }
        let keys = keyStore()
        let w = try wallet(env, keys: keys)
        let offer = try OID4VC.call { env.env.authorizationCodeOffer($0) }
        let s = try await w.startIssuance(offer: offer)
        try await s.completeAuthorization(redirect: env.approve(try await s.beginAuthorization()))
        let result = try await s.requestCredentials()
        try await s.close()
        for d in result.deferred { try await w.abandonDeferred(id: d.id) }
        let left = try await w.deferredCredentials()
        XCTAssertTrue(left.isEmpty)
        XCTAssertEqual(try keys.keyIDs(), [])
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

    /// The sweep keeps the keys the wallet's credentials are bound to and
    /// deletes the rest.
    func testSweepOrphanedKeys() async throws {
        let env = try TestEnv()
        defer { env.close() }
        let keys = keyStore()
        let w = try wallet(env, keys: keys)
        let received = try await Self.receive(env, w)
        XCTAssertEqual(received.credentials.count, 2)
        let stray = try keys.createKey(purpose: .dpop)
        let swept = try await w.sweepOrphanedKeys(in: keys)
        XCTAssertEqual(swept, 1)
        XCTAssertNil(try keys.publicKey(id: stray))
        let held = try await w.credentials()
        XCTAssertTrue(held.allSatisfy { $0.holderKeyPresent == true }, "a credential's key was swept")
    }

    /// An issuance dropped without close() still deletes its keys.
    func testDroppedIssuanceClosesItself() async throws {
        let env = try TestEnv()
        defer { env.close() }
        let keys = keyStore()
        let w = try wallet(env, keys: keys)
        let offer = try OID4VC.call { env.env.authorizationCodeOffer($0) }
        do {
            let s = try await w.startIssuance(offer: offer)
            _ = try await s.beginAuthorization()
            XCTAssertEqual(try keys.keyIDs().count, 2, "the instance and DPoP keys")
        }
        for _ in 0..<50 where try keys.keyIDs().count > 0 {
            try await Task.sleep(for: .milliseconds(100))
        }
        XCTAssertEqual(try keys.keyIDs(), [])
    }
}
