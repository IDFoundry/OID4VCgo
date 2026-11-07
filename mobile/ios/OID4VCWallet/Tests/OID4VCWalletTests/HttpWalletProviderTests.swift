import CryptoKit
import Foundation
import XCTest
@testable import OID4VCWallet

final class HttpWalletProviderTests: XCTestCase {
    /// The client data, its hash and the thumbprints match the Go
    /// provider's (WALLET_PROVIDER.md's test vectors,
    /// walletprovider/appattest's TestClientDataVectors), so the two
    /// can't drift.
    func testClientDataVectors() throws {
        let key1 = try vectorKey(last: 0x20)
        let key2 = try vectorKey(last: 0x21)
        XCTAssertEqual(jwkThumbprint(point: key1), "6UoWwDCkLjV0J-pQG8c0THxbVhBcpR0AZDift1Yl5DM")
        XCTAssertEqual(jwkThumbprint(point: key2), "6rpgUp9sT-ItA87f0SCoStuYFvCFUFrnT9HqUF0sY_8")
        XCTAssertEqual(jwk(point: key1)["x"] as? String, "UVw9brnjlrkE0_7Kf1T9zQzB6Ze_N13KUVrQpsO0A18")
        let challenge = encodeBase64URL(Data(0..<32))
        XCTAssertEqual(challenge, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
        XCTAssertEqual(String(decoding: AppAttestClientData.data(purpose: "registration", challenge: challenge, keys: [key1]), as: UTF8.self),
                       "OID4VCgo-WalletProvider-AppAttest/1\nregistration\nAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\n6UoWwDCkLjV0J-pQG8c0THxbVhBcpR0AZDift1Yl5DM\n")
        XCTAssertEqual(hex(AppAttestClientData.hash(purpose: "registration", challenge: challenge, keys: [key1])),
                       "659141d12dbf4b9421adb6a080d4245a01ead653218a6289376baa869a8f477f")
        XCTAssertEqual(hex(AppAttestClientData.hash(purpose: "holder", challenge: challenge, keys: [key1, key2])),
                       "3ba79d8b12988b5db62d590f308d273093573803711f21315bb2b3e504b1b38c")
    }

    /// The installation registers once, with an attestation over the
    /// registration key; each new instance key's Wallet Attestation
    /// carries an assertion over it, a known one's none; every request
    /// after registration is signed with the registration key, over its
    /// path and body.
    func testRegistersOnceAndAttests() async throws {
        let env = Env()
        let a = env.instanceKey(), b = env.instanceKey()
        let jwtA = try await env.provider.walletAttestation(clientID: "wallet", instanceKey: a.json)
        XCTAssertEqual(unverifiedClaims(jwtA)?["sub"] as? String, "wallet")
        _ = try await env.provider.walletAttestation(clientID: "wallet", instanceKey: b.json)
        _ = try await env.provider.walletAttestation(clientID: "wallet", instanceKey: a.json)

        let s = env.server.state.withLock { $0 }
        XCTAssertEqual(s.registrations, 1)
        XCTAssertEqual(env.attest.calls.withLock { $0 }, ["generateKey", "attestKey", "generateAssertion", "generateAssertion"])
        XCTAssertEqual(s.walletAttestations.map(\.hadEvidence), [true, true, false])
        XCTAssertEqual(s.walletAttestations.map(\.path), Array(repeating: "/wp/v1/wallet-attestation", count: 3))
        let kept = try XCTUnwrap(env.registry.instance())
        XCTAssertEqual(kept.instanceID, "instance-1")
        XCTAssertEqual(kept.appAttestKeyID, "attest-key-1")
    }

    /// A known instance key the provider no longer has a record of
    /// (`evidence_required`) is asserted again.
    func testEvidenceRequiredAssertsAgain() async throws {
        let env = Env()
        let a = env.instanceKey()
        _ = try await env.provider.walletAttestation(clientID: "wallet", instanceKey: a.json)
        env.server.state.withLock { $0.recorded.removeAll() }
        _ = try await env.provider.walletAttestation(clientID: "wallet", instanceKey: a.json)
        XCTAssertEqual(env.server.state.withLock { $0.walletAttestations.map(\.hadEvidence) }, [true, false, true])
    }

    /// A Key Attestation sends one assertion over every holder key, in
    /// order, and is checked to attest only keys sent, over the nonce.
    func testKeyAttestation() async throws {
        let env = Env()
        let instance = env.instanceKey()
        let holders = [env.instanceKey(), env.instanceKey()]
        do {
            _ = try await env.provider.keyAttestation(instanceKey: instance.json, keys: holders.map(\.json), nonce: "n")
            XCTFail("a Key Attestation before any registration")
        } catch let e as StoreError {
            XCTAssertTrue(e.message.contains("isn't registered"), e.message)
        }
        _ = try await env.provider.walletAttestation(clientID: "wallet", instanceKey: instance.json)
        let jwt = try await env.provider.keyAttestation(instanceKey: instance.json, keys: holders.map(\.json), nonce: "n")
        XCTAssertEqual(unverifiedClaims(jwt)?["nonce"] as? String, "n")
        let s = env.server.state.withLock { $0 }
        XCTAssertEqual(s.keyAttestationEvidence, [1])

        env.server.state.withLock { $0.attestStranger = true }
        do {
            _ = try await env.provider.keyAttestation(instanceKey: instance.json, keys: holders.map(\.json), nonce: "n")
            XCTFail("a Key Attestation of a key not sent was accepted")
        } catch let e as StoreError {
            XCTAssertTrue(e.message.contains("wasn't sent"), e.message)
        }
    }

    /// Without App Attest there's no registration, and no request.
    func testUnsupported() async throws {
        let env = Env(supported: false)
        do {
            _ = try await env.provider.walletAttestation(clientID: "wallet", instanceKey: env.instanceKey().json)
            XCTFail("registered without App Attest")
        } catch let e as StoreError {
            XCTAssertTrue(e.message.contains("App Attest isn't supported"), e.message)
        }
        XCTAssertEqual(env.server.state.withLock { $0.requests }, 0)
    }

    /// `instance_revoked` forgets the registration and deletes its key:
    /// the next Wallet Attestation registers again.
    func testRevokedForgets() async throws {
        let env = Env()
        _ = try await env.provider.walletAttestation(clientID: "wallet", instanceKey: env.instanceKey().json)
        let first = try XCTUnwrap(env.registry.instance())
        env.server.state.withLock { $0.revoked = true }
        do {
            _ = try await env.provider.walletAttestation(clientID: "wallet", instanceKey: env.instanceKey().json)
            XCTFail("a revoked instance attested")
        } catch let e as WalletProviderRefusedError {
            XCTAssertEqual(e.error, "instance_revoked")
            XCTAssertEqual(e.status, 403)
        }
        XCTAssertNil(try env.registry.instance())
        XCTAssertNil(try env.keys.publicKey(id: first.keyID))
        env.server.state.withLock { $0.revoked = false }
        _ = try await env.provider.walletAttestation(clientID: "wallet", instanceKey: env.instanceKey().json)
        XCTAssertEqual(try env.registry.instance()?.instanceID, "instance-2")
    }

    /// A kept registration whose key ID now names another key is
    /// forgotten, and that key deleted: the next Wallet Attestation
    /// registers again, leaving one key.
    func testKeptRegistrationWithAnotherKeyIsForgotten() async throws {
        let env = Env()
        let stray = try env.keys.createKey(purpose: .instance)
        try env.registry.put(RegisteredInstance(keyThumbprint: "another key's", keyID: stray, instanceID: "instance-0",
                                                appAttestKeyID: "attest-key-0"))
        _ = try await env.provider.walletAttestation(clientID: "wallet", instanceKey: env.instanceKey().json)
        XCTAssertNil(try env.keys.publicKey(id: stray))
        XCTAssertEqual(env.keys.count, 1)
        XCTAssertEqual(try env.registry.instance()?.instanceID, "instance-1")
    }

    /// The sweep deletes every registration key a registration didn't
    /// keep — one an earlier launch left, ending mid-registration — and
    /// keeps the registration's, which goes on signing; with nothing
    /// registered it deletes them all. Over a store that can't list its
    /// keys it deletes nothing.
    func testSweepOrphanedRegistrationKeys() async throws {
        let store = KeychainKeyStore(options: .init(secureEnclave: false, persistent: false,
                                                    tagPrefix: HttpWalletProvider.registrationKeyTagPrefix))
        let env = Env(registrationKeys: store)
        let left = try store.createKey(purpose: .instance)
        let swept = try await env.provider.sweepOrphanedRegistrationKeys()
        XCTAssertEqual(swept, 1)
        XCTAssertNil(try store.publicKey(id: left))

        _ = try await env.provider.walletAttestation(clientID: "wallet", instanceKey: env.instanceKey().json)
        let kept = try XCTUnwrap(env.registry.instance())
        let orphans = [try store.createKey(purpose: .instance), try store.createKey(purpose: .instance)]
        let sweptAgain = try await env.provider.sweepOrphanedRegistrationKeys()
        XCTAssertEqual(sweptAgain, 2)
        XCTAssertEqual(try store.keyIDs(), [kept.keyID])
        for id in orphans { XCTAssertNil(try store.publicKey(id: id)) }
        _ = try await env.provider.walletAttestation(clientID: "wallet", instanceKey: env.instanceKey().json)
        XCTAssertEqual(env.server.state.withLock { $0.registrations }, 1)

        let memory = Env()
        _ = try memory.keys.createKey(purpose: .instance)
        let none = try await memory.provider.sweepOrphanedRegistrationKeys()
        XCTAssertEqual(none, 0)
        XCTAssertEqual(memory.keys.count, 1)
    }

    /// A registration key the provider has seen is replaced by another,
    /// once; the refused one is deleted.
    func testInstanceKeyRegisteredRetries() async throws {
        let env = Env()
        env.server.state.withLock { $0.refuseRegistrations = 1 }
        _ = try await env.provider.walletAttestation(clientID: "wallet", instanceKey: env.instanceKey().json)
        XCTAssertEqual(env.server.state.withLock { $0.registrations }, 1)
        XCTAssertEqual(env.keys.count, 1)
    }

    /// A lost App Attest key (restore, reinstall) registers the
    /// installation again and attests the instance key under it.
    func testAppAttestKeyLostRegistersAgain() async throws {
        let env = Env()
        _ = try await env.provider.walletAttestation(clientID: "wallet", instanceKey: env.instanceKey().json)
        env.attest.loseKey.withLock { $0 = true }
        _ = try await env.provider.walletAttestation(clientID: "wallet", instanceKey: env.instanceKey().json)
        XCTAssertEqual(env.server.state.withLock { $0.registrations }, 2)
        XCTAssertEqual(try env.registry.instance()?.appAttestKeyID, "attest-key-2")
    }

    /// Of two Wallet Attestations whose App Attest key is gone, the
    /// second to find out forgets only the registration whose key it
    /// used, not the one the first has made since.
    func testAppAttestKeyLostForgetsOnlyTheRegistrationThatFailed() async throws {
        let registry = CountingRegistry()
        let env = Env(registry: registry)
        _ = try await env.provider.walletAttestation(clientID: "wallet", instanceKey: env.instanceKey().json)
        let reads = registry.reads.withLock { $0 }
        env.attest.lostKeys.withLock { $0 = ["attest-key-1"] }
        // Both calls read the registration before the first finds its
        // key gone; the second finds out once the first has registered
        // again.
        env.attest.onLost.withLock {
            $0 = { n in
                if n == 1 {
                    await until("both calls read the registration") { registry.reads.withLock { $0 } >= reads + 2 }
                } else {
                    await until("the first registered again") { (try? registry.instance())?.appAttestKeyID == "attest-key-2" }
                }
            }
        }
        async let a = env.provider.walletAttestation(clientID: "wallet", instanceKey: env.instanceKey().json)
        async let b = env.provider.walletAttestation(clientID: "wallet", instanceKey: env.instanceKey().json)
        _ = try await (a, b)
        XCTAssertEqual(env.server.state.withLock { $0.registrations }, 2)
        let kept = try XCTUnwrap(env.registry.instance())
        XCTAssertEqual(kept.instanceID, "instance-2")
        XCTAssertNotNil(try env.keys.publicKey(id: kept.keyID))
        XCTAssertEqual(env.keys.count, 1)
    }

    /// Providers over the same registry file — an app rebuilding its
    /// wallet mid-issuance — register the installation once.
    func testProvidersOverOneRegistryFileRegisterOnce() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("wp/instance.json")
        let env = Env(registry: FileInstanceRegistry(url: url))
        let other = env.provider(over: FileInstanceRegistry(url: dir.appendingPathComponent("wp/./instance.json")))
        env.server.state.withLock { $0.registrationDelay = 50_000_000 }
        async let a = env.provider.walletAttestation(clientID: "wallet", instanceKey: env.instanceKey().json)
        async let b = other.walletAttestation(clientID: "wallet", instanceKey: env.instanceKey().json)
        _ = try await (a, b)
        XCTAssertEqual(env.server.state.withLock { $0.registrations }, 1)
        XCTAssertEqual(env.keys.count, 1)
    }

    /// An App Attest key a transient failure left unregistered — App
    /// Attest's server, or the provider, unavailable — is tried again by
    /// the next registration; a refusal needs a new one.
    func testUnavailableKeepsTheAppAttestKey() async throws {
        let env = Env()
        env.attest.attestFailures.withLock {
            $0 = [WalletProviderUnavailableError(status: nil, error: nil, message: "App Attest's server is unavailable")]
        }
        do {
            _ = try await env.provider.walletAttestation(clientID: "wallet", instanceKey: env.instanceKey().json)
            XCTFail("registered without App Attest's server")
        } catch is WalletProviderUnavailableError {}
        env.server.state.withLock { $0.registrationError = (503, "server_error") }
        do {
            _ = try await env.provider.walletAttestation(clientID: "wallet", instanceKey: env.instanceKey().json)
            XCTFail("registered with the provider unavailable")
        } catch is WalletProviderUnavailableError {}
        env.server.state.withLock { $0.registrationError = (403, "evidence_rejected") }
        do {
            _ = try await env.provider.walletAttestation(clientID: "wallet", instanceKey: env.instanceKey().json)
            XCTFail("registered with its evidence rejected")
        } catch is WalletProviderRefusedError {}
        env.server.state.withLock { $0.registrationError = nil }
        _ = try await env.provider.walletAttestation(clientID: "wallet", instanceKey: env.instanceKey().json)
        XCTAssertEqual(env.attest.attested.withLock { $0 }, ["attest-key-1", "attest-key-1", "attest-key-1", "attest-key-2"])
        XCTAssertEqual(try env.registry.instance()?.appAttestKeyID, "attest-key-2")
        XCTAssertEqual(env.keys.count, 1)
    }

    /// A kept App Attest key App Attest won't attest again is replaced.
    func testKeptAppAttestKeyAppAttestRefusesIsReplaced() async throws {
        let env = Env()
        env.server.state.withLock { $0.registrationError = (503, "server_error") }
        do {
            _ = try await env.provider.walletAttestation(clientID: "wallet", instanceKey: env.instanceKey().json)
            XCTFail("registered with the provider unavailable")
        } catch is WalletProviderUnavailableError {}
        env.server.state.withLock { $0.registrationError = nil }
        env.attest.refuseReattest.withLock { $0 = true }
        _ = try await env.provider.walletAttestation(clientID: "wallet", instanceKey: env.instanceKey().json)
        XCTAssertEqual(env.attest.attested.withLock { $0 }, ["attest-key-1", "attest-key-1", "attest-key-2"])
        XCTAssertEqual(try env.registry.instance()?.appAttestKeyID, "attest-key-2")
    }

    /// An issuer without a Nonce Endpoint gives an empty nonce, which the
    /// provider omits from the Key Attestation; a nonce other than the
    /// one sent, or none for one sent, is refused.
    func testKeyAttestationWithoutNonce() async throws {
        let env = Env()
        let instance = env.instanceKey()
        _ = try await env.provider.walletAttestation(clientID: "wallet", instanceKey: instance.json)
        let jwt = try await env.provider.keyAttestation(instanceKey: instance.json, keys: [env.instanceKey().json], nonce: "")
        XCTAssertNil(unverifiedClaims(jwt)?["nonce"])
        for (claim, sent) in [("n", ""), (nil, "n")] as [(String?, String)] {
            env.server.state.withLock { $0.nonceClaim = .some(claim) }
            do {
                _ = try await env.provider.keyAttestation(instanceKey: instance.json, keys: [env.instanceKey().json], nonce: sent)
                XCTFail("a Key Attestation over \(claim ?? "no nonce") for \(sent) was accepted")
            } catch let e as StoreError {
                XCTAssertTrue(e.message.contains("nonce"), e.message)
            }
        }
    }

    /// A base URL whose path is percent-encoded signs the path as sent.
    func testEscapedBasePath() async throws {
        let env = Env(baseURL: "https://wp.example/w%20p")
        _ = try await env.provider.walletAttestation(clientID: "wallet", instanceKey: env.instanceKey().json)
        XCTAssertEqual(env.server.state.withLock { $0.walletAttestations.map(\.path) }, ["/w%20p/v1/wallet-attestation"])
    }

    /// 5xx, 429 and `invalid_challenge` are network failures, marked
    /// for Go; other refusals name the protocol's code.
    func testFailures() async throws {
        let env = Env()
        env.server.state.withLock { $0.challengeStatus = 503 }
        do {
            _ = try await env.provider.walletAttestation(clientID: "wallet", instanceKey: env.instanceKey().json)
            XCTFail("a 503 succeeded")
        } catch let e as WalletProviderUnavailableError {
            XCTAssertEqual(e.status, 503)
            XCTAssertTrue(e.localizedDescription.hasPrefix("[network] "), e.localizedDescription)
        }
        env.server.state.withLock { $0.challengeStatus = 200; $0.registrationError = (403, "evidence_rejected") }
        do {
            _ = try await env.provider.walletAttestation(clientID: "wallet", instanceKey: env.instanceKey().json)
            XCTFail("rejected evidence succeeded")
        } catch let e as WalletProviderRefusedError {
            XCTAssertEqual(e.error, "evidence_rejected")
            XCTAssertEqual(e.localizedDescription, "the Wallet Provider refused /v1/instances: HTTP 403 evidence_rejected")
        }
        XCTAssertEqual(env.keys.count, 0, "an unregistered registration key was kept")
    }

    /// The base URL must be https, without user info, query or fragment;
    /// its path prefixes every protocol path.
    func testBaseURL() throws {
        XCTAssertEqual(try HttpWalletProvider.parseBaseURL(URL(string: "https://wp.example/wp/")!, allowHTTP: false).absoluteString,
                       "https://wp.example/wp")
        for bad in ["http://wp.example", "https://u@wp.example", "https://wp.example?q", "https://wp.example#f", "wp.example"] {
            XCTAssertThrowsError(try HttpWalletProvider.parseBaseURL(URL(string: bad)!, allowHTTP: false), bad)
        }
        XCTAssertThrowsError(try HttpWalletProvider(baseURL: URL(string: "https://wp.example")!, instances: InMemoryInstanceRegistry(),
                                                    registrationKeys: MemoryKeys(), appAttest: FakeAppAttest(supported: true), timeout: 0))
    }

    /// A file registry keeps a registration across instances, forgets
    /// only the one kept, and refuses a malformed file.
    func testFileInstanceRegistry() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("wp/instance.json")
        let a = RegisteredInstance(keyThumbprint: "t", keyID: "k", instanceID: "i", appAttestKeyID: "a")
        XCTAssertNil(try FileInstanceRegistry(url: url).instance())
        try FileInstanceRegistry(url: url).put(a)
        XCTAssertEqual(try FileInstanceRegistry(url: url).instance(), a)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: [String: String]])
        XCTAssertEqual(json["instance"]?["app_attest_key_id"], "a")
        var b = a
        b.instanceID = "j"
        try FileInstanceRegistry(url: url).remove(b)
        XCTAssertEqual(try FileInstanceRegistry(url: url).instance(), a)
        try FileInstanceRegistry(url: url).remove(a)
        XCTAssertNil(try FileInstanceRegistry(url: url).instance())
        try Data("{".utf8).write(to: url)
        XCTAssertThrowsError(try FileInstanceRegistry(url: url).instance())
    }

    /// The URLSession transport follows no redirect and reads a bounded
    /// answer.
    func testTransport() async throws {
        let transport = URLSessionTransport(timeout: 5, protocolClasses: [StubProtocol.self])
        StubProtocol.answer.withLock { $0 = (302, ["Location": "https://elsewhere.example/"], Data()) }
        let redirected = try await transport.post(url: URL(string: "https://wp.example/v1/challenge")!, headers: [:], body: Data())
        XCTAssertEqual(redirected.status, 302)
        StubProtocol.answer.withLock { $0 = (200, ["Content-Type": "application/json"], Data(count: HttpWalletProvider.maxResponseBytes + 1)) }
        do {
            _ = try await transport.post(url: URL(string: "https://wp.example/v1/challenge")!, headers: [:], body: Data())
            XCTFail("an oversized answer was read")
        } catch let e as StoreError {
            XCTAssertTrue(e.message.contains("larger than"), e.message)
        }
    }
}

// MARK: Helpers

private func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

/// The vector keys: private scalars 0x01…0x20, the last byte replaced by `last`.
private func vectorKey(last: UInt8) throws -> Data {
    var raw = [UInt8](1...32)
    raw[31] = last
    return try P256.Signing.PrivateKey(rawRepresentation: raw).publicKey.x963Representation
}

/// A provider wired to a fake server and a fake App Attest.
private struct Env {
    let registry: any InstanceRegistry
    let keys = MemoryKeys()
    /// The provider's registration key store: `keys` unless one is given.
    let registrationKeys: any KeyStore
    let attest: FakeAppAttest
    let server: FakeServer
    let provider: HttpWalletProvider
    private let baseURL: URL

    init(supported: Bool = true, registry: any InstanceRegistry = InMemoryInstanceRegistry(),
         baseURL: String = "https://wp.example/wp", registrationKeys: (any KeyStore)? = nil) {
        self.registry = registry
        self.baseURL = URL(string: baseURL)!
        self.registrationKeys = registrationKeys ?? keys
        attest = FakeAppAttest(supported: supported)
        server = FakeServer(keys: keys, prefix: URLComponents(string: baseURL)!.percentEncodedPath)
        provider = try! HttpWalletProvider(baseURL: self.baseURL, instances: registry, registrationKeys: self.registrationKeys,
                                           appAttest: attest, transport: server, clock: { 1_767_225_600 }, allowHTTP: false)
    }

    /// Another provider over `registry`, as an app rebuilding its
    /// wallet makes, with the same keys, App Attest and server.
    func provider(over registry: any InstanceRegistry) -> HttpWalletProvider {
        try! HttpWalletProvider(baseURL: baseURL, instances: registry, registrationKeys: registrationKeys,
                                appAttest: attest, transport: server, clock: { 1_767_225_600 }, allowHTTP: false)
    }

    func instanceKey() -> (point: Data, json: Data) {
        let point = P256.Signing.PrivateKey().publicKey.x963Representation
        return (point, try! JSONSerialization.data(withJSONObject: jwk(point: point)))
    }
}

/// A KeyStore of software P-256 keys in memory.
private final class MemoryKeys: KeyStore, @unchecked Sendable {
    private let keys = Locked<[String: P256.Signing.PrivateKey]>(initialState: [:])
    private let next = Locked(initialState: 0)

    var count: Int { keys.withLock { $0.count } }

    func createKey(purpose: KeyPurpose) throws -> String {
        let id = "reg-\(next.withLock { $0 += 1; return $0 })"
        keys.withLock { $0[id] = P256.Signing.PrivateKey() }
        return id
    }

    func publicKey(id: String) throws -> Data? { keys.withLock { $0[id]?.publicKey.x963Representation } }

    func sign(id: String, digest: Data) throws -> Data {
        guard let k = keys.withLock({ $0[id] }) else { throw StoreError("no key \(id)") }
        return try k.signature(for: Digest(digest)).derRepresentation
    }

    func deleteKey(id: String) throws { keys.withLock { $0[id] = nil } }

    func privateKey(_ id: String) -> P256.Signing.PrivateKey? { keys.withLock { $0[id] } }
}

/// A precomputed SHA-256 digest, to sign as it is.
private struct Digest: CryptoKit.Digest {
    static let byteCount = 32
    let bytes: [UInt8]
    init(_ d: Data) { bytes = [UInt8](d) }
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R { try bytes.withUnsafeBytes(body) }
    func makeIterator() -> Array<UInt8>.Iterator { bytes.makeIterator() }
    var description: String { hex(Data(bytes)) }
    func hash(into hasher: inout Hasher) { hasher.combine(bytes) }
}

/// App Attest whose attestations and assertions name the client data
/// hash they're over, and the key, so the fake server can check them.
private final class FakeAppAttest: AppAttestService, @unchecked Sendable {
    let isSupported: Bool
    let calls = Locked<[String]>(initialState: [])
    let loseKey = Locked(initialState: false)
    /// The keys `attestKey` was asked to attest, in order.
    let attested = Locked<[String]>(initialState: [])
    /// Errors the next `attestKey` calls throw, first first.
    let attestFailures = Locked<[Error]>(initialState: [])
    /// Refuses to attest a key it has attested before, as lost.
    let refuseReattest = Locked(initialState: false)
    /// Keys gone for good: every assertion by one is refused as lost,
    /// after `onLost` returns, given how many have been.
    let lostKeys = Locked<Set<String>>(initialState: [])
    let onLost = Locked<@Sendable (Int) async -> Void>(initialState: { _ in })
    private let lostCount = Locked(initialState: 0)
    private let keys = Locked(initialState: 0)

    init(supported: Bool) { isSupported = supported }

    func generateKey() async throws -> String {
        calls.withLock { $0.append("generateKey") }
        return "attest-key-\(keys.withLock { $0 += 1; return $0 })"
    }

    func attestKey(_ keyID: String, clientDataHash: Data) async throws -> Data {
        calls.withLock { $0.append("attestKey") }
        let before = attested.withLock { a in
            defer { a.append(keyID) }
            return a.contains(keyID)
        }
        if let failure = attestFailures.withLock({ $0.isEmpty ? nil : $0.removeFirst() }) { throw failure }
        if before && refuseReattest.withLock({ $0 }) { throw AppAttestKeyLostError() }
        return Data("attestation:\(keyID):\(hex(clientDataHash))".utf8)
    }

    func generateAssertion(_ keyID: String, clientDataHash: Data) async throws -> Data {
        calls.withLock { $0.append("generateAssertion") }
        if loseKey.withLock({ let l = $0; $0 = false; return l }) { throw AppAttestKeyLostError() }
        if lostKeys.withLock({ $0.contains(keyID) }) {
            let n = lostCount.withLock { $0 += 1; return $0 }
            await onLost.withLock { $0 }(n)
            throw AppAttestKeyLostError()
        }
        return Data("assertion:\(keyID):\(hex(clientDataHash))".utf8)
    }
}

/// An in-memory registry counting its reads.
private final class CountingRegistry: InstanceRegistry, @unchecked Sendable {
    private let kept = InMemoryInstanceRegistry()
    let reads = Locked(initialState: 0)

    func instance() throws -> RegisteredInstance? {
        reads.withLock { $0 += 1 }
        return try kept.instance()
    }

    func put(_ instance: RegisteredInstance) throws { try kept.put(instance) }
    func remove(_ instance: RegisteredInstance) throws { try kept.remove(instance) }
}

/// Waits until `condition` holds, failing the test after five seconds.
private func until(_ what: String, _ condition: @Sendable () -> Bool) async {
    let deadline = Date().addingTimeInterval(5)
    while !condition() {
        if Date() > deadline {
            XCTFail("timed out waiting until \(what)")
            return
        }
        try? await Task.sleep(nanoseconds: 1_000_000)
    }
}

/// What the fake server saw and how it answers.
private struct ServerState: Sendable {
    var requests = 0
    var registrations = 0
    var refuseRegistrations = 0
    var registrationError: (Int, String)?
    var challengeStatus = 200
    var revoked = false
    var attestStranger = false
    /// The Key Attestation's nonce claim: nil, the nonce sent, omitted
    /// when empty, as the Go provider does; .some(nil), none.
    var nonceClaim: String?? = nil
    /// How long a registration takes, in nanoseconds.
    var registrationDelay: UInt64 = 0
    var challenges: [String: String] = [:]
    var instances: [String: (key: Data, attestKey: String)] = [:]
    var recorded: Set<Data> = []
    var walletAttestations: [(path: String, hadEvidence: Bool)] = []
    var keyAttestationEvidence: [Int] = []
}

/// The Wallet Provider protocol, enough of it to drive the client, and
/// checking what the client sends: challenges by purpose, evidence over
/// the expected client data, signed requests by the registration key.
private final class FakeServer: WalletProviderTransport, @unchecked Sendable {
    let state = Locked(initialState: ServerState())
    let keys: MemoryKeys
    /// The base URL's path, percent-encoded.
    let prefix: String

    init(keys: MemoryKeys, prefix: String) {
        self.keys = keys
        self.prefix = prefix
    }

    func post(url: URL, headers: [String: String], body: Data) async throws -> WalletProviderAnswer {
        state.withLock { $0.requests += 1 }
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        let path = try XCTUnwrap(URLComponents(url: url, resolvingAgainstBaseURL: false)).percentEncodedPath
        XCTAssertTrue(path.hasPrefix(prefix), path)
        switch path.dropFirst(prefix.count) {
        case "/v1/challenge":
            let status = state.withLock { $0.challengeStatus }
            if status != 200 { return answer(status, ["error": "server_error"]) }
            let purpose = try XCTUnwrap(object["purpose"] as? String)
            let value = encodeBase64URL(Data((0..<32).map { _ in UInt8.random(in: 0...255) }))
            state.withLock { $0.challenges[value] = purpose }
            return answer(200, ["challenge": value, "purpose": purpose, "expires_at": 1_767_225_900])
        case "/v1/instances":
            let delay = state.withLock { $0.registrationDelay }
            if delay > 0 { try await Task.sleep(nanoseconds: delay) }
            return try register(object)
        case "/v1/wallet-attestation":
            return try walletAttestation(path, headers, body, object)
        case "/v1/key-attestation":
            return try keyAttestation(path, headers, body, object)
        default:
            return answer(404, [:])
        }
    }

    private func register(_ o: [String: Any]) throws -> WalletProviderAnswer {
        if let (status, code) = state.withLock({ $0.registrationError }) { return answer(status, ["error": code]) }
        let challenge = try use(o["challenge"], "registration")
        let key = try jwkPoint(try XCTUnwrap(o["registration_key"] as? [String: Any]))
        let (kind, keyID, hash) = try evidence(o["evidence"], "attestation")
        XCTAssertEqual(kind, "apple-app-attest")
        XCTAssertEqual(hash, AppAttestClientData.hash(purpose: "registration", challenge: challenge, keys: [key]))
        if state.withLock({ s in s.refuseRegistrations > 0 ? { s.refuseRegistrations -= 1; return true }() : false }) {
            return answer(409, ["error": "instance_key_registered"])
        }
        let id = state.withLock { s in
            s.registrations += 1
            let id = "instance-\(s.registrations)"
            s.instances[id] = (key, keyID)
            return id
        }
        return answer(201, ["instance_id": id])
    }

    private func walletAttestation(_ path: String, _ headers: [String: String], _ body: Data, _ o: [String: Any]) throws -> WalletProviderAnswer {
        let instance = try verifySigned(path, headers, body)
        if state.withLock({ $0.revoked }) { return answer(403, ["error": "instance_revoked"]) }
        let key = try jwkPoint(try XCTUnwrap(o["instance_key"] as? [String: Any]))
        let hadEvidence = o["evidence"] != nil
        state.withLock { $0.walletAttestations.append((path, hadEvidence)) }
        if hadEvidence {
            let challenge = try use(o["challenge"], "instance")
            let (_, keyID, hash) = try evidence(o["evidence"], "assertion")
            XCTAssertEqual(keyID, instance.attestKey)
            XCTAssertEqual(hash, AppAttestClientData.hash(purpose: "instance", challenge: challenge, keys: [key]))
            state.withLock { _ = $0.recorded.insert(key) }
        } else if !state.withLock({ $0.recorded.contains(key) }) {
            return answer(400, ["error": "evidence_required"])
        }
        let client = try XCTUnwrap(o["client_id"] as? String)
        return answer(200, ["wallet_attestation": jwt(["sub": client, "cnf": ["jwk": jwk(point: key)]])])
    }

    private func keyAttestation(_ path: String, _ headers: [String: String], _ body: Data, _ o: [String: Any]) throws -> WalletProviderAnswer {
        let instance = try verifySigned(path, headers, body)
        let challenge = try use(o["challenge"], "holder")
        let keys = try XCTUnwrap(o["keys"] as? [[String: Any]]).map { try jwkPoint($0) }
        let evidence = try XCTUnwrap(o["evidence"] as? [Any])
        state.withLock { $0.keyAttestationEvidence.append(evidence.count) }
        let (_, keyID, hash) = try self.evidence(evidence.first, "assertion")
        XCTAssertEqual(keyID, instance.attestKey)
        XCTAssertEqual(hash, AppAttestClientData.hash(purpose: "holder", challenge: challenge, keys: keys))
        var attested = keys.map { jwk(point: $0) }
        if state.withLock({ $0.attestStranger }) { attested.append(jwk(point: P256.Signing.PrivateKey().publicKey.x963Representation)) }
        var claims: [String: Any] = ["attested_keys": attested]
        let sent = try XCTUnwrap(o["nonce"] as? String)
        switch state.withLock({ $0.nonceClaim }) {
        case .none: if !sent.isEmpty { claims["nonce"] = sent }
        case .some(let claim): if let claim { claims["nonce"] = claim }
        }
        return answer(200, ["key_attestation": jwt(claims)])
    }

    /// Checks the signed request: by the instance's registration key,
    /// over this path, body and a `request` challenge.
    private func verifySigned(_ path: String, _ headers: [String: String], _ body: Data) throws -> (key: Data, attestKey: String) {
        let token = try XCTUnwrap(headers["Wallet-Provider-Request"])
        let parts = token.split(separator: ".").map(String.init)
        XCTAssertEqual(parts.count, 3)
        XCTAssertEqual(decodeBase64URL(parts[0]).map { String(decoding: $0, as: UTF8.self) }, #"{"alg":"ES256","typ":"wallet-provider-request+jwt"}"#)
        let claims = try XCTUnwrap(unverifiedClaims(token))
        let id = try XCTUnwrap(claims["sub"] as? String)
        let instance = try XCTUnwrap(state.withLock { $0.instances[id] })
        let pub = try P256.Signing.PublicKey(x963Representation: instance.key)
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: try XCTUnwrap(decodeBase64URL(parts[2])))
        XCTAssertTrue(pub.isValidSignature(signature, for: Data((parts[0] + "." + parts[1]).utf8)), "the request's signature")
        XCTAssertEqual(claims["method"] as? String, "POST")
        XCTAssertEqual(claims["path"] as? String, path)
        XCTAssertEqual(claims["body_sha256"] as? String, encodeBase64URL(Data(SHA256.hash(data: body))))
        XCTAssertEqual(claims["iat"] as? Int, 1_767_225_600)
        _ = try use(claims["challenge"], "request")
        return instance
    }

    /// Uses up a challenge issued for `purpose`.
    private func use(_ value: Any?, _ purpose: String) throws -> String {
        let v = try XCTUnwrap(value as? String)
        XCTAssertEqual(state.withLock { $0.challenges.removeValue(forKey: v) }, purpose, "a challenge for \(purpose)")
        return v
    }

    /// The fake evidence's kind, key ID and client data hash.
    private func evidence(_ value: Any?, _ type: String) throws -> (String, String, Data) {
        let o = try XCTUnwrap(value as? [String: Any])
        let data = try XCTUnwrap((o["data"] as? String).flatMap(decodeBase64URL))
        let fields = String(decoding: data, as: UTF8.self).split(separator: ":").map(String.init)
        XCTAssertEqual(fields.count, 3)
        XCTAssertEqual(fields.first, type)
        let hash = Data(stride(from: 0, to: fields[2].count, by: 2).map {
            let i = fields[2].index(fields[2].startIndex, offsetBy: $0)
            return UInt8(fields[2][i...fields[2].index(after: i)], radix: 16)!
        })
        return (try XCTUnwrap(o["kind"] as? String), fields[1], hash)
    }

    private func jwt(_ claims: [String: Any]) -> String {
        encodeBase64URL(Data(#"{"alg":"ES256"}"#.utf8)) + "." + encodeBase64URL(try! JSONSerialization.data(withJSONObject: claims)) + ".c2ln"
    }

    private func answer(_ status: Int, _ object: [String: Any]) -> WalletProviderAnswer {
        WalletProviderAnswer(status: status, contentType: "application/json; charset=utf-8",
                             body: try! JSONSerialization.data(withJSONObject: object))
    }
}

/// A URLProtocol answering every request with `answer`.
private final class StubProtocol: URLProtocol, @unchecked Sendable {
    static let answer = Locked<(Int, [String: String], Data)>(initialState: (200, [:], Data()))

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let (status, headers, body) = Self.answer.withLock { $0 }
        let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)!
        if status / 100 == 3, let location = headers["Location"], let target = URL(string: location) {
            client?.urlProtocol(self, wasRedirectedTo: URLRequest(url: target), redirectResponse: response)
        }
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}
