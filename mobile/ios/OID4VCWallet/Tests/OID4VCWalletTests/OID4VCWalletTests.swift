import CryptoKit
import Foundation
import Network
import XCTest
@testable import OID4VCWallet

final class OID4VCWalletTests: XCTestCase {
    func testABIVersion() {
        XCTAssertEqual(OID4VC.abiVersion, 6)
        XCTAssertTrue(OID4VC.isTestBuild, "the tests run on the mobiletest build")
    }

    func testParseRequestLink() async throws {
        let link = try await OID4VC.parseRequestLink(
            "openid4vp://?client_id=x509_hash%3Aabc&request_uri=https%3A%2F%2Fverifier.example%2Fr%2F1")
        XCTAssertEqual(link, RequestLink(clientID: "x509_hash:abc", requestURI: "https://verifier.example/r/1", requestURIMethod: "get"))
    }

    func testGoErrorsBecomeWalletErrors() async {
        do {
            _ = try await OID4VC.parseRequestLink("openid4vp://?client_id=x")
            XCTFail("a link without request_uri was accepted")
        } catch let error as WalletError {
            XCTAssertEqual(error.code, .invalidInput)
            XCTAssertFalse(error.message.isEmpty)
            XCTAssertNotNil(error.errorDescription)
        } catch {
            XCTFail("unexpected error \(error)")
        }
    }

    func testWalletErrorParsing() {
        func parse(_ text: String) -> WalletError {
            WalletError(NSError(domain: "go", code: 1, userInfo: [NSLocalizedDescriptionKey: text]))
        }
        let pin = parse("[protocol:invalid_grant] walletflow: token: wrong tx_code")
        XCTAssertEqual(pin.code, .protocolError)
        XCTAssertEqual(pin.protocolError, "invalid_grant")
        XCTAssertTrue(pin.isRetryable)
        XCTAssertEqual(pin.localizedDescription, "That code or PIN wasn't accepted.")
        XCTAssertEqual(pin.description, "[protocol:invalid_grant] walletflow: token: wrong tx_code")

        let network = parse("[network] dial tcp: refused")
        XCTAssertEqual(network.code, .network)
        XCTAssertNil(network.protocolError)
        XCTAssertTrue(network.isRetryable)

        XCTAssertTrue(parse("[unavailable] the issuer refused the request (HTTP 503)").isRetryable)
        XCTAssertTrue(parse("[protocol:invalid_nonce] stale").isRetryable)
        XCTAssertFalse(parse("[protocol:invalid_client] no").isRetryable)
        XCTAssertFalse(parse("[delivery_unknown] maybe").isRetryable)
        XCTAssertFalse(parse("[credential_denied] no").isRetryable)
        let plain = parse("no code")
        XCTAssertEqual(plain.code, .internalError)
        XCTAssertEqual(plain.message, "no code")
    }

    /// A Swift error thrown in a callback reaches Go, which reports it as
    /// a platform error carrying the Swift error's message.
    func testSwiftCallbackErrorsReachGo() async throws {
        do {
            _ = try await OID4VC.checkKeyStore(Misbehaving(signError: "the user cancelled Face ID"))
            XCTFail("a refusing store passed")
        } catch let error as WalletError {
            XCTAssertEqual(error.code, .platform)
            XCTAssertTrue(error.message.contains("the user cancelled Face ID"), error.message)
        }
        do {
            _ = try await OID4VC.checkKeyStore(Misbehaving(createError: "no enclave"))
            XCTFail("a store that can't create keys passed")
        } catch let error as WalletError {
            XCTAssertEqual(error.code, .platform)
            XCTAssertTrue(error.message.contains("no enclave"), error.message)
        }
    }

    func testCheckKeyStoreSoftwareInMemory() async throws {
        let checked = try await OID4VC.checkKeyStore(KeychainKeyStore(options: .init(secureEnclave: false, persistent: false)))
        XCTAssertEqual(checked, KeyPurpose.allCases)
    }

    /// Keys kept in the Keychain: found again by a new store, listed, and
    /// swept. (Hostless iOS Simulator tests have no Keychain.)
    func testKeychainKeysAndSweep() async throws {
        #if targetEnvironment(simulator)
        throw XCTSkip("the iOS Simulator's Keychain needs a signed host app")
        #else
        let options = KeychainKeyStore.Options(secureEnclave: false, persistent: true, holderUserPresence: false,
                                               tagPrefix: "org.idfoundry.oid4vcgo.test.\(UUID()).")
        let checked = try await OID4VC.checkKeyStore(KeychainKeyStore(options: options))
        XCTAssertEqual(checked.count, 3)

        let store = KeychainKeyStore(options: options)
        let kept = try store.createKey(purpose: .holder)
        let orphan = try store.createKey(purpose: .dpop)
        let again = KeychainKeyStore(options: options)
        XCTAssertNotNil(try again.publicKey(id: kept))
        XCTAssertFalse(try again.sign(id: kept, digest: Data(repeating: 1, count: 32)).isEmpty)
        XCTAssertEqual(Set(try again.keyIDs()), [kept, orphan])
        XCTAssertEqual(try again.deleteKeys(except: [kept]), 1)
        XCTAssertNil(try again.publicKey(id: orphan))
        XCTAssertEqual(try again.keyIDs(), [kept])
        try again.deleteKey(id: kept)
        XCTAssertEqual(try again.keyIDs(), [])
        #endif
    }

    /// Keys in the Secure Enclave — simulated by the iOS Simulator; a
    /// real device needs the demo app.
    func testCheckKeyStoreSecureEnclave() async throws {
        #if targetEnvironment(simulator)
        let store = KeychainKeyStore(options: .init(secureEnclave: true, persistent: false, holderUserPresence: false))
        let checked = try await OID4VC.checkKeyStore(store)
        XCTAssertEqual(checked.count, 3)
        #else
        throw XCTSkip("Secure Enclave keys need the iOS Simulator or a signed app")
        #endif
    }

    func testMemoryKeySweep() throws {
        let store = KeychainKeyStore(options: .init(secureEnclave: false, persistent: false))
        let a = try store.createKey(purpose: .instance)
        let b = try store.createKey(purpose: .holder)
        XCTAssertEqual(try store.deleteKeys(except: [b]), 1)
        XCTAssertNil(try store.publicKey(id: a))
        XCTAssertNotNil(try store.publicKey(id: b))
    }

    /// The async provider bridge: Go blocks its thread while a Swift
    /// async provider answers.
    func testAsyncProviderBridge() throws {
        struct Slow: WalletProvider {
            func walletAttestation(clientID: String, instanceKey: Data) async throws -> String {
                try await Task.sleep(for: .milliseconds(50))
                return "wa-\(clientID)-\(instanceKey.count)"
            }
            func keyAttestation(keys: [Data], nonce: String) async throws -> String {
                if nonce == "fail" { throw StoreError("provider down") }
                return "ka-\(keys.count)-\(nonce)"
            }
        }
        let adapter = WalletProviderAdapter(Slow())
        XCTAssertEqual(String(decoding: try adapter.walletAttestation("c", instanceKeyJWK: Data("{\"kty\":\"EC\"}".utf8)), as: UTF8.self), "wa-c-12")
        XCTAssertEqual(String(decoding: try adapter.keyAttestation(Data("[{\"a\":1},{\"b\":2}]".utf8), nonce: "n"), as: UTF8.self), "ka-2-n")
        XCTAssertThrowsError(try adapter.keyAttestation(Data("[]".utf8), nonce: "fail"))
        XCTAssertThrowsError(try adapter.keyAttestation(Data("{}".utf8), nonce: "n"), "keys that aren't an array")

        // A provider's URLError reaches Go marked as a network failure.
        struct Offline: WalletProvider {
            func walletAttestation(clientID _: String, instanceKey _: Data) async throws -> String { throw URLError(.notConnectedToInternet) }
            func keyAttestation(keys _: [Data], nonce _: String) async throws -> String { "" }
        }
        XCTAssertThrowsError(try WalletProviderAdapter(Offline()).walletAttestation("c", instanceKeyJWK: Data("{}".utf8))) { error in
            XCTAssertTrue(error.localizedDescription.hasPrefix("[network] "), error.localizedDescription)
        }
    }
}

/// A key store that fails as it's told to.
final class Misbehaving: KeyStore, @unchecked Sendable {
    let inner = KeychainKeyStore(options: .init(secureEnclave: false, persistent: false))
    let createError: String?
    let signError: String?

    init(createError: String? = nil, signError: String? = nil) {
        self.createError = createError
        self.signError = signError
    }

    func createKey(purpose: KeyPurpose) throws -> String {
        if let createError { throw StoreError(createError) }
        return try inner.createKey(purpose: purpose)
    }

    func publicKey(id: String) throws -> Data? { try inner.publicKey(id: id) }

    func sign(id: String, digest: Data) throws -> Data {
        if let signError { throw StoreError(signError) }
        return try inner.sign(id: id, digest: digest)
    }

    func deleteKey(id: String) throws { try inner.deleteKey(id: id) }
}

func base64url(_ s: String) throws -> Data {
    var b = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    b += String(repeating: "=", count: (4 - b.count % 4) % 4)
    guard let d = Data(base64Encoded: b) else { throw WalletError(NSError(domain: "test", code: 0)) }
    return d
}

final class SilentServer: @unchecked Sendable {
    final class Connections: @unchecked Sendable {
        let lock = NSLock()
        var all: [NWConnection] = []
        func add(_ c: NWConnection) { lock.withLock { all.append(c) } }
    }

    let listener: NWListener
    let port: UInt16
    private let connections = Connections()

    init() throws {
        let params = NWParameters.tcp
        params.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        listener = try NWListener(using: params)
        let ready = DispatchSemaphore(value: 0)
        let connections = self.connections
        listener.stateUpdateHandler = { if case .ready = $0 { ready.signal() } }
        listener.newConnectionHandler = { c in
            c.start(queue: .global())
            connections.add(c)
        }
        listener.start(queue: .global())
        guard ready.wait(timeout: .now() + 5) == .success, let p = listener.port?.rawValue else {
            throw WalletError(NSError(domain: "test", code: 0, userInfo: [NSLocalizedDescriptionKey: "listener didn't start"]))
        }
        port = p
    }

    func stop() {
        connections.lock.withLock { connections.all.forEach { $0.cancel() } }
        listener.cancel()
    }
}
