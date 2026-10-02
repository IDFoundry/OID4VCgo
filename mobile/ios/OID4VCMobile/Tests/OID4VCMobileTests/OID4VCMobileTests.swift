import CryptoKit
import Foundation
import Network
import XCTest
@testable import OID4VCMobile

final class OID4VCMobileTests: XCTestCase {
    func testABIVersion() {
        XCTAssertEqual(OID4VC.abiVersion, 1)
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
        } catch {
            XCTFail("unexpected error \(error)")
        }
    }

    /// A Swift error thrown in a callback reaches Go, which reports it as
    /// a platform error carrying the Swift error's message.
    func testSwiftCallbackErrorsReachGo() async throws {
        let refusing = Misbehaving(signError: "the user cancelled Face ID")
        do {
            _ = try await OID4VC.checkKeyStore(refusing)
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
        XCTAssertEqual(checked, [KeyPurpose.instance, KeyPurpose.dpop, KeyPurpose.holder])
    }

    /// Keys kept in the Keychain: found again by a new store, and gone
    /// once deleted. (Hostless iOS Simulator tests have no Keychain.)
    func testCheckKeyStoreKeychain() async throws {
        #if targetEnvironment(simulator)
        throw XCTSkip("the iOS Simulator's Keychain needs a signed host app")
        #else
        let options = KeychainKeyStore.Options(secureEnclave: false, persistent: true, holderUserPresence: false, tagPrefix: "org.idfoundry.oid4vcgo.test.\(UUID()).")
        let checked = try await OID4VC.checkKeyStore(KeychainKeyStore(options: options))
        XCTAssertEqual(checked.count, 3)

        var error: NSError?
        let id = KeychainKeyStore(options: options).createKey(KeyPurpose.holder, error: &error)
        XCTAssertNil(error)
        let again = KeychainKeyStore(options: options)
        XCTAssertFalse(try again.publicKey(id).isEmpty)
        XCTAssertFalse(try again.sign(id, digest: Data(repeating: 1, count: 32)).isEmpty)
        try again.deleteKey(id)
        XCTAssertTrue(try again.publicKey(id).isEmpty)
        #endif
    }

    /// Keys in the Secure Enclave — simulated by the iOS Simulator; a
    /// real device needs the demo app (MOBILE.md Phase 4).
    func testCheckKeyStoreSecureEnclave() async throws {
        #if targetEnvironment(simulator)
        let store = KeychainKeyStore(options: .init(secureEnclave: true, persistent: false, holderUserPresence: false))
        let checked = try await OID4VC.checkKeyStore(store)
        XCTAssertEqual(checked.count, 3)
        #else
        throw XCTSkip("Secure Enclave keys need the iOS Simulator or a signed app")
        #endif
    }

    func testWalletErrorParsing() {
        XCTAssertEqual(WalletError(NSError(domain: "go", code: 1, userInfo: [NSLocalizedDescriptionKey: "[network] status 404"])).code, .network)
        let plain = WalletError(NSError(domain: "go", code: 1, userInfo: [NSLocalizedDescriptionKey: "no code"]))
        XCTAssertEqual(plain.code, .internal)
        XCTAssertEqual(plain.message, "no code")
    }
}

/// A key store that fails as it's told to.
final class Misbehaving: NSObject, PlatformKeyStore {
    let inner = KeychainKeyStore(options: .init(secureEnclave: false, persistent: false))
    let createError: String?
    let signError: String?

    init(createError: String? = nil, signError: String? = nil) {
        self.createError = createError
        self.signError = signError
    }

    func createKey(_ purpose: String?, error: NSErrorPointer) -> String {
        if let createError {
            error?.pointee = NSError(domain: "test", code: 1, userInfo: [NSLocalizedDescriptionKey: createError])
            return ""
        }
        return inner.createKey(purpose, error: error)
    }

    func publicKey(_ id: String?) throws -> Data { try inner.publicKey(id) }

    func sign(_ id: String?, digest: Data?) throws -> Data {
        if let signError {
            throw NSError(domain: "test", code: 7, userInfo: [NSLocalizedDescriptionKey: signError])
        }
        return try inner.sign(id, digest: digest)
    }

    func deleteKey(_ id: String?) throws { try inner.deleteKey(id) }
}

func base64url(_ s: String) throws -> Data {
    var b = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    b += String(repeating: "=", count: (4 - b.count % 4) % 4)
    guard let d = Data(base64Encoded: b) else { throw WalletError(NSError(domain: "test", code: 0)) }
    return d
}

/// A TCP server on loopback that accepts connections and never answers.
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
