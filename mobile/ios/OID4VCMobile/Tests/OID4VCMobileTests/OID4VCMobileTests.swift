import CryptoKit
import Foundation
import Network
import XCTest
@testable import OID4VCMobile

final class OID4VCMobileTests: XCTestCase {
    func testABIVersion() {
        XCTAssertEqual(OID4VC.abiVersion, 0)
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

    /// Go builds the proof and asks the Swift key to sign it; the
    /// signature is checked here with CryptoKit too.
    func testDPoPProofSignedBySwiftKey() async throws {
        let signer = try SecKeySigner.software()
        let proof = try await OID4VC.dpopProof(signer: signer, method: "POST", url: "https://issuer.example/token")
        let parts = proof.split(separator: ".").map(String.init)
        XCTAssertEqual(parts.count, 3)
        let pub = try P256.Signing.PublicKey(x963Representation: signer.publicKey())
        let sig = try P256.Signing.ECDSASignature(rawRepresentation: base64url(parts[2]))
        XCTAssertTrue(pub.isValidSignature(sig, for: Data((parts[0] + "." + parts[1]).utf8)))
        let header = try JSONSerialization.jsonObject(with: base64url(parts[0])) as? [String: Any]
        XCTAssertEqual(header?["typ"] as? String, "dpop+jwt")
    }

    /// A Swift error thrown in a callback reaches Go, which reports it as
    /// a platform error carrying the Swift error's message.
    func testSwiftCallbackErrorsReachGo() async throws {
        final class Refusing: NSObject, PlatformSigner {
            let inner: SecKeySigner
            init(_ inner: SecKeySigner) { self.inner = inner }
            func publicKey() throws -> Data { try inner.publicKey() }
            func sign(_ digest: Data?) throws -> Data {
                throw NSError(domain: "test", code: 7, userInfo: [NSLocalizedDescriptionKey: "the user cancelled Face ID"])
            }
        }
        do {
            _ = try await OID4VC.dpopProof(signer: Refusing(try SecKeySigner.software()), method: "POST", url: "https://issuer.example/token")
            XCTFail("a refusing signer produced a proof")
        } catch let error as WalletError {
            XCTAssertEqual(error.code, .platform)
            XCTAssertTrue(error.message.contains("the user cancelled Face ID"), error.message)
        }
    }

    /// Cancelling the Swift Task cancels the Go call blocked on the network.
    func testCancellation() async throws {
        let server = try SilentServer()
        defer { server.stop() }
        let task = Task { try await OID4VC.fetch("http://127.0.0.1:\(server.port)/") }
        try await Task.sleep(for: .milliseconds(200))
        task.cancel()
        do {
            _ = try await task.value
            XCTFail("a cancelled fetch returned")
        } catch let error as WalletError {
            XCTAssertEqual(error.code, .cancelled)
        }
    }

    func testTimeout() async throws {
        let server = try SilentServer()
        defer { server.stop() }
        do {
            _ = try await OID4VC.fetch("http://127.0.0.1:\(server.port)/", timeout: .milliseconds(100))
            XCTFail("a timed-out fetch returned")
        } catch let error as WalletError {
            XCTAssertEqual(error.code, .cancelled)
        }
    }

    /// Many Swift tasks calling Go, and back into Swift, at once.
    func testConcurrentCalls() async throws {
        let signer = try SecKeySigner.software()
        try await withThrowingTaskGroup(of: String.self) { group in
            for i in 0..<64 {
                group.addTask { try await OID4VC.dpopProof(signer: signer, method: "GET", url: "https://issuer.example/\(i)") }
            }
            var proofs = Set<String>()
            for try await proof in group { proofs.insert(proof) }
            XCTAssertEqual(proofs.count, 64)
        }
    }

    func testWalletErrorParsing() {
        XCTAssertEqual(WalletError(NSError(domain: "go", code: 1, userInfo: [NSLocalizedDescriptionKey: "[network] status 404"])).code, .network)
        let plain = WalletError(NSError(domain: "go", code: 1, userInfo: [NSLocalizedDescriptionKey: "no code"]))
        XCTAssertEqual(plain.code, .internal)
        XCTAssertEqual(plain.message, "no code")
    }
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
