import CryptoKit
import Foundation
import OID4VCWallet

/// The Wallet Provider's backend, over the passport-vdc demo Wallet
/// Provider's own HTTP API: POST /wallet-attestation and
/// /key-attestation, answered with {"attestation"}, with no evidence: it
/// attests any caller, as the Simulator needs. On a device,
/// `provider_protocol` `v1` uses the library's `HttpWalletProvider`
/// instead, which proves the app genuine with App Attest. Like it, this
/// client follows no redirects, caches nothing and reads a bounded
/// answer.
struct HTTPWalletProvider: WalletProvider {
    let baseURL: URL
    /// The wallet's key store, which holds each issuance's instance key:
    /// a Key Attestation request proves it with the key's signature.
    let keyStore: KeychainKeyStore

    /// The largest answer read: an attestation is a few KiB.
    static let maxAnswerBytes = 256 * 1024

    /// An ephemeral session (no cache, no cookies) that refuses
    /// redirects, so a 3xx can't send the request on elsewhere.
    private static let session: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.urlCache = nil
        config.httpCookieStorage = nil
        config.httpShouldSetCookies = false
        config.timeoutIntervalForRequest = 15
        config.timeoutIntervalForResource = 15
        return URLSession(configuration: config, delegate: NoRedirects(), delegateQueue: nil)
    }()

    func walletAttestation(clientID: String, instanceKey: Data) async throws -> String {
        try await post("wallet-attestation", ["client_id": clientID, "instance_key": try JSONSerialization.jsonObject(with: instanceKey)])
    }

    // instanceKey is the issuance's: walletAttestation sent it first.
    // With instance_key_proof, the demo provider issues the Key
    // Attestation under its instance, so suspending or revoking the
    // instance withdraws it too.
    func keyAttestation(instanceKey: Data, keys: [Data], nonce: String) async throws -> String {
        try await post("key-attestation", [
            "instance_key": try JSONSerialization.jsonObject(with: instanceKey),
            "instance_key_proof": try InstanceKeyProof.sign(nonce: nonce, keys: keys, instanceKey: instanceKey, in: keyStore),
            "keys": try keys.map { try JSONSerialization.jsonObject(with: $0) },
            "nonce": nonce,
        ])
    }

    private func post(_ path: String, _ body: [String: Any]) async throws -> String {
        var request = URLRequest(url: baseURL.appending(path: path), timeoutInterval: 15)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (bytes, response) = try await Self.session.bytes(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw StoreError("the Wallet Provider refused \(path)")
        }
        var data = Data()
        for try await byte in bytes {
            data.append(byte)
            if data.count > Self.maxAnswerBytes {
                throw StoreError("the Wallet Provider's answer is larger than \(Self.maxAnswerBytes) bytes")
            }
        }
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let attestation = object["attestation"] as? String else {
            throw StoreError("the Wallet Provider refused \(path)")
        }
        return attestation
    }
}

/// The passport-vdc demo provider's `instance_key_proof`: the issuance's
/// instance key's ECDSA P-256 signature, DER, base64url without padding,
/// over "passport-vdc instance key proof", the nonce, then each attested
/// key's RFC 7638 thumbprint, each on a line of its own (its
/// walletprovider's `instanceKeyProofDigest`).
enum InstanceKeyProof {
    /// The proof over `keys` and `nonce` by the key in `store` whose
    /// public key is `instanceKey`. Go made that key in the store, and
    /// it signs without asking the holder, as it does at PAR and the
    /// token endpoint. A key the store doesn't hold, or can't sign with,
    /// fails the Key Attestation: sent without the proof, it would come
    /// back under the provider's shared instance instead, with nothing
    /// to show it.
    static func sign(nonce: String, keys: [Data], instanceKey: Data, in store: KeychainKeyStore) throws -> String {
        let point = try uncompressedPoint(instanceKey)
        // The store finds keys by ID only: compare each one's public key.
        guard let id = try store.keyIDs().first(where: { try store.publicKey(id: $0) == point }) else {
            throw StoreError("the wallet's key store doesn't hold the issuance's instance key")
        }
        let digest = Data(SHA256.hash(data: try message(nonce: nonce, keys: keys)))
        return base64URL(try store.sign(id: id, digest: digest))
    }

    /// What the proof signs.
    static func message(nonce: String, keys: [Data]) throws -> Data {
        let lines = try ["passport-vdc instance key proof", nonce] + keys.map(thumbprint)
        return Data(lines.joined(separator: "\n").utf8)
    }

    /// A P-256 public JWK's RFC 7638 thumbprint, over its required
    /// members as the provider writes them from its point.
    static func thumbprint(_ jwk: Data) throws -> String {
        let point = try uncompressedPoint(jwk)
        let x = base64URL(point[1...32])
        let y = base64URL(point[33...])
        return base64URL(Data(SHA256.hash(data: Data(#"{"crv":"P-256","kty":"EC","x":"\#(x)","y":"\#(y)"}"#.utf8))))
    }

    /// A P-256 public JWK's point, 0x04 || x || y.
    static func uncompressedPoint(_ jwk: Data) throws -> Data {
        let members = try? JSONSerialization.jsonObject(with: jwk) as? [String: Any]
        let coordinate = { (name: String) -> Data? in
            (members?[name] as? String).flatMap(base64URLDecoded).flatMap { $0.count == 32 ? $0 : nil }
        }
        guard members?["kty"] as? String == "EC", members?["crv"] as? String == "P-256",
              let x = coordinate("x"), let y = coordinate("y") else {
            throw StoreError("a key to attest isn't a P-256 JWK")
        }
        return Data([0x04]) + x + y
    }

    static func base64URL(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .trimmingCharacters(in: CharacterSet(charactersIn: "="))
    }

    static func base64URLDecoded(_ text: String) -> Data? {
        let standard = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        return Data(base64Encoded: standard.padding(toLength: (standard.count + 3) / 4 * 4, withPad: "=", startingAt: 0))
    }
}

/// Answers a redirect as the 3xx it is, which `post` refuses.
private final class NoRedirects: NSObject, URLSessionTaskDelegate, Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest) async -> URLRequest? {
        nil
    }
}
