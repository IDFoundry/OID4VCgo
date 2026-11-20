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
    // Without instance_key_proof, which this app can't make (it's given
    // no instance key signer), the demo provider issues the Key
    // Attestation under its shared holder instance.
    func keyAttestation(instanceKey: Data, keys: [Data], nonce: String) async throws -> String {
        try await post("key-attestation", [
            "instance_key": try JSONSerialization.jsonObject(with: instanceKey),
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

/// Answers a redirect as the 3xx it is, which `post` refuses.
private final class NoRedirects: NSObject, URLSessionTaskDelegate, Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest) async -> URLRequest? {
        nil
    }
}
