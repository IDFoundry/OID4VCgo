import Foundation
import OID4VCMobile

/// The Wallet Provider's backend, over the passport-vdc demo Wallet
/// Provider's HTTP API: POST /wallet-attestation and /key-attestation,
/// answered with {"attestation"}. Go calls it on its own thread and waits,
/// so it waits for each request too.
final class HTTPWalletProvider: NSObject, PlatformWalletProvider {
    let baseURL: URL

    init(baseURL: URL) { self.baseURL = baseURL }

    func walletAttestation(_ clientID: String?, instanceKeyJWK: Data?) throws -> Data {
        let jwk = try JSONSerialization.jsonObject(with: instanceKeyJWK ?? Data())
        return try post("wallet-attestation", ["client_id": clientID ?? "", "instance_key": jwk])
    }

    func keyAttestation(_ keysJWK: Data?, nonce: String?) throws -> Data {
        let keys = try JSONSerialization.jsonObject(with: keysJWK ?? Data())
        return try post("key-attestation", ["keys": keys, "nonce": nonce ?? ""])
    }

    private func post(_ path: String, _ body: [String: Any]) throws -> Data {
        var request = URLRequest(url: baseURL.appending(path: path), timeoutInterval: 15)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        let done = DispatchSemaphore(value: 0)
        nonisolated(unsafe) var result: Result<Data, Error> = .failure(ProviderError("no answer"))
        URLSession.shared.dataTask(with: request) { data, response, error in
            defer { done.signal() }
            if let error { result = .failure(error); return }
            guard let http = response as? HTTPURLResponse, http.statusCode == 200, let data,
                  let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let attestation = object["attestation"] as? String else {
                result = .failure(ProviderError("the Wallet Provider refused \(path)"))
                return
            }
            result = .success(Data(attestation.utf8))
        }.resume()
        done.wait()
        return try result.get()
    }
}

struct ProviderError: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}
