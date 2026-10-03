import Foundation
import OID4VCMobile

/// The Wallet Provider's backend, over the passport-vdc demo Wallet
/// Provider's HTTP API: POST /wallet-attestation and /key-attestation,
/// answered with {"attestation"}. A production provider would first
/// prove the app genuine with App Attest.
struct HTTPWalletProvider: WalletProvider {
    let baseURL: URL

    func walletAttestation(clientID: String, instanceKey: Data) async throws -> String {
        try await post("wallet-attestation", ["client_id": clientID, "instance_key": try JSONSerialization.jsonObject(with: instanceKey)])
    }

    func keyAttestation(keys: [Data], nonce: String) async throws -> String {
        try await post("key-attestation", ["keys": try keys.map { try JSONSerialization.jsonObject(with: $0) }, "nonce": nonce])
    }

    private func post(_ path: String, _ body: [String: Any]) async throws -> String {
        var request = URLRequest(url: baseURL.appending(path: path), timeoutInterval: 15)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let attestation = object["attestation"] as? String else {
            throw StoreError("the Wallet Provider refused \(path)")
        }
        return attestation
    }
}
