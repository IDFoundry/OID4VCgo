import Foundation
import OID4VCWallet

/// The Wallet Provider's backend, over the passport-vdc demo Wallet
/// Provider's own HTTP API: POST /wallet-attestation and
/// /key-attestation, answered with {"attestation"}, with no evidence: it
/// attests any caller, as the Simulator needs. On a device,
/// `provider_protocol` `v1` uses the library's `HttpWalletProvider`
/// instead, which proves the app genuine with App Attest.
struct HTTPWalletProvider: WalletProvider {
    let baseURL: URL

    func walletAttestation(clientID: String, instanceKey: Data) async throws -> String {
        try await post("wallet-attestation", ["client_id": clientID, "instance_key": try JSONSerialization.jsonObject(with: instanceKey)])
    }

    // instanceKey is the issuance's, whose status the Key Attestation
    // carries: walletAttestation sent it first.
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
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let attestation = object["attestation"] as? String else {
            throw StoreError("the Wallet Provider refused \(path)")
        }
        return attestation
    }
}
