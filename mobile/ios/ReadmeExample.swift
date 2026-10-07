import Foundation
import OID4VCWallet

// Your Wallet Provider's backend, which attests the wallet and its keys
// after checking App Attest evidence.
struct MyWalletProvider: WalletProvider {
    func walletAttestation(clientID: String, instanceKey: Data) async throws -> String {
        fatalError("call your Wallet Provider")
    }
    func keyAttestation(keys: [Data], nonce: String) async throws -> String {
        fatalError("call your Wallet Provider")
    }
}

func example(offerLink: String, requestLink: String, pin: String) async throws {
    let keys = KeychainKeyStore()                  // Secure Enclave keys
    let wallet = try Wallet(
        configuration: WalletConfiguration(clientID: "my-wallet", redirectURI: "com.example.wallet:/callback"),
        keyStore: keys,
        credentialStore: try FileCredentialStore.standard(),
        provider: MyWalletProvider())
    _ = try await wallet.sweepOrphanedKeys(in: keys)   // at launch

    // Receive: an openid-credential-offer:// link.
    let issuance = try await wallet.startIssuance(offer: offerLink)
    if issuance.offer.grant == .preAuthorizedCode {
        try await issuance.redeemPreAuthorizedCode(pin: pin)
    } else {
        let url = try await issuance.beginAuthorization()
        // Open url in an ASWebAuthenticationSession, then:
        let redirect: URL = url
        try await issuance.completeAuthorization(redirect: redirect)
    }
    let received = try await issuance.requestCredentials()
    try await issuance.close()
    _ = received

    // Present: an openid4vp:// link. presentation.queries lists what each
    // of the Verifier's queries can be answered with, for the holder to
    // choose; defaultSelection() is the first choice for each.
    let presentation = try await wallet.startPresentation(request: requestLink)
    let selection = try await presentation.defaultSelection()
    let disclosed = try await presentation.preview(selection: selection)   // show the holder
    _ = disclosed
    _ = try await presentation.respond(selection: selection)              // Face ID here
}

func handle(_ error: Error) -> String {
    guard let e = error as? WalletError else { return error.localizedDescription }
    return e.isRetryable ? e.localizedDescription + " Try again." : e.localizedDescription
}
