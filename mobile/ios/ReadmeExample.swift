import Foundation
import OID4VCWallet

// Your Wallet Provider, built on OID4VCgo's walletprovider, which attests
// the wallet and its keys after checking App Attest evidence. A backend
// of your own needs a WalletProvider of your own: the Getting started
// article lists the checks it makes.
func makeWallet(issuerRoots: String, verifierRoots: String, crls: String) throws -> (Wallet, KeychainKeyStore, HttpWalletProvider) {
    let keys = KeychainKeyStore()                  // Secure Enclave keys
    let provider = try HttpWalletProvider(baseURL: URL(string: "https://provider.example.com/wp")!,
                                          instances: FileInstanceRegistry.standard())
    let wallet = try Wallet(
        configuration: WalletConfiguration(
            clientID: "my-wallet",
            redirectURI: "com.example.wallet:/callback",  // a URL scheme in your Info.plist
            issuerRoots: issuerRoots,                      // PEM: the issuers you trust
            verifierRoots: verifierRoots,                  // PEM: the Verifiers you answer
            crls: crls,
            revocation: [.issuer, .status, .verifier]),
        keyStore: keys,
        credentialStore: try FileCredentialStore.standard(),
        provider: provider)
    return (wallet, keys, provider)
}

// signIn opens the issuer's page in an ASWebAuthenticationSession and
// returns the URL it redirects back to.
func example(wallet: Wallet, offerLink: String, requestLink: String, pin: String,
             signIn: (URL) async throws -> URL) async throws {
    // Receive: an openid-credential-offer:// link.
    let issuance = try await wallet.startIssuance(offer: offerLink)
    if issuance.offer.grant == .preAuthorizedCode {
        try await issuance.redeemPreAuthorizedCode(pin: issuance.offer.txCode == nil ? "" : pin)
    } else {
        let url = try await issuance.beginAuthorization()
        let redirect = try await signIn(url)
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

// At launch, before any issuance: delete keys an interrupted issuance or
// registration left behind.
func atLaunch(wallet: Wallet, keys: KeychainKeyStore, provider: HttpWalletProvider) async throws {
    try await wallet.sweepOrphanedKeys(in: keys)
    try await provider.sweepOrphanedRegistrationKeys()
}

func handle(_ error: Error) -> String {
    guard let e = error as? WalletError else { return error.localizedDescription }
    return e.isRetryable ? e.localizedDescription + " Try again." : e.localizedDescription
}
