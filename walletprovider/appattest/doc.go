// Package appattest verifies Apple App Attest for a Wallet Provider:
// the attestation object DCAppAttestService.attestKey returns for a
// new App Attest key, and the assertions generateAssertion makes with
// it afterwards, following Apple's "Validating apps that connect to
// your server".
//
// App Attest attests the app, not the wallet's keys. Its key lives in
// the Secure Enclave and only signs assertions: it can't sign a JWT,
// and nothing attests the other keys the app makes. What an
// attestation proves is that a genuine copy of one of Verifier.Apps,
// on a genuine Apple device, made the App Attest key over the client
// data the provider expects; each assertion, that the same copy of
// the app signed later client data. The wallet's registration,
// instance and holder keys are bound in through that client data
// (ClientData): the provider learns that the genuine app asked for
// them, not where they are. EvidenceVerifier reports them with
// walletprovider.KeyBindingAppAssertion, so a Key Attestation claims
// key_storage for them only where the provider's Policy says so.
//
// Verifier.VerifyAttestation checks, and refuses with an error
// wrapping one of this package's Err values when one fails:
//
//   - the format and shape, at most MaxAttestationBytes, no duplicate
//     CBOR map key;
//   - the certificates: the credential certificate chains to one of
//     Verifier.Roots (the Apple App Attestation Root CA by default,
//     AppleRoots), each valid at Verifier.Now;
//   - the nonce in the credential certificate (NonceExtensionOID):
//     SHA-256 of the authenticator data and the client data hash;
//   - the key ID: SHA-256 of the attested key is the credential ID;
//   - the App ID, whose SHA-256 is the RP ID hash: one of
//     Verifier.Apps;
//   - the counter, zero, and the environment: production, or
//     development with Verifier.AllowDevelopment.
//
// The receipt isn't checked: it's what the app's server exchanges with
// Apple for a fraud metric, a separate service.
//
// Verifier.VerifyAssertion checks an assertion's signature, by the
// attested key, over SHA-256 of its authenticator data and the client
// data hash; its App ID; and that its counter exceeds the last one
// accepted. Storing that counter so a replayed assertion is refused is
// the caller's part: EvidenceVerifier hands it to the provider, which
// stores it with a compare-and-swap.
//
// mobile/WALLET_PROVIDER.md in the repository is the protocol an app
// follows: what each request's evidence is, and the client data's
// exact bytes, with test vectors.
package appattest
