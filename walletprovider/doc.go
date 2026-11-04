// Package walletprovider is the Wallet Provider role: the service that
// vouches for a wallet app's instances and keys. It checks platform
// evidence, registers wallet instances, and issues the two attestations
// HAIP 1.0 has a Credential Issuer rely on — the Wallet Attestation
// (§4.4.1, OID4VCI 1.0 Appendix E) that authenticates a wallet instance
// as an OAuth client, and the Key Attestation (§4.5.1, OID4VCI 1.0
// Appendix D) that vouches for the holder keys a credential is bound
// to — claiming in each only what the evidence proved. It withdraws
// that trust through a Token Status List (draft-ietf-oauth-status-list-14)
// every attestation it issues references, which issuers check with
// haip.WalletAttestationStatusList and issuer.StatusListAttestationStatus.
//
// Package attestation mints and parses the two JWTs; this package
// decides whether to mint them at all.
//
// # Evidence
//
// Nothing is attested without platform evidence: a registration or a
// Key Attestation request carrying none is refused, in development as
// in production, and there is no setting that changes that. Evidence is
// checked by an EvidenceVerifier for its Kind: an Android Key
// Attestation verifier, an Apple App Attest verifier, or one of the
// integrator's own (Play Integrity, a WSCD's attestation, a TPM). Tests
// and emulators plug in a verifier of their own;
// walletprovidertest.FakeVerifier is one, never for production.
//
// Every piece of evidence is bound to a challenge the provider issued
// (Provider.Challenge): random, used once, short-lived, and bound to its
// Purpose, so a challenge issued for registering an instance can't
// attest a holder key, nor one issued for a request be replayed.
//
// The two platforms fit the one interface differently:
//
//   - Android Key Attestation attests each key itself: the key's
//     certificate chain, with the challenge in its attestation
//     extension, proves the key was generated in a TEE or StrongBox
//     for this challenge. The verifier returns that key in
//     VerifiedEvidence.Keys with KeyBindingAttested and the chain's
//     security level, and needs no state from the instance.
//   - Apple App Attest attests the app, not its keys. At registration
//     the attestation object's client data hash covers the challenge
//     and the instance key, and the verifier returns the instance key
//     with KeyBindingAppAssertion, plus VerifiedEvidence.Credential
//     (the App Attest key) and Counter, which the provider stores in
//     the Instance. A later request carries an assertion over the
//     challenge and the keys it names; the verifier checks it against
//     EvidenceInput.Instance's Credential and Counter and returns the
//     new Counter, which the provider stores with a compare-and-swap
//     (InstanceStore.Update), so an assertion is accepted once.
//
// # Policy
//
// Policy decides what verified evidence is good enough: per platform,
// the accepted security levels, a minimum app version and verified
// boot; and the table that alone decides a Key Attestation's
// key_storage and user_authentication claims (Appendix D.2), keyed by
// what the evidence proved, never by what the app says. A key vouched
// for by an app assertion (App Attest) matches only a row naming
// KeyBindingAppAssertion: a Secure Enclave key's storage is never
// claimed unless the integrator says so. The policy is applied again at
// every attestation, so tightening it stops existing instances too.
//
// # Instances and status
//
// Each registered instance holds one index in the provider's status
// list, reserved by statuslist.Allocator when it registers and never
// reused. Suspend, Resume and Revoke set it SUSPENDED, VALID and
// INVALID; a revocation is final. Provider.StatusList serves the list
// (JWT or CWT form, by the request's Accept header), signed with the
// provider's own key and certificate chain, so an issuer's default
// check — the list signed with the attestation's own key — accepts it.
//
// # Requests after registration
//
// Proving possession of the instance key on each later request is the
// HTTP layer's job; SignRequest and Provider.VerifyRequest are the
// signed request it uses: a short JWT over the method, path, a hash of
// the body and a fresh challenge, signed with the instance key, so an
// instance ID alone is useless to anyone who learns it.
package walletprovider
