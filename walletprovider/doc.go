// Package walletprovider is the Wallet Provider role: the service that
// vouches for a wallet app's instances and keys. It checks platform
// evidence, registers wallet instances and records their per-issuance
// instance keys, and issues the two attestations
// HAIP 1.0 has a Credential Issuer rely on — the Wallet Attestation
// (§4.4.1, OID4VCI 1.0 Appendix E) that authenticates a wallet instance
// as an OAuth client, and the Key Attestation (§4.5.1, OID4VCI 1.0
// Appendix D) that vouches for the holder keys a credential is bound
// to — claiming in each only what the evidence proved. It withdraws
// that trust through Token Status Lists (draft-ietf-oauth-status-list-14)
// every attestation it issues references, which issuers check with
// haip.WalletAttestationStatusList and issuer.StatusListAttestationStatus.
//
// Package attestation mints and parses the two JWTs; this package
// decides whether to mint them at all.
//
// # Evidence
//
// Nothing is attested without platform evidence: a registration, a
// Wallet Attestation for an instance key not yet recorded, or a Key
// Attestation request carrying none is refused, in development as in
// production, and there is no setting that changes that. Evidence is
// checked by an EvidenceVerifier for its Kind: an Android Key
// Attestation verifier, an Apple App Attest verifier, or one of the
// integrator's own (Play Integrity, a WSCD's attestation, a TPM). Tests
// and emulators plug in a verifier of their own;
// walletprovidertest.FakeVerifier is one, never for production.
//
// Every piece of evidence is bound to a challenge the provider issued
// (Provider.Challenge): random, used once, short-lived, and bound to its
// Purpose, so a challenge issued for registering an instance can't
// attest an instance key or a holder key, nor one issued for a request
// be replayed.
//
// The two platforms fit the one interface differently:
//
//   - Android Key Attestation attests each key itself: the key's
//     certificate chain, with the challenge in its attestation
//     extension, proves the key was generated in a TEE or StrongBox
//     for this challenge. The verifier returns that key in
//     VerifiedEvidence.Keys with KeyBindingAttested and the chain's
//     security level, and needs no state from the instance.
//     Nor does it tie the key to the device the instance registered
//     from: Android attests no device identity a provider can rely
//     on, so a holder key need only come from the instance's platform
//     and app. A user with two registered devices can have a key made
//     on one attested under the other's instance; what the Key
//     Attestation claims of the key still holds, but its status is
//     that of an instance key of the instance it was attested under, so
//     revoking the other device's instance doesn't withdraw it. Revoke
//     every instance of a user whose device is lost, where the provider
//     knows which they are. An instance key is likewise tied only to
//     the instance's platform and app.
//   - Apple App Attest attests the app, not its keys. At registration
//     the attestation object's client data hash covers the challenge
//     and the registration key, and the verifier returns the
//     registration key with KeyBindingAppAssertion, plus
//     VerifiedEvidence.Credential (the App Attest key) and Counter,
//     which the provider stores in the Instance. A later request — an
//     instance key's first Wallet Attestation, or a Key Attestation —
//     carries an assertion over the challenge and the keys it names;
//     the verifier checks it against EvidenceInput.Instance's
//     Credential and Counter and returns the new Counter, which the
//     provider stores with a compare-and-swap (InstanceStore.Update),
//     so an assertion is accepted once.
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
// # Instances, instance keys and status
//
// An Instance is one installation of the wallet app (HAIP 1.0's Wallet
// Instance), registered once with a registration key that signs its
// requests to the provider and is never named to an issuer. A Wallet
// Attestation's cnf names an instance key (InstanceKey) instead: a key
// the wallet makes for one issuance, so that no two Credential Issuers
// see the same Wallet Attestation, key or status entry (HAIP 1.0
// §4.4.1; draft-ietf-oauth-attestation-based-client-auth-07 §11.1).
// Platform evidence vouches for an instance key the first time a
// Wallet Attestation is asked for it; the provider then records it
// against the instance (InstanceKeyStore) with an index of its own on
// one of the provider's status lists, reserved by statuslist.Allocator
// and never reused, which every Wallet Attestation for the key and
// every Key Attestation issued with it reference. Issuers see only
// per-issuance keys, per-issuance status indices and the shared client
// ID; the provider alone knows which instance keys belong to which
// instance (HAIP 1.0 §11.1 asks a Wallet Provider's backend to be
// designed with its users' privacy in mind), so keep its stores as
// private as the users they describe.
//
// The lists belong to periods (Config.StatusListPeriod, a week by
// default): each period has up to MaxStatusListsPerPeriod lists of
// Config.StatusListSize indices, at Config.StatusListBaseURI/{start}/{n},
// filled one after another, and every attestation names an index on a
// list of the current period. An instance key used in a later period
// than its index's gets a fresh index there first, keeping the previous
// period's as InstanceKey.PreviousStatus, since an attestation issued
// then may still be live; an attestation outlives its period by less
// than another. So a period's lists hold the instance keys used in it,
// not every one ever recorded, and a list is served through the two
// periods after its own, by the end of which no live attestation names
// it.
//
// Suspend, Resume and Revoke set the status of every one of an
// instance's instance keys SUSPENDED, VALID and INVALID, at both its
// indices, so revoking an installation withdraws every attestation
// issued for it; a revocation is final. Provider.StatusLists serves the
// lists (JWT or CWT form, by the request's Accept header), signed with
// the provider's own key and certificate chain, so an issuer's default
// check — the list signed with the attestation's own key — accepts
// them. Size Config.StatusListSize for the instance keys used in a
// period. With Dependencies.StatusListTokens, the replicas serving the
// lists share their tokens: one signs a list's token at a time, and a
// status change is served by every replica from its next check.
//
// Neither store of instance keys and their statuses grows for good. An
// instance key's record is kept for Config.InstanceKeyRetention after
// the start of the period it was last used in (InstanceKey.RetainUntil),
// and then the InstanceKeyStore may delete it, as sqlstore's DB.Sweep
// does: a key used again after that needs evidence, as a new one does.
// Provider.SweepStatusLists deletes the lists of the periods no longer
// served; run it periodically. It also gives the instance keys recorded
// before retention a RetainUntil, when the InstanceKeyStore can list
// them (UnretainedInstanceKeyLister, as sqlstore's can). The single
// list of v0.67.0 and before, at the old Config.StatusListURI, is no
// longer served or changed: delete it once with
// statuslist.IndexStore.Delete. A key still naming it moves on its next
// use, as one on any deleted list does. Instances themselves are kept.
//
// # Requests after registration
//
// Proving possession of the registration key on each later request is
// the HTTP layer's job; SignRequest and Provider.VerifyRequest are the
// signed request it uses: a short JWT over the method, path, a hash of
// the body and a fresh challenge, signed with the registration key, so
// an instance ID alone is useless to anyone who learns it. The
// signature is checked first: a request that doesn't verify learns
// nothing of the instance's state and leaves its challenge unused.
//
// # HTTP
//
// No standard defines how a wallet talks to its provider. Provider.Handler
// serves this package's own JSON protocol, versioned in its paths
// (ChallengePath, InstancesPath, WalletAttestationPath,
// KeyAttestationPath, StatusPath), and Client speaks it for a wallet
// written in Go. Requests are bounded and decoded strictly; refusals
// carry fixed error codes, never internal error text; and every signed
// request that doesn't verify gets the same 401. The handler does no
// rate limiting: an integrator wraps it with their own, per client, as
// the challenge and registration endpoints answer anyone.
//
// Evidence kinds plug in from subpackages: androidkey.EvidenceVerifier
// for Android Key Attestation.
package walletprovider
