// Package androidkey verifies Android Key Attestation for a Wallet
// Provider: the certificate chain Android Keystore returns for a key
// generated with an attestation challenge
// (KeyGenParameterSpec.Builder.setAttestationChallenge), whose leaf
// carries the key description extension (ExtensionOID).
//
// Verifier.Verify checks, and refuses with an error wrapping one of
// this package's Err values when one fails:
//
//   - the chain: two to MaxChainLength certificates of at most
//     MaxCertificateBytes, each signed by the next, ending at one of
//     Verifier.Roots (Google's hardware attestation roots by default,
//     GoogleRoots) or a certificate one of them signed, every
//     certificate valid at Verifier.Now, a leaf whose key isn't a
//     root's, and the attestation extension on the leaf alone;
//   - the key description, parsed for attestation versions 1 to 4
//     (Keymaster) and 100 to 500 (KeyMint), and later ones, whose added
//     fields it skips;
//   - the attestation challenge, compared in constant time;
//   - the attestation version, and both security levels: the TEE or
//     StrongBox, unless AllowSoftware (StrongBox alone with
//     RequireStrongBox);
//   - the key, from the hardware-enforced authorization list: SIGN
//     among its purposes, an EC key on an allowed curve matching the
//     leaf's key (by its attested curve, or by its key size where the
//     curve is left out, as Keymaster 4 may), generated in the secure
//     hardware;
//   - the root of trust: a locked bootloader and a verified boot,
//     unless AllowUntrustedBoot; optionally a minimum OS patch level;
//   - the app that made the key: every package Keystore names, with
//     every signing certificate digest, must be one of Verifier.Apps;
//   - revocation: every certificate's serial number against Google's
//     attestation status list (StatusSource fetches and caches it),
//     refusing when no current list is held unless RevocationOptional.
//
// The Result carries the attested public key, to bind to the key the
// wallet presented, the parsed key description with both authorization
// lists, the security levels (StrongBox reported apart from the TEE),
// the user authentication requirements the key was made with, and the
// app's identity: what a Wallet Provider maps to the key_storage and
// user_authentication it attests.
//
// The app's identity is in the software-enforced list: Android's
// Keystore service, not the secure hardware, reports which app asked
// for the key. A device whose boot state the hardware attests as
// verified and locked runs an OS that reports it faithfully.
//
// EvidenceVerifier adapts a Verifier to walletprovider.EvidenceVerifier,
// for a walletprovider.Provider's Dependencies.Evidence: the evidence
// is one key's chain (Evidence), and what the Verifier proves becomes
// the VerifiedEvidence the provider's Policy decides on. It reports the
// chain's Facts too, which the provider keeps with an instance it
// registers and with an instance key it records, and is a
// walletprovider.EvidenceRechecker and InstanceKeyRechecker: before
// each attestation, Verifier.Recheck judges the instance's Facts, and
// those of the recorded instance key the attestation relies on, by the
// Verifier as it is then, so a certificate the status list names since,
// in either chain, a certificate of either chain past its validity
// period (Remote Key Provisioning's attestation certificates live for
// weeks), or a policy tightened since, refuses it. A certificate the list names
// REVOKED or SUSPENDED also has the provider revoke or suspend the
// instance (walletprovider.ErrEvidenceRevoked, ErrEvidenceSuspended);
// a root removed from Roots, a tightened policy or an expired
// certificate only refuses, since the operator may undo the first two,
// and the wallet can send fresh evidence for the last: register again
// when the registration chain expired, or attest a new instance key
// when only an instance key's did. A record an earlier version kept
// that can't be judged — an instance or instance key with no Facts, or
// Facts without the certificates' validity periods — is refused too
// (ErrLegacyFacts), unless EvidenceVerifier.AllowUncheckedLegacyEvidence,
// for an upgrade window, which logs each record it lets through
// (EvidenceVerifier.Logger).
//
// Keys attested with an app's own attestation key
// (setAttestKeyAlias) are refused: their chains carry the extension
// below the leaf.
package androidkey
