// Package attestation implements OID4VCI 1.0's two attestation
// mechanisms:
//
//   - Appendix D, Key Attestation: a JWT a Wallet's key storage
//     component (or Wallet Provider) issues, vouching for the security
//     properties of one or more cryptographic keys — fully
//     self-contained in this package (keyattestation.go): issuance,
//     parsing, verification, and matching a Credential Request proof's
//     signing key against the attested set (Appendix D.1's own MUST:
//     "the Credential Issuer MUST validate that the JWT used as a proof
//     is signed by a key contained in the attestation").
//
//   - Appendix E, Wallet Attestation: OID4VCI does not define a new
//     client-authentication mechanism here — it reuses OAuth 2.0
//     Attestation-Based Client Authentication (draft-07) wholesale,
//     adding three OID4VCI-specific claims (wallet_name, wallet_link,
//     status) on top. The base Client Attestation JWT handshake —
//     everything except those three claims — lives in FAPIgo's
//     internal/clientattestation, not here (see ARCHITECTURE.md's
//     "Relationship to FAPIgo"). walletattestation.go covers only what
//     FAPIgo's server-side verification doesn't surface: FAPIgo's
//     clientattestation.VerifiedAttestation exposes ClientID/ExpiresAt/
//     ConfirmationJWK and nothing else, so an OID4VCI issuer that wants
//     wallet_name/wallet_link/status has to read them itself.
//     ParseWalletAttestationClaims does exactly that — from the same
//     compact JWT string an HTTP adapter already has in hand (the
//     OAuth-Client-Attestation header value), without re-verifying the
//     signature FAPIgo's server already checked authoritatively. It is
//     not a substitute for that verification and must never be used to
//     make an authentication decision on its own. On the Wallet
//     Provider's side, IssueWalletAttestation mints a Wallet
//     Attestation JWT — base claims plus those three — since FAPIgo
//     only consumes one (fapigo/client via its AttestationSource,
//     fapigo/server by verifying it).
package attestation
