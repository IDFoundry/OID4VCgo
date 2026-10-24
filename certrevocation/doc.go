// Package certrevocation checks whether an X.509 certificate a relying
// party is about to trust has been revoked by the CA that issued it.
//
// A verified certificate chain says only that a trusted CA issued each
// certificate and that each is inside its validity period. It says
// nothing about a certificate the CA has since revoked: a document
// signer or SD-JWT VC issuer whose key was stolen keeps signing
// credentials a chain check accepts until its certificate expires.
// Revocation information closes that gap. ISO/IEC 18013-5 has every
// IACA-issued certificate name a CRL distribution point (Annex B, B.1)
// and profiles the CRL itself (B.2), and expects a reader to hold
// current revocation information for the document signers it trusts
// (§12.8.4 of the second edition). HAIP 1.0 and OpenID4VP leave X.509
// revocation to the trust framework the verifier operates under.
//
// # Checker
//
// Checker is the one interface: given a verified chain, leaf first and
// ending at the trust anchor, and the instant of the verification, it
// returns nil when no certificate below the anchor has been revoked.
// The anchor itself is never checked: a relying party distrusts an
// anchor by removing it from its trust anchor set, not by asking it.
//
// CRLs implements Checker with Certificate Revocation Lists (RFC 5280
// §5) the caller supplies. It does no fetching of its own: a
// deployment downloads each CA's CRL from the distribution point its
// certificates name, keeps the parsed lists in memory and refreshes
// them in the background before their nextUpdate. A missing or stale
// list fails closed: the certificate is refused, with ErrNoCurrentCRL,
// rather than accepted unchecked. A revoked certificate is refused with
// ErrRevoked.
//
// NoCheck declines checking revocation at all, as a visible line of
// code rather than a field left unset. OCSP (RFC 6960), or any other
// source of revocation status, can implement Checker; this package
// ships none.
//
// # Where it's used
//
// verifier.X5CIssuerKeyResolver and verifier.X5ChainIssuerKeyResolver
// require a Checker (their Revocation field) and apply it to every
// verified path from a credential's issuer certificate to a trust
// anchor: a credential is accepted only through a path no revoked
// certificate is on. The wallet's and issuer's own certificate checks
// (a relying party's access certificate, a wallet attestation's chain)
// don't check revocation yet.
package certrevocation
