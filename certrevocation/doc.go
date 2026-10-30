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
// A self-signed anchor, a root, is never checked: a relying party
// distrusts a root by removing it from its trust anchor set, not by
// asking it. An anchor that isn't self-signed — a leaf pinned as an
// anchor, or an intermediate CA placed among the roots — is checked
// against its CA's CRL, which needs that CA's certificate in
// CRLs.Issuers. Where revocation is checked, keep intermediates out of
// the trust anchors: one there beside its root yields a path ending at
// the intermediate, which without that check would never ask the root
// whether it revoked it.
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
// Refresher does that fetching for CRLs served over http or https: it
// fetches the distribution points the deployment configures, from
// public addresses only by default, keeps the last good list from each
// and replaces it only with one a configured CA signed that isn't
// older, so a failed or replayed fetch can't evict or roll back a good
// list. That rollback floor is kept per CA, by its name and the key
// that signs its lists, and two configured CAs by one name with
// different keys are refused unless AllowSameNameIssuers is set.
// URLIssuers binds each URL to its CA, Floors and OnAccept carry the
// rollback floor across a restart, and RequireHTTPS refuses plain
// http distribution points. Its Run loop refreshes each list well before its nextUpdate,
// in a goroutine the caller starts; Refresher.Checker is the CRLs to
// check against. On a phone, the operating system's background
// scheduler should drive refreshes instead, handing the lists to the
// mobile library's SetCRLs.
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
// certificate is on. So do issuer.X5CAttestationVerifier and
// issuer.X5CProofBindingKeyResolver under issuer.AssuranceProduction,
// a wallet.X5CVerifierRoots and wallet.Config.IssuerMetadataRevocation
// under wallet.AssuranceProduction, and walletflow.Config outside
// Development: it has one field per role, since CRLs fails closed for a
// CA it has no list from, and requires each role in use to have one.
//
// Every other X.509 trust decision takes an optional Checker beside the
// roots it applies to, nil checking nothing: a wallet's issuer trust
// (wallet.VerifyIssuedCredentialParams.IssuerRevocation), registrars
// (registration.Registrars), mdoc readers (proximity.ReaderTrust,
// mdocdcapi.ReaderTrust), a proximity reader's document signers
// (proximity.WithIssuerRevocation), status list signers
// (statuslist.VerifyOptions.Revocation), the same wallet and walletflow
// settings in development, and, outside issuer.AssuranceProduction, key
// attestations and jwt proofs at the issuer.
package certrevocation
