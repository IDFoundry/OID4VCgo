package dcql

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // RFC 5280's key identifier method
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/idfoundry/oid4vcgo/internal/certchain"
)

// AKITrustedAuthoritiesChecker implements TrustedAuthoritiesChecker for
// TrustedAuthorityAKI only (§6.1.1.1) — HAIP 1.0 §5's own required
// TrustedAuthoritiesType. Each requested value is a CA's Subject Key
// Identifier, base64url-encoded (see AKITrustedAuthorities); §6.1.1.1
// matches it against the Authority Key Identifier (RFC 5280 §4.2.1.1)
// of a certificate in the credential's chain.
//
// How it matches depends on Roots and Anchors:
//
//   - With Roots or Anchors set, it verifies issuerChain against them
//     and matches the requested values against the key identifiers of
//     the certificate authorities actually on a verified path: every
//     CA's identifier derived from its own public key (RFC 5280
//     §4.2.1.2 method 1, RFC 7093 method 1), and, given Anchors, the
//     trust anchor's declared Subject Key Identifier when no other
//     anchor claims it. That establishes which CA really issued the
//     credential's certificate, so it's a verification control.
//     verifier.VerifyResponse requires one of them.
//   - Without either, it reads the leaf certificate's own Authority Key
//     Identifier extension. That's what the leaf states about its
//     issuer, not something chain validation checks: any CA can issue
//     a certificate naming another CA's key identifier there. It's only
//     fit for a Wallet narrowing which of its own credentials to offer
//     (wallet.MatchDCQLQuery), never for deciding whether to trust a
//     presented credential.
//
// A declared Subject Key Identifier is what the certificate says about
// itself: a second trusted root declaring another's would pass that
// root's "aki" filter. One derived from the key can't be claimed by a
// certificate for another key, and most CAs' identifiers are derived
// so (method 1, or RFC 7093's). Roots, a CertPool, can't be listed,
// so with Roots alone an anchor matches only by its derived
// identifiers. An anchor whose identifier is made another way (RFC
// 5280 §4.2.1.2 leaves it open) needs Anchors: its declared identifier
// then matches as long as no anchor with another key declares the same
// one or has it as a derived identifier — Validate reports one that
// does, and CheckTrustedAuthorities refuses every match while it's
// configured.
//
// Either way it only narrows trust in an issuer that a role package's
// own key resolver already established (e.g. verifier.X5CIssuerKeyResolver's
// Roots); OID4VP §6.1.1 calls trusted_authorities chiefly a data
// minimisation aid, and a Verifier must still decide issuer trust on
// its own.
type AKITrustedAuthoritiesChecker struct {
	// Roots, if set, are the trust anchors issuerChain is verified
	// against before matching (see the type's doc comment) — normally
	// the same anchors the Verifier's issuer key resolver uses. Each
	// matches only by the identifiers derived from its key.
	Roots *x509.CertPool

	// Anchors, if set in place of Roots, are the trust anchors as
	// certificates: issuerChain is verified against them, and an
	// anchor's declared Subject Key Identifier matches too, when it's
	// unambiguous among them (see the type's doc comment).
	Anchors []*x509.Certificate
}

// Validate reports a configuration CheckTrustedAuthorities refuses:
// both Roots and Anchors, a nil anchor, or two anchors with different
// keys claiming the same key identifier, declared by one and declared
// by or derived for the other. An anchor reissued for the same key
// keeps its identifier, and isn't a conflict.
func (c AKITrustedAuthoritiesChecker) Validate() error {
	if c.Roots != nil && len(c.Anchors) > 0 {
		return errors.New("dcql: AKITrustedAuthoritiesChecker: set Roots or Anchors, not both")
	}
	type claim struct {
		cert     *x509.Certificate
		declared bool
	}
	claims := map[string][]claim{}
	for i, anchor := range c.Anchors {
		if anchor == nil {
			return fmt.Errorf("dcql: AKITrustedAuthoritiesChecker: Anchors[%d] is nil", i)
		}
		for _, id := range derivedKeyIdentifiers(anchor) {
			claims[string(id)] = append(claims[string(id)], claim{anchor, false})
		}
		if len(anchor.SubjectKeyId) > 0 && !slices.ContainsFunc(derivedKeyIdentifiers(anchor), func(id []byte) bool { return bytes.Equal(id, anchor.SubjectKeyId) }) {
			claims[string(anchor.SubjectKeyId)] = append(claims[string(anchor.SubjectKeyId)], claim{anchor, true})
		}
	}
	// Sorted, so the conflict reported is the same every time.
	for _, id := range slices.Sorted(maps.Keys(claims)) {
		cs := claims[id]
		for i, a := range cs {
			for _, b := range cs[i+1:] {
				if (a.declared || b.declared) && !bytes.Equal(a.cert.RawSubjectPublicKeyInfo, b.cert.RawSubjectPublicKeyInfo) {
					return fmt.Errorf("dcql: AKITrustedAuthoritiesChecker: anchors %q and %q, with different keys, both claim the key identifier %s", a.cert.Subject, b.cert.Subject, base64.RawURLEncoding.EncodeToString([]byte(id)))
				}
			}
		}
	}
	return nil
}

// CheckTrustedAuthorities implements TrustedAuthoritiesChecker.
func (c AKITrustedAuthoritiesChecker) CheckTrustedAuthorities(ctx context.Context, authorities []TrustedAuthoritiesQuery, issuerChain [][]byte) error {
	var wantAKIs []string
	for _, ta := range authorities {
		if ta.Type == TrustedAuthorityAKI {
			wantAKIs = append(wantAKIs, ta.Values...)
		}
	}
	if len(wantAKIs) == 0 {
		return fmt.Errorf("dcql: no %q entry in trusted_authorities", TrustedAuthorityAKI)
	}
	if len(issuerChain) == 0 {
		return fmt.Errorf("dcql: no issuer certificate chain to check an %q trusted_authorities entry against", TrustedAuthorityAKI)
	}
	if c.Roots != nil || len(c.Anchors) > 0 {
		roots := c.Roots
		if roots == nil {
			set := c.anchorSetOf()
			if set.err != nil {
				return set.err
			}
			roots = set.roots
		} else if err := c.Validate(); err != nil {
			return err
		}
		return c.checkVerifiedChainAKI(ctx, issuerChain, roots, wantAKIs)
	}
	// OpenID4VP §6.1.1.1: the value "MUST match with the
	// AuthorityKeyIdentifier element of an X.509 certificate in the
	// certificate chain", which may carry intermediates but omit the
	// anchor. Any certificate's authority key identifier counts, and the
	// topmost one's own subject key identifier, when it's the authority
	// asked for. Unverified: this only chooses what to present.
	for i, der := range issuerChain {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("dcql: parse issuer certificate %d: %w", i, err)
		}
		if len(cert.AuthorityKeyId) > 0 && slices.Contains(wantAKIs, base64.RawURLEncoding.EncodeToString(cert.AuthorityKeyId)) {
			return nil
		}
		if i == len(issuerChain)-1 && i > 0 && len(cert.SubjectKeyId) > 0 && slices.Contains(wantAKIs, base64.RawURLEncoding.EncodeToString(cert.SubjectKeyId)) {
			return nil
		}
	}
	return fmt.Errorf("dcql: no authority key identifier in the issuer's certificate chain is among the requested trusted_authorities")
}

// checkVerifiedChainAKI succeeds when a certificate authority on a
// verified path from issuerChain's leaf to c's anchors has one of
// wantAKIs as its key identifier, roots being c's anchors as a pool.
//
// A CA's declared Subject Key Identifier is written by whoever issued
// its certificate — the CA itself, for an anchor — so another trusted
// CA could declare someone else's: a CA matches by an identifier
// derived from its own public key (RFC 5280 §4.2.1.2 method 1, RFC 7093
// method 1), which no certificate for another key can carry and still
// sign the leaf, and an anchor in Anchors by its declared one too,
// which Validate has checked no other anchor claims.
func (c AKITrustedAuthoritiesChecker) checkVerifiedChainAKI(ctx context.Context, issuerChain [][]byte, roots *x509.CertPool, wantAKIs []string) error {
	// At the verification time the verifier set, as its own certificate
	// checks are.
	//
	// It checks no revocation of its own. verifier.VerifyResponse passes
	// it the path its issuer key resolver verified, without the anchor,
	// and that resolver's Revocation has already passed every
	// certificate on it. A path built here runs only through those
	// certificates and an anchor (which revocation never checks), and a
	// certificate's revocation is its issuer's to state whichever path
	// it's on, so no path here crosses a certificate revocation refused.
	// A custom resolver that isn't an SDJWTVCIssuerChainResolver hands
	// on the presented chain instead: its revocation is that resolver's
	// to check.
	_, chains, err := certchain.VerifyChainsAt(issuerChain, roots, certchain.TimeFrom(ctx))
	if err != nil {
		return fmt.Errorf("dcql: issuer certificate chain: %w", err)
	}
	for _, chain := range chains {
		anchor := len(chain) - 1
		for i, ca := range chain[1:] {
			for _, id := range c.caKeyIdentifiers(ca, i+1 == anchor) {
				if slices.Contains(wantAKIs, base64.RawURLEncoding.EncodeToString(id)) {
					return nil
				}
			}
		}
	}
	return fmt.Errorf("dcql: no certificate authority on the issuer's verified chain is among the requested trusted_authorities")
}

// caKeyIdentifiers are the key identifiers ca can be matched by: those
// derived from its public key, and its declared Subject Key Identifier
// where it's a trust anchor in Anchors.
func (c AKITrustedAuthoritiesChecker) caKeyIdentifiers(ca *x509.Certificate, anchor bool) [][]byte {
	ids := derivedKeyIdentifiers(ca)
	if anchor && len(ca.SubjectKeyId) > 0 && slices.ContainsFunc(c.Anchors, func(a *x509.Certificate) bool { return bytes.Equal(a.Raw, ca.Raw) }) {
		ids = append(ids, ca.SubjectKeyId)
	}
	return ids
}

// derivedKeyIdentifiers are RFC 5280 §4.2.1.2 method 1's key
// identifier (SHA-1 of the subjectPublicKey BIT STRING's value) and
// RFC 7093 method 1's (SHA-256 of it, truncated to 160 bits).
func derivedKeyIdentifiers(cert *x509.Certificate) [][]byte {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if rest, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err != nil || len(rest) != 0 {
		return nil
	}
	sha1Sum := sha1.Sum(spki.PublicKey.Bytes) //nolint:gosec // RFC 5280's key identifier method, not a security use of SHA-1
	sha256Sum := sha256.Sum256(spki.PublicKey.Bytes)
	return [][]byte{sha1Sum[:], sha256Sum[:20]}
}
