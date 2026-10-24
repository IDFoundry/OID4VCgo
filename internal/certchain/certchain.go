// Package certchain implements the one certificate-chain-trust
// primitive shared by every X5C/X5C-chain-shaped resolver this repo
// ships (verifier.X5CIssuerKeyResolver, verifier.X5ChainIssuerKeyResolver,
// issuer.X5CAttestationVerifier, issuer.X5CProofBindingKeyResolver):
// parse a leaf-first chain and verify it against a trust anchor set,
// rejecting a self-signed leaf even when that leaf is itself a
// configured root. Promoted here once a second package (issuer)
// needed the identical logic verifier already had — see
// ARCHITECTURE.md's own stance on not sharing code across a boundary
// until a second real consumer exists.
package certchain

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
)

// MaxChainLength is the most certificates a presented chain may hold,
// leaf included. Real chains are two or three long; the bound keeps a
// chain an attacker sends from costing a parse (and, in CheckNoAnchor
// and path building, more) per entry without limit.
const MaxChainLength = 8

// X5CDERsFromHeader extracts header's own "x5c" member (RFC 7515
// §4.1.6: a JSON array of standard-base64-encoded DER certificates,
// leaf first) as raw DER bytes, requiring at least one entry —
// promoted here (from a private copy verifier once kept to itself)
// once wallet needed the identical logic to check a held credential's
// own issuer chain against a Credential Query's own TrustedAuthorities
// — see ARCHITECTURE.md's own stance on not sharing code across a
// boundary until a second real consumer exists, the same reason
// VerifyLeaf/DERsFromBase64 already live here rather than in one role
// package.
func X5CDERsFromHeader(header map[string]any) ([][]byte, error) {
	raw, ok := header["x5c"]
	if !ok {
		return nil, fmt.Errorf("certchain: header has no x5c member")
	}
	entries, ok := raw.([]any)
	if !ok || len(entries) == 0 {
		return nil, fmt.Errorf("certchain: x5c header is not a non-empty array")
	}
	return DERsFromBase64(entries)
}

// VerifyLeaf parses ders (leaf first, then any intermediates — RFC
// 7515 §4.1.6's own "x5c" ordering, which RFC 9360 §2's own "x5chain"
// mirrors) and verifies the leaf against roots, rejecting a
// self-signed leaf even when that leaf is itself a configured root —
// HAIP's own trust model wants a leaf issued by a separate CA (so the
// leaf can be rotated/revoked without redistributing a new trust
// anchor to every relying party), not a leaf that doubles as its own
// anchor.
func VerifyLeaf(ders [][]byte, roots *x509.CertPool) (*x509.Certificate, error) {
	leaf, _, err := VerifyChains(ders, roots)
	return leaf, err
}

// VerifyLeafWithPolicy is VerifyLeaf, then policy (if non-nil) on the
// verified leaf and its verified paths — the role-specific check
// (extended key usage, certificate policy, issuer) chain validation
// alone doesn't make, since it accepts any key usage.
func VerifyLeafWithPolicy(ders [][]byte, roots *x509.CertPool, policy func(leaf *x509.Certificate, chains [][]*x509.Certificate) error) (*x509.Certificate, error) {
	return VerifyLeafWithPolicyAt(ders, roots, policy, time.Time{})
}

// VerifyLeafWithPolicyAt is VerifyLeafWithPolicy, checking every
// certificate's validity period at now, the current time when zero.
func VerifyLeafWithPolicyAt(ders [][]byte, roots *x509.CertPool, policy func(leaf *x509.Certificate, chains [][]*x509.Certificate) error, now time.Time) (*x509.Certificate, error) {
	leaf, chains, err := VerifyChainsAt(ders, roots, now)
	if err != nil {
		return nil, err
	}
	if policy != nil {
		if err := policy(leaf, chains); err != nil {
			return nil, fmt.Errorf("certchain: leaf certificate policy: %w", err)
		}
	}
	return leaf, nil
}

// ApprovedChains is chains, leaf's verified paths, narrowed to those
// policy approves on its own, after policy has approved them together.
// A policy over every path passes when one of them does (EKUInPath
// does), so the paths a caller goes on to rely on — the issuer chain it
// reports, authorizes and binds status to — would otherwise include
// ones the policy refused: through a CA certified twice, a path to an
// anchor that restricts it beside one to an anchor that doesn't. A nil
// policy approves every path.
func ApprovedChains(leaf *x509.Certificate, chains [][]*x509.Certificate, policy func(leaf *x509.Certificate, chains [][]*x509.Certificate) error) ([][]*x509.Certificate, error) {
	if policy == nil {
		return chains, nil
	}
	if err := policy(leaf, chains); err != nil {
		return nil, fmt.Errorf("certchain: leaf certificate policy: %w", err)
	}
	approved := make([][]*x509.Certificate, 0, len(chains))
	lastErr := errors.New("no verified path")
	for _, chain := range chains {
		if lastErr = policy(leaf, [][]*x509.Certificate{chain}); lastErr == nil {
			approved = append(approved, chain)
		}
	}
	if len(approved) == 0 {
		return nil, fmt.Errorf("certchain: leaf certificate policy: no verified path passes it on its own: %w", lastErr)
	}
	return approved, nil
}

// VerifyTrustedChainsAt is VerifyChainsAt, then ApprovedChains with
// policy, then NotRevokedChains with revocation: the leaf, and the
// verified paths from it that policy approves each on its own and that
// pass revocation. The leaf is accepted when at least one path is left,
// and every path returned has passed both, so whatever a caller goes on
// to rely on — the issuer chain it reports, authorizes and binds status
// to — never runs through a certificate revocation refused. A nil
// policy approves every path; a nil revocation checks none.
func VerifyTrustedChainsAt(ctx context.Context, ders [][]byte, roots *x509.CertPool, policy func(leaf *x509.Certificate, chains [][]*x509.Certificate) error, revocation certrevocation.Checker, now time.Time) (*x509.Certificate, [][]*x509.Certificate, error) {
	leaf, chains, err := VerifyChainsAt(ders, roots, now)
	if err != nil {
		return nil, nil, err
	}
	approved, err := ApprovedChains(leaf, chains, policy)
	if err != nil {
		return nil, nil, err
	}
	good, err := NotRevokedChains(ctx, approved, revocation, now)
	if err != nil {
		return nil, nil, err
	}
	return leaf, good, nil
}

// NotRevokedChains is chains narrowed to those revocation passes, each
// checked on its own at now (the current time when zero). Through a CA
// certified twice, one path may run through an intermediate that's
// been revoked beside another that hasn't; the leaf is on every path,
// so a revoked leaf leaves none. When none passes, the error wraps the
// last path's, so errors.Is finds certrevocation.ErrRevoked or
// certrevocation.ErrNoCurrentCRL through it. A nil revocation passes
// every path.
func NotRevokedChains(ctx context.Context, chains [][]*x509.Certificate, revocation certrevocation.Checker, now time.Time) ([][]*x509.Certificate, error) {
	if revocation == nil {
		return chains, nil
	}
	if now.IsZero() {
		now = time.Now()
	}
	good := make([][]*x509.Certificate, 0, len(chains))
	lastErr := errors.New("no verified path")
	for _, chain := range chains {
		if lastErr = revocation.CheckRevocation(ctx, certrevocation.Check{Chain: chain, Now: now}); lastErr == nil {
			good = append(good, chain)
		}
	}
	if len(good) == 0 {
		return nil, fmt.Errorf("certchain: revocation: no verified path passes it: %w", lastErr)
	}
	return good, nil
}

// VerifyChains is VerifyLeaf, also returning every verified path from
// the leaf to a certificate in roots (leaf first, root last), as
// crypto/x509's own Verify builds them. What a verified path says
// about who issued what can be relied on; what a certificate merely
// states about its own issuer (its Authority Key Identifier extension)
// can't — chain building doesn't require it to match.
//
// roots must be set: crypto/x509 treats a nil pool as "the system's
// roots", which would trust any publicly trusted certificate. A leaf
// that's itself a CA certificate is refused too: every role here signs
// with an end-entity certificate, so a leaf whose key usage extension
// doesn't allow digitalSignature is refused as well.
func VerifyChains(ders [][]byte, roots *x509.CertPool) (*x509.Certificate, [][]*x509.Certificate, error) {
	return VerifyChainsAt(ders, roots, time.Time{})
}

// VerifyChainsAt is VerifyChains, checking every certificate's validity
// period at now instead of the current time — for a caller whose own
// API takes an explicit verification time (proximity's reader). A zero
// now means the current time.
func VerifyChainsAt(ders [][]byte, roots *x509.CertPool, now time.Time) (*x509.Certificate, [][]*x509.Certificate, error) {
	if roots == nil {
		return nil, nil, fmt.Errorf("certchain: no trust anchors configured (a nil root pool would mean the system roots)")
	}
	switch {
	case len(ders) == 0:
		return nil, nil, fmt.Errorf("certchain: certificate chain is empty")
	case len(ders) > MaxChainLength:
		return nil, nil, fmt.Errorf("certchain: certificate chain has %d entries, more than %d", len(ders), MaxChainLength)
	}
	certs := make([]*x509.Certificate, 0, len(ders))
	for i, der := range ders {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, nil, fmt.Errorf("certchain: parse certificate chain entry %d: %w", i, err)
		}
		certs = append(certs, cert)
	}
	leaf := certs[0]
	if IsSelfSigned(leaf) {
		return nil, nil, fmt.Errorf("certchain: leaf certificate must not be self-signed")
	}
	if leaf.BasicConstraintsValid && leaf.IsCA {
		return nil, nil, fmt.Errorf("certchain: leaf certificate must not be a CA certificate")
	}
	// Every leaf here signs: a key usage extension, when present, must
	// allow it (RFC 5280 §4.2.1.3), as ISO/IEC 18013-5 and HAIP's
	// certificate profiles also have it. One without the extension
	// isn't restricted.
	if leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, nil, fmt.Errorf("certchain: leaf certificate's key usage doesn't allow digitalSignature")
	}
	// A small-order Ed25519 key verifies a forged signature over any
	// message; jwk and COSE_Key parsing refuse one, and so must a
	// certificate.
	if pub, ok := leaf.PublicKey.(ed25519.PublicKey); ok && jwk.IsSmallOrderEd25519(pub) {
		return nil, nil, fmt.Errorf("certchain: leaf certificate's Ed25519 key is of small order")
	}

	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime:   now,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("certchain: certificate chain does not verify against a trusted root: %w", err)
	}
	return leaf, chains, nil
}

// IsSelfSigned reports whether cert's own signature was produced by
// its own public key (regardless of any IsCA/BasicConstraints
// extension) — deliberately not x509.Certificate.CheckSignatureFrom,
// which additionally enforces CA constraints that a self-signed *leaf*
// (the exact shape VerifyLeaf rejects) typically doesn't carry.
func IsSelfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawIssuer, cert.RawSubject) &&
		cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

// DERsFromBase64 decodes entries (RFC 7515 §4.1.6: a JSON array of
// standard-base64-encoded DER certificates, leaf first, e.g. a JOSE
// "x5c" header member already type-asserted to []any) into raw DER
// bytes suitable for VerifyLeaf.
func DERsFromBase64(entries []any) ([][]byte, error) {
	if len(entries) > MaxChainLength {
		return nil, fmt.Errorf("certchain: certificate chain has %d entries, more than %d", len(entries), MaxChainLength)
	}
	ders := make([][]byte, 0, len(entries))
	for i, e := range entries {
		s, ok := e.(string)
		if !ok {
			return nil, fmt.Errorf("certchain: entry %d is not a string", i)
		}
		der, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("certchain: decode entry %d: %w", i, err)
		}
		ders = append(ders, der)
	}
	return ders, nil
}

// CheckPresentedChain checks a certificate chain a signer presents in
// x5c or x5chain, leaf first, as HAIP 1.0 requires it (§4.1, §5,
// §6.1.1): the leaf isn't self-signed, each intermediate signs the
// certificate before it, and the trust anchor isn't included (a
// self-signed intermediate is one). A verifier then builds the path to
// its own anchors.
func CheckPresentedChain(leaf *x509.Certificate, intermediates []*x509.Certificate) error {
	if leaf == nil {
		return errors.New("certchain: no leaf certificate")
	}
	if IsSelfSigned(leaf) {
		return errors.New("certchain: the leaf certificate is self-signed; it must be issued by a CA")
	}
	child := leaf
	for i, parent := range intermediates {
		if parent == nil {
			return fmt.Errorf("certchain: intermediate %d is nil", i)
		}
		if err := child.CheckSignatureFrom(parent); err != nil {
			return fmt.Errorf("certchain: intermediate %d didn't sign the certificate before it: %w", i, err)
		}
		if IsSelfSigned(parent) {
			return fmt.Errorf("certchain: intermediate %d is self-signed: leave the trust anchor out of the chain", i)
		}
		child = parent
	}
	return nil
}

// CheckIssuerName checks that iss, an SD-JWT VC's issuer claim, names
// the end-entity certificate leaf its key came from (SD-JWT VC, the
// x5c header): a "dns:" URI's DNS name must be one of leaf's dNSName
// subject alternative names, and any other iss one of its
// uniformResourceIdentifier names, compared exactly. A certificate a
// trusted root issued to another issuer can then sign nothing in this
// issuer's name, nor can one that shares only its host.
func CheckIssuerName(leaf *x509.Certificate, iss string) error {
	if strings.HasPrefix(iss, "dns:") {
		name := strings.TrimPrefix(strings.TrimPrefix(iss, "dns:"), "//")
		if name != "" && slices.ContainsFunc(leaf.DNSNames, func(d string) bool { return strings.EqualFold(d, name) }) {
			return nil
		}
		return fmt.Errorf("certchain: iss %q isn't a DNS name of the signing certificate", iss)
	}
	if iss != "" && slices.ContainsFunc(leaf.URIs, func(u *url.URL) bool { return u.String() == iss }) {
		return nil
	}
	return fmt.Errorf("certchain: iss %q isn't a URI of the signing certificate", iss)
}

// CheckNoAnchor refuses a presented chain that includes a self-issued
// certificate (its issuer its own subject) after the leaf: a trust
// anchor, which HAIP 1.0 (§4.1, §5, §6.1.1) has the sender leave out of
// x5c, since the receiver's own roots decide on it. It doesn't check
// the certificate's signature: no intermediate a path is built through
// names itself as its issuer, so a self-issued one is refused whether
// or not it's actually self-signed, without the cost of a signature
// check per entry. It's for JOSE x5c chains: an mdoc's x5chain and a
// reader's certificate chain often include the root.
func CheckNoAnchor(ders [][]byte) error {
	if len(ders) > MaxChainLength {
		return fmt.Errorf("certchain: certificate chain has %d entries, more than %d", len(ders), MaxChainLength)
	}
	for i, der := range ders[min(1, len(ders)):] {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("certchain: parse certificate chain entry %d: %w", i+1, err)
		}
		if bytes.Equal(cert.RawIssuer, cert.RawSubject) {
			return fmt.Errorf("certchain: certificate chain entry %d is self-issued: the trust anchor must not be included", i+1)
		}
	}
	return nil
}

// SameKey reports whether a and b are the same public key; false when
// either is nil.
func SameKey(a, b crypto.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	eq, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && eq.Equal(b)
}
