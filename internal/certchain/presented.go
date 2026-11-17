package certchain

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
)

// MaxPresentedRSABits is the largest RSA modulus a presented
// intermediate may carry when no trust anchor the chain reaches has an
// RSA key at least that large. Above it, as with a P-521 key, each
// signature check costs several times a P-256, P-384 or RSA-3072 one.
const MaxPresentedRSABits = 3072

// ErrChainBudget is wrapped by VerifyPresented's error when path
// building gave up at crypto/x509's cap on signature checks rather than
// finding no path: a caller verifying more chains from the same sender
// can stop there.
var ErrChainBudget = errors.New("certchain: path building ran out of signature checks")

// signatureLimitText is how crypto/x509 reports its cap on signature
// checks per Verify; the error itself isn't exported.
const signatureLimitText = "signature check attempts limit reached"

// VerifyPresented verifies certs, a certificate chain an untrusted
// party presented leaf first (a JOSE x5c, a COSE x5chain, a reader's
// chain), against opts.Roots, under the one policy every verifier of a
// presented chain applies before and around crypto/x509's path
// building:
//
//   - the certificates are in their presented order (RFC 7515 §4.1.6,
//     RFC 9360 §2): each one's issuer name is the next one's subject;
//   - no two of them share a subject name or a SubjectPublicKeyInfo;
//   - an intermediate (any entry after the leaf) has a P-521 key, or an
//     RSA key over MaxPresentedRSABits, only when a trust anchor the
//     last presented certificate chains to has a key of that type and
//     size;
//   - every path returned runs through the presented certificates in
//     order, up to the anchor it ends at.
//
// The first three are checked before any signature: with unique, linked
// names, each certificate has at most one presented candidate issuer,
// so path building is linear in the chain's length, rather than running
// to crypto/x509's cap of a hundred signature checks over intermediates
// that issue each other. The last presented certificate may be the
// anchor itself (an mdoc x5chain may include it). opts.Intermediates is
// replaced; opts.Roots must be set.
func VerifyPresented(certs []*x509.Certificate, opts x509.VerifyOptions) ([][]*x509.Certificate, error) {
	if opts.Roots == nil {
		return nil, errors.New("certchain: no trust anchors configured (a nil root pool would mean the system roots)")
	}
	if len(certs) == 0 {
		return nil, errors.New("certchain: certificate chain is empty")
	}
	if err := CheckPresentedOrder(certs); err != nil {
		return nil, err
	}
	if err := checkPresentedKeys(certs, opts); err != nil {
		return nil, err
	}
	opts.Intermediates = x509.NewCertPool()
	for _, c := range certs[1:] {
		opts.Intermediates.AddCert(c)
	}
	chains, err := certs[0].Verify(opts)
	if err != nil {
		if strings.Contains(err.Error(), signatureLimitText) {
			err = fmt.Errorf("%w: %w", ErrChainBudget, err)
		}
		return nil, fmt.Errorf("certchain: certificate chain does not verify against a trusted root: %w", err)
	}
	ordered := chains[:0]
	for _, chain := range chains {
		if inPresentedOrder(chain, certs) {
			ordered = append(ordered, chain)
		}
	}
	if len(ordered) == 0 {
		return nil, errors.New("certchain: certificate chain verifies only through a path other than the one presented")
	}
	return ordered, nil
}

// CheckPresentedOrder checks, without any signature check, that certs,
// a presented chain leaf first, is listed in order — each entry's
// issuer name the next one's subject — and that no two entries share a
// subject name or a SubjectPublicKeyInfo. Path building over such a
// chain has one presented candidate issuer per certificate at most.
func CheckPresentedOrder(certs []*x509.Certificate) error {
	subjects := make(map[string]int, len(certs))
	keys := make(map[string]int, len(certs))
	for i, c := range certs {
		if c == nil {
			return fmt.Errorf("certchain: certificate chain entry %d is nil", i)
		}
		if j, dup := subjects[string(c.RawSubject)]; dup {
			return fmt.Errorf("certchain: certificate chain entries %d and %d have the same subject name", j, i)
		}
		if j, dup := keys[string(c.RawSubjectPublicKeyInfo)]; dup {
			return fmt.Errorf("certchain: certificate chain entries %d and %d have the same public key", j, i)
		}
		subjects[string(c.RawSubject)] = i
		keys[string(c.RawSubjectPublicKeyInfo)] = i
		if i > 0 && !bytes.Equal(certs[i-1].RawIssuer, c.RawSubject) {
			return fmt.Errorf("certchain: certificate chain entry %d doesn't name entry %d as its issuer: list the chain in order, leaf first", i-1, i)
		}
	}
	return nil
}

// checkPresentedKeys refuses an intermediate whose key is costlier to
// check signatures with than the usual ones (P-256, P-384, Ed25519,
// RSA up to MaxPresentedRSABits) unless an anchor the chain reaches
// has a key at least as costly of the same type. The anchors are found
// only when such a key is presented, from the last presented
// certificate alone, so building that path costs a signature check per
// configured root of the right name at most.
func checkPresentedKeys(certs []*x509.Certificate, opts x509.VerifyOptions) error {
	var anchors []any
	found := false
	for i, c := range certs[1:] {
		if !costlyKey(c.PublicKey) {
			continue
		}
		if !found {
			anchors, found = anchorKeys(certs[len(certs)-1], opts), true
		}
		if !coveredBy(c.PublicKey, anchors) {
			return fmt.Errorf("certchain: certificate chain entry %d has %s, and no trust anchor the chain reaches has one", i+1, describeKey(c.PublicKey))
		}
	}
	return nil
}

// anchorKeys is the public keys of the trust anchors last chains to
// with no intermediates (last's own key when it's an anchor itself).
func anchorKeys(last *x509.Certificate, opts x509.VerifyOptions) []any {
	opts.Intermediates = nil
	chains, err := last.Verify(opts)
	if err != nil {
		return nil
	}
	keys := make([]any, 0, len(chains))
	for _, chain := range chains {
		keys = append(keys, chain[len(chain)-1].PublicKey)
	}
	return keys
}

func costlyKey(pub any) bool {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return k.Curve == elliptic.P521()
	case *rsa.PublicKey:
		return k.N.BitLen() > MaxPresentedRSABits
	}
	return false
}

// coveredBy reports whether one of anchors is a key of pub's type at
// least as costly: a P-521 key for a P-521 one, an RSA key of at least
// as many bits for an RSA one.
func coveredBy(pub any, anchors []any) bool {
	for _, a := range anchors {
		switch k := pub.(type) {
		case *ecdsa.PublicKey:
			if ak, ok := a.(*ecdsa.PublicKey); ok && ak.Curve == k.Curve {
				return true
			}
		case *rsa.PublicKey:
			if ak, ok := a.(*rsa.PublicKey); ok && ak.N.BitLen() >= k.N.BitLen() {
				return true
			}
		}
	}
	return false
}

func describeKey(pub any) string {
	if k, ok := pub.(*rsa.PublicKey); ok {
		return fmt.Sprintf("an RSA key of %d bits, over the %d allowed", k.N.BitLen(), MaxPresentedRSABits)
	}
	return "a P-521 key"
}

// inPresentedOrder reports whether chain, a verified path, runs through
// certs in their presented order until it reaches its anchor: every
// entry but the anchor is the presented certificate at its position,
// and the anchor is either the next presented one, one with the same
// subject and key, or follows the last presented one.
func inPresentedOrder(chain, certs []*x509.Certificate) bool {
	last := len(chain) - 1
	for i, c := range chain {
		switch {
		case i >= len(certs):
			return i == last
		case c.Equal(certs[i]):
		case i == last && bytes.Equal(c.RawSubject, certs[i].RawSubject) &&
			bytes.Equal(c.RawSubjectPublicKeyInfo, certs[i].RawSubjectPublicKeyInfo):
		default:
			return false
		}
	}
	return true
}
