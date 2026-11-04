package certchain

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"
)

// SignerChainDERs checks chain starts with signer's certificate and is
// the chain HAIP 1.0 §6.1 has a status list signer present
// (CheckPresentedChain), and returns its DER encodings. Its errors carry
// no package prefix but CheckPresentedChain's, for the caller to add
// its own.
func SignerChainDERs(signer crypto.Signer, chain []*x509.Certificate) ([][]byte, error) {
	if len(chain) == 0 {
		return nil, errors.New("a certificate chain is required")
	}
	pub, ok := chain[0].PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(signer.Public()) {
		return nil, errors.New("the chain's first certificate isn't the signer's")
	}
	if err := CheckPresentedChain(chain[0], chain[1:]); err != nil {
		return nil, err
	}
	ders := make([][]byte, len(chain))
	for i, c := range chain {
		ders[i] = c.Raw
	}
	return ders, nil
}

// SignerKeyIsEdDSA reports whether a JWT token signer's key, pub, signs
// with EdDSA (Ed25519) rather than ES256 (ECDSA on P-256), the two algs
// this module verifies JWTs with; any other key is an error, with no
// package prefix. A COSE token's signer takes cose.AlgForKey, which
// also has P-384 and P-521.
func SignerKeyIsEdDSA(pub crypto.PublicKey) (bool, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return false, fmt.Errorf("an ECDSA key on %s, but only P-256 (ES256) is supported", k.Curve.Params().Name)
		}
		return false, nil
	case ed25519.PublicKey:
		return true, nil
	default:
		return false, fmt.Errorf("unsupported key type %T", pub)
	}
}

// BothPolicies is a leaf policy passing only what first and second
// both pass, first checked first; a nil one passes everything.
func BothPolicies(first, second func(*x509.Certificate, [][]*x509.Certificate) error) func(*x509.Certificate, [][]*x509.Certificate) error {
	if first == nil {
		return second
	}
	if second == nil {
		return first
	}
	return func(leaf *x509.Certificate, chains [][]*x509.Certificate) error {
		if err := first(leaf, chains); err != nil {
			return err
		}
		return second(leaf, chains)
	}
}
