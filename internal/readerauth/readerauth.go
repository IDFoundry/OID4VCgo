// Package readerauth signs and verifies ISO/IEC 18013-5 mdoc reader
// authentication (§9.1.4): a COSE_Sign1 with a null payload over a
// detached ReaderAuthenticationBytes, the reader's certificate chain in
// its unprotected x5chain header. mdocdcapi (the Digital Credentials
// API's org-iso-mdoc) and proximity (device retrieval) share it.
package readerauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/internal/cose"
)

// EKU is the extended key usage of an mdoc reader authentication
// certificate (ISO/IEC 18013-5 Annex B.1.7: 1.0.18013.5.1.6).
var EKU = asn1.ObjectIdentifier{1, 0, 18013, 5, 1, 6}

// RequireEKU is a Trust.LeafPolicy refusing a reader certificate
// without EKU.
func RequireEKU(leaf *x509.Certificate, _ [][]*x509.Certificate) error {
	for _, eku := range leaf.UnknownExtKeyUsage {
		if eku.Equal(EKU) {
			return nil
		}
	}
	return errors.New("the reader certificate lacks the mdoc reader authentication extended key usage (1.0.18013.5.1.6)")
}

// Trust is which mdoc readers a holder recognizes.
type Trust struct {
	// Roots are the trust anchors a reader's certificate must chain to;
	// a nil pool recognizes no reader (never the system's roots).
	Roots *x509.CertPool
	// LeafPolicy, if set, is run on the chain-verified reader
	// certificate and its verified paths, and can refuse it.
	LeafPolicy func(leaf *x509.Certificate, chains [][]*x509.Certificate) error
	// Now is when the certificates must be valid; zero: the current
	// time.
	Now time.Time
}

// Sign signs detached, an encoded ReaderAuthentication(All), as the
// reader whose key signer is and whose certificate chain, leaf first,
// is chain: the leaf must certify signer's public key.
func Sign(signer crypto.Signer, chain []*x509.Certificate, detached []byte) ([]byte, error) {
	alg, err := CheckKey(signer, chain)
	if err != nil {
		return nil, err
	}
	ders := make([][]byte, len(chain))
	for i, c := range chain {
		ders[i] = c.Raw
	}
	return cose.SignDetached(alg, signer, cose.Headers{Alg: alg}, cose.Headers{X5Chain: ders}, detached, nil)
}

// CheckKey is the COSE algorithm signer signs with, after checking
// chain's leaf certifies its key.
func CheckKey(signer crypto.Signer, chain []*x509.Certificate) (cose.Alg, error) {
	if signer == nil || len(chain) == 0 || chain[0] == nil {
		return 0, errors.New("a signer and its certificate chain are required")
	}
	pub := signer.Public()
	if leaf, ok := chain[0].PublicKey.(interface{ Equal(crypto.PublicKey) bool }); !ok || !leaf.Equal(pub) {
		return 0, errors.New("the leaf certificate doesn't certify the signer's key")
	}
	return KeyAlg(pub)
}

// KeyAlg is the COSE algorithm a reader key signs with: ES256 for
// P-256, EdDSA for Ed25519.
func KeyAlg(pub crypto.PublicKey) (cose.Alg, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return 0, errors.New("an ECDSA reader key must be P-256")
		}
		return cose.ES256, nil
	case ed25519.PublicKey:
		return cose.EdDSA, nil
	default:
		return 0, fmt.Errorf("unsupported reader key type %T", pub)
	}
}

// Chain is the certificate chain in sig's x5chain header, leaf first,
// unverified: both its DER encodings and the parsed certificates.
func Chain(sig []byte) ([][]byte, []*x509.Certificate, error) {
	_, unprotected, _, err := cose.DecodeUnverified(sig)
	if err != nil {
		return nil, nil, fmt.Errorf("decode reader signature: %w", err)
	}
	if len(unprotected.X5Chain) == 0 {
		return nil, nil, errors.New("the reader signature carries no x5chain")
	}
	certs := make([]*x509.Certificate, len(unprotected.X5Chain))
	for i, der := range unprotected.X5Chain {
		if certs[i], err = x509.ParseCertificate(der); err != nil {
			return nil, nil, fmt.Errorf("reader certificate %d: %w", i, err)
		}
	}
	return unprotected.X5Chain, certs, nil
}

// VerifySignature checks sig over detached by leaf's key, the algorithm
// leaf's key's, not the signature's own header's.
func VerifySignature(sig, detached []byte, leaf *x509.Certificate) error {
	alg, err := KeyAlg(leaf.PublicKey)
	if err != nil {
		return err
	}
	if _, _, err := cose.VerifyDetached(alg, leaf.PublicKey, sig, detached, nil); err != nil {
		return fmt.Errorf("reader signature: %w", err)
	}
	return nil
}

// VerifyTrust checks ders, a chain leaf first, chains to t.Roots at
// t.Now and its leaf passes t.LeafPolicy, and returns the leaf.
func VerifyTrust(ders [][]byte, t Trust) (*x509.Certificate, error) {
	leaf, chains, err := certchain.VerifyChainsAt(ders, t.Roots, t.Now)
	if err != nil {
		return nil, err
	}
	if t.LeafPolicy != nil {
		if err := t.LeafPolicy(leaf, chains); err != nil {
			return nil, err
		}
	}
	return leaf, nil
}

// Verify verifies sig over detached by the certificate in its x5chain,
// which must chain to t's roots and pass its LeafPolicy, and returns
// that certificate.
func Verify(sig, detached []byte, t Trust) (*x509.Certificate, error) {
	ders, _, err := Chain(sig)
	if err != nil {
		return nil, err
	}
	leaf, err := VerifyTrust(ders, t)
	if err != nil {
		return nil, err
	}
	if err := VerifySignature(sig, detached, leaf); err != nil {
		return nil, err
	}
	return leaf, nil
}
