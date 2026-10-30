package androidattest

import (
	"bytes"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// MaxChainLength is the most certificates Verify takes in a chain.
const MaxChainLength = 10

// Attestation is a verified chain's outcome.
type Attestation struct {
	// Leaf is the attested key's certificate, the chain's first.
	Leaf *x509.Certificate
	// KeyDescription is Leaf's attestation extension.
	KeyDescription
	// Anchored reports whether the chain ends at one of the roots Verify
	// was given: Google's, for a device that passed Google's
	// certification. An emulator's software attestation, or a device
	// outside Google's program, chains to another root.
	Anchored bool
	// OutOfValidity names the certificates (by position, the leaf 0)
	// that aren't valid at the time Verify was given. A trusted root
	// in the chain is judged by the root Verify was given instead, as a
	// re-issued root has the same key.
	OutOfValidity []int
}

// Hardware reports whether the attestation is one Google says comes
// from secure hardware: it chains to a Google root, every certificate
// is valid, and both the attestation and the key are in the TEE or
// StrongBox.
func (a *Attestation) Hardware() bool {
	return a.Anchored && len(a.OutOfValidity) == 0 &&
		a.AttestationSecurityLevel.Hardware() && a.KeyMintSecurityLevel.Hardware()
}

// Verify checks chain, DER certificates with the attested key's first,
// as Android Keystore's getCertificateChain gives it: each certificate
// is signed by the next, the leaf has the attestation extension and no
// other certificate does (so a key Keystore attested can't sign a
// "leaf" of its own claiming anything), and the extension parses. It
// returns an error for any of those; whether the chain ends at one of
// roots, and the certificates' validity at now, it reports in the
// Attestation for the caller's policy.
func Verify(chain [][]byte, roots []*x509.Certificate, now time.Time) (*Attestation, error) {
	if len(chain) == 0 || len(chain) > MaxChainLength {
		return nil, fmt.Errorf("androidattest: a chain of %d certificates, want 1 to %d", len(chain), MaxChainLength)
	}
	certs := make([]*x509.Certificate, len(chain))
	for i, der := range chain {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("androidattest: certificate %d: %w", i, err)
		}
		certs[i] = c
	}
	for i := 0; i+1 < len(certs); i++ {
		// CheckSignature rather than CheckSignatureFrom: Android's
		// attestation keys needn't be marked as CAs.
		child, parent := certs[i], certs[i+1]
		if err := parent.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature); err != nil {
			return nil, fmt.Errorf("androidattest: certificate %d isn't signed by certificate %d: %w", i, i+1, err)
		}
	}
	var ext []byte
	for i, c := range certs {
		for _, e := range c.Extensions {
			if !e.Id.Equal(OID) {
				continue
			}
			if i != 0 {
				return nil, fmt.Errorf("androidattest: certificate %d, not the leaf, has an attestation extension", i)
			}
			ext = e.Value
		}
	}
	if ext == nil {
		return nil, errors.New("androidattest: the leaf has no attestation extension")
	}
	kd, err := ParseKeyDescription(ext)
	if err != nil {
		return nil, err
	}
	a := &Attestation{Leaf: certs[0], KeyDescription: kd}
	top := certs[len(certs)-1]
	for i, c := range certs {
		root := isRoot(c, roots)
		if c == top && (root || signedByRoot(c, roots)) {
			a.Anchored = true
		}
		if !root && (now.Before(c.NotBefore) || now.After(c.NotAfter)) {
			a.OutOfValidity = append(a.OutOfValidity, i)
		}
	}
	return a, nil
}

// isRoot reports whether c has the key of one of roots: a root itself,
// or a re-issuance of one.
func isRoot(c *x509.Certificate, roots []*x509.Certificate) bool {
	for _, r := range roots {
		if bytes.Equal(c.RawSubjectPublicKeyInfo, r.RawSubjectPublicKeyInfo) {
			return true
		}
	}
	return false
}

// signedByRoot reports whether one of roots signed c: a chain that
// leaves its root out.
func signedByRoot(c *x509.Certificate, roots []*x509.Certificate) bool {
	for _, r := range roots {
		if r.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil {
			return true
		}
	}
	return false
}

// googleRootsPEM holds Google's hardware attestation roots, as listed at
// https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate
// and served at https://android.googleapis.com/attestation/root
// (fetched 2026-10-30, both sources byte-identical):
//
//   - SERIALNUMBER=f92009e853b6b045, RSA 4096, 2022-03-20 to 2042-03-15,
//     SHA-256 CE:DB:1C:B6:DC:89:6A:E5:EC:79:73:48:BC:E9:28:67:53:C2:B3:8E:E7:1C:E0:FB:E3:4A:9A:12:48:80:0D:FC.
//     Its key is the one Google's earlier root certificates (2016,
//     2019, 2021) have, so chains to those are anchored too.
//   - CN=Key Attestation CA1, OU=Android, O=Google LLC, C=US, ECDSA
//     P-384, 2025-07-17 to 2035-07-15, signing chains from 2026-02-01,
//     SHA-256 6D:9D:B4:CE:6C:5C:0B:29:31:66:D0:89:86:E0:57:74:A8:77:6C:EB:52:5D:9E:43:29:52:0D:E1:2B:A4:BC:C0.
//
// Google's page gives no fingerprints; TestGoogleRoots pins these.
//
//go:embed google_roots.pem
var googleRootsPEM []byte

// GoogleRoots returns Google's hardware attestation roots.
func GoogleRoots() []*x509.Certificate {
	var roots []*x509.Certificate
	for block, rest := pem.Decode(googleRootsPEM); block != nil; block, rest = pem.Decode(rest) {
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			panic("androidattest: embedded Google root: " + err.Error())
		}
		roots = append(roots, c)
	}
	return roots
}
