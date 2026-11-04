package androidkey

import (
	"crypto/x509"
	_ "embed" // google_roots.pem
	"encoding/pem"
	"slices"
	"sync"
)

// googleRootsPEM holds Google's hardware attestation root certificates,
// as published at
// https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate
// and served at https://android.googleapis.com/attestation/root
// (fetched 2026-10-30 and again 2026-11-05, identical):
//
//   - SERIALNUMBER=f92009e853b6b045: RSA 4096, valid 2022-03-20 to
//     2042-03-15, SHA-256 cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc.
//     Google's earlier root certificates (2016, 2019, 2021) carry the
//     same key, so chains ending at one of those are anchored too.
//   - CN=Key Attestation CA1, OU=Android, O=Google LLC, C=US: ECDSA
//     P-384, valid 2025-07-17 to 2035-07-15, SHA-256
//     6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0.
//     Google's documentation has it signing chains from 2026-02-01.
//
// Google rotates its roots: Verifier.Roots replaces this set, and
// GoogleRoots plus a newly published root extends it.
//
//go:embed google_roots.pem
var googleRootsPEM []byte

var googleRoots = sync.OnceValue(func() []*x509.Certificate {
	var roots []*x509.Certificate
	for block, rest := pem.Decode(googleRootsPEM); block != nil; block, rest = pem.Decode(rest) {
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			panic("androidkey: embedded Google root doesn't parse: " + err.Error())
		}
		roots = append(roots, c)
	}
	return roots
})

// GoogleRoots returns Google's hardware attestation roots, the default
// Verifier.Roots. The slice is the caller's own; the certificates are
// shared and must not be modified.
func GoogleRoots() []*x509.Certificate { return slices.Clone(googleRoots()) }
