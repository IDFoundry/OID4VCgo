package appattest

import (
	"crypto/x509"
	_ "embed" // apple_app_attestation_root_ca.pem
	"encoding/pem"
	"slices"
	"sync"
)

// appleRootPEM is the Apple App Attestation Root CA, as published at
// https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
// (fetched 2026-11-07): CN=Apple App Attestation Root CA, O=Apple Inc.,
// ST=California, ECDSA P-384, serial 0bf3be0ef1cdd2e0fb8c6e721f621798,
// valid 2020-03-18 to 2045-03-15, SHA-256
// 1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932.
//
//go:embed apple_app_attestation_root_ca.pem
var appleRootPEM []byte

var appleRoots = sync.OnceValue(func() []*x509.Certificate {
	var roots []*x509.Certificate
	for block, rest := pem.Decode(appleRootPEM); block != nil; block, rest = pem.Decode(rest) {
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			panic("appattest: embedded Apple root doesn't parse: " + err.Error())
		}
		roots = append(roots, c)
	}
	return roots
})

// AppleRoots returns the Apple App Attestation Root CA, the default
// Verifier.Roots. The slice is the caller's own; the certificate is
// shared and must not be modified.
func AppleRoots() []*x509.Certificate { return slices.Clone(appleRoots()) }
