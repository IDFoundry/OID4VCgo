package androidkey_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"log"

	"github.com/idfoundry/oid4vcgo/walletprovider/androidkey"
)

// A Wallet Provider verifies the attestation chain its Android app
// sends for a new key, over a challenge it issued, then binds the
// attested key to the JWK the app presented.
func ExampleVerifier() {
	// The app's signing certificate digest, as `apksigner verify
	// --print-certs` prints it.
	digest, _ := hex.DecodeString("8a1f0c3c5d2e4b6a79880f1e2d3c4b5a69788796a5b4c3d2e1f0a9b8c7d6e5f4")
	v := &androidkey.Verifier{
		// Roots: nil, Google's hardware attestation roots.
		Revocation: &androidkey.StatusSource{}, // Google's status list, fetched daily
		Apps: []androidkey.AllowedApp{{
			Package:                   "com.example.wallet",
			SigningCertificateDigests: [][]byte{digest},
		}},
		MinOSPatchLevel: 202501,
	}

	var chain [][]byte             // the app's certificate chain, DER, leaf first
	var challenge []byte           // the challenge the provider issued, used once
	var presented *ecdsa.PublicKey // the key the app's JWK names

	r, err := v.Verify(context.Background(), chain, challenge)
	switch {
	case errors.Is(err, androidkey.ErrRevoked), errors.Is(err, androidkey.ErrBootState):
		log.Printf("refusing a compromised device: %v", err)
		return
	case err != nil:
		log.Printf("refusing: %v", err)
		return
	case !presented.Equal(r.PublicKey):
		log.Print("the attestation is for another key")
		return
	}
	log.Printf("StrongBox: %v, user authentication required: %v", r.StrongBox(), !r.Enforced.NoAuthRequired)
}
