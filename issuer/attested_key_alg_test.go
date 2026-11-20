package issuer_test

import (
	"crypto"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// withProofAlgs has the SD-JWT VC configuration take the jwt proof type
// signed with jwtAlgs and the attestation proof type with
// attestationAlgs, and not take a proof type whose algorithms are nil.
func withProofAlgs(jwtAlgs, attestationAlgs []string) func(*issuer.Config, *issuer.Dependencies) {
	return func(cfg *issuer.Config, _ *issuer.Dependencies) {
		c := cfg.CredentialConfigurationsSupported[testSDJWTConfigID]
		c.ProofTypesSupported = map[string]oid4vci.ProofTypeConfiguration{}
		for proofType, algs := range map[string][]string{oid4vci.ProofTypeJWT: jwtAlgs, oid4vci.ProofTypeAttestation: attestationAlgs} {
			if algs != nil {
				c.ProofTypesSupported[proofType] = oid4vci.ProofTypeConfiguration{ProofSigningAlgValuesSupported: algs}
			}
		}
		cfg.CredentialConfigurationsSupported[testSDJWTConfigID] = c
	}
}

// publicKeyFor is a new public key for alg, EdDSA or ES384.
func publicKeyFor(t *testing.T, alg string) crypto.PublicKey {
	t.Helper()
	if alg == oid4vci.EdDSA {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return pub
	}
	return &newECKey(t, elliptic.P384()).PublicKey
}

// A key a key attestation attests is bound only when it's a key for an
// algorithm the credential configuration takes for it. Beside a jwt
// proof's own key, that's one the jwt proof type's
// proof_signing_alg_values_supported lists, as for the proof's key.
// Under the attestation proof type, whose list is for the attestation's
// own signature (OpenID4VCI 1.0 Appendix F.3), it's one either proof
// type lists. Here every key attestation attests a P-256 key and one
// for alg; the proof, or the attestation, is signed ES256.
func TestRequestCredential_AttestedKeyAlgorithms(t *testing.T) {
	es256, withES384 := []string{oid4vci.ES256}, []string{oid4vci.ES256, oid4vci.ES384}
	for name, tc := range map[string]struct {
		jwtAlgs, attestationAlgs []string
		proofType, alg           string
		refused                  bool
	}{
		"jwt, an Ed25519 key":                            {es256, es256, oid4vci.ProofTypeJWT, oid4vci.EdDSA, true},
		"jwt, a P-384 key only attestation takes":        {es256, withES384, oid4vci.ProofTypeJWT, oid4vci.ES384, true},
		"jwt, a P-384 key it takes":                      {withES384, es256, oid4vci.ProofTypeJWT, oid4vci.ES384, false},
		"attestation, an Ed25519 key":                    {es256, es256, oid4vci.ProofTypeAttestation, oid4vci.EdDSA, true},
		"attestation, a P-384 key jwt takes":             {withES384, es256, oid4vci.ProofTypeAttestation, oid4vci.ES384, false},
		"attestation, a P-384 key it takes":              {es256, withES384, oid4vci.ProofTypeAttestation, oid4vci.ES384, false},
		"attestation alone, a P-384 key it doesn't take": {nil, es256, oid4vci.ProofTypeAttestation, oid4vci.ES384, true},
	} {
		t.Run(name, func(t *testing.T) {
			f := newCredentialEndpointFixture(t, withProofAlgs(tc.jwtAlgs, tc.attestationAlgs))
			holder, other := testP256Key(t), publicKeyFor(t, tc.alg)
			n := f.issueNonce(t)
			proof := buildAttestation(t, f.attestationSigner, n, &holder.PublicKey, other)
			if tc.proofType == oid4vci.ProofTypeJWT {
				proof = jwtProofWithKeyAttestation(t, holder, n, keyAttestationForJWT(t, f.attestationSigner, n, false, &holder.PublicKey, other))
			}
			resp, err := requestSDJWTWith(f, tc.proofType, proof)
			if tc.refused {
				assertIssuerError(t, err, issuer.ErrorInvalidProof)
				return
			}
			if err != nil || len(resp.Credentials) != 2 {
				t.Fatalf("issued %d credentials, %v; want 2", len(resp.Credentials), err)
			}
		})
	}
}
