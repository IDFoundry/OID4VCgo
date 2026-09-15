package haip_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/fapigo/fapihttp"

	"github.com/idfoundry/oid4vcigo/attestation"
	"github.com/idfoundry/oid4vcigo/haip"
	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/issuer"
	"github.com/idfoundry/oid4vcigo/storage"
	"github.com/idfoundry/oid4vcigo/wallet"
)

// fixedAttestationVerifier is a minimal issuer.AttestationVerifier for
// this test — trusting a single fixed key, standing in for whatever
// trust policy a real deployment would apply.
type fixedAttestationVerifier struct {
	pub crypto.PublicKey
	alg jose.Alg
}

func (v fixedAttestationVerifier) ResolveAttestationKey(context.Context, attestation.KeyAttestation) (crypto.PublicKey, jose.Alg, error) {
	return v.pub, v.alg, nil
}

// TestRecommendedIssuerConfigWorksWithIssuerNew wires
// RecommendedIssuerConfig's own ProofTypesSupported into a real
// CredentialConfiguration and confirms the result both passes
// issuer.New and satisfies ValidateIssuerConfig — this package's real
// purpose, and the simplest way to keep its recommendations from
// silently drifting out of sync with what issuer actually accepts.
func TestRecommendedIssuerConfigWorksWithIssuerNew(t *testing.T) {
	issuerURL, err := fapi.ParseIssuerURL("https://issuer.example.com")
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	credentialEndpoint, err := fapi.ParseEndpointURL("https://issuer.example.com/credential")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	nonceEndpoint, err := fapi.ParseEndpointURL("https://issuer.example.com/nonce")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	rec := haip.RecommendedIssuerConfig()
	cfg := issuer.Config{
		Issuer: issuerURL,
		Endpoints: issuer.Endpoints{
			Credential: credentialEndpoint,
			Nonce:      nonceEndpoint,
		},
		Limits: issuer.Limits{NonceLifetime: time.Minute},
		CredentialConfigurationsSupported: map[string]issuer.CredentialConfiguration{
			"IdentityCredential": {
				Format:                               "dc+sd-jwt",
				Scope:                                "identity_credential",
				VCT:                                  "https://credentials.example.com/identity_credential",
				CryptographicBindingMethodsSupported: []string{"jwk"},
				CredentialSigningAlgValuesSupported:  []string{string(haip.RecommendedJOSEAlgorithm)},
				ProofTypesSupported:                  rec.ProofTypesSupported,
			},
		},
	}

	if err := haip.ValidateIssuerConfig(cfg); err != nil {
		t.Fatalf("ValidateIssuerConfig: %v", err)
	}
	if _, err := issuer.New(cfg, issuer.Dependencies{
		Nonces:      storage.NewNonceStore(),
		Clock:       issuer.ClockFunc(time.Now),
		Random:      rand.Reader,
		SDJWTSigner: &issuer.SDJWTSigner{Signer: signer, Alg: haip.RecommendedJOSEAlgorithm},
		AttestationVerifier: fixedAttestationVerifier{
			pub: &signer.PublicKey, alg: haip.RecommendedJOSEAlgorithm,
		},
	}); err != nil {
		t.Fatalf("issuer.New: %v", err)
	}
}

// TestRecommendedWalletConfigWorksWithWalletNew wires
// RecommendedWalletConfig's own ProofSigningAlg into a real wallet.Config
// and confirms the result passes wallet.New — the simplest way to keep
// this recommendation from silently drifting out of sync with what
// wallet actually accepts.
func TestRecommendedWalletConfigWorksWithWalletNew(t *testing.T) {
	rec := haip.RecommendedWalletConfig()
	_, err := wallet.New(wallet.Config{
		ProofSigningAlg: rec.ProofSigningAlg,
		Fetch:           fapihttp.Config{MaxResponseBytes: 1 << 20, RequestTimeout: 5 * time.Second},
	}, wallet.Dependencies{
		// wallet.New never actually dials out — it only needs a non-nil
		// HTTPClient to validate Dependencies, so http.DefaultClient (a
		// real *http.Client, which trivially satisfies the interface)
		// stands in rather than a test-only fake this package has no
		// other use for.
		HTTP:  http.DefaultClient,
		Clock: wallet.ClockFunc(time.Now),
	})
	if err != nil {
		t.Fatalf("wallet.New: %v", err)
	}
}
