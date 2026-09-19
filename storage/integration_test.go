package storage_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/storage"
)

// accessTokenStub is a minimal issuer.AccessTokenIssuer test double —
// this package deliberately doesn't provide one of its own (see
// issuer.AccessTokenIssuer's own doc comment: minting a real access
// token is entirely a deployment's own concern), so
// TestStoresSatisfyIssuerDependencies supplies just enough to satisfy
// issuer.New's own validation when wiring the Pre-Authorized Code Flow.
type accessTokenStub struct{}

func (accessTokenStub) IssueAccessToken(context.Context, issuer.AccessTokenParams) (string, string, error) {
	return "", "", nil
}

// TestStoresSatisfyIssuerDependencies wires every store in this
// package into issuer.New with every optional endpoint and flow
// enabled — this package's real purpose, and the simplest way to keep
// each store's method set from silently drifting out of sync with
// what issuer actually requires.
func TestStoresSatisfyIssuerDependencies(t *testing.T) {
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
	deferredEndpoint, err := fapi.ParseEndpointURL("https://issuer.example.com/deferred_credential")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	notificationEndpoint, err := fapi.ParseEndpointURL("https://issuer.example.com/notification")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	credentialOfferEndpoint, err := fapi.ParseEndpointURL("https://issuer.example.com/credential-offer")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}

	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	_, err = issuer.New(issuer.Config{
		Assurance: issuer.AssuranceDevelopment,
		Issuer:    issuerURL,
		Endpoints: issuer.Endpoints{
			Credential:         credentialEndpoint,
			Nonce:              nonceEndpoint,
			DeferredCredential: deferredEndpoint,
			Notification:       notificationEndpoint,
		},
		Limits: issuer.Limits{
			NonceLifetime:                time.Minute,
			CredentialOfferLifetime:      time.Hour,
			DeferredIssuancePollInterval: 10 * time.Second,
			AccessTokenLifetime:          time.Hour,
			MaxDPoPProofAge:              time.Minute,
			MaxTxCodeAttempts:            3,
			MaxDPoPClockSkew:             time.Minute,
			DPoPNonceLifetime:            time.Minute,
		},
		CredentialOfferEndpoint: credentialOfferEndpoint,
		CredentialConfigurationsSupported: map[string]issuer.CredentialConfiguration{
			"IdentityCredential": {
				Format:                               "dc+sd-jwt",
				CryptographicBindingMethodsSupported: []string{"jwk"},
				ProofTypesSupported: map[string]oid4vci.ProofTypeConfiguration{
					oid4vci.ProofTypeJWT: {ProofSigningAlgValuesSupported: []string{"ES256"}},
				},
			},
		},
	}, issuer.Dependencies{
		Nonces:               storage.NewNonceStore(),
		CredentialOffers:     storage.NewCredentialOfferStore(),
		DeferredTransactions: storage.NewDeferredTransactionStore(),
		Notifications:        storage.NewNotificationStore(),
		PreAuthorizedCodes:   storage.NewPreAuthorizedCodeStore(),
		DPoPReplay:           storage.NewDPoPReplayChecker(),
		DPoPNonces:           storage.NewDPoPNonceStore(),
		AccessTokens:         accessTokenStub{},
		Clock:                issuer.ClockFunc(time.Now),
		Random:               rand.Reader,
		SDJWTSigner:          &issuer.SDJWTSigner{Signer: signer, Alg: jose.ES256},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
}
