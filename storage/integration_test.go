package storage_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcigo"
	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/issuer"
	"github.com/idfoundry/oid4vcigo/storage"
)

// TestStoresSatisfyIssuerDependencies wires every store in this
// package into issuer.New with every optional endpoint enabled — this
// package's real purpose, and the simplest way to keep each store's
// method set from silently drifting out of sync with what issuer
// actually requires.
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
		Issuer: issuerURL,
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
		},
		CredentialOfferEndpoint: credentialOfferEndpoint,
		CredentialConfigurationsSupported: map[string]issuer.CredentialConfiguration{
			"IdentityCredential": {
				Format:                               "dc+sd-jwt",
				CryptographicBindingMethodsSupported: []string{"jwk"},
				ProofTypesSupported: map[string]issuer.ProofTypeConfiguration{
					oid4vci.ProofTypeJWT: {ProofSigningAlgValuesSupported: []string{"ES256"}},
				},
			},
		},
	}, issuer.Dependencies{
		Nonces:               storage.NewNonceStore(),
		CredentialOffers:     storage.NewCredentialOfferStore(),
		DeferredTransactions: storage.NewDeferredTransactionStore(),
		Notifications:        storage.NewNotificationStore(),
		Clock:                issuer.ClockFunc(time.Now),
		Random:               rand.Reader,
		SDJWTSigner:          &issuer.SDJWTSigner{Signer: signer, Alg: jose.ES256},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
}
