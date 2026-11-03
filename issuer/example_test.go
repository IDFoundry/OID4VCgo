package issuer_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	fapi "github.com/idfoundry/fapigo"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/issuer/fapiresource"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/storage"
)

// randomState is a 256-bit random issuer_state, base64url encoded.
func randomState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func exampleURL(parse func(string, ...fapi.URLOption) (fapi.URL, error), raw string) fapi.URL {
	u, err := parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}

// A Credential Issuer of one SD-JWT VC, with the endpoints it publishes
// and the stores it keeps, making a Credential Offer for the
// authorization code flow. In production, set Assurance to
// AssuranceProduction, which also requires durable stores (sqlstore's),
// a signer certificate issued by a CA, an Audit sink, and a status
// check on key attestations.
func ExampleNew() {
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	// Unguessable, and kept with the holder it's for: issuer_state names
	// the offer, but anyone the offer reaches can send it, so the
	// consent step authenticates the holder and checks it's this one.
	issuerState, err := randomState()
	if err != nil {
		panic(err)
	}
	iss, err := issuer.New(issuer.Config{
		Assurance: issuer.AssuranceDevelopment,
		Issuer:    exampleURL(fapi.ParseIssuerURL, "https://issuer.example.com"),
		Endpoints: issuer.Endpoints{
			Credential: exampleURL(fapi.ParseEndpointURL, "https://issuer.example.com/credential"),
			Nonce:      exampleURL(fapi.ParseEndpointURL, "https://issuer.example.com/nonce"),
		},
		Limits: issuer.Limits{NonceLifetime: time.Minute, CredentialOfferLifetime: time.Hour},
		CredentialConfigurationsSupported: map[string]issuer.CredentialConfiguration{
			"pid": {
				Format: sdjwtvc.CredentialFormat, Scope: "pid", VCT: "urn:eudi:pid:1",
				CryptographicBindingMethodsSupported: []string{"jwk"},
				CredentialSigningAlgValuesSupported:  []string{"ES256"},
				ProofTypesSupported: map[string]oid4vci.ProofTypeConfiguration{
					oid4vci.ProofTypeJWT: {ProofSigningAlgValuesSupported: []string{"ES256"}},
				},
			},
		},
	}, issuer.Dependencies{
		Random:      rand.Reader, // and a nil Clock, the system's
		SDJWTSigner: &issuer.SDJWTSigner{Signer: signer, Alg: oid4vci.ES256},
		Nonces:      storage.NewNonceStore(), CredentialOffers: storage.NewCredentialOfferStore(),
		DeferredTransactions: storage.NewDeferredTransactionStore(), Notifications: storage.NewNotificationStore(),
	})
	if err != nil {
		panic(err)
	}

	// Serve iss.Metadata() at /.well-known/openid-credential-issuer, and
	// the Credential Endpoint as ExampleIssuer_CredentialHandler shows.
	offer, err := iss.CreateCredentialOffer(context.Background(), issuer.CreateCredentialOfferRequest{
		CredentialConfigurationIDs: []string{"pid"},
		Grants:                     &oid4vci.Grants{AuthorizationCode: &oid4vci.GrantAuthorizationCode{IssuerState: issuerState}},
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(strings.SplitN(offer.URI, "?", 2)[0], iss.Metadata().CredentialIssuer)
	// Output: openid-credential-offer:// https://issuer.example.com
}

// The Credential Endpoint: tokens checks each request's access token
// and its DPoP proof, here with a fapigo resource verifier sharing the
// Authorization Server's keys (fapiresource.New). Prepare decides what
// to issue for the token's subject. The handler's URL is the
// Credential Endpoint Config.Endpoints publishes.
func ExampleIssuer_CredentialHandler() {
	var iss *issuer.Issuer            // from issuer.New, as in ExampleNew
	var tokens *fapiresource.Verifier // from fapiresource.New
	lookup := func(subject string) (string, bool) { return "Jean", subject != "" }

	handler, err := iss.CredentialHandler(issuer.CredentialHandlerConfig{
		Tokens: tokens,
		Prepare: func(_ context.Context, grant issuer.Grant, req *issuer.CredentialRequest) (func(bool), error) {
			givenName, ok := lookup(grant.Subject)
			if !ok {
				return nil, issuer.NewError(issuer.ErrorCredentialRequestDenied, "no credential for this holder")
			}
			req.SDJWTClaims = &sdjwtvc.Claims{
				VCT:        "urn:eudi:pid:1",
				Additional: map[string]any{"given_name": sdjwtvc.SD(givenName)},
			}
			return nil, nil
		},
	})
	if err != nil {
		panic(err)
	}
	http.Handle("POST /credential", handler)
}

// statusListAttestationStatus checks a key attestation's Token Status
// List reference: lists fetches and verifies the Status List Token,
// through its hardened statuslist.Fetcher, against the Wallet
// Providers' trust anchors.
type statusListAttestationStatus struct {
	lists statuslist.Checker
}

func (s statusListAttestationStatus) CheckAttestationStatus(ctx context.Context, a issuer.VerifiedKeyAttestation) error {
	if a.Claims.Status == nil {
		// This issuer's policy: every key attestation carries a status.
		return fmt.Errorf("%w: the key attestation has no status claim", issuer.ErrKeyAttestationRevoked)
	}
	ref, err := statuslist.ParseStatusClaim(a.Claims.Status)
	if err != nil {
		return fmt.Errorf("%w: %w", issuer.ErrKeyAttestationRevoked, err)
	}
	// Only the attestation's own signer, or a certificate naming its
	// issuer, may sign the list that decides it.
	lists := s.lists
	lists.Options.IssuerKey, lists.Options.Issuer = a.SignerKey, a.Claims.Issuer
	var notValid *statuslist.NotValidError
	err = lists.RequireValid(ctx, ref, false)
	if errors.As(err, &notValid) {
		return fmt.Errorf("%w: %w", issuer.ErrKeyAttestationRevoked, err)
	}
	// nil, or a list that couldn't be fetched or verified now: the
	// Credential Request is then a server error, and a deferred
	// transaction stays pending.
	return err
}

// An AttestationStatusChecker over Token Status Lists: an attestation
// whose list says it isn't VALID wraps ErrKeyAttestationRevoked, and a
// list that can't be fetched or verified now is a plain error.
func ExampleAttestationStatusChecker() {
	var walletProviderRoots *x509.CertPool // the Wallet Providers' CAs
	deps := issuer.Dependencies{
		AttestationStatus: statusListAttestationStatus{lists: statuslist.Checker{
			Fetcher: statuslist.Fetcher{}, // public addresses only: the uri is the attestation's
			Roots:   walletProviderRoots,
		}},
		// ... the rest of the issuer's dependencies, as in ExampleNew.
	}
	_ = deps
}
