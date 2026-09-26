package verifier_test

import (
	"context"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo/verifier"
)

func TestNewRejectsInvalidAssurance(t *testing.T) {
	for _, level := range []verifier.AssuranceLevel{0, 99} {
		cfg, deps := validConfig(t)
		cfg.Assurance = level
		if _, err := verifier.New(cfg, deps); err == nil {
			t.Errorf("New(Assurance=%d) = nil error, want error", level)
		}
	}
}

func loopbackResponseURI(t *testing.T) fapi.URL {
	t.Helper()
	u, err := fapi.ParseEndpointURL("http://127.0.0.1:8080/response", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	return u
}

func TestNewLoopbackResponseURIByAssurance(t *testing.T) {
	cfg, deps := validConfig(t)
	cfg.ResponseURI = loopbackResponseURI(t)
	if _, err := verifier.New(cfg, deps); err != nil {
		t.Fatalf("New(AssuranceDevelopment, loopback http response_uri): %v", err)
	}

	cfg.Assurance = verifier.AssuranceProduction
	_, err := verifier.New(cfg, deps)
	if err == nil || !strings.Contains(err.Error(), "AllowLoopbackHTTP") {
		t.Fatalf("New(AssuranceProduction, loopback http response_uri) error = %v, want an AllowLoopbackHTTP rejection", err)
	}
}

func TestNewProductionAcceptsHTTPSResponseURI(t *testing.T) {
	cfg, deps := validConfig(t)
	cfg.Assurance = verifier.AssuranceProduction
	if _, err := verifier.New(cfg, deps); err != nil {
		t.Fatalf("New(AssuranceProduction): %v", err)
	}
}

// declaringSDJWTVCIssuerKeyResolver is fixedSDJWTVCIssuerKeyResolver
// plus a KeySourceAssurance declaration of hardened.
type declaringSDJWTVCIssuerKeyResolver struct {
	fixedSDJWTVCIssuerKeyResolver
	hardened bool
}

func (r declaringSDJWTVCIssuerKeyResolver) Capabilities() verifier.KeySourceCapabilities {
	return verifier.KeySourceCapabilities{LiveFetchHardened: r.hardened}
}

func TestVerifyResponseKeySourceAssurance(t *testing.T) {
	roots := x509.NewCertPool()
	cases := []struct {
		name       string
		assurance  verifier.AssuranceLevel
		req        verifier.VerifyResponseRequest
		wantReject string // "" means the assurance check must not reject
	}{
		{
			name: "production, undeclared issuer_keys", assurance: verifier.AssuranceProduction,
			req:        verifier.VerifyResponseRequest{IssuerKeys: fixedSDJWTVCIssuerKeyResolver{}},
			wantReject: "issuer_keys must implement verifier.KeySourceAssurance",
		},
		{
			name: "production, issuer_keys not hardened", assurance: verifier.AssuranceProduction,
			req:        verifier.VerifyResponseRequest{IssuerKeys: declaringSDJWTVCIssuerKeyResolver{}},
			wantReject: "issuer_keys must declare LiveFetchHardened",
		},
		{
			name: "production, X5CIssuerKeyResolver", assurance: verifier.AssuranceProduction,
			req: verifier.VerifyResponseRequest{IssuerKeys: verifier.X5CIssuerKeyResolver{Roots: roots}},
		},
		{
			name: "production, hardened issuer_keys", assurance: verifier.AssuranceProduction,
			req: verifier.VerifyResponseRequest{IssuerKeys: declaringSDJWTVCIssuerKeyResolver{hardened: true}},
		},
		{
			name: "production, X5ChainIssuerKeyResolver", assurance: verifier.AssuranceProduction,
			req: verifier.VerifyResponseRequest{MdocIssuerKeys: verifier.X5ChainIssuerKeyResolver{Roots: roots}},
		},
		{
			name: "development, undeclared issuer_keys", assurance: verifier.AssuranceDevelopment,
			req: verifier.VerifyResponseRequest{IssuerKeys: fixedSDJWTVCIssuerKeyResolver{}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, deps := validConfig(t)
			cfg.Assurance = tc.assurance
			v, err := verifier.New(cfg, deps)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			req := tc.req
			req.Query = testIdentityQuery(t)
			req.ExpectedNonce = "nonce"
			req.MaxKeyBindingAge = time.Hour

			// req carries no real response, so VerifyResponse always
			// fails; what matters is whether it fails on the assurance
			// check or gets past it.
			_, err = v.VerifyResponse(context.Background(), req)
			if err == nil {
				t.Fatal("VerifyResponse with an empty response = nil error, want error")
			}
			rejected := strings.Contains(err.Error(), "under AssuranceProduction")
			switch {
			case tc.wantReject != "" && !strings.Contains(err.Error(), tc.wantReject):
				t.Fatalf("error = %v, want it to contain %q", err, tc.wantReject)
			case tc.wantReject == "" && rejected:
				t.Fatalf("error = %v, want the assurance check to pass", err)
			}
		})
	}
}
