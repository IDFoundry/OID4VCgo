package verifier_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
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
	caIssuedClientCert(t, &cfg, &deps)
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
	caIssuedClientCert(t, &cfg, &deps)
	cfg.Assurance = verifier.AssuranceProduction
	if _, err := verifier.New(cfg, deps); err != nil {
		t.Fatalf("New(AssuranceProduction): %v", err)
	}
}

// TestNewProductionRequiresCryptoRand: under AssuranceProduction every
// request secret must come from crypto/rand.Reader; a predictable
// reader would make nonces, response_codes and response keys
// guessable.
func TestNewProductionRequiresCryptoRand(t *testing.T) {
	cfg, deps := validConfig(t)
	caIssuedClientCert(t, &cfg, &deps)
	deps.Random = bytes.NewReader(make([]byte, 1<<16))
	if _, err := verifier.New(cfg, deps); err != nil {
		t.Fatalf("New(AssuranceDevelopment, another reader): %v", err)
	}
	cfg.Assurance = verifier.AssuranceProduction
	if _, err := verifier.New(cfg, deps); err == nil || !strings.Contains(err.Error(), "crypto/rand") {
		t.Errorf("New(AssuranceProduction, another reader) error = %v, want refused", err)
	}
}

// The enc values a Verifier advertises are ones it can decrypt, and in
// production include both of HAIP 1.0 §5's.
func TestNewValidatesEncValues(t *testing.T) {
	for name, tc := range map[string]struct {
		values     []oid4vci.JWEEnc
		production bool
		ok         bool
	}{
		"HAIP pair":           {values: []oid4vci.JWEEnc{oid4vci.A128GCM, oid4vci.A256GCM}, production: true, ok: true},
		"A256GCM alone, dev":  {values: []oid4vci.JWEEnc{oid4vci.A256GCM}, ok: true},
		"A256GCM alone, prod": {values: []oid4vci.JWEEnc{oid4vci.A256GCM}, production: true},
		"undecryptable":       {values: []oid4vci.JWEEnc{oid4vci.A128GCM, "A128CBC-HS256"}},
		"empty":               {},
	} {
		cfg, deps := validConfig(t)
		caIssuedClientCert(t, &cfg, &deps)
		cfg.EncValuesSupported = tc.values
		if tc.production {
			cfg.Assurance = verifier.AssuranceProduction
		}
		if _, err := verifier.New(cfg, deps); (err == nil) != tc.ok {
			t.Errorf("%s: New = %v, want ok=%v", name, err, tc.ok)
		}
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

// hardenedKeyOnlyResolver is a keyOnlyResolver, verifying no chain,
// that declares LiveFetchHardened.
type hardenedKeyOnlyResolver struct{ keyOnlyResolver }

func (hardenedKeyOnlyResolver) Capabilities() verifier.KeySourceCapabilities {
	return verifier.KeySourceCapabilities{LiveFetchHardened: true}
}

// wrappingResolver wraps another MdocIssuerKeyResolver, as a caching or
// logging layer would: it declares LiveFetchHardened and Unwraps to it.
type wrappingResolver struct {
	inner verifier.MdocIssuerKeyResolver
}

func (w wrappingResolver) ResolveMdocIssuerKey(ctx context.Context, x5chain [][]byte, docType string) (crypto.PublicKey, oid4vci.COSEAlg, error) {
	return w.inner.ResolveMdocIssuerKey(ctx, x5chain, docType)
}

func (wrappingResolver) Capabilities() verifier.KeySourceCapabilities {
	return verifier.KeySourceCapabilities{LiveFetchHardened: true}
}

func (w wrappingResolver) Unwrap() verifier.MdocIssuerKeyResolver { return w.inner }

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
			req: verifier.VerifyResponseRequest{IssuerKeys: verifier.X5CIssuerKeyResolver{Roots: roots, Revocation: certrevocation.NoCheck{}}},
		},
		{
			name: "production, hardened issuer_keys", assurance: verifier.AssuranceProduction,
			req: verifier.VerifyResponseRequest{IssuerKeys: declaringSDJWTVCIssuerKeyResolver{hardened: true}},
		},
		{
			name: "production, X5ChainIssuerKeyResolver", assurance: verifier.AssuranceProduction,
			req: verifier.VerifyResponseRequest{MdocIssuerKeys: verifier.X5ChainIssuerKeyResolver{Roots: roots, Revocation: certrevocation.NoCheck{}}},
		},
		{
			name: "production, undeclared mdoc_issuer_keys", assurance: verifier.AssuranceProduction,
			req:        verifier.VerifyResponseRequest{MdocIssuerKeys: keyOnlyResolver{verifier.X5ChainIssuerKeyResolver{Roots: roots, Revocation: certrevocation.NoCheck{}}}},
			wantReject: "mdoc_issuer_keys must implement verifier.KeySourceAssurance",
		},
		{
			name: "production, mdoc_issuer_keys verifying no chain", assurance: verifier.AssuranceProduction,
			req:        verifier.VerifyResponseRequest{MdocIssuerKeys: hardenedKeyOnlyResolver{keyOnlyResolver{verifier.X5ChainIssuerKeyResolver{Roots: roots, Revocation: certrevocation.NoCheck{}}}}},
			wantReject: "mdoc_issuer_keys must verify issuer chains",
		},
		{
			name: "production, a wrapped X5ChainIssuerKeyResolver", assurance: verifier.AssuranceProduction,
			req: verifier.VerifyResponseRequest{MdocIssuerKeys: wrappingResolver{verifier.X5ChainIssuerKeyResolver{Roots: roots, Revocation: certrevocation.NoCheck{}}}},
		},
		{
			name: "development, undeclared issuer_keys", assurance: verifier.AssuranceDevelopment,
			req: verifier.VerifyResponseRequest{IssuerKeys: fixedSDJWTVCIssuerKeyResolver{}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, deps := validConfig(t)
			caIssuedClientCert(t, &cfg, &deps)
			cfg.Assurance = tc.assurance
			v, err := verifier.New(cfg, deps)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			req := tc.req
			req.Query = testIdentityQuery(t)
			req.ExpectedNonce = "nonce"
			req.MaxKeyBindingAge = time.Hour
			req.AnyIssuerForAnyType, req.NoStatusCheck = true, true

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

// caIssuedClientCert gives cfg a CA-issued client certificate, with
// deps' signer its key: AssuranceProduction refuses a self-signed one.
func caIssuedClientCert(t *testing.T, cfg *verifier.Config, deps *verifier.Dependencies) {
	t.Helper()
	ca, caKey := testcert.CA(t, "verifier test CA")
	cert, key := testcert.Leaf(t, "verifier test", ca, caKey)
	cfg.ClientCertificate, deps.Signer = cert, key
}

// A direct VerifyResponse under AssuranceProduction must decide which
// issuers may issue which types, and whether revocation is checked, as
// Transactions must: left undecided, each accepts what it shouldn't.
func TestVerifyResponse_ProductionDecisions(t *testing.T) {
	cfg, deps := validConfig(t)
	caIssuedClientCert(t, &cfg, &deps)
	cfg.Assurance = verifier.AssuranceProduction
	v, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatal(err)
	}
	accept := func(context.Context, string, verifier.VerifyResponseResult) error { return nil }
	authorized := func(context.Context, verifier.IssuerAuthorization) error { return nil }
	status := productionStatus()
	for name, tc := range map[string]struct {
		set    func(*verifier.VerifyResponseRequest)
		refuse string
	}{
		"neither":                    {func(*verifier.VerifyResponseRequest) {}, "any_issuer_for_any_type"},
		"issuers decided, no status": {func(r *verifier.VerifyResponseRequest) { r.AnyIssuerForAnyType = true }, "NoStatusCheck"},
		"status decided, no issuers": {func(r *verifier.VerifyResponseRequest) { r.NoStatusCheck = true }, "any_issuer_for_any_type"},
		// A business-rules Accept doesn't decide revocation.
		"IssuerAuthorized and Accept": {func(r *verifier.VerifyResponseRequest) { r.IssuerAuthorized, r.Accept = authorized, accept }, "NoStatusCheck"},
		"IssuerAuthorized and Status": {func(r *verifier.VerifyResponseRequest) { r.IssuerAuthorized, r.Status = authorized, status }, ""},
		"Status and NoStatusCheck": {func(r *verifier.VerifyResponseRequest) {
			r.AnyIssuerForAnyType, r.Status, r.NoStatusCheck = true, status, true
		}, "not both"},
	} {
		req := verifier.VerifyResponseRequest{
			Query: testIdentityQuery(t), ExpectedNonce: "nonce", MaxKeyBindingAge: time.Hour,
			IssuerKeys: verifier.X5CIssuerKeyResolver{Roots: x509.NewCertPool(), Revocation: certrevocation.NoCheck{}},
		}
		tc.set(&req)
		_, err := v.VerifyResponse(context.Background(), req)
		switch {
		case tc.refuse != "" && (err == nil || !strings.Contains(err.Error(), tc.refuse)):
			t.Errorf("%s: %v, want refused naming %s", name, err, tc.refuse)
		case tc.refuse == "" && err != nil && strings.Contains(err.Error(), "under AssuranceProduction"):
			t.Errorf("%s: %v", name, err)
		}
	}
}

// MaxClockSkew and MaxKeyBindingAge are bounded: a year's skew would
// take a credential that expired long ago as current.
func TestVerifyResponse_TimeBounds(t *testing.T) {
	v := newTestVerifier(t)
	for name, req := range map[string]verifier.VerifyResponseRequest{
		"skew of a day":       {MaxClockSkew: 24 * time.Hour, MaxKeyBindingAge: time.Minute},
		"negative skew":       {MaxClockSkew: -time.Second, MaxKeyBindingAge: time.Minute},
		"KB-JWT age of a day": {MaxKeyBindingAge: 24 * time.Hour},
	} {
		req.Query, req.ExpectedNonce = testIdentityQuery(t), "nonce"
		req.IssuerKeys = verifier.X5CIssuerKeyResolver{Roots: x509.NewCertPool(), Revocation: certrevocation.NoCheck{}}
		if _, err := v.VerifyResponse(context.Background(), req); err == nil || !strings.Contains(err.Error(), "outside") {
			t.Errorf("%s: %v, want refused", name, err)
		}
	}
}
