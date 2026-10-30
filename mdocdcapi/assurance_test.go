package mdocdcapi_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/mdocdcapi"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// exchange is one org-iso-mdoc exchange up to the response: an mDL
// issued under an IACA, carrying a status reference, answered for
// origin. It returns what VerifyResponse takes, the roots that trust
// the IACA, and the document signer's certificate.
func exchange(t *testing.T) (mdocdcapi.VerifyParams, *x509.CertPool, *x509.Certificate) {
	t.Helper()
	return exchangeAt(t, "https://shop.example")
}

// exchangeAt is exchange from a page at origin, which the VerifyParams
// lists as the Verifier's Origins.
func exchangeAt(t *testing.T, origin string) (mdocdcapi.VerifyParams, *x509.CertPool, *x509.Certificate) {
	t.Helper()
	const (
		docType = "org.iso.18013.5.1.mDL"
		ns      = "org.iso.18013.5.1"
	)
	iaca, iacaKey := newCA("Test IACA")
	ds, dsKey := newLeaf("Test Document Signer", iaca, iacaKey, mdoc.MDLDocumentSignerEKU)
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	issuerSigned, err := mdoc.Issue(dsKey, oid4vci.COSEES256, mdoc.Claims{
		DocType: docType, NameSpaces: map[string]map[string]any{ns: {"age_over_18": true}}, DeviceKey: &deviceKey.PublicKey,
		Signed: now, ValidFrom: now, ValidUntil: now.Add(time.Hour),
		Status: &mdoc.StatusListRef{Idx: 7, URI: "https://issuer.example/status"},
	}, mdoc.IssueOptions{X5Chain: [][]byte{ds.Raw}})
	if err != nil {
		t.Fatal(err)
	}
	req, err := mdocdcapi.BuildRequest(mdocdcapi.RequestParams{Origin: origin, DocType: docType, Elements: map[string]map[string]bool{ns: {"age_over_18": false}}})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(req.Data)
	if err != nil {
		t.Fatal(err)
	}
	in, err := mdocdcapi.ParseRequest(data, origin)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := in.Respond(0, issuerSigned, deviceKey, [][2]string{{ns, "age_over_18"}})
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(iaca)
	return mdocdcapi.VerifyParams{
		Pending: req.Pending, Response: base64.RawURLEncoding.EncodeToString(encrypted),
		IssuerKeys: verifier.X5ChainIssuerKeyResolver{Roots: roots, Revocation: certrevocation.NoCheck{}},
		Origins:    []string{origin},
	}, roots, ds
}

// keyOnlyResolver authenticates the issuer key alone: it verifies no
// chain, though it declares itself hardened.
type keyOnlyResolver struct {
	inner verifier.X5ChainIssuerKeyResolver
}

func (r keyOnlyResolver) ResolveMdocIssuerKey(ctx context.Context, x5chain [][]byte, docType string) (crypto.PublicKey, oid4vci.COSEAlg, error) {
	return r.inner.ResolveMdocIssuerKey(ctx, x5chain, docType)
}

func (keyOnlyResolver) Capabilities() verifier.KeySourceCapabilities {
	return verifier.KeySourceCapabilities{LiveFetchHardened: true}
}

// wrappingResolver is keyOnlyResolver unwrapping to the resolver it
// delegates to, as a caching or logging layer would.
type wrappingResolver struct{ keyOnlyResolver }

func (w wrappingResolver) Unwrap() verifier.MdocIssuerKeyResolver { return w.inner }

// systemPool is a copy of the system root pool, skipping without one.
func systemPool(t *testing.T) *x509.CertPool {
	t.Helper()
	system, err := x509.SystemCertPool()
	if err != nil {
		t.Skipf("no system root pool: %v", err)
	}
	return system
}

// VerifyResponse needs an Assurance, and under AssuranceProduction the
// decisions verifier.VerifyResponse needs there: an issuer key source
// that verifies chains, which issuers may issue the doctype, and
// whether revocation is checked.
func TestVerifyResponse_ProductionDecisions(t *testing.T) {
	ctx := context.Background()
	accept := func(context.Context, string, verifier.VerifyResponseResult) error { return nil }
	for name, tc := range map[string]struct {
		mutate  func(*mdocdcapi.VerifyParams)
		wantErr string
	}{
		"no assurance": {func(*mdocdcapi.VerifyParams) {}, "Assurance is required"},
		"no issuer decision": {func(p *mdocdcapi.VerifyParams) {
			p.Assurance, p.Accept = verifier.AssuranceProduction, accept
		}, "AnyIssuerForAnyType"},
		"no status decision": {func(p *mdocdcapi.VerifyParams) {
			p.Assurance, p.AnyIssuerForAnyType = verifier.AssuranceProduction, true
		}, "NoStatusCheck"},
		// An Accept may check business rules alone: it doesn't decide
		// revocation.
		"an Accept alone": {func(p *mdocdcapi.VerifyParams) {
			p.Assurance, p.AnyIssuerForAnyType, p.Accept = verifier.AssuranceProduction, true, accept
		}, "NoStatusCheck"},
		"Status and NoStatusCheck": {func(p *mdocdcapi.VerifyParams) {
			p.Assurance, p.AnyIssuerForAnyType, p.NoStatusCheck = verifier.AssuranceProduction, true, true
			p.Status = &verifier.StatusPolicy{Checker: statuslist.Checker{Roots: x509.NewCertPool(), Options: statuslist.VerifyOptions{Revocation: certrevocation.NoCheck{}}}}
		}, "not both"},
		"an unhardened status fetcher": {func(p *mdocdcapi.VerifyParams) {
			p.Assurance, p.AnyIssuerForAnyType = verifier.AssuranceProduction, true
			p.Status = &verifier.StatusPolicy{Checker: statuslist.Checker{
				Fetcher: statuslist.Fetcher{AllowPrivate: true}, Roots: x509.NewCertPool(), Options: statuslist.VerifyOptions{Revocation: certrevocation.NoCheck{}},
			}}
		}, "HardenedForProduction"},
		"no chain": {func(p *mdocdcapi.VerifyParams) {
			p.Assurance, p.AnyIssuerForAnyType, p.NoStatusCheck = verifier.AssuranceProduction, true, true
			p.IssuerKeys = keyOnlyResolver{p.IssuerKeys.(verifier.X5ChainIssuerKeyResolver)}
		}, "verify issuer chains"},
		"decided": {func(p *mdocdcapi.VerifyParams) {
			p.Assurance, p.AnyIssuerForAnyType, p.NoStatusCheck = verifier.AssuranceProduction, true, true
		}, ""},
		"the system root pool": {func(p *mdocdcapi.VerifyParams) {
			p.Assurance, p.AnyIssuerForAnyType, p.NoStatusCheck = verifier.AssuranceProduction, true, true
			p.IssuerKeys = verifier.X5ChainIssuerKeyResolver{Roots: systemPool(t), Revocation: certrevocation.NoCheck{}}
		}, "system root pool"},
		"the system root pool, by pointer": {func(p *mdocdcapi.VerifyParams) {
			p.Assurance, p.AnyIssuerForAnyType, p.NoStatusCheck = verifier.AssuranceProduction, true, true
			p.IssuerKeys = &verifier.X5ChainIssuerKeyResolver{Roots: systemPool(t), Revocation: certrevocation.NoCheck{}}
		}, "system root pool"},
		"the system root pool, for a doctype": {func(p *mdocdcapi.VerifyParams) {
			p.Assurance, p.AnyIssuerForAnyType, p.NoStatusCheck = verifier.AssuranceProduction, true, true
			roots := p.IssuerKeys.(verifier.X5ChainIssuerKeyResolver).Roots
			p.IssuerKeys = verifier.X5ChainIssuerKeyResolver{
				Roots: roots, RootsByDocType: map[string]*x509.CertPool{"org.iso.18013.5.1.mDL": systemPool(t)}, Revocation: certrevocation.NoCheck{},
			}
		}, "system root pool"},
		"the system root pool, wrapped": {func(p *mdocdcapi.VerifyParams) {
			p.Assurance, p.AnyIssuerForAnyType, p.NoStatusCheck = verifier.AssuranceProduction, true, true
			p.IssuerKeys = wrappingResolver{keyOnlyResolver{inner: verifier.X5ChainIssuerKeyResolver{Roots: systemPool(t), Revocation: certrevocation.NoCheck{}}}}
		}, "system root pool"},
		"a wrapped resolver": {func(p *mdocdcapi.VerifyParams) {
			p.Assurance, p.AnyIssuerForAnyType, p.NoStatusCheck = verifier.AssuranceProduction, true, true
			p.IssuerKeys = wrappingResolver{keyOnlyResolver{inner: p.IssuerKeys.(verifier.X5ChainIssuerKeyResolver)}}
		}, ""},
		"no origins": {func(p *mdocdcapi.VerifyParams) {
			p.Assurance, p.AnyIssuerForAnyType, p.NoStatusCheck, p.Origins = verifier.AssuranceProduction, true, true, nil
		}, "set Origins"},
		"development": {func(p *mdocdcapi.VerifyParams) { p.Assurance, p.Origins = verifier.AssuranceDevelopment, nil }, ""},
		// Revocation is required at every level, and applied: the IACA
		// here publishes no CRL, so CRLs fails closed.
		"no revocation": {func(p *mdocdcapi.VerifyParams) {
			p.Assurance = verifier.AssuranceDevelopment
			p.IssuerKeys = verifier.X5ChainIssuerKeyResolver{Roots: p.IssuerKeys.(verifier.X5ChainIssuerKeyResolver).Roots}
		}, "Revocation is required"},
		"no current CRL": {func(p *mdocdcapi.VerifyParams) {
			p.Assurance = verifier.AssuranceDevelopment
			p.IssuerKeys = verifier.X5ChainIssuerKeyResolver{
				Roots:      p.IssuerKeys.(verifier.X5ChainIssuerKeyResolver).Roots,
				Revocation: certrevocation.CRLs{Lists: func(context.Context) ([]*x509.RevocationList, error) { return nil, nil }},
			}
		}, "no current CRL"},
	} {
		p, _, _ := exchange(t)
		tc.mutate(&p)
		_, err := mdocdcapi.VerifyResponse(ctx, p)
		switch {
		case tc.wantErr == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
			t.Errorf("%s: %v, want an error naming %q", name, err, tc.wantErr)
		}
	}
}

// A request built for an origin the Verifier doesn't serve — one taken
// from the request, say — can't be answered: BuildRequest refuses it
// when Origins are set, and VerifyResponse refuses its response. An
// http page's request is answered only under AssuranceDevelopment.
func TestOrigins(t *testing.T) {
	ctx := context.Background()
	elements := map[string]map[string]bool{"org.iso.18013.5.1": {"age_over_18": false}}
	if _, err := mdocdcapi.BuildRequest(mdocdcapi.RequestParams{
		Origin: "https://evil.example", Origins: []string{"https://shop.example"}, DocType: "org.iso.18013.5.1.mDL", Elements: elements,
	}); err == nil || !strings.Contains(err.Error(), "Origins") {
		t.Errorf("BuildRequest for an origin not in Origins: %v", err)
	}

	decided := func(p *mdocdcapi.VerifyParams) {
		p.Assurance, p.AnyIssuerForAnyType, p.NoStatusCheck = verifier.AssuranceProduction, true, true
	}
	p, _, _ := exchangeAt(t, "https://evil.example")
	decided(&p)
	p.Origins = []string{"https://shop.example"}
	if _, err := mdocdcapi.VerifyResponse(ctx, p); err == nil || !strings.Contains(err.Error(), "Origins") {
		t.Errorf("a response to a request for an origin not in Origins: %v", err)
	}
	p.Assurance, p.Origins = verifier.AssuranceDevelopment, []string{"https://shop.example"}
	if _, err := mdocdcapi.VerifyResponse(ctx, p); err == nil {
		t.Error("under development, a response to a request for an origin not in Origins: accepted")
	}

	p, _, _ = exchangeAt(t, "http://localhost:8080")
	decided(&p)
	p.Origins = nil
	if _, err := mdocdcapi.VerifyResponse(ctx, p); err == nil || !strings.Contains(err.Error(), "Origins") {
		t.Errorf("under production without Origins: %v", err)
	}
	p.Origins = []string{"http://localhost:8080"}
	if _, err := mdocdcapi.VerifyResponse(ctx, p); err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("a loopback http origin under production: %v", err)
	}
	p.Assurance = verifier.AssuranceDevelopment
	if _, err := mdocdcapi.VerifyResponse(ctx, p); err != nil {
		t.Errorf("a loopback http origin under development: %v", err)
	}
	// Only loopback http, even under development: a browser offers the
	// Digital Credentials API to no other http page. BuildRequest
	// refuses to build such a request; a Pending carrying one is
	// refused too.
	if _, err := mdocdcapi.BuildRequest(mdocdcapi.RequestParams{Origin: "http://shop.example", DocType: "org.iso.18013.5.1.mDL", Elements: elements}); err == nil {
		t.Error("BuildRequest for a non-loopback http origin: accepted")
	}
	for name, origin := range map[string]string{
		"a non-loopback http": "http://shop.example",
		"an uppercase host":   "https://Shop.example",
		"a default port":      "https://shop.example:443",
		"a trailing slash":    "https://shop.example/",
		"not a URL":           "https://shop.example:port",
	} {
		p, _, _ := exchange(t)
		p.Assurance, p.Pending.Origin, p.Origins = verifier.AssuranceDevelopment, origin, nil
		if _, err := mdocdcapi.VerifyResponse(ctx, p); err == nil || !strings.Contains(err.Error(), "origin") {
			t.Errorf("a Pending.Origin with %s (%q): %v", name, origin, err)
		}
	}
}

// Origins are normalized as a browser serializes an origin, in
// BuildRequest's Origin and Origins and in VerifyParams.Origins alike,
// and an entry that's no page's origin is refused.
func TestOriginsNormalized(t *testing.T) {
	ctx := context.Background()
	req, err := mdocdcapi.BuildRequest(mdocdcapi.RequestParams{
		Origin: "HTTPS://Shop.Example:443/", Origins: []string{"https://SHOP.example/"},
		DocType: "org.iso.18013.5.1.mDL", Elements: map[string]map[string]bool{"org.iso.18013.5.1": {"age_over_18": false}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if req.Pending.Origin != "https://shop.example" {
		t.Errorf("Pending.Origin = %q, want the normalized https://shop.example", req.Pending.Origin)
	}

	p, _, _ := exchange(t)
	p.Assurance = verifier.AssuranceDevelopment
	p.Origins = []string{"https://Shop.Example:443"}
	if _, err := mdocdcapi.VerifyResponse(ctx, p); err != nil {
		t.Errorf("Origins spelled otherwise than the browser does: %v", err)
	}
	for _, origins := range [][]string{{"shop.example"}, {"https://shop.example/app"}, {"http://shop.example"}} {
		p.Origins = origins
		if _, err := mdocdcapi.VerifyResponse(ctx, p); err == nil || !strings.Contains(err.Error(), "Origins") {
			t.Errorf("Origins %q: %v, want refused", origins, err)
		}
	}
}

// Accept sees the document as a verifier.VerifiedCredential, with its
// status reference and the issuer chain its status list can be bound
// to (verifier.StatusPolicy), and its error refuses the response.
func TestVerifyResponse_Accept(t *testing.T) {
	ctx := context.Background()
	p, _, ds := exchange(t)
	p.Assurance, p.AnyIssuerForAnyType, p.NoStatusCheck = verifier.AssuranceProduction, true, true
	var seen verifier.VerifyResponseResult
	p.Accept = func(_ context.Context, id string, result verifier.VerifyResponseResult) error {
		seen = result
		return nil
	}
	verified, err := mdocdcapi.VerifyResponse(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(seen.Credentials) != 1 {
		t.Fatalf("Accept saw %+v, want one credential", seen)
	}
	vc := seen.Credentials[0]
	ref, cwt, ok, err := vc.StatusListRef()
	if err != nil || !ok || !cwt || ref.URI != "https://issuer.example/status" || ref.Idx != 7 {
		t.Errorf("StatusListRef = %+v, %v, %v, %v", ref, cwt, ok, err)
	}
	if len(vc.IssuerChain) == 0 || !bytes.Equal(vc.IssuerChain[0], ds.Raw) || len(verified.IssuerChain) != len(vc.IssuerChain) {
		t.Errorf("IssuerChain = %d certificates, want the document signer's path", len(vc.IssuerChain))
	}
	if ns, ok := vc.Claims["org.iso.18013.5.1"].(map[string]any); !ok || ns["age_over_18"] != true {
		t.Errorf("Claims = %v", vc.Claims)
	}

	revoked := errors.New("revoked")
	p, _, _ = exchange(t)
	p.Assurance, p.AnyIssuerForAnyType, p.NoStatusCheck = verifier.AssuranceProduction, true, true
	p.Accept = func(context.Context, string, verifier.VerifyResponseResult) error { return revoked }
	if _, err := mdocdcapi.VerifyResponse(ctx, p); !errors.Is(err, revoked) {
		t.Errorf("Accept refusing: %v, want its error", err)
	}
}

// Status checks the document's status before Accept runs: a status
// list that can't be fetched refuses the response, and Accept never
// sees it.
func TestVerifyResponse_StatusBeforeAccept(t *testing.T) {
	p, _, _ := exchange(t)
	unreachable := errors.New("unreachable")
	p.Assurance, p.AnyIssuerForAnyType = verifier.AssuranceDevelopment, true
	p.Status = &verifier.StatusPolicy{Checker: statuslist.Checker{
		Fetcher: statuslist.Fetcher{HTTP: &http.Client{Transport: failingTransport{unreachable}}}, Roots: x509.NewCertPool(),
	}}
	accepted := false
	p.Accept = func(context.Context, string, verifier.VerifyResponseResult) error {
		accepted = true
		return nil
	}
	if _, err := mdocdcapi.VerifyResponse(context.Background(), p); err == nil || accepted {
		t.Errorf("VerifyResponse = %v, Accept ran %v; want refused by Status before Accept", err, accepted)
	}
}

// failingTransport fails every request with err.
type failingTransport struct{ err error }

func (f failingTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, f.err }
