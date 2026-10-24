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
	"strings"
	"testing"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/mdocdcapi"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// exchange is one org-iso-mdoc exchange up to the response: an mDL
// issued under an IACA, carrying a status reference, answered for
// origin. It returns what VerifyResponse takes, the roots that trust
// the IACA, and the document signer's certificate.
func exchange(t *testing.T) (mdocdcapi.VerifyParams, *x509.CertPool, *x509.Certificate) {
	t.Helper()
	const (
		origin  = "https://shop.example"
		docType = "org.iso.18013.5.1.mDL"
		ns      = "org.iso.18013.5.1"
	)
	iaca, iacaKey := newCA("Test IACA")
	ds, dsKey := newLeaf("Test Document Signer", iaca, iacaKey)
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
		"no chain": {func(p *mdocdcapi.VerifyParams) {
			p.Assurance, p.AnyIssuerForAnyType, p.NoStatusCheck = verifier.AssuranceProduction, true, true
			p.IssuerKeys = keyOnlyResolver{p.IssuerKeys.(verifier.X5ChainIssuerKeyResolver)}
		}, "verify issuer chains"},
		"decided": {func(p *mdocdcapi.VerifyParams) {
			p.Assurance, p.AnyIssuerForAnyType, p.NoStatusCheck = verifier.AssuranceProduction, true, true
		}, ""},
		"development": {func(p *mdocdcapi.VerifyParams) { p.Assurance = verifier.AssuranceDevelopment }, ""},
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

// Accept sees the document as a verifier.VerifiedCredential, with its
// status reference and the issuer chain its status list can be bound
// to (verifier.RequireValidStatus), and its error refuses the response.
func TestVerifyResponse_Accept(t *testing.T) {
	ctx := context.Background()
	p, _, ds := exchange(t)
	p.Assurance, p.AnyIssuerForAnyType = verifier.AssuranceProduction, true
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
	p.Assurance, p.AnyIssuerForAnyType = verifier.AssuranceProduction, true
	p.Accept = func(context.Context, string, verifier.VerifyResponseResult) error { return revoked }
	if _, err := mdocdcapi.VerifyResponse(ctx, p); !errors.Is(err, revoked) {
		t.Errorf("Accept refusing: %v, want its error", err)
	}
}
