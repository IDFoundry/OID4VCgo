package verifier_test

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/internal/testverify"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// overDisclosureFixture is a verifier and a held SD-JWT VC with
// selectively disclosable claims at the top level, nested in an object
// and as array elements, besides one that's always disclosed.
type overDisclosureFixture struct {
	v        *verifier.Verifier
	held     wallet.HeldCredential
	resolver fixedSDJWTVCIssuerKeyResolver
	nonce    string
}

func newOverDisclosureFixture(t *testing.T) overDisclosureFixture {
	t.Helper()
	_, _, v := newTestVerifierWithConfig(t)
	issuerKey, holderKey := testP256Key(t), testP256Key(t)
	holderJWK, err := jwkFromECDSA(&holderKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	cred, _, err := sdjwtvc.Issue(issuerKey, jose.ES256, sdjwtvc.Claims{
		VCT: testVCT, CNF: map[string]any{"jwk": holderJWK},
		Additional: map[string]any{
			"given_name": sdjwtvc.SD("Jean"), "national_id": sdjwtvc.SD("123-45-6789"), "family_name": "Dupont",
			"address":       sdjwtvc.SD(map[string]any{"country": sdjwtvc.SD("FR"), "street_address": sdjwtvc.SD("1 rue de la Paix")}),
			"nationalities": []any{sdjwtvc.SDElement("FR"), sdjwtvc.SDElement("DE")},
		},
	}, sdjwtvc.IssueOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return overDisclosureFixture{
		v: v, held: wallet.HeldCredential{Format: sdjwtvc.CredentialFormat, Credential: cred, HolderKey: holderKey, HolderKeyAlg: jose.ES256},
		resolver: fixedSDJWTVCIssuerKeyResolver{pub: &issuerKey.PublicKey, alg: jose.ES256}, nonce: "nonce-over-disclosure",
	}
}

// verify presents the credential disclosing disclosed (every disclosure
// when nil) and verifies it against a query asking for asked.
func (f overDisclosureFixture) verify(t *testing.T, asked, disclosed []dcql.Path, allow bool) (verifier.VerifyResponseResult, error) {
	t.Helper()
	var presented string
	var err error
	if disclosed == nil {
		presented, err = wallet.PresentSDJWTVC(f.held, f.v.ClientID(), f.nonce)
	} else {
		presented, err = wallet.PresentSDJWTVCSelective(f.held, f.v.ClientID(), f.nonce, disclosed)
	}
	if err != nil {
		t.Fatalf("present: %v", err)
	}
	query := testIdentityQuery(t)
	query.Credentials[0].Claims = nil
	for _, path := range asked {
		query.Credentials[0].Claims = append(query.Credentials[0].Claims, dcql.ClaimsQuery{Path: path})
	}
	return f.v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query:         query,
		Response:      verifier.ParsedResponse{VPToken: map[string][]string{"identity_credential": {presented}}},
		ExpectedNonce: f.nonce, IssuerKeys: f.resolver, MaxKeyBindingAge: time.Hour, AllowUnrequestedClaims: allow,
	})
}

func path(elements ...any) dcql.Path {
	p := make(dcql.Path, len(elements))
	for i, e := range elements {
		switch e := e.(type) {
		case string:
			p[i] = dcql.PathKey(e)
		case int:
			p[i] = dcql.PathIndex(e)
		default:
			p[i] = dcql.Wildcard
		}
	}
	return p
}

// TestVerifyResponse_RefusesUnrequestedSDJWTVCClaims: a presentation
// disclosing a selectively disclosable claim the query didn't ask for
// — as wallet.PresentSDJWTVC's full disclosure does — is discarded as
// ReasonUnrequestedClaims, unless AllowUnrequestedClaims; one disclosing
// what was asked, and what that needs, verifies.
func TestVerifyResponse_RefusesUnrequestedSDJWTVCClaims(t *testing.T) {
	f := newOverDisclosureFixture(t)
	givenName, country := path("given_name"), path("address", "country")

	refused := map[string]struct{ asked, disclosed []dcql.Path }{
		"everything, for given_name":                     {[]dcql.Path{givenName}, nil},
		"national_id too":                                {[]dcql.Path{givenName}, []dcql.Path{givenName, path("national_id")}},
		"the street, for the country":                    {[]dcql.Path{country}, []dcql.Path{path("address")}},
		"a selectively disclosable claim, for no claims": {nil, []dcql.Path{givenName}},
		"a nationality, for the address":                 {[]dcql.Path{country}, []dcql.Path{country, path("nationalities", 0)}},
	}
	for name, c := range refused {
		_, err := f.verify(t, c.asked, c.disclosed, false)
		var verr *verifier.Error
		if !errors.As(err, &verr) || verr.Reason() != verifier.ReasonUnrequestedClaims {
			t.Errorf("%s: %v, want ReasonUnrequestedClaims", name, err)
		}
	}

	accepted := map[string]struct{ asked, disclosed []dcql.Path }{
		"given_name":                              {[]dcql.Path{givenName}, []dcql.Path{givenName}},
		"the address object, and what it holds":   {[]dcql.Path{path("address")}, []dcql.Path{path("address")}},
		"the country, and the address it's in":    {[]dcql.Path{country}, []dcql.Path{country}},
		"no claims: those always disclosed alone": {nil, []dcql.Path{}},
		"every nationality":                       {[]dcql.Path{path("nationalities", nil)}, []dcql.Path{path("nationalities", nil)}},
		"the first nationality":                   {[]dcql.Path{path("nationalities", 0)}, []dcql.Path{path("nationalities", 0)}},
	}
	for name, c := range accepted {
		result, err := f.verify(t, c.asked, c.disclosed, false)
		vc := testverify.RequireOneCredential(t, result, err, "identity_credential")
		if vc.Claims["family_name"] != "Dupont" {
			t.Errorf("%s: claims %v, want the always-disclosed family_name", name, vc.Claims)
		}
	}

	// The option keeps the earlier behavior.
	result, err := f.verify(t, []dcql.Path{givenName}, nil, true)
	if vc := testverify.RequireOneCredential(t, result, err, "identity_credential"); vc.Claims["national_id"] != "123-45-6789" {
		t.Errorf("AllowUnrequestedClaims: claims %v, want national_id kept", vc.Claims)
	}
}

// TestVerifyResponse_RefusesUnrequestedMdocElements: an mdoc disclosing
// an element the query didn't ask for is discarded, as mdocdcapi
// refuses one, unless AllowUnrequestedClaims.
func TestVerifyResponse_RefusesUnrequestedMdocElements(t *testing.T) {
	mf := newMdocVerifyFixture(t)
	mf.query = testmdoc.Query(t) // given_name only; testmdoc.Present discloses family_name too
	_, err := mf.verify(t, mf.nonce)
	var verr *verifier.Error
	if !errors.As(err, &verr) || verr.Reason() != verifier.ReasonUnrequestedClaims {
		t.Errorf("an mdoc disclosing family_name, unasked: %v, want ReasonUnrequestedClaims", err)
	}
	result, err := mf.verifyWith(t, mf.nonce, func(r *verifier.VerifyResponseRequest) { r.AllowUnrequestedClaims = true })
	assertMdocGivenNameAlice(t, result, err)
}

// TestTransactions_RefusesOverDisclosure: Transactions records an
// over-disclosing answer as refused and leaves the request open, so
// the Verifier never stores claims it didn't ask for.
func TestTransactions_RefusesOverDisclosure(t *testing.T) {
	ctx := context.Background()
	f := newTxFixture(t, nil)
	ca, caKey := testcert.CA(t, "over-disclosure CA")
	issuerCert, issuerKey := testcert.Leaf(t, "over-disclosure issuer", ca, caKey)
	holderKey := testP256Key(t)
	holderJWK, err := jwkFromECDSA(&holderKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	cred, _, err := sdjwtvc.Issue(issuerKey, jose.ES256, sdjwtvc.Claims{
		VCT: "urn:tx:1", CNF: map[string]any{"jwk": holderJWK},
		Additional: map[string]any{"given_name": sdjwtvc.SD("Jean"), "national_id": sdjwtvc.SD("123-45-6789")},
	}, sdjwtvc.IssueOptions{IssuerCertificate: issuerCert})
	if err != nil {
		t.Fatal(err)
	}
	f.held = wallet.HeldCredential{Format: sdjwtvc.CredentialFormat, Credential: cred, HolderKey: holderKey, HolderKeyAlg: jose.ES256}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	verify := f.verify
	verify.IssuerKeys = verifier.X5CIssuerKeyResolver{Roots: roots, Revocation: certrevocation.NoCheck{}}
	if f.txs, err = verifier.NewTransactions(f.v, f.store, verifier.TransactionsConfig{RequestURIBase: txBase, Verify: verify}); err != nil {
		t.Fatal(err)
	}

	begun := f.begin("browser-binding-over-01", false)
	full := f.answerWith(begun, nil, func(req wallet.AuthorizationRequest) (map[string][]string, error) {
		presented, err := wallet.PresentSDJWTVC(f.held, req.ClientID, req.Nonce)
		return map[string][]string{"cred": {presented}}, err
	})
	_, err = f.txs.HandleResponse(ctx, full)
	var verr *verifier.Error
	if !errors.As(err, &verr) || verr.Reason() != verifier.ReasonUnrequestedClaims {
		t.Fatalf("HandleResponse of an answer disclosing national_id, unasked: %v, want ReasonUnrequestedClaims", err)
	}
	view, err := f.txs.Lookup(ctx, begun.ID, "browser-binding-over-01")
	if err != nil || view.Status != verifier.TransactionPending || view.Result != nil || view.LastError == "" {
		t.Errorf("Lookup = %+v, %v; want still pending, the refusal recorded", view, err)
	}
	if _, err := f.txs.HandleResponse(ctx, f.answer(begun, nil)); err != nil {
		t.Errorf("a minimal answer after the refused one: %v", err)
	}
}
