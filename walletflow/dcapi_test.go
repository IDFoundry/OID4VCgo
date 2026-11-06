package walletflow_test

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

const dcapiOrigin = "https://verifier.walletflowtest.example"

func (v testVerifier) BeginDCAPI(t *testing.T, query dcql.Query, origin string) *walletflowtest.DCAPIRequest {
	t.Helper()
	r, err := v.Verifier.BeginDCAPI(query, origin)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// A signed DC API request is answered with no network request: the
// encrypted response, bound to the origin, goes back through the
// platform, and the page verifies it.
func TestDCAPIPresentation_Signed(t *testing.T) {
	f, v, w := presentationFixture(t)
	held := receive(t, f, w, walletflowtest.SDJWTConfigurationID, walletflowtest.MdocConfigurationID)
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		query dcql.CredentialQuery
		check func(verifier.VerifiedCredential) bool
	}{
		{"sd-jwt vc", f.env.SDJWTQuery(t, "pid", "given_name"), func(c verifier.VerifiedCredential) bool {
			return c.Claims["given_name"] == walletflowtest.GivenName
		}},
		{"mdoc", mdocQuery(t, "mdoc", "given_name"), func(c verifier.VerifiedCredential) bool {
			ns, _ := c.Claims[walletflowtest.NameSpace].(map[string]any)
			return ns["given_name"] == walletflowtest.GivenName
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := v.BeginDCAPI(t, dcql.Query{Credentials: []dcql.CredentialQuery{tc.query}}, dcapiOrigin)
			p, err := w.StartDCAPIPresentation(ctx, r.Protocol, r.Data, r.Origin)
			if err != nil {
				t.Fatal(err)
			}
			if got := p.Verifier(); got.Name != v.Name || got.Origin != dcapiOrigin || got.ResponseURI != "" {
				t.Errorf("Verifier = %+v", got)
			}
			sel, err := p.DefaultSelection(ctx)
			if err != nil {
				t.Fatal(err)
			}
			presented, err := p.Respond(ctx, sel)
			if err != nil {
				t.Fatal(err)
			}
			if len(presented.QueryIDs) != 1 || len(presented.DCAPIResponse) == 0 || presented.RedirectURI != "" {
				t.Fatalf("Presented = %+v", presented)
			}
			result, err := v.VerifyDCAPIResponse(ctx, r, presented.DCAPIResponse)
			if err != nil {
				t.Fatalf("the page refused the response: %v", err)
			}
			if len(result.Credentials) != 1 || !tc.check(result.Credentials[0]) {
				t.Errorf("verified = %+v", result.Credentials)
			}
			if _, err := p.Respond(ctx, sel); !errors.Is(err, walletflow.ErrWrongStep) {
				t.Errorf("Respond twice = %v, want ErrWrongStep", err)
			}
		})
	}
	// Each presentation used a copy, recorded as shown to this Verifier
	// at the origin, not to the origin alone.
	r := v.BeginDCAPI(t, dcql.Query{Credentials: []dcql.CredentialQuery{f.env.SDJWTQuery(t, "pid", "given_name"), mdocQuery(t, "mdoc", "given_name")}}, dcapiOrigin)
	again, err := w.StartDCAPIPresentation(ctx, r.Protocol, r.Data, r.Origin)
	if err != nil {
		t.Fatal(err)
	}
	all, err := w.Credentials(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range all {
		if !again.ShownTo(c.ID) {
			t.Errorf("credential %s isn't recorded as shown to the Verifier", c.ID)
		}
		if c.ShownTo("origin:" + dcapiOrigin) {
			t.Errorf("credential %s is recorded as shown to the origin alone", c.ID)
		}
	}
	_ = held
}

// Two Verifiers whose signed requests come from one page are two
// Verifiers: the copy one has seen goes to the other only as linkable,
// as it would over the redirect flow.
func TestDCAPIPresentation_SharedOrigin(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
	v1, v2 := f.env.StartVerifier(t), f.env.StartVerifier(t)
	roots := x509.NewCertPool()
	roots.AddCert(v1.CA)
	roots.AddCert(v2.CA)
	w := f.newWalletTrusting(t, f.env.IssuerRoots, wallet.X5CVerifierRoots{Roots: roots})
	held := receive(t, f, w, walletflowtest.SDJWTConfigurationID)
	ctx := context.Background()
	q := dcql.Query{Credentials: []dcql.CredentialQuery{f.env.SDJWTQuery(t, "pid", "given_name")}}
	present := func(v testVerifier) (shown, linkable bool, presented walletflow.Presented) {
		t.Helper()
		r := v.BeginDCAPI(t, q, dcapiOrigin)
		p, err := w.StartDCAPIPresentation(ctx, r.Protocol, r.Data, r.Origin)
		if err != nil {
			t.Fatal(err)
		}
		shown, linkable = p.ShownTo(held[0].ID), p.Linkable(held[0].ID)
		presented, err = p.Respond(ctx, walletflow.Selection{"pid": {held[0].ID}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.VerifyDCAPIResponse(ctx, r, presented.DCAPIResponse); err != nil {
			t.Fatal(err)
		}
		return shown, linkable, presented
	}
	if shown, linkable, _ := present(v1); shown || linkable {
		t.Fatalf("first presentation: shown %v, linkable %v", shown, linkable)
	}
	shown, linkable, presented := present(v2)
	if shown || !linkable || len(presented.Linkable) != 1 {
		t.Errorf("the second Verifier at the origin: shown %v, linkable %v, Presented.Linkable %v; want unseen and linkable", shown, linkable, presented.Linkable)
	}
	if shown, linkable, _ := present(v1); !shown {
		t.Errorf("the first Verifier again: shown %v, linkable %v; want shown", shown, linkable)
	}
}

// A copy recorded as shown to an origin alone, as a signed request's
// presentation once was, counts as another Verifier's: a signed
// Verifier at that origin isn't told it has seen it, and presenting it
// is linkable.
func TestDCAPIPresentation_OriginOnlyRecord(t *testing.T) {
	f, v, w := presentationFixture(t)
	held := receive(t, f, w, walletflowtest.SDJWTConfigurationID)
	ctx := context.Background()
	c := held[0]
	copies := c.AllCopies()
	for i := range copies {
		copies[i].Presented, copies[i].ShownTo = true, []string{walletflow.VerifierHash("origin:" + dcapiOrigin)}
	}
	c.Copies = copies
	if err := f.store.Put(ctx, c); err != nil {
		t.Fatal(err)
	}
	r := v.BeginDCAPI(t, dcql.Query{Credentials: []dcql.CredentialQuery{f.env.SDJWTQuery(t, "pid", "given_name")}}, dcapiOrigin)
	p, err := w.StartDCAPIPresentation(ctx, r.Protocol, r.Data, r.Origin)
	if err != nil {
		t.Fatal(err)
	}
	if p.ShownTo(c.ID) || !p.Linkable(c.ID) {
		t.Errorf("shown %v, linkable %v; want unseen and linkable", p.ShownTo(c.ID), p.Linkable(c.ID))
	}
	// An unsigned request from the origin is that origin's.
	unsigned := unsignedOf(t, r)
	u, err := w.StartDCAPIPresentation(ctx, unsigned.Protocol, unsigned.Data, unsigned.Origin)
	if err != nil {
		t.Fatal(err)
	}
	if !u.ShownTo(c.ID) || u.Linkable(c.ID) {
		t.Errorf("unsigned: shown %v, linkable %v; want shown and not linkable", u.ShownTo(c.ID), u.Linkable(c.ID))
	}
}

// An unsigned request names no Verifier but its origin, and is answered
// the same way.
func TestDCAPIPresentation_Unsigned(t *testing.T) {
	f, v, w := presentationFixture(t)
	receive(t, f, w, walletflowtest.SDJWTConfigurationID)
	ctx := context.Background()
	r := v.BeginDCAPI(t, dcql.Query{Credentials: []dcql.CredentialQuery{f.env.SDJWTQuery(t, "pid", "given_name")}}, dcapiOrigin)
	unsigned := unsignedOf(t, r)
	p, err := w.StartDCAPIPresentation(ctx, unsigned.Protocol, unsigned.Data, unsigned.Origin)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Verifier(); got.ClientID != "" || got.Certificate != nil || got.Origin != dcapiOrigin {
		t.Errorf("Verifier = %+v", got)
	}
	sel, err := p.DefaultSelection(ctx)
	if err != nil {
		t.Fatal(err)
	}
	presented, err := p.Respond(ctx, sel)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.VerifyDCAPIResponse(ctx, r, presented.DCAPIResponse); err != nil {
		t.Fatalf("the page refused the response: %v", err)
	}
	// The same request from another origin is bound to that one, so the
	// page refuses it.
	other := *unsigned
	other.Origin = "https://elsewhere.example"
	q, err := w.StartDCAPIPresentation(ctx, other.Protocol, other.Data, other.Origin)
	if err != nil {
		t.Fatal(err)
	}
	sel, err = q.DefaultSelection(ctx)
	if err != nil {
		t.Fatal(err)
	}
	misbound, err := q.Respond(ctx, sel)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.VerifyDCAPIResponse(ctx, r, misbound.DCAPIResponse); err == nil {
		t.Error("the page accepted a presentation bound to another origin")
	}
}

// A wallet requiring signed requests refuses an unsigned one as from an
// untrusted Verifier, before the holder sees it, and still opens a
// signed one.
func TestDCAPIPresentation_RequireSigned(t *testing.T) {
	f, v, _ := presentationFixture(t)
	w, err := walletflow.New(walletflow.Config{
		ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, IssuerRoots: f.env.IssuerRoots,
		VerifierTrust: v.Trust, RequireSignedDCAPIRequests: true, Development: true,
	}, walletflow.Dependencies{Keys: f.keys, Credentials: f.store, Provider: f.env.Provider, HTTP: f.env.HTTP})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	r := v.BeginDCAPI(t, dcql.Query{Credentials: []dcql.CredentialQuery{f.env.SDJWTQuery(t, "pid", "given_name")}}, dcapiOrigin)
	unsigned := unsignedOf(t, r)
	if _, err := w.StartDCAPIPresentation(ctx, unsigned.Protocol, unsigned.Data, unsigned.Origin); !errors.Is(err, walletflow.ErrUntrustedVerifier) {
		t.Errorf("an unsigned request: %v, want ErrUntrustedVerifier", err)
	}
	// What the platform handed over doesn't parse: malformed, not untrusted.
	_, err = w.StartDCAPIPresentation(ctx, r.Protocol, []byte(`{"request":"not.a.jws"}`), r.Origin)
	if !errors.Is(err, walletflow.ErrMalformedRequest) || errors.Is(err, walletflow.ErrUntrustedVerifier) {
		t.Errorf("a garbled request: %v, want ErrMalformedRequest alone", err)
	}
	if _, err := w.StartDCAPIPresentation(ctx, r.Protocol, r.Data, r.Origin); err != nil {
		t.Errorf("a signed request: %v", err)
	}
}

// Declining hands back the encrypted refusal; Respond is refused after it.
func TestDCAPIPresentation_Decline(t *testing.T) {
	f, v, w := presentationFixture(t)
	receive(t, f, w, walletflowtest.SDJWTConfigurationID)
	ctx := context.Background()
	r := v.BeginDCAPI(t, dcql.Query{Credentials: []dcql.CredentialQuery{f.env.SDJWTQuery(t, "pid", "given_name")}}, dcapiOrigin)
	p, err := w.StartDCAPIPresentation(ctx, r.Protocol, r.Data, r.Origin)
	if err != nil {
		t.Fatal(err)
	}
	declined, err := p.Decline(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var refusal *verifier.ResponseError
	if _, err := v.VerifyDCAPIResponse(ctx, r, declined.DCAPIResponse); !errors.As(err, &refusal) || refusal.Code != "access_denied" {
		t.Fatalf("the page got %v, want access_denied", err)
	}
	again, err := p.Decline(ctx)
	if err != nil || string(again.DCAPIResponse) != string(declined.DCAPIResponse) {
		t.Errorf("Decline again = %s, %v; want the same refusal", again.DCAPIResponse, err)
	}
	sel := walletflow.Selection{"pid": {"x"}}
	if _, err := p.Respond(ctx, sel); !errors.Is(err, walletflow.ErrWrongStep) {
		t.Errorf("Respond after Decline = %v, want ErrWrongStep", err)
	}
}

// A signed request from a Verifier the wallet doesn't trust is refused
// before anything is shown.
func TestDCAPIPresentation_RefusesAnUntrustedVerifier(t *testing.T) {
	f, v, _ := presentationFixture(t)
	stranger := f.env.StartVerifier(t)
	w := f.newWalletTrusting(t, f.env.IssuerRoots, v.Trust)
	r := stranger.BeginDCAPI(t, dcql.Query{Credentials: []dcql.CredentialQuery{f.env.SDJWTQuery(t, "pid")}}, dcapiOrigin)
	if _, err := w.StartDCAPIPresentation(context.Background(), r.Protocol, r.Data, r.Origin); err == nil {
		t.Fatal("an untrusted Verifier's request was opened")
	}
}

// A DC API request carrying transaction_data, which the wallet doesn't
// support, is refused with the error OpenID4VP §8.4 requires, for the
// platform to hand back to the page.
func TestDCAPIPresentation_RefusesTransactionData(t *testing.T) {
	f, v, w := presentationFixture(t)
	r := unsignedOf(t, v.BeginDCAPI(t, dcql.Query{Credentials: []dcql.CredentialQuery{f.env.SDJWTQuery(t, "pid", "given_name")}}, dcapiOrigin))
	var claims map[string]any
	if err := json.Unmarshal(r.Data, &claims); err != nil {
		t.Fatal(err)
	}
	claims["transaction_data"] = []string{base64.RawURLEncoding.EncodeToString([]byte(`{"type":"payment","credential_ids":["pid"]}`))}
	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	_, err = w.StartDCAPIPresentation(context.Background(), r.Protocol, data, r.Origin)
	var refused *walletflow.RequestRefusedError
	if !errors.As(err, &refused) || refused.Code != "invalid_transaction_data" {
		t.Fatalf("StartDCAPIPresentation = %v; want refused with invalid_transaction_data", err)
	}
	var response map[string]string
	if err := json.Unmarshal(refused.DCAPIResponse, &response); err != nil || response["error"] != "invalid_transaction_data" {
		t.Errorf("DCAPIResponse = %s, %v", refused.DCAPIResponse, err)
	}
}

// A trusted DC API request for another response mode is refused with
// invalid_request, for the platform to hand back to the page (OpenID4VP
// Appendix A.4).
func TestDCAPIPresentation_RefusesAnotherResponseMode(t *testing.T) {
	f, v, w := presentationFixture(t)
	r := unsignedOf(t, v.BeginDCAPI(t, dcql.Query{Credentials: []dcql.CredentialQuery{f.env.SDJWTQuery(t, "pid", "given_name")}}, dcapiOrigin))
	var claims map[string]any
	if err := json.Unmarshal(r.Data, &claims); err != nil {
		t.Fatal(err)
	}
	claims["response_mode"] = "direct_post.jwt"
	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	_, err = w.StartDCAPIPresentation(context.Background(), r.Protocol, data, r.Origin)
	var refused *walletflow.RequestRefusedError
	if !errors.As(err, &refused) || refused.Code != "invalid_request" {
		t.Fatalf("StartDCAPIPresentation = %v; want refused with invalid_request", err)
	}
	if string(refused.DCAPIResponse) != `{"error":"invalid_request"}` {
		t.Errorf("DCAPIResponse = %s", refused.DCAPIResponse)
	}
}

// unsignedOf is r as an unsigned request: its Request Object's claims,
// without the signature, client_id or expected_origins.
func unsignedOf(t *testing.T, r *walletflowtest.DCAPIRequest) *walletflowtest.DCAPIRequest {
	t.Helper()
	var signed struct {
		Request string `json:"request"`
	}
	if err := json.Unmarshal(r.Data, &signed); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(signed.Request, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	delete(claims, "client_id")
	delete(claims, "expected_origins")
	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	out := *r
	out.Protocol, out.Data = wallet.DCAPIProtocolUnsigned, data
	return &out
}
