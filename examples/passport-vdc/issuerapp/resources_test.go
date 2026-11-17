package issuerapp_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demotest"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/issuerapp"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletapp"
)

// otherResource is another Credential Issuer the Authorization Server
// accepts as a resource in these tests (issuerapp.WithExtraResources).
const otherResource = "https://other-issuer.example.com"

// formRewriter has rewrite change the form of each request it sends, by
// its URL path.
type formRewriter struct {
	next    http.RoundTripper
	rewrite func(path string, form url.Values)
}

func (f formRewriter) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		return f.next.RoundTrip(r)
	}
	body, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil {
		return nil, err
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}
	f.rewrite(r.URL.Path, form)
	encoded := []byte(form.Encode())
	r = r.Clone(r.Context())
	r.Body = io.NopCloser(bytes.NewReader(encoded))
	r.ContentLength = int64(len(encoded))
	r.Header.Set("Content-Length", strconv.Itoa(len(encoded)))
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(encoded)), nil }
	return f.next.RoundTrip(r)
}

// rewriteRequests has every request over env.HTTP go through rewrite,
// and records the access tokens of the Token Responses.
func rewriteRequests(env *demotest.Env, rewrite func(path string, form url.Values)) *tokenRecorder {
	next := env.HTTP.Transport
	if next == nil {
		next = http.DefaultTransport
	}
	recorder := &tokenRecorder{next: formRewriter{next: next, rewrite: rewrite}}
	httpClient := *env.HTTP
	httpClient.Transport = recorder
	env.HTTP = &httpClient
	return recorder
}

// TestApproval_GrantsOnlyTheCredentialIssuer: the approval step grants
// the Credential Issuer alone (issuer.Issuer.AuthorizationResources).
// With the Authorization Server also accepting another resource, a
// pushed authorization request naming both gets a token for the
// Credential Issuer alone, and one naming only the other is denied.
func TestApproval_GrantsOnlyTheCredentialIssuer(t *testing.T) {
	ctx := context.Background()
	env := demotest.New(t, nil, issuerapp.WithExtraResources(otherResource))
	var parResources []string
	recorder := rewriteRequests(env, func(path string, form url.Values) {
		switch {
		case strings.HasSuffix(path, "/par"):
			form["resource"] = parResources
		case strings.HasSuffix(path, "/token"):
			// The grant's resources decide the token's audience.
			delete(form, "resource")
		}
	})
	w := refreshingWallet(t, env)
	for name, resources := range map[string][]string{
		"the Credential Issuer and another": {env.IssuerURL, otherResource},
		"another alone":                     {otherResource},
	} {
		parResources = resources
		offer, err := env.Issuer.CreateTransaction(ctx, demotest.SyntheticEvidence())
		if err != nil {
			t.Fatal(err)
		}
		s, err := w.StartIssuance(ctx, offer.URI)
		if err != nil {
			t.Fatal(err)
		}
		authURL, err := s.BeginAuthorization(ctx)
		if err != nil {
			t.Fatalf("%s: BeginAuthorization: %v", name, err)
		}
		loc, err := walletapp.HeadlessApprover{HTTP: env.HTTP, Code: offer.ConfirmationCode}.Redirect(ctx, authURL)
		if err != nil {
			t.Fatal(err)
		}
		if len(resources) == 1 {
			if q := loc.Query(); q.Get("code") != "" || q.Get("error") != "access_denied" {
				t.Errorf("%s: redirect %s, want error=access_denied", name, loc)
			}
			continue
		}
		if err := s.CompleteAuthorization(ctx, loc.String()); err != nil {
			t.Fatalf("%s: CompleteAuthorization: %v", name, err)
		}
		recorder.mu.Lock()
		token := recorder.tokens[len(recorder.tokens)-1]
		recorder.mu.Unlock()
		if aud := accessTokenClaim(t, token, "aud"); aud != env.IssuerURL {
			t.Errorf("%s: access token aud = %v, want %s alone", name, aud, env.IssuerURL)
		}
	}
}

// TestPreAuthorized_RefusesAnotherResource: a pre-authorized Token
// Request also naming another resource is refused with invalid_target,
// leaving the code redeemable: the Token Endpoint passes the request's
// resources to the redemption.
func TestPreAuthorized_RefusesAnotherResource(t *testing.T) {
	ctx := context.Background()
	env := demotest.New(t, nil)
	nameAnother := true
	rewriteRequests(env, func(path string, form url.Values) {
		if nameAnother && strings.HasSuffix(path, "/token") && form.Get("pre-authorized_code") != "" {
			form.Add("resource", otherResource)
		}
	})
	w := refreshingWallet(t, env)
	offer, err := env.Issuer.CreatePreAuthorizedTransaction(ctx, demotest.SyntheticEvidence())
	if err != nil {
		t.Fatal(err)
	}
	s, err := w.StartIssuance(ctx, offer.URI)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close(ctx) }()
	if err := s.RedeemPreAuthorizedCode(ctx, offer.ConfirmationCode); err == nil || !strings.Contains(err.Error(), "invalid_target") {
		t.Errorf("a Token Request also naming another resource: %v, want invalid_target", err)
	}
	nameAnother = false
	if err := s.RedeemPreAuthorizedCode(ctx, offer.ConfirmationCode); err != nil {
		t.Errorf("the same code afterwards: %v, want it still redeemable", err)
	}
}
