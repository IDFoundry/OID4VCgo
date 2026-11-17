package walletflowtest_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// otherResource is another Credential Issuer the Authorization Server
// accepts as a resource in these tests (WithExtraResources).
const otherResource = "https://other-issuer.example.com"

// formRewriter is a wallet's transport that has rewrite change the form
// of each request it sends, by its URL path, and records the access
// token of each Token Response.
type formRewriter struct {
	base    http.RoundTripper
	rewrite func(path string, form url.Values)

	mu     sync.Mutex
	tokens []string
}

func (f *formRewriter) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodPost && r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
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
	}
	resp, err := f.base.RoundTrip(r)
	if err != nil || !strings.HasSuffix(r.URL.Path, "/token") || resp.StatusCode != http.StatusOK {
		return resp, err
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if json.Unmarshal(body, &token) == nil {
		f.mu.Lock()
		f.tokens = append(f.tokens, token.AccessToken)
		f.mu.Unlock()
	}
	return resp, nil
}

// lastToken is the access token of the last Token Response.
func (f *formRewriter) lastToken(t *testing.T) string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.tokens) == 0 {
		t.Fatal("no Token Response")
	}
	return f.tokens[len(f.tokens)-1]
}

// newRewritingWallet is a walletflow wallet of env whose requests rewrite
// changes.
func newRewritingWallet(t *testing.T, env *walletflowtest.Env, profile walletflow.IssuanceProfile, rewrite func(path string, form url.Values)) (*walletflow.Wallet, *formRewriter) {
	t.Helper()
	base := env.HTTP.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	rw := &formRewriter{base: base, rewrite: rewrite}
	hc := *env.HTTP
	hc.Transport = rw
	w, err := walletflow.New(walletflow.Config{
		ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, CredentialIssuers: []string{env.IssuerURL},
		IssuerRoots: env.IssuerRoots, Development: true, IssuanceProfile: profile,
	}, walletflow.Dependencies{
		Keys: walletflow.NewMemoryKeyStore(), Credentials: walletflow.NewMemoryCredentialStore(), Provider: env.Provider, HTTP: &hc,
	})
	if err != nil {
		t.Fatal(err)
	}
	return w, rw
}

// accessTokenAudience is a JWT access token's "aud".
func accessTokenAudience(t *testing.T, accessToken string) any {
	t.Helper()
	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		t.Fatalf("access token %q isn't a JWT", accessToken)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	return claims["aud"]
}

// The consent step grants the Credential Issuer alone
// (issuer.Issuer.AuthorizationResources): with the Authorization Server
// also accepting another resource, a pushed authorization request
// naming both gets a token for the Credential Issuer alone, and one
// naming only the other is denied.
func TestConsent_GrantsOnlyTheCredentialIssuer(t *testing.T) {
	env, err := walletflowtest.New(walletflowtest.WithExtraResources(walletflowtest.Options{}, otherResource))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(env.Close)
	ctx := context.Background()
	for name, resources := range map[string][]string{
		"the Credential Issuer and another": {env.IssuerURL, otherResource},
		"another alone":                     {otherResource},
	} {
		w, rw := newRewritingWallet(t, env, walletflow.ProfileHAIP, func(path string, form url.Values) {
			switch {
			case strings.HasSuffix(path, "/par"):
				form["resource"] = resources
			case strings.HasSuffix(path, "/token"):
				// The grant's resources decide the token's audience.
				delete(form, "resource")
			}
		})
		offer, err := env.AuthorizationCodeOffer(walletflowtest.SDJWTConfigurationID)
		if err != nil {
			t.Fatal(err)
		}
		s, err := w.StartIssuance(ctx, offer)
		if err != nil {
			t.Fatal(err)
		}
		authURL, err := s.BeginAuthorization(ctx)
		if err != nil {
			t.Fatalf("%s: BeginAuthorization: %v", name, err)
		}
		redirect, err := env.Approve(ctx, authURL)
		if err != nil {
			t.Fatal(err)
		}
		if len(resources) == 1 {
			if !strings.Contains(redirect, "error=access_denied") {
				t.Errorf("%s: redirect %s, want error=access_denied", name, redirect)
			}
			continue
		}
		if err := s.CompleteAuthorization(ctx, redirect); err != nil {
			t.Fatalf("%s: CompleteAuthorization: %v", name, err)
		}
		if aud := accessTokenAudience(t, rw.lastToken(t)); aud != env.IssuerURL {
			t.Errorf("%s: access token aud = %v, want %s alone", name, aud, env.IssuerURL)
		}
	}
}

// A pre-authorized Token Request naming another resource is refused
// with invalid_target, whether the client is attested or, under
// Anonymous, not: the Token Endpoint passes the request's resources to
// the redemption (issuer.ExchangePreAuthorizedCodeRequest.Resources).
func TestPreAuthorizedCode_RefusesAnotherResource(t *testing.T) {
	ctx := context.Background()
	for name, c := range map[string]struct {
		opts    walletflowtest.Options
		profile walletflow.IssuanceProfile
	}{
		"attested":  {walletflowtest.Options{}, walletflow.ProfileHAIP},
		"anonymous": {walletflowtest.Options{Anonymous: true}, walletflow.ProfileOpenID4VCI},
	} {
		env, err := walletflowtest.New(c.opts)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(env.Close)
		w, _ := newRewritingWallet(t, env, c.profile, func(path string, form url.Values) {
			if strings.HasSuffix(path, "/token") && form.Get("pre-authorized_code") != "" {
				form.Add("resource", otherResource)
			}
		})
		offer, err := env.PreAuthorizedOffer("", walletflowtest.SDJWTConfigurationID)
		if err != nil {
			t.Fatal(err)
		}
		s, err := w.StartIssuance(ctx, offer)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.RedeemPreAuthorizedCode(ctx, ""); err == nil || !strings.Contains(err.Error(), "invalid_target") {
			t.Errorf("%s: a Token Request also naming another resource: %v, want invalid_target", name, err)
		}
	}
}
