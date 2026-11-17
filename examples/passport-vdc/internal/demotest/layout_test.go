package demotest_test

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demoaccess"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demotest"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/issuerapp"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/verifierapp"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletapp"
)

// TestPagesRefuseCrossOriginFraming: every page — the operator pages
// whose forms revoke, approve and forget, the verifier's and the web
// wallet's — forbids framing by another origin, so a page that frames
// them can't clickjack their forms; same-origin frames still load.
func TestPagesRefuseCrossOriginFraming(t *testing.T) {
	env := demotest.New(t, nil)
	env.StartVerifier(t, nil)
	env.StartWebWallet(t, walletapp.Store{Dir: t.TempDir()})
	for _, url := range []string{
		env.IssuerURL + "/demo/", env.IssuerURL + "/demo/status", env.IssuerURL + "/demo/review", env.IssuerURL + "/demo/kept",
		env.VerifierURL + "/demo/", env.WebWalletURL + "/",
	} {
		resp, err := env.HTTP.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %d", url, resp.StatusCode)
		}
		if got := resp.Header.Get("Content-Security-Policy"); got != "frame-ancestors 'self'" {
			t.Errorf("GET %s: Content-Security-Policy = %q, want frame-ancestors 'self'", url, got)
		}
		if got := resp.Header.Get("X-Frame-Options"); got != "SAMEORIGIN" {
			t.Errorf("GET %s: X-Frame-Options = %q, want SAMEORIGIN", url, got)
		}
	}
}

// TestPagesUnderDemo: the pages people use are all under /demo/ on the
// issuer and the verifier, so one access rule on that path guards them,
// and nothing else needs one; the old paths are gone, / redirects there,
// and the protocol endpoints wallets call stay outside it.
func TestPagesUnderDemo(t *testing.T) {
	env := demotest.New(t, nil)
	env.StartVerifier(t, nil)
	client := *env.HTTP
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	status := func(method, url string) int {
		t.Helper()
		req, err := http.NewRequest(method, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	for _, base := range []string{env.IssuerURL, env.VerifierURL} {
		if got := status(http.MethodGet, base+"/"); got != http.StatusSeeOther {
			t.Errorf("GET %s/ = %d, want a redirect to /demo/", base, got)
		}
		if got := status(http.MethodGet, base+"/demo/"); got != http.StatusOK {
			t.Errorf("GET %s/demo/ = %d", base, got)
		}
	}
	for _, page := range []string{"/review", "/status", "/kept"} {
		if got := status(http.MethodGet, env.IssuerURL+page); got != http.StatusNotFound {
			t.Errorf("GET issuer %s = %d, want gone (moved under /demo/)", page, got)
		}
		if got := status(http.MethodGet, env.IssuerURL+"/demo"+page); got != http.StatusOK {
			t.Errorf("GET issuer /demo%s = %d", page, got)
		}
	}
	for _, path := range []string{"/passport", "/sample"} {
		if got := status(http.MethodPost, env.IssuerURL+path); got != http.StatusNotFound && got != http.StatusMethodNotAllowed {
			t.Errorf("POST issuer %s = %d, want gone (moved under /demo/)", path, got)
		}
	}
	if got := status(http.MethodPost, env.VerifierURL+"/requests"); got != http.StatusNotFound && got != http.StatusMethodNotAllowed {
		t.Errorf("POST verifier /requests = %d, want gone (moved under /demo/)", got)
	}
	for _, path := range []string{"/.well-known/openid-credential-issuer", "/.well-known/oauth-authorization-server", "/jwks"} {
		if got := status(http.MethodGet, env.IssuerURL+path); got != http.StatusOK {
			t.Errorf("GET issuer %s = %d, want the protocol endpoint outside /demo/", path, got)
		}
	}
}

// TestFormTargetsRedirectOnGet: a GET to the target of a form under
// /demo/ — what Cloudflare Access sends after a login interrupted a form
// post — redirects to the form's page rather than answering 405.
func TestFormTargetsRedirectOnGet(t *testing.T) {
	env := demotest.New(t, nil)
	env.StartVerifier(t, nil)
	client := *env.HTTP
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for _, tc := range []struct{ url, want string }{
		{env.IssuerURL + "/demo/passport", "/demo/"},
		{env.IssuerURL + "/demo/sample", "/demo/"},
		{env.IssuerURL + "/demo/review/decision", "/demo/review"},
		{env.IssuerURL + "/demo/kept/forget", "/demo/kept"},
		{env.IssuerURL + "/demo/status/revoke", "/demo/status"},
		{env.VerifierURL + "/demo/requests", "/demo/"},
		{env.VerifierURL + "/demo/requests/abc/dcapi", "/demo/requests/abc"},
		{env.VerifierURL + "/demo/requests/abc/dcapi/response", "/demo/requests/abc"},
	} {
		resp, err := client.Get(tc.url)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != tc.want {
			t.Errorf("GET %s = %d to %q, want %d to %q", tc.url, resp.StatusCode, resp.Header.Get("Location"), http.StatusSeeOther, tc.want)
		}
	}
}

// demoRequest sends method to base+rawPath, the path spelled exactly as
// given, with header, not following redirects; it returns the status.
func demoRequest(t *testing.T, env *demotest.Env, method, base, rawPath string, header map[string]string) int {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	if u.Path, err = url.PathUnescape(rawPath); err != nil {
		t.Fatal(err)
	}
	u.RawPath = rawPath
	var body io.Reader
	if method == http.MethodPost {
		body = strings.NewReader("scenario=age&keep=1")
	}
	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range header {
		req.Header.Set(k, v)
	}
	client := *env.HTTP
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// TestDemoPagesRefuseAliasesAndOriginlessPosts: the pages under /demo/
// answer only to their plain path — a percent-encoded or uncleaned
// alias, which an edge rule on the raw path wouldn't match, is refused
// — and a state-changing request needs the app's own Origin or
// Referer, so a client sending neither can't revoke the document
// signer, issue the unchecked sample or start a verifier request.
func TestDemoPagesRefuseAliasesAndOriginlessPosts(t *testing.T) {
	env := demotest.New(t, nil)
	env.StartVerifier(t, nil)
	for _, tc := range []struct {
		method, base, path string
	}{
		{http.MethodGet, env.IssuerURL, "/%64emo/status"},
		{http.MethodGet, env.IssuerURL, "/demo%2Fstatus"},
		{http.MethodPost, env.IssuerURL, "/%64emo/sample"},
		{http.MethodPost, env.IssuerURL, "/%64emo/signer/revoke"},
		{http.MethodPost, env.IssuerURL, "/x/%2e%2e/demo/signer/revoke"},
		{http.MethodPost, env.VerifierURL, "/%64emo/requests"},
	} {
		origin := map[string]string{"Origin": tc.base}
		if got := demoRequest(t, env, tc.method, tc.base, tc.path, origin); got != http.StatusBadRequest {
			t.Errorf("%s %s%s = %d, want 400", tc.method, tc.base, tc.path, got)
		}
	}
	for _, tc := range []struct{ base, path string }{
		{env.IssuerURL, "/demo/sample"},
		{env.IssuerURL, "/demo/signer/revoke"},
		{env.IssuerURL, "/demo/status/revoke"},
		{env.IssuerURL, "/demo/kept/forget"},
		{env.IssuerURL, "/demo/review/decision"},
		{env.VerifierURL, "/demo/requests"},
	} {
		if got := demoRequest(t, env, http.MethodPost, tc.base, tc.path, nil); got != http.StatusForbidden {
			t.Errorf("POST %s%s with no Origin or Referer = %d, want 403", tc.base, tc.path, got)
		}
	}
	if n := len(env.Issuer.RevokedSigners()); n != 0 {
		t.Errorf("%d document signers revoked, want none", n)
	}
	if got := demoRequest(t, env, http.MethodPost, env.IssuerURL, "/demo/sample", map[string]string{"Referer": env.IssuerURL + "/demo/"}); got != http.StatusOK {
		t.Errorf("POST /demo/sample with the issuer's Referer = %d, want 200", got)
	}
}

// TestDemoPagesNeedAccessToken: with Cloudflare Access configured, the
// pages under /demo/ need its token, and the protocol surface outside
// them doesn't.
func TestDemoPagesNeedAccessToken(t *testing.T) {
	access := demoaccess.Settings{TeamDomain: "team.cloudflareaccess.example", Audience: "aud"}
	env := demotest.New(t, nil, func(c *issuerapp.Config) { c.Access = access })
	env.StartVerifier(t, nil, func(c *verifierapp.Config) { c.Access = access })
	for _, base := range []string{env.IssuerURL, env.VerifierURL} {
		if got := demoRequest(t, env, http.MethodGet, base, "/demo/", nil); got != http.StatusForbidden {
			t.Errorf("GET %s/demo/ without an Access token = %d, want 403", base, got)
		}
	}
	if got := demoRequest(t, env, http.MethodGet, env.IssuerURL, "/.well-known/openid-credential-issuer", nil); got != http.StatusOK {
		t.Errorf("GET the issuer's metadata = %d, want it served without a token", got)
	}
}
