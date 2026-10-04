package demotest_test

import (
	"net/http"
	"testing"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demotest"
)

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
