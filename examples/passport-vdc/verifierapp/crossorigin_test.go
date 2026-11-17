package verifierapp_test

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demotest"
)

// TestCreateRequest_RefusesCrossOrigin: a form another site posts to
// /demo/requests is refused before a session is made, so its
// Set-Cookie can't replace the operator's session and end the requests
// their browser has open.
func TestCreateRequest_RefusesCrossOrigin(t *testing.T) {
	env := demotest.New(t, nil)
	env.StartVerifier(t, nil)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	operator := *env.HTTP
	operator.Jar = jar
	operator.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	post := func(c *http.Client, origin string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, env.VerifierURL+"/demo/requests", strings.NewReader("scenario=age"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", origin)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp
	}
	pageStatus := func(path string) int {
		t.Helper()
		resp, err := operator.Get(env.VerifierURL + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	own := post(&operator, env.VerifierURL)
	page := own.Header.Get("Location")
	if own.StatusCode != http.StatusSeeOther || pageStatus(page) != http.StatusOK {
		t.Fatalf("the operator's own request: %d %q", own.StatusCode, page)
	}
	// Another site's form: the browser sends it no Lax cookie, but would
	// keep any Set-Cookie it gets back.
	crossSite := *env.HTTP
	crossSite.CheckRedirect = operator.CheckRedirect
	resp := post(&crossSite, "https://evil.example")
	if resp.StatusCode != http.StatusForbidden || len(resp.Cookies()) != 0 {
		t.Fatalf("cross-site POST /demo/requests: %d, cookies %v; want 403 and none", resp.StatusCode, resp.Cookies())
	}
	if got := pageStatus(page); got != http.StatusOK {
		t.Errorf("the operator's request page after the cross-site post: %d, want 200", got)
	}
}
