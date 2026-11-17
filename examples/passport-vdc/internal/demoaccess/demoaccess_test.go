package demoaccess

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const testOrigin = "https://issuer.example"

func guarded(access *AccessVerifier) http.Handler {
	return Guard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), testOrigin, access)
}

// request is a request for rawPath, as the client spelled it.
func request(t *testing.T, method, rawPath string, header map[string]string) *http.Request {
	t.Helper()
	u, err := url.ParseRequestURI(rawPath)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(method, "/", nil)
	r.URL, r.RequestURI = u, rawPath
	for k, v := range header {
		r.Header.Set(k, v)
	}
	return r
}

func serve(h http.Handler, r *http.Request) int {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

// A path under /demo/ is served only as spelled canonically: an
// encoded or uncleaned alias, which ServeMux would route to the same
// handler, is refused, so an edge rule on the raw path can't be
// stepped round. Outside /demo/, nothing changes.
func TestGuard_RefusesNonCanonicalDemoPaths(t *testing.T) {
	h := guarded(nil)
	for _, tc := range []struct {
		path string
		want int
	}{
		{"/demo/status", http.StatusNoContent},
		{"/demo/", http.StatusNoContent},
		{"/demo", http.StatusNoContent},
		{"/%64emo/status", http.StatusBadRequest},
		{"/demo%2Fstatus", http.StatusBadRequest},
		{"/de%6Do/", http.StatusBadRequest},
		{"/x/../demo/status", http.StatusBadRequest},
		{"/x/%2e%2e/demo/status", http.StatusBadRequest},
		{"//demo/status", http.StatusBadRequest},
		{"/demo/./status", http.StatusBadRequest},
		{"/demo//status", http.StatusBadRequest},
		{"/s/%61ge/response", http.StatusNoContent},
		{"/credential", http.StatusNoContent},
	} {
		if got := serve(h, request(t, http.MethodGet, tc.path, nil)); got != tc.want {
			t.Errorf("GET %s: %d, want %d", tc.path, got, tc.want)
		}
	}
}

// A state-changing request under /demo/ needs the app's own Origin or,
// without one, Referer; one with neither, as a non-browser client
// sends, is refused.
func TestGuard_StateChangingRequestsNeedOwnOrigin(t *testing.T) {
	h := guarded(nil)
	for _, tc := range []struct {
		name   string
		header map[string]string
		want   int
	}{
		{"own Origin", map[string]string{"Origin": testOrigin}, http.StatusNoContent},
		{"own Referer", map[string]string{"Referer": testOrigin + "/demo/status"}, http.StatusNoContent},
		{"neither", nil, http.StatusForbidden},
		{"other Origin", map[string]string{"Origin": "https://evil.example"}, http.StatusForbidden},
		{"null Origin", map[string]string{"Origin": "null"}, http.StatusForbidden},
		{"other Origin, own Referer", map[string]string{"Origin": "https://evil.example", "Referer": testOrigin + "/demo/"}, http.StatusForbidden},
		{"other Referer", map[string]string{"Referer": "https://issuer.example.evil.example/demo/"}, http.StatusForbidden},
		{"relative Referer", map[string]string{"Referer": "/demo/"}, http.StatusForbidden},
	} {
		if got := serve(h, request(t, http.MethodPost, "/demo/signer/revoke", tc.header)); got != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, got, tc.want)
		}
	}
	if got := serve(h, request(t, http.MethodGet, "/demo/status", nil)); got != http.StatusNoContent {
		t.Errorf("GET with neither: %d, want it served", got)
	}
	if got := serve(h, request(t, http.MethodPost, "/token", nil)); got != http.StatusNoContent {
		t.Errorf("POST outside /demo/: %d, want it passed through", got)
	}
}

// testTeam is a Cloudflare Access team: its certs endpoint, and the
// tokens it signs.
type testTeam struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	kid    string
	domain string
	certs  int
}

func newTestTeam(t *testing.T) *testTeam {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	team := &testTeam{key: key, kid: "k1"}
	team.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cdn-cgi/access/certs" {
			http.NotFound(w, r)
			return
		}
		team.certs++
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": team.kid, "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	t.Cleanup(team.srv.Close)
	team.domain = strings.TrimPrefix(team.srv.URL, "https://")
	return team
}

func (team *testTeam) token(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, team.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// With Access configured, every request under /demo/ needs a token the
// team signed for the application; outside /demo/, none is needed.
func TestGuard_ChecksAccessToken(t *testing.T) {
	team := newTestTeam(t)
	v, err := NewAccessVerifier(team.domain, "aud-1", team.srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	h := guarded(v)
	now := time.Now().Unix()
	header := map[string]any{"alg": "RS256", "kid": team.kid}
	claims := func(change func(map[string]any)) map[string]any {
		c := map[string]any{"iss": "https://" + team.domain, "aud": []string{"aud-1"}, "exp": now + 600, "nbf": now - 10}
		if change != nil {
			change(c)
		}
		return c
	}
	valid := team.token(t, header, claims(nil))
	for _, tc := range []struct {
		name  string
		token string
		want  int
	}{
		{"valid", valid, http.StatusNoContent},
		{"aud as a string", team.token(t, header, claims(func(c map[string]any) { c["aud"] = "aud-1" })), http.StatusNoContent},
		{"none", "", http.StatusForbidden},
		{"another application", team.token(t, header, claims(func(c map[string]any) { c["aud"] = []string{"aud-2"} })), http.StatusForbidden},
		{"another team", team.token(t, header, claims(func(c map[string]any) { c["iss"] = "https://other.cloudflareaccess.com" })), http.StatusForbidden},
		{"expired", team.token(t, header, claims(func(c map[string]any) { c["exp"] = now - 3600 })), http.StatusForbidden},
		{"no exp", team.token(t, header, claims(func(c map[string]any) { delete(c, "exp") })), http.StatusForbidden},
		{"not yet valid", team.token(t, header, claims(func(c map[string]any) { c["nbf"] = now + 3600 })), http.StatusForbidden},
		{"unknown key", team.token(t, map[string]any{"alg": "RS256", "kid": "k2"}, claims(nil)), http.StatusForbidden},
		{"another alg", team.token(t, map[string]any{"alg": "HS256", "kid": team.kid}, claims(nil)), http.StatusForbidden},
		{"tampered", valid[:strings.LastIndex(valid, ".")] + "x" + valid[strings.LastIndex(valid, "."):], http.StatusForbidden},
	} {
		r := request(t, http.MethodGet, "/demo/status", map[string]string{AccessTokenHeader: tc.token})
		if got := serve(h, r); got != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, got, tc.want)
		}
	}
	if got := serve(h, request(t, http.MethodGet, "/credential", nil)); got != http.StatusNoContent {
		t.Errorf("outside /demo/ without a token: %d, want it passed through", got)
	}
	if team.certs != 1 {
		t.Errorf("certs fetched %d times, want once (cached; an unknown key refetches at most once a minute)", team.certs)
	}
}

func TestNewAccessVerifier_NeedsBoth(t *testing.T) {
	for _, args := range [][2]string{{"", "aud"}, {"team.cloudflareaccess.com", ""}, {"team.cloudflareaccess.com/x", "aud"}} {
		if _, err := NewAccessVerifier(args[0], args[1], nil); err == nil {
			t.Errorf("NewAccessVerifier(%q, %q): no error", args[0], args[1])
		}
	}
}
