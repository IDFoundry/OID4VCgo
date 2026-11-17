package demoaccess

import (
	"context"
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
	"sync"
	"sync/atomic"
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
		// ServeMux routes these to a /demo/ handler with "../../../x" as
		// the wildcard, although the decoded path cleans to /x/dcapi.
		{"/demo/requests/..%2F..%2F..%2Fx/dcapi", http.StatusBadRequest},
		{"/%64emo/requests/..%2F..%2F..%2Fx/dcapi", http.StatusBadRequest},
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
	certs  atomic.Int32 // certs requests served
	down   atomic.Bool  // the certs endpoint answers 503
	// rotated, once set, is published too, as kid "k2".
	rotated atomic.Pointer[rsa.PrivateKey]
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
		team.certs.Add(1)
		if team.down.Load() {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		jwk := func(kid string, k *rsa.PrivateKey) map[string]string {
			return map[string]string{
				"kty": "RSA", "kid": kid, "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
			}
		}
		keys := []map[string]string{jwk(team.kid, key)}
		if k2 := team.rotated.Load(); k2 != nil {
			keys = append(keys, jwk("k2", k2))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	}))
	t.Cleanup(team.srv.Close)
	team.domain = strings.TrimPrefix(team.srv.URL, "https://")
	return team
}

func (team *testTeam) token(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	return signToken(t, team.key, header, claims)
}

// signToken is an RS256 JWT of header and claims, signed with key.
func signToken(t *testing.T, key *rsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
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
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// Valid claims under a signature that is well-formed but wrong: by
	// another key, or the team's over other claims.
	signedByOther := signToken(t, other, header, claims(nil))
	otherClaims := team.token(t, header, claims(func(c map[string]any) { c["aud"] = "aud-1" }))
	swapped := valid[:strings.LastIndex(valid, ".")] + otherClaims[strings.LastIndex(otherClaims, "."):]
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
		{"signed with another key", signedByOther, http.StatusForbidden},
		{"another token's signature", swapped, http.StatusForbidden},
	} {
		r := request(t, http.MethodGet, "/demo/status", map[string]string{AccessTokenHeader: tc.token})
		if got := serve(h, r); got != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, got, tc.want)
		}
	}
	if got := serve(h, request(t, http.MethodGet, "/credential", nil)); got != http.StatusNoContent {
		t.Errorf("outside /demo/ without a token: %d, want it passed through", got)
	}
	if n := team.certs.Load(); n != 1 {
		t.Errorf("certs fetched %d times, want once (cached; an unknown key refetches at most once a minute)", n)
	}
}

func TestNewAccessVerifier_NeedsBoth(t *testing.T) {
	for _, args := range [][2]string{{"", "aud"}, {"team.cloudflareaccess.com", ""}, {"team.cloudflareaccess.com/x", "aud"}} {
		if _, err := NewAccessVerifier(args[0], args[1], nil); err == nil {
			t.Errorf("NewAccessVerifier(%q, %q): no error", args[0], args[1])
		}
	}
}

// testClock is a settable clock, safe to read from the verifier's
// background fetch.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newTestVerifier(t *testing.T, team *testTeam) (*AccessVerifier, *testClock) {
	t.Helper()
	v, err := NewAccessVerifier(team.domain, "aud-1", team.srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	clock := &testClock{now: time.Now()}
	v.now = clock.Now
	return v, clock
}

// validToken is a token for the verifier's application, signed with
// key as kid.
func (team *testTeam) validToken(t *testing.T, kid string, key *rsa.PrivateKey, at time.Time) string {
	t.Helper()
	return signToken(t, key, map[string]any{"alg": "RS256", "kid": kid},
		map[string]any{"iss": "https://" + team.domain, "aud": "aud-1", "exp": at.Unix() + 7200})
}

// unknownKidToken names a key the team doesn't have. It needs no
// credential: Verify fetches the keys before checking any signature.
func unknownKidToken(kid string) string {
	h, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": kid})
	return base64.RawURLEncoding.EncodeToString(h) + ".e30.AAAA"
}

// A client that names an unknown key and hangs up before the keys
// arrive doesn't cut their fetch short: it finishes for the requests
// after it, so the operator's token verifies, even one signed with a
// key Access has just rotated in.
func TestVerify_HungUpClientDoesntBlockFetch(t *testing.T) {
	team := newTestTeam(t)
	v, clock := newTestVerifier(t, team)
	hungUp, cancel := context.WithCancel(context.Background())
	cancel()
	if err := v.Verify(hungUp, unknownKidToken("x")); err == nil {
		t.Fatal("unknown key verified")
	}
	clock.Add(30 * time.Second)
	if err := v.Verify(context.Background(), team.validToken(t, team.kid, team.key, clock.Now())); err != nil {
		t.Fatalf("operator's token after a hung-up request: %v", err)
	}

	k2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	team.rotated.Store(k2)
	clock.Add(2 * time.Minute)
	if err := v.Verify(hungUp, unknownKidToken("y")); err == nil {
		t.Fatal("unknown key verified")
	}
	clock.Add(20 * time.Second)
	if err := v.Verify(context.Background(), team.validToken(t, "k2", k2, clock.Now())); err != nil {
		t.Fatalf("operator's token with the rotated key after a hung-up request: %v", err)
	}
}

// A fetch that fails holds off the next for a minute; the one after
// that is made, and its keys used.
func TestVerify_BacksOffAfterFailedFetch(t *testing.T) {
	team := newTestTeam(t)
	v, clock := newTestVerifier(t, team)
	token := func() string { return team.validToken(t, team.kid, team.key, clock.Now()) }
	team.down.Store(true)
	if err := v.Verify(context.Background(), token()); err == nil {
		t.Fatal("verified with the certs endpoint down")
	}
	team.down.Store(false)
	clock.Add(30 * time.Second)
	if err := v.Verify(context.Background(), token()); err == nil {
		t.Fatal("verified without a fetch: the keys were refetched within a minute of a failure")
	}
	if n := team.certs.Load(); n != 1 {
		t.Errorf("certs fetched %d times within the minute, want once", n)
	}
	clock.Add(time.Minute)
	if err := v.Verify(context.Background(), token()); err != nil {
		t.Fatalf("a minute after the failed fetch: %v", err)
	}
}

// Prefetch fetches the keys before the first request, which then
// verifies without fetching them again.
func TestPrefetch(t *testing.T) {
	team := newTestTeam(t)
	v, clock := newTestVerifier(t, team)
	v.Prefetch()
	v.mu.Lock()
	f := v.fetch
	v.mu.Unlock()
	if f == nil {
		t.Fatal("Prefetch started no fetch")
	}
	<-f.done
	if err := v.Verify(context.Background(), team.validToken(t, team.kid, team.key, clock.Now())); err != nil {
		t.Fatal(err)
	}
	if n := team.certs.Load(); n != 1 {
		t.Errorf("certs fetched %d times, want once", n)
	}
}
