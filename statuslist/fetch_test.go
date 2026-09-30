package statuslist

import (
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// statusServer serves one Status List Token in each form (index 1
// revoked), choosing by the Accept header as an issuer would.
func statusServer(t *testing.T) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	ca, caKey := testcert.CA(t, "status CA")
	leaf, leafKey := testcert.Leaf(t, "status signer", ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	var uri string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sl, err := New(Bits1, []uint8{0, 1}, "")
		if err != nil {
			t.Error(err)
			return
		}
		claims := TokenClaims{Sub: uri, Iat: time.Now().Unix(), StatusList: sl}
		if r.Header.Get("Accept") == CWTTokenMediaType {
			token, err := IssueTokenCWTX5Chain(leafKey, cose.ES256, claims, []*x509.Certificate{leaf})
			if err != nil {
				t.Error(err)
			}
			w.Header().Set("Content-Type", CWTTokenMediaType)
			_, _ = w.Write(token)
			return
		}
		token, err := IssueTokenX5C(leafKey, jose.ES256, claims, []*x509.Certificate{leaf})
		if err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", TokenMediaType)
		_, _ = w.Write([]byte(token))
	}))
	uri = srv.URL + "/statuslists/1"
	t.Cleanup(srv.Close)
	return srv, roots
}

func TestChecker_BothForms(t *testing.T) {
	srv, roots := statusServer(t)
	c := Checker{Fetcher: Fetcher{HTTP: srv.Client(), AllowLoopback: true}, Roots: roots}
	for _, cwt := range []bool{false, true} {
		for idx, want := range map[uint64]StatusType{0: StatusValid, 1: StatusInvalid} {
			got, _, err := c.Check(context.Background(), StatusListRef{Idx: idx, URI: srv.URL + "/statuslists/1"}, cwt)
			if err != nil || got != want {
				t.Errorf("cwt=%v idx %d: %v, %v; want %v", cwt, idx, got, err, want)
			}
		}
	}
	if _, _, err := (Checker{Fetcher: c.Fetcher}).Check(context.Background(), StatusListRef{URI: srv.URL}, false); err == nil {
		t.Error("a Checker without Roots checked a token")
	}
	other := x509.NewCertPool()
	otherCA, _ := testcert.CA(t, "unrelated CA")
	other.AddCert(otherCA)
	if _, _, err := (Checker{Fetcher: c.Fetcher, Roots: other}).Check(context.Background(), StatusListRef{URI: srv.URL + "/statuslists/1"}, false); err == nil {
		t.Error("a token whose signer doesn't chain to Roots was accepted")
	}
}

func TestFetcher_Refuses(t *testing.T) {
	var followed bool
	plain := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed = true }))
	defer plain.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, plain.URL, http.StatusFound)
		case "/wrong-type":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("x"))
		case "/big":
			w.Header().Set("Content-Type", TokenMediaType)
			_, _ = w.Write([]byte(strings.Repeat("a", 100)))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	f := Fetcher{HTTP: srv.Client(), MaxBytes: 10, AllowLoopback: true}
	for name, uri := range map[string]string{
		"plain http":   plain.URL + "/x",
		"redirect":     srv.URL + "/redirect",
		"wrong type":   srv.URL + "/wrong-type",
		"too big":      srv.URL + "/big",
		"not found":    srv.URL + "/missing",
		"not a URL":    "::",
		"relative URL": "/statuslists/1",
	} {
		if _, err := f.Fetch(context.Background(), uri, TokenMediaType); err == nil {
			t.Errorf("%s: fetched", name)
		}
	}
	if followed {
		t.Error("a redirect was followed")
	}
}

// TestFetcher_AddressPolicy: without AllowLoopback a loopback status
// list is refused when dialled — whichever client is passed — and the
// policy classifies the other address ranges.
func TestFetcher_AddressPolicy(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", TokenMediaType)
		_, _ = w.Write([]byte("token"))
	}))
	defer srv.Close()
	for name, f := range map[string]Fetcher{
		"caller's client": {HTTP: srv.Client()},
		"default client":  {},
	} {
		if _, err := f.Fetch(context.Background(), srv.URL+"/statuslists/1", TokenMediaType); err == nil || !strings.Contains(err.Error(), "not a public address") {
			t.Errorf("%s: loopback fetch = %v, want refused", name, err)
		}
	}
	if _, err := (Fetcher{HTTP: srv.Client(), AllowLoopback: true}).Fetch(context.Background(), srv.URL+"/statuslists/1", TokenMediaType); err != nil {
		t.Errorf("AllowLoopback fetch: %v", err)
	}

	cases := map[string]struct{ plain, loopback, private bool }{
		"93.184.215.14":    {true, true, true},
		"2606:4700::6810":  {true, true, true},
		"127.0.0.1":        {false, true, false},
		"::1":              {false, true, false},
		"::ffff:127.0.0.1": {false, true, false},
		"10.1.2.3":         {false, false, true},
		"192.168.0.1":      {false, false, true},
		"172.16.0.1":       {false, false, true},
		"169.254.169.254":  {false, false, true},
		"100.64.0.1":       {false, false, true},
		"fd00::1":          {false, false, true},
		"fe80::1":          {false, false, true},
		"0.0.0.0":          {false, false, false},
		"224.0.0.1":        {false, false, false},
	}
	for addr, want := range cases {
		ip := netip.MustParseAddr(addr).Unmap()
		got := [3]bool{
			Fetcher{}.addressAllowed(ip),
			Fetcher{AllowLoopback: true}.addressAllowed(ip),
			Fetcher{AllowPrivate: true}.addressAllowed(ip),
		}
		if got != [3]bool{want.plain, want.loopback, want.private} {
			t.Errorf("%s: allowed (default, loopback, private) = %v, want %v", addr, got, want)
		}
	}
	if err := (Fetcher{}).checkDial("tcp", "no-port", nil); err == nil {
		t.Error("checkDial accepted an address without a port")
	}
	if err := (Fetcher{}).checkDial("tcp", "name.example:443", nil); err == nil {
		t.Error("checkDial accepted an unresolved name")
	}
}

// TestFetcher_OtherRoundTripperIsUsedAsIs: a RoundTripper that isn't an
// *http.Transport keeps its own address policy.
func TestFetcher_OtherRoundTripperIsUsedAsIs(t *testing.T) {
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {TokenMediaType}},
			Body: io.NopCloser(strings.NewReader("token")), Request: r}, nil
	})
	body, err := Fetcher{HTTP: &http.Client{Transport: rt}}.Fetch(context.Background(), "https://127.0.0.1/statuslists/1", TokenMediaType)
	if err != nil || string(body) != "token" {
		t.Errorf("Fetch = %q, %v", body, err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
