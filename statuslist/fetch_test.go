package statuslist

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
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
	c := Checker{Fetcher: Fetcher{HTTP: srv.Client()}, Roots: roots}
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
	f := Fetcher{HTTP: srv.Client(), MaxBytes: 10}
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
