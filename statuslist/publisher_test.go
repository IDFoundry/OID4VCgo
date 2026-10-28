package statuslist

import (
	"compress/gzip"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// edLeaf issues an Ed25519 signer certificate under ca.
func edLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (*x509.Certificate, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "ed25519 status signer"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}, ca, pub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, priv
}

// TestPublisher_CheckerRoundTrip: a Checker reads what a Publisher
// serves, in both forms, for both key types.
func TestPublisher_CheckerRoundTrip(t *testing.T) {
	ca, caKey := testcert.CA(t, "status CA")
	ecCert, ecKey := testcert.Leaf(t, "ec status signer", ca, caKey)
	edCert, edKey := edLeaf(t, ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	for name, signer := range map[string]struct {
		key  crypto.Signer
		cert *x509.Certificate
	}{"ES256": {ecKey, ecCert}, "EdDSA": {edKey, edCert}} {
		t.Run(name, func(t *testing.T) {
			var uri string
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				(&Publisher{
					URI: uri, Signer: signer.key, Chain: []*x509.Certificate{signer.cert}, TTL: time.Minute,
					Statuses: func(context.Context) ([]uint8, error) { return []uint8{0, 1, 0}, nil },
				}).ServeHTTP(w, r)
			}))
			defer srv.Close()
			uri = srv.URL + "/statuslists/1"
			c := Checker{Fetcher: Fetcher{HTTP: srv.Client(), AllowLoopback: true}, Roots: roots}
			for _, cwt := range []bool{false, true} {
				for idx, want := range map[uint64]StatusType{0: StatusValid, 1: StatusInvalid, 2: StatusValid} {
					got, claims, err := c.Check(context.Background(), StatusListRef{Idx: idx, URI: uri}, cwt)
					if err != nil || got != want {
						t.Errorf("cwt=%v idx %d: %v, %v; want %v", cwt, idx, got, err, want)
					}
					if err == nil && (claims.TTL == nil || *claims.TTL != 60 || claims.Exp == nil) {
						t.Errorf("cwt=%v: ttl/exp claims = %v/%v", cwt, claims.TTL, claims.Exp)
					}
				}
			}
			resp, err := srv.Client().Get(uri)
			if err != nil || resp.Header.Get("Cache-Control") != "max-age=60" {
				t.Errorf("Cache-Control = %q, %v", resp.Header.Get("Cache-Control"), err)
			}
		})
	}
}

func TestPublisher_Refuses(t *testing.T) {
	ca, caKey := testcert.CA(t, "status CA")
	cert, key := testcert.Leaf(t, "signer", ca, caKey)
	statuses := func(context.Context) ([]uint8, error) { return []uint8{0}, nil }
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]*Publisher{
		"no URI":          {Signer: key, Chain: []*x509.Certificate{cert}, Statuses: statuses},
		"no chain":        {URI: "https://i.example/s", Signer: key, Statuses: statuses},
		"no statuses":     {URI: "https://i.example/s", Signer: key, Chain: []*x509.Certificate{cert}},
		"statuses error":  {URI: "https://i.example/s", Signer: key, Chain: []*x509.Certificate{cert}, Statuses: func(context.Context) ([]uint8, error) { return nil, errors.New("db down") }},
		"P-384 signer":    {URI: "https://i.example/s", Signer: p384, Chain: []*x509.Certificate{cert}, Statuses: statuses},
		"bad status bits": {URI: "https://i.example/s", Signer: key, Chain: []*x509.Certificate{cert}, Statuses: func(context.Context) ([]uint8, error) { return []uint8{2}, nil }},
	} {
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/s", nil))
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("%s: status %d, want 500", name, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	(&Publisher{}).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/s", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: status %d, want 405", rec.Code)
	}
}

// TestPublisher_CachesTokens: requests within the cache window share
// one signed token per form; a new one is signed once it has passed,
// and a negative CacheFor signs for every request.
func TestPublisher_CachesTokens(t *testing.T) {
	ca, caKey := testcert.CA(t, "status CA")
	cert, key := testcert.Leaf(t, "status signer", ca, caKey)
	now := time.Now()
	calls := 0
	p := &Publisher{
		URI: "https://issuer.example/statuslists/1", Signer: key, Chain: []*x509.Certificate{cert}, TTL: time.Minute,
		Statuses: func(context.Context) ([]uint8, error) { calls++; return []uint8{0, 1}, nil },
		Now:      func() time.Time { return now },
	}
	get := func(accept string) string {
		t.Helper()
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/s", nil)
		r.Header.Set("Accept", accept)
		p.ServeHTTP(rec, r)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
		return rec.Body.String()
	}
	first := get(TokenMediaType)
	if get(TokenMediaType) != first || calls != 1 {
		t.Errorf("second JWT request: %d signings, want 1 (served from cache)", calls)
	}
	get(CWTTokenMediaType)
	if calls != 2 {
		t.Errorf("first CWT request: %d signings, want 2 (each form cached on its own)", calls)
	}
	now = now.Add(time.Minute)
	if get(TokenMediaType) == first || calls != 3 {
		t.Errorf("after the window: %d signings, want a new token", calls)
	}

	p.Invalidate()
	if get(TokenMediaType); calls != 4 {
		t.Errorf("after Invalidate: %d signings, want a new token (4)", calls)
	}

	p.CacheFor = -1
	get(TokenMediaType)
	get(TokenMediaType)
	if calls != 6 {
		t.Errorf("CacheFor < 0: %d signings, want 6", calls)
	}
	for _, c := range []struct {
		cacheFor, ttl, lifetime, want time.Duration
	}{
		{0, 0, 0, 30 * time.Second},
		{0, time.Hour, 10 * time.Minute, 5 * time.Minute},
		{time.Second, time.Hour, 0, time.Second},
		{-1, time.Hour, 0, 0},
	} {
		q := &Publisher{CacheFor: c.cacheFor, TTL: c.ttl, Lifetime: c.lifetime}
		if got := q.cacheWindow(); got != c.want {
			t.Errorf("cacheWindow(CacheFor %v, TTL %v, Lifetime %v) = %v, want %v", c.cacheFor, c.ttl, c.lifetime, got, c.want)
		}
	}
}

// A request for the list at a past time (the time query parameter) is
// answered 501: the Publisher keeps only the current list
// (draft-ietf-oauth-status-list §8.4). Without it, the current list is
// served.
func TestPublisher_HistoricalResolutionNotImplemented(t *testing.T) {
	ca, caKey := testcert.CA(t, "status CA")
	cert, key := testcert.Leaf(t, "signer", ca, caKey)
	p := &Publisher{URI: "https://i.example/s", Signer: key, Chain: []*x509.Certificate{cert},
		Statuses: func(context.Context) ([]uint8, error) { return []uint8{0}, nil }}
	for target, want := range map[string]int{"/s?time=1767225600": http.StatusNotImplemented, "/s": http.StatusOK} {
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		if rec.Code != want {
			t.Errorf("GET %s: status %d, want %d", target, rec.Code, want)
		}
	}
}

// draft-14 §8.2: the response "SHOULD use gzip Content-Encoding" when
// the client accepts it (q above zero), and varies by Accept-Encoding.
func TestPublisher_Gzip(t *testing.T) {
	ca, caKey := testcert.CA(t, "status CA")
	cert, key := testcert.Leaf(t, "status signer", ca, caKey)
	p := &Publisher{
		URI: "https://issuer.example/statuslists/1", Signer: key, Chain: []*x509.Certificate{cert}, TTL: time.Minute,
		Statuses: func(context.Context) ([]uint8, error) { return []uint8{0, 1}, nil },
	}
	get := func(acceptEncoding string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/s", nil)
		if acceptEncoding != "" {
			r.Header.Set("Accept-Encoding", acceptEncoding)
		}
		p.ServeHTTP(rec, r)
		return rec
	}
	plain := get("")
	if plain.Header().Get("Content-Encoding") != "" || plain.Header().Get("Vary") != "Accept, Accept-Encoding" {
		t.Errorf("without Accept-Encoding: headers %v", plain.Header())
	}
	for _, ae := range []string{"gzip", "br, gzip;q=0.5"} {
		rec := get(ae)
		if rec.Header().Get("Content-Encoding") != "gzip" {
			t.Fatalf("Accept-Encoding %q: Content-Encoding %q, want gzip", ae, rec.Header().Get("Content-Encoding"))
		}
		zr, err := gzip.NewReader(rec.Body)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(zr)
		if err != nil || string(body) != plain.Body.String() {
			t.Errorf("Accept-Encoding %q: decompressed body isn't the token: %v", ae, err)
		}
	}
	if rec := get("gzip;q=0"); rec.Header().Get("Content-Encoding") != "" {
		t.Error("gzip;q=0 was answered with gzip")
	}
}

// TestPublisher_DefaultForm: the form Accept names alone is served;
// otherwise DefaultForm, JWT when unset (draft-14 §8.1's absent Accept).
// Every Accept line counts, as RFC 9110 §5.3 lets a client split the list.
func TestPublisher_DefaultForm(t *testing.T) {
	ca, caKey := testcert.CA(t, "status CA")
	cert, key := testcert.Leaf(t, "status signer", ca, caKey)
	for _, tc := range []struct {
		accept      []string // Accept header lines
		defaultForm Form
		want        string
	}{
		{nil, FormJWT, TokenMediaType},
		{nil, FormCWT, CWTTokenMediaType},
		{[]string{"*/*"}, FormJWT, TokenMediaType},
		{[]string{"*/*"}, FormCWT, CWTTokenMediaType},
		{[]string{"text/html"}, FormCWT, CWTTokenMediaType},
		{[]string{TokenMediaType}, FormCWT, TokenMediaType},
		{[]string{CWTTokenMediaType}, FormJWT, CWTTokenMediaType},
		{[]string{CWTTokenMediaType + ", " + TokenMediaType}, FormJWT, CWTTokenMediaType},
		{[]string{"application/json", CWTTokenMediaType}, FormJWT, CWTTokenMediaType},
		{[]string{"text/html", TokenMediaType}, FormCWT, TokenMediaType},
	} {
		p := &Publisher{URI: "https://i.example/s", Signer: key, Chain: []*x509.Certificate{cert}, DefaultForm: tc.defaultForm,
			Statuses: func(context.Context) ([]uint8, error) { return []uint8{0}, nil }}
		r := httptest.NewRequest(http.MethodGet, "/s", nil)
		for _, line := range tc.accept {
			r.Header.Add("Accept", line)
		}
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, r)
		if got := rec.Header().Get("Content-Type"); got != tc.want {
			t.Errorf("Accept %q, DefaultForm %v: served %q, want %q", tc.accept, tc.defaultForm, got, tc.want)
		}
	}
}

// TestPublisher_UnknownDefaultForm: a DefaultForm other than FormJWT or
// FormCWT is refused, not served as JWT.
func TestPublisher_UnknownDefaultForm(t *testing.T) {
	ca, caKey := testcert.CA(t, "status CA")
	cert, key := testcert.Leaf(t, "status signer", ca, caKey)
	p := &Publisher{URI: "https://i.example/s", Signer: key, Chain: []*x509.Certificate{cert}, DefaultForm: Form(2),
		Statuses: func(context.Context) ([]uint8, error) { return []uint8{0}, nil }}
	if _, err := p.Token(context.Background(), false); err == nil || !strings.Contains(err.Error(), "DefaultForm is Form(2)") {
		t.Errorf("Token err = %v, want DefaultForm refused", err)
	}
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/s", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("ServeHTTP status = %d, want 500", rec.Code)
	}
}

func TestForm_String(t *testing.T) {
	for f, want := range map[Form]string{FormJWT: "jwt", FormCWT: "cwt", Form(2): "Form(2)"} {
		if got := f.String(); got != want {
			t.Errorf("Form(%d).String() = %q, want %q", int(f), got, want)
		}
	}
}
