package statuslist

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
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
				Publisher{
					URI: uri, Signer: signer.key, Chain: []*x509.Certificate{signer.cert}, TTL: time.Minute,
					Statuses: func(context.Context) ([]uint8, error) { return []uint8{0, 1, 0}, nil },
				}.ServeHTTP(w, r)
			}))
			defer srv.Close()
			uri = srv.URL + "/statuslists/1"
			c := Checker{Fetcher: Fetcher{HTTP: srv.Client()}, Roots: roots}
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
	for name, p := range map[string]Publisher{
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
	Publisher{}.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/s", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: status %d, want 405", rec.Code)
	}
}
