package teststatuslist

import (
	"crypto"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// JWTServer serves one JWT Status List Token over TLS, at URI, until
// the test ends: whatever Publish last signed, or HTTP 503 before.
type JWTServer struct {
	// URI is the token's status_list uri, and its sub.
	URI string
	// Fetcher fetches from the server: it trusts its certificate and
	// allows its loopback address.
	Fetcher statuslist.Fetcher
	// Certificate is the server's TLS certificate.
	Certificate *x509.Certificate
	// Fetches counts the requests the server has answered.
	Fetches atomic.Int64

	token atomic.Pointer[[]byte]
}

// ServeJWT starts a JWTServer.
func ServeJWT(t testing.TB) *JWTServer {
	t.Helper()
	s := &JWTServer{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.Fetches.Add(1)
		token := s.token.Load()
		if token == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", statuslist.TokenMediaType)
		_, _ = w.Write(*token)
	}))
	t.Cleanup(srv.Close)
	s.URI = srv.URL + "/statuslists/1"
	s.Fetcher = statuslist.Fetcher{HTTP: srv.Client(), AllowLoopback: true}
	s.Certificate = srv.Certificate()
	return s
}

// Publish has s serve a token signed by key, with chain (its
// certificate first, without the trust anchor) in its x5c header,
// whose 2-bit list holds statuses, valid for an hour with a ttl of five
// minutes.
func (s *JWTServer) Publish(t testing.TB, key crypto.Signer, chain []*x509.Certificate, statuses ...uint8) {
	t.Helper()
	list, err := statuslist.New(statuslist.Bits2, statuses, "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	exp, ttl := now.Add(time.Hour).Unix(), int64(300)
	token, err := statuslist.IssueTokenX5C(key, oid4vci.ES256, statuslist.TokenClaims{
		Sub: s.URI, Iat: now.Add(-5 * time.Second).Unix(), Exp: &exp, TTL: &ttl, StatusList: list,
	}, chain)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(token)
	s.token.Store(&raw)
}

// Claim is the "status" claim of a token whose entry is idx on s's
// list, as decoded from JSON.
func (s *JWTServer) Claim(idx int) map[string]any {
	return map[string]any{"status_list": map[string]any{"idx": float64(idx), "uri": s.URI}}
}
