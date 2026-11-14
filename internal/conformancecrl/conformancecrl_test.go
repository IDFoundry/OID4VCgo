package conformancecrl_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/internal/conformancecrl"
)

// TestTrustChecksPublishedCRLs publishes a CA's CRL revoking one of its
// two leaves, and a second CA's expired CRL, and checks a Trust
// fetching them over https accepts the good leaf, refuses the revoked
// one with ErrRevoked and the second CA's with ErrNoCurrentCRL.
func TestTrustChecksPublishedCRLs(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host := "localhost:" + portOf(t, ln.Addr())

	ca, err := conformancecrl.NewAuthority("test-ca", conformancecrl.URL(host, "test-ca"))
	if err != nil {
		t.Fatal(err)
	}
	stale, err := conformancecrl.NewAuthority("stale-ca", conformancecrl.URL(host, "stale-ca"))
	if err != nil {
		t.Fatal(err)
	}
	_, good, err := ca.IssueKey("good", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, revoked, err := ca.IssueKey("revoked", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, unchecked, err := stale.IssueKey("unchecked", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := good.Cert.CRLDistributionPoints; len(got) != 1 || got[0] != ca.URL {
		t.Fatalf("leaf names distribution points %q, want [%q]", got, ca.URL)
	}
	crl, err := ca.CRL(revoked.Cert)
	if err != nil {
		t.Fatal(err)
	}
	expired, err := stale.ExpiredCRL()
	if err != nil {
		t.Fatal(err)
	}

	tlsCertPEM, tlsKeyPEM, err := conformancecert.SelfSignedPEM("localhost", []string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	pub := conformancecrl.Publisher{
		TLSCertificatePEM: tlsCertPEM, TLSPrivateKeyPEM: tlsKeyPEM,
		CRLs: map[string]string{ca.Path(): crl, stale.Path(): expired},
	}
	handler, err := pub.Handler()
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair([]byte(tlsCertPEM), []byte(tlsKeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(handler)
	_ = srv.Listener.Close()
	srv.Listener = ln
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	trust := conformancecrl.Trust{
		DistributionPoints: []conformancecrl.DistributionPoint{ca.DistributionPoint(), stale.DistributionPoint()},
		TLSTrustAnchorsPEM: tlsCertPEM,
	}
	var logged []string
	checker, err := trust.Start(ctx, func(format string, args ...any) { logged = append(logged, format) })
	if err != nil {
		t.Fatal(err)
	}
	if len(logged) == 0 {
		t.Error("the stale CA's expired CRL was accepted without a logged failure")
	}

	now := time.Now()
	check := func(leaf *x509.Certificate, root *x509.Certificate) error {
		return checker.CheckRevocation(ctx, certrevocation.Check{Chain: []*x509.Certificate{leaf, root}, Now: now})
	}
	if err := check(good.Cert, ca.Cert); err != nil {
		t.Errorf("good leaf: %v", err)
	}
	if err := check(revoked.Cert, ca.Cert); !errors.Is(err, certrevocation.ErrRevoked) {
		t.Errorf("revoked leaf: %v, want ErrRevoked", err)
	}
	if err := check(unchecked.Cert, stale.Cert); !errors.Is(err, certrevocation.ErrNoCurrentCRL) {
		t.Errorf("leaf of a CA without a current CRL: %v, want ErrNoCurrentCRL", err)
	}
}

func TestPublisherServesDERAndNotFound(t *testing.T) {
	ca, err := conformancecrl.NewAuthority("ca", conformancecrl.URL("crl.test", "ca"))
	if err != nil {
		t.Fatal(err)
	}
	crl, err := ca.CRL()
	if err != nil {
		t.Fatal(err)
	}
	handler, err := conformancecrl.Publisher{CRLs: map[string]string{ca.Path(): crl}}.Handler()
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, ca.URL, nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != conformancecrl.ContentType {
		t.Fatalf("GET %s: %d %q", ca.URL, rec.Code, rec.Header().Get("Content-Type"))
	}
	if _, err := x509.ParseRevocationList(rec.Body.Bytes()); err != nil {
		t.Fatalf("served CRL: %v", err)
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://crl.test/crl/other.crl", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown path: %d, want 404", rec.Code)
	}
}

func TestNewAuthorityRefusesHTTP(t *testing.T) {
	if _, err := conformancecrl.NewAuthority("ca", "http://crl.test/ca.crl"); err == nil {
		t.Fatal("an http distribution point was accepted")
	}
}

func portOf(t *testing.T, addr net.Addr) string {
	t.Helper()
	_, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		t.Fatal(err)
	}
	return port
}
