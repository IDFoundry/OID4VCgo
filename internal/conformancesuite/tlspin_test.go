package conformancesuite

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
)

// TestPinnedHTTPClient checks the client reaches a server presenting
// the certificate ServerCertificate read off it, and refuses one
// presenting another.
func TestPinnedHTTPClient(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	pinnedServer := httptest.NewTLSServer(handler)
	defer pinnedServer.Close()
	// httptest's servers all present one built-in certificate.
	certPEM, keyPEM, err := conformancecert.SelfSignedPEM("other", []string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	otherCert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	otherServer := httptest.NewUnstartedServer(handler)
	otherServer.TLS = &tls.Config{Certificates: []tls.Certificate{otherCert}, MinVersion: tls.VersionTLS12}
	otherServer.StartTLS()
	defer otherServer.Close()

	cert, err := ServerCertificate(context.Background(), pinnedServer.URL)
	if err != nil {
		t.Fatalf("ServerCertificate: %v", err)
	}
	client := PinnedHTTPClient(cert)

	res, err := client.Get(pinnedServer.URL)
	if err != nil {
		t.Fatalf("pinned server refused: %v", err)
	}
	_ = res.Body.Close()
	if res, err := client.Get(otherServer.URL); err == nil {
		_ = res.Body.Close()
		t.Fatal("a server presenting another certificate was accepted")
	}
	if _, err := ServerCertificate(context.Background(), "https:///no-host"); err == nil {
		t.Error("a URL naming no host was accepted")
	}
}
