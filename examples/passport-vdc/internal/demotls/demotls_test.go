package demotls

import (
	"bytes"
	"net/http"
	"testing"
)

// TestAbandonedHandshakeFilter checks the servers' error log drops only
// a browser's abandoned TLS handshake (EOF), keeping real handshake
// failures and every other line.
func TestAbandonedHandshakeFilter(t *testing.T) {
	for name, tc := range map[string]struct {
		line string
		kept bool
	}{
		"abandoned handshake": {"2026/09/28 00:44:48 http: TLS handshake error from 127.0.0.1:49319: EOF\n", false},
		"unknown certificate": {"2026/09/28 00:42:21 http: TLS handshake error from 127.0.0.1:49272: remote error: tls: unknown certificate\n", true},
		"other server error":  {"2026/09/28 00:45:00 http: panic serving 127.0.0.1:49400: boom\n", true},
		"unrelated EOF":       {"2026/09/28 00:45:00 http: read request: EOF\n", true},
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			f := abandonedHandshakeFilter{w: &out}
			n, err := f.Write([]byte(tc.line))
			if err != nil || n != len(tc.line) {
				t.Fatalf("Write = %d, %v; want %d, nil", n, err, len(tc.line))
			}
			if kept := out.Len() > 0; kept != tc.kept {
				t.Errorf("kept = %v, want %v", kept, tc.kept)
			}
		})
	}
}

// TestPersistentCertificate: a second call returns the saved
// certificate, so a browser's exception for it keeps applying.
func TestPersistentCertificate(t *testing.T) {
	dir := t.TempDir()
	_, first, err := PersistentCertificate(dir, "test")
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	pair, second, err := PersistentCertificate(dir, "test")
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if !second.Equal(first) || pair.PrivateKey == nil {
		t.Error("the certificate wasn't reused")
	}
	if !ClientTrusting(first).Transport.(*http.Transport).TLSClientConfig.RootCAs.Equal(ClientTrusting(second).Transport.(*http.Transport).TLSClientConfig.RootCAs) {
		t.Error("ClientTrusting doesn't trust the same certificate")
	}
}
