package verifierapp

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestSigningIdentity_Persists: a saved identity is reused — same CA,
// same key — until its certificate is within renewBefore of expiring,
// and a damaged file is an error, not a silent new CA.
func TestSigningIdentity_Persists(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	key, cert, ca, err := signingIdentity(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	key2, cert2, ca2, err := signingIdentity(dir, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !ca2.Equal(ca) || !cert2.Equal(cert) || !key2.Equal(key) {
		t.Error("a restart made a new verifier identity")
	}

	_, cert3, ca3, err := signingIdentity(dir, cert.NotAfter.Add(-renewBefore))
	if err != nil {
		t.Fatal(err)
	}
	if ca3.Equal(ca) || cert3.Equal(cert) {
		t.Error("an identity about to expire wasn't renewed")
	}

	if _, _, ca4, _ := signingIdentity("", now); ca4.Equal(ca3) {
		t.Error("without a state directory the identity was reused")
	}

	if err := os.WriteFile(filepath.Join(dir, identityFile), []byte("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := signingIdentity(dir, now); err == nil {
		t.Error("a damaged identity file was accepted")
	}
}
