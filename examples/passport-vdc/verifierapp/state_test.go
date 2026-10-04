package verifierapp

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestIdentities_Persist: saved identities are reused — same CAs, same
// keys — until a certificate is within renewBefore of expiring; each
// scenario's names its relying party and chains to the CA its trust
// calls for; and a damaged file is an error, not a silent new CA.
func TestIdentities_Persist(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	ids, err := loadIdentities(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range Scenarios {
		info, _ := s.Info()
		sg := ids.signers[s]
		if sg.cert.Subject.CommonName != info.Verifier {
			t.Errorf("%s: certificate names %q, want %q", s, sg.cert.Subject.CommonName, info.Verifier)
		}
		ca, other := ids.ca, ids.untrustedCA
		if !info.Trusted {
			ca, other = other, ca
		}
		if sg.cert.CheckSignatureFrom(ca) != nil || sg.cert.CheckSignatureFrom(other) == nil {
			t.Errorf("%s (trusted %v): not issued by the CA its trust calls for", s, info.Trusted)
		}
	}

	again, err := loadIdentities(dir, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !again.ca.Equal(ids.ca) || !again.signers[ScenarioBank].key.Equal(ids.signers[ScenarioBank].key) {
		t.Error("a restart made new verifier identities")
	}

	renewed, err := loadIdentities(dir, ids.signers[ScenarioAge].cert.NotAfter.Add(-renewBefore))
	if err != nil {
		t.Fatal(err)
	}
	if renewed.ca.Equal(ids.ca) {
		t.Error("identities about to expire weren't renewed")
	}

	if fresh, _ := loadIdentities("", now); fresh.ca.Equal(renewed.ca) {
		t.Error("without a state directory the identities were reused")
	}

	if err := os.WriteFile(filepath.Join(dir, identityFile), []byte("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadIdentities(dir, now); err == nil {
		t.Error("a damaged identity file was accepted")
	}
}
