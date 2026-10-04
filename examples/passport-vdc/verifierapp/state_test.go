package verifierapp

import (
	"crypto/x509"
	"encoding/pem"
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

	if ids.registrarCA == nil || ids.registrar.cert.CheckSignatureFrom(ids.registrarCA) != nil {
		t.Error("no registrar, or it doesn't chain to its CA")
	}

	again, err := loadIdentities(dir, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !again.ca.Equal(ids.ca) || !again.signers[ScenarioBank].key.Equal(ids.signers[ScenarioBank].key) || !again.registrar.key.Equal(ids.registrar.key) {
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

// TestIdentities_ReplacesAnOlderLayout: a file from before the
// scenarios, with one CA and one request signer, is replaced, not an
// error that stops the verifier starting.
func TestIdentities_ReplacesAnOlderLayout(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	ca, caKey, err := newCA(now, "passport-vdc demo verifier CA")
	if err != nil {
		t.Fatal(err)
	}
	sg, err := newSigner(now, "passport-vdc demo verifier", ca, caKey, "")
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(sg.key)
	if err != nil {
		t.Fatal(err)
	}
	var old []byte
	old = append(old, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{roleHeader: "ca"}, Bytes: ca.Raw})...)
	old = append(old, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Headers: map[string]string{roleHeader: "request-signer"}, Bytes: der})...)
	old = append(old, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{roleHeader: "request-signer"}, Bytes: sg.cert.Raw})...)
	if err := os.WriteFile(filepath.Join(dir, identityFile), old, 0o600); err != nil {
		t.Fatal(err)
	}
	ids, err := loadIdentities(dir, now)
	if err != nil {
		t.Fatalf("loading an older layout: %v", err)
	}
	if ids.ca.Equal(ca) || ids.untrustedCA == nil || ids.registrarCA == nil || len(ids.signers) != len(Scenarios) {
		t.Error("the older layout wasn't replaced with a full set of identities")
	}
	again, err := loadIdentities(dir, now)
	if err != nil || !again.ca.Equal(ids.ca) {
		t.Errorf("the replacement wasn't saved: %v", err)
	}
}
