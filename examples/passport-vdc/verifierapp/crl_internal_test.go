package verifierapp

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// testVerifierURL is the VerifierURL the tests' identities are for.
const testVerifierURL = "https://verifier.example"

// TestIdentities_CAsPublishCRLs: the CAs wallets trust keep their keys,
// saved with the identities, and they and the certificates they issue
// name their CRL's distribution point under the VerifierURL; the
// untrusted CA names none.
func TestIdentities_CAsPublishCRLs(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	ids, err := loadIdentities(dir, now, testVerifierURL)
	if err != nil {
		t.Fatal(err)
	}
	for path, ca := range map[string]signer{
		VerifierCRLPath:  {cert: ids.ca, key: ids.caKey},
		ReaderCRLPath:    {cert: ids.readerCA, key: ids.readerCAKey},
		RegistrarCRLPath: {cert: ids.registrarCA, key: ids.registrarCAKey},
	} {
		if ca.key == nil || !ca.key.PublicKey.Equal(ca.cert.PublicKey) || ca.cert.KeyUsage&x509.KeyUsageCRLSign == 0 ||
			!slices.Equal(ca.cert.CRLDistributionPoints, []string{testVerifierURL + path}) {
			t.Errorf("%q: no key, can't sign a CRL, or names %v", ca.cert.Subject.CommonName, ca.cert.CRLDistributionPoints)
		}
	}
	if len(ids.untrustedCA.CRLDistributionPoints) != 0 {
		t.Error("the untrusted CA names a CRL distribution point")
	}
	if dp := ids.signers[ScenarioAge].cert.CRLDistributionPoints; !slices.Equal(dp, []string{testVerifierURL + VerifierCRLPath}) {
		t.Errorf("a request signer names %v, not its CA's CRL", dp)
	}
	if dp := ids.readers[ScenarioAge].cert.CRLDistributionPoints; !slices.Equal(dp, []string{testVerifierURL + ReaderCRLPath}) {
		t.Errorf("a reader names %v, not its CA's CRL", dp)
	}
	again, err := loadIdentities(dir, now, testVerifierURL)
	if err != nil {
		t.Fatal(err)
	}
	if !again.ca.Equal(ids.ca) || !again.caKey.Equal(ids.caKey) || !again.readerCAKey.Equal(ids.readerCAKey) || !again.registrarCAKey.Equal(ids.registrarCAKey) {
		t.Error("the CA keys weren't kept across a reload")
	}
}

// TestIdentities_MigrateWithoutCAKeys: identities saved before the CAs
// kept their keys are replaced by CAs that publish CRLs; so are ones
// naming distribution points under another VerifierURL.
func TestIdentities_MigrateWithoutCAKeys(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	ids, err := loadIdentities(dir, now, testVerifierURL)
	if err != nil {
		t.Fatal(err)
	}
	// The file as it was saved before: no CA keys.
	data, err := os.ReadFile(filepath.Join(dir, identityFile))
	if err != nil {
		t.Fatal(err)
	}
	var old []byte
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		if block.Type == "EC PRIVATE KEY" && !strings.Contains(block.Headers[roleHeader], ":") && block.Headers[roleHeader] != roleRegistrar {
			continue
		}
		old = append(old, pem.EncodeToMemory(block)...)
	}
	if err := os.WriteFile(filepath.Join(dir, identityFile), old, 0o600); err != nil {
		t.Fatal(err)
	}
	migrated, err := loadIdentities(dir, now, testVerifierURL)
	if err != nil {
		t.Fatalf("loading identities without CA keys: %v", err)
	}
	if migrated.ca.Equal(ids.ca) || !migrated.publishesCRLs(testVerifierURL) {
		t.Error("identities without CA keys weren't replaced by ones publishing CRLs")
	}
	moved, err := loadIdentities(dir, now, "https://elsewhere.example")
	if err != nil {
		t.Fatal(err)
	}
	if moved.ca.Equal(migrated.ca) || !moved.publishesCRLs("https://elsewhere.example") {
		t.Error("identities naming another VerifierURL's CRLs were kept")
	}
}
