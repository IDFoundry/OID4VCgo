package issuerapp

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/credential"
)

// TestIdentity_PersistsInStateDir: a second load returns the same CA and
// signers, so credentials issued before a restart still verify.
func TestIdentity_PersistsInStateDir(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	first, err := loadOrCreateIdentity(dir, now, testCRLURL)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	second, err := loadOrCreateIdentity(dir, now, testCRLURL)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if !second.caCert.Equal(first.caCert) || !second.documentSignerCert.Equal(first.documentSignerCert) ||
		!second.metadataSignerCert.Equal(first.metadataSignerCert) || !second.documentSigner.Equal(first.documentSigner) {
		t.Error("the reloaded identity isn't the saved one")
	}
	if info, err := os.Stat(filepath.Join(dir, identityFile)); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("identity file mode = %v, %v; want 0600", info.Mode().Perm(), err)
	}
}

// TestIdentity_RenewsWhenSignersWouldExpire: a saved identity whose
// signers wouldn't outlive a credential issued now is replaced.
func TestIdentity_RenewsWhenSignersWouldExpire(t *testing.T) {
	dir := t.TempDir()
	old, err := loadOrCreateIdentity(dir, time.Now().AddDate(-2, 0, 0), testCRLURL)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	renewed, err := loadOrCreateIdentity(dir, time.Now(), testCRLURL)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if renewed.caCert.Equal(old.caCert) {
		t.Error("an identity about to expire was reused")
	}
}

// TestIdentity_ValidFromBeforeToday: an mdoc issued now is signed at the
// start of today (UTC), so the document signer must be valid from then:
// a new identity is, and a saved one that isn't is replaced.
func TestIdentity_ValidFromBeforeToday(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	id, err := loadOrCreateIdentity(dir, now, testCRLURL)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if nb := id.documentSignerCert.NotBefore; nb.After(credential.ValidFrom(now)) {
		t.Errorf("document signer valid from %v, after the start of today", nb)
	}

	dir = t.TempDir()
	late, err := loadOrCreateIdentity(dir, now.Add(48*time.Hour), testCRLURL)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	renewed, err := loadOrCreateIdentity(dir, now, testCRLURL)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if renewed.documentSignerCert.Equal(late.documentSignerCert) {
		t.Error("an identity not yet valid at the start of today was reused")
	}
}

// TestIdentity_RenewsDocumentSignerWithoutEKU: a saved identity from
// before the document signer carried the mDL document signer's extended
// key usage, which verifiers now require, is replaced.
func TestIdentity_RenewsDocumentSignerWithoutEKU(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	old, err := newIssuerIdentityWithSignerEKUs(now, testCRLURL)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := encodeIdentity(old)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(filepath.Join(dir, identityFile), encoded); err != nil {
		t.Fatal(err)
	}
	renewed, err := loadOrCreateIdentity(dir, now, testCRLURL)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if renewed.documentSignerCert.Equal(old.documentSignerCert) {
		t.Error("a document signer without the mDL document signer's extended key usage was reused")
	}
	if err := mdoc.DefaultDocumentSignerPolicy(renewed.documentSignerCert, nil); err != nil {
		t.Errorf("renewed document signer: %v", err)
	}
}

func TestIdentity_RejectsDamagedFile(t *testing.T) {
	for name, content := range map[string]string{
		"not PEM":    "garbage",
		"incomplete": "-----BEGIN CERTIFICATE-----\nRole: ca\n\nMA==\n-----END CERTIFICATE-----\n",
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, identityFile), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadOrCreateIdentity(dir, time.Now(), testCRLURL); err == nil {
			t.Errorf("%s: a damaged identity file was accepted", name)
		}
	}
}
