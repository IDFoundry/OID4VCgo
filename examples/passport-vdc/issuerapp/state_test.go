package issuerapp

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestIdentity_PersistsInStateDir: a second load returns the same CA and
// signers, so credentials issued before a restart still verify.
func TestIdentity_PersistsInStateDir(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	first, err := loadOrCreateIdentity(dir, now)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	second, err := loadOrCreateIdentity(dir, now)
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
	old, err := loadOrCreateIdentity(dir, time.Now().AddDate(-2, 0, 0))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	renewed, err := loadOrCreateIdentity(dir, time.Now())
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if renewed.caCert.Equal(old.caCert) {
		t.Error("an identity about to expire was reused")
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
		if _, err := loadOrCreateIdentity(dir, time.Now()); err == nil {
			t.Errorf("%s: a damaged identity file was accepted", name)
		}
	}
}

// TestStatusList_PersistsInStateDir: allocations and revocations survive
// a reload; released indices don't.
func TestStatusList_PersistsInStateDir(t *testing.T) {
	dir := t.TempDir()
	s, err := loadStatusList(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	now := time.Now().Truncate(time.Second)
	kept, err := s.allocate("dc+sd-jwt", now)
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := s.allocate("mso_mdoc", now)
	if err != nil {
		t.Fatal(err)
	}
	released, err := s.allocate("mso_mdoc", now)
	if err != nil {
		t.Fatal(err)
	}
	s.release(released)
	if !s.revoke(revoked) {
		t.Fatal("revoke failed")
	}

	reloaded, err := loadStatusList(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	bits, entries := reloaded.snapshot()
	if len(entries) != 2 {
		t.Fatalf("reloaded %d entries, want 2", len(entries))
	}
	if bits[kept] != 0 || bits[revoked] != 1 {
		t.Errorf("reloaded status bits: kept=%d revoked=%d, want 0 and 1", bits[kept], bits[revoked])
	}
	if _, ok := reloaded.entries[released]; ok {
		t.Error("a released index came back after reload")
	}
}

func TestStatusList_RejectsDamagedFile(t *testing.T) {
	for name, content := range map[string]string{
		"not JSON":     "{",
		"out of range": `[{"Idx":70000,"Format":"mso_mdoc"}]`,
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, statusListFile), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadStatusList(dir); err == nil {
			t.Errorf("%s: a damaged status list was accepted", name)
		}
	}
}

// TestStatusList_InMemoryWithoutStateDir: an issuer without StateDir
// writes nothing.
func TestStatusList_InMemoryWithoutStateDir(t *testing.T) {
	s := newStatusList()
	if _, err := s.allocate("mso_mdoc", time.Now()); err != nil {
		t.Fatal(err)
	}
	if s.path != "" {
		t.Error("an in-memory status list has a file")
	}
}

// TestStatusPage_HidesIndices: the public revocation page names entries
// by handle, never by status list index, and a handle revokes its entry.
func TestStatusPage_HidesIndices(t *testing.T) {
	s := newStatusList()
	idx, err := s.allocate("mso_mdoc", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, entries := s.snapshot()
	var page strings.Builder
	if err := statusTemplate.Execute(&page, struct {
		URI     string
		Entries []IssuedStatus
	}{"https://issuer.example/statuslists/1", entries}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(page.String(), ">"+strconv.Itoa(idx)+"<") || strings.Contains(page.String(), `name="idx"`) {
		t.Error("the revocation page shows a status list index")
	}
	if !strings.Contains(page.String(), `value="`+entries[0].Handle+`"`) {
		t.Error("the revocation page doesn't name the entry by its handle")
	}
	if s.revokeHandle("") || s.revokeHandle("unknown") {
		t.Error("an empty or unknown handle revoked something")
	}
	if !s.revokeHandle(entries[0].Handle) {
		t.Fatal("revoking by handle failed")
	}
	if bits, _ := s.snapshot(); bits[idx] != 1 {
		t.Error("the handle didn't revoke its entry")
	}
}
