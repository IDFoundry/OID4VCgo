package walletprovider

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	wp "github.com/idfoundry/oid4vcgo/walletprovider"
	"github.com/idfoundry/oid4vcgo/walletprovider/walletprovidertest"
)

// TestFileInstanceStore_Contract: the file store is an InstanceStore,
// in a file and in memory alike.
func TestFileInstanceStore_Contract(t *testing.T) {
	for name, path := range map[string]func(t *testing.T) string{
		"file":   func(t *testing.T) string { return filepath.Join(t.TempDir(), "instances.json") },
		"memory": func(*testing.T) string { return "" },
	} {
		t.Run(name, func(t *testing.T) {
			walletprovidertest.TestInstanceStoreContract(t, func(t *testing.T) wp.InstanceStore {
				s, err := openFileInstanceStore(path(t))
				if err != nil {
					t.Fatal(err)
				}
				return s
			})
		})
	}
}

// TestFileInstanceStore_Reopens: what the store saved, and the shared
// holder instance's ID, are there when it's opened again; a damaged
// file is refused.
func TestFileInstanceStore_Reopens(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "instances.json")
	s, err := openFileInstanceStore(path)
	if err != nil {
		t.Fatal(err)
	}
	in := wp.Instance{ID: "a", KeyThumbprint: "tp-a", Key: []byte(`{"kty":"EC"}`), Credential: []byte{1, 2}, State: wp.StateActive}
	if err := s.Create(ctx, in); err != nil {
		t.Fatal(err)
	}
	stored, err := s.Get(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	stored.State = wp.StateSuspended
	if err := s.Update(ctx, stored); err != nil {
		t.Fatal(err)
	}
	if err := s.setHolderInstance("a"); err != nil {
		t.Fatal(err)
	}

	again, err := openFileInstanceStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := again.Get(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != wp.StateSuspended || got.Revision != 2 || !bytes.Equal(got.Credential, in.Credential) || string(got.Key) != string(in.Key) {
		t.Fatalf("reopened instance = %+v", got)
	}
	if again.holderInstance() != "a" || len(again.byThumbprint()) != 0 {
		t.Fatal("the holder instance or the thumbprint index wasn't restored")
	}

	for name, content := range map[string]string{
		"not JSON":          "{",
		"ID mismatch":       `{"instances":{"a":{"ID":"b","KeyThumbprint":"tp"}}}`,
		"no thumbprint":     `{"instances":{"a":{"ID":"a"}}}`,
		"shared thumbprint": `{"instances":{"a":{"ID":"a","KeyThumbprint":"tp"},"b":{"ID":"b","KeyThumbprint":"tp"}}}`,
	} {
		bad := filepath.Join(t.TempDir(), "instances.json")
		if err := os.WriteFile(bad, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := openFileInstanceStore(bad); err == nil {
			t.Errorf("%s: a damaged instances file was accepted", name)
		}
	}
}

// TestService_KeepsInstancesAcrossRestart: with InstancesPath and
// StatusIndicesPath, a restarted service finds an instance key's
// instance, and the shared Key Attestation instance, where it left
// them — same status index, revocation still in force — and hands out
// no index twice.
func TestService_KeepsInstancesAcrossRestart(t *testing.T) {
	ctx := context.Background()
	p, err := New(testIssuer)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := ServiceConfig{
		ClientID: "wallet-1", Logf: func(string, ...any) {},
		InstancesPath:     filepath.Join(dir, "instances.json"),
		StatusIndicesPath: filepath.Join(dir, "status-indices.json"),
	}
	start := func() (*service, Client) {
		t.Helper()
		s, err := p.newService(cfg)
		if err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewTLSServer(s.handler())
		t.Cleanup(srv.Close)
		return s, Client{URL: srv.URL, HTTP: srv.Client()}
	}
	statusIdx := func(t *testing.T, jwt string) float64 {
		t.Helper()
		claims := jwtClaims(t, jwt)
		status, _ := claims["status"].(map[string]any)
		list, _ := status["status_list"].(map[string]any)
		idx, ok := list["idx"].(float64)
		if !ok {
			t.Fatalf("no status index in %v", claims)
		}
		return idx
	}

	s1, c1 := start()
	kept, revoked, holder := p256(t), p256(t), p256(t)
	waKept, err := c1.WalletAttestation(ctx, "wallet-1", &kept.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c1.WalletAttestation(ctx, "wallet-1", &revoked.PublicKey); err != nil {
		t.Fatal(err)
	}
	ka, err := c1.KeyAttestation(ctx, []*ecdsa.PublicKey{&holder.PublicKey}, "n")
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.lib.Revoke(ctx, s1.instances[thumbprintOf(t, &revoked.PublicKey)], "test"); err != nil {
		t.Fatal(err)
	}

	s2, c2 := start()
	if len(s2.instances) != len(s1.instances) || s2.holderInstance != s1.holderInstance || s2.holderInstance == "" {
		t.Fatalf("after a restart: %d instances, holder %q; before: %d, %q", len(s2.instances), s2.holderInstance, len(s1.instances), s1.holderInstance)
	}
	again, err := c2.WalletAttestation(ctx, "wallet-1", &kept.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if statusIdx(t, again) != statusIdx(t, waKept) {
		t.Fatal("the instance's status index changed across a restart")
	}
	if _, err := c2.WalletAttestation(ctx, "wallet-1", &revoked.PublicKey); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("a revoked instance after a restart: %v, want refused as revoked", err)
	}
	ka2, err := c2.KeyAttestation(ctx, []*ecdsa.PublicKey{&holder.PublicKey}, "n")
	if err != nil {
		t.Fatal(err)
	}
	if statusIdx(t, ka2) != statusIdx(t, ka) {
		t.Fatal("Key Attestations moved to another instance across a restart")
	}
	fresh, err := c2.WalletAttestation(ctx, "wallet-1", &p256(t).PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, old := range []string{waKept, ka} {
		if statusIdx(t, fresh) == statusIdx(t, old) {
			t.Fatal("a new instance got an index handed out before the restart")
		}
	}
	if st, err := s2.store.Get(ctx, s2.instances[thumbprintOf(t, &revoked.PublicKey)]); err != nil || st.State != wp.StateRevoked {
		t.Fatalf("revoked instance after a restart: %v, %v", st.State, err)
	}
}

// TestAndroidAppsFlag: package:sha256[,sha256...], colons in a digest
// allowed; anything else refused.
func TestAndroidAppsFlag(t *testing.T) {
	d1, d2 := strings.Repeat("ab", 32), strings.Repeat("CD:", 31)+"CD"
	var f AndroidAppsFlag
	if err := f.Set("com.example.wallet:" + d1 + "," + d2); err != nil {
		t.Fatal(err)
	}
	if err := f.Set("com.example.other:" + d1); err != nil {
		t.Fatal(err)
	}
	if len(f) != 2 || f[0].Package != "com.example.wallet" || len(f[0].SigningCertificateDigests) != 2 || f[0].SigningCertificateDigests[1][0] != 0xcd || f.String() != "com.example.wallet com.example.other" {
		t.Fatalf("parsed %+v", f)
	}
	for _, bad := range []string{"", "com.example", ":" + d1, "com.example:", "com.example:abcd", "com.example:" + d1 + ",zz"} {
		if err := new(AndroidAppsFlag).Set(bad); err == nil {
			t.Errorf("Set(%q) was accepted", bad)
		}
	}
}
