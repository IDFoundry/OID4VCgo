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
// and its keys an InstanceKeyStore, in a file and in memory alike.
func TestFileInstanceStore_Contract(t *testing.T) {
	for name, path := range map[string]func(t *testing.T) string{
		"file":   func(t *testing.T) string { return filepath.Join(t.TempDir(), "instances.json") },
		"memory": func(*testing.T) string { return "" },
	} {
		open := func(t *testing.T) *fileInstanceStore {
			s, err := openFileInstanceStore(path(t))
			if err != nil {
				t.Fatal(err)
			}
			return s
		}
		t.Run(name, func(t *testing.T) {
			walletprovidertest.TestInstanceStoreContract(t, func(t *testing.T) wp.InstanceStore { return open(t) })
			walletprovidertest.TestInstanceKeyStoreContract(t, func(t *testing.T) wp.InstanceKeyStore { return open(t).keys() })
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
	ik := wp.InstanceKey{Thumbprint: "tp-k", Key: []byte(`{"kty":"EC"}`), InstanceID: "a", SecurityLevel: wp.SecurityLevelTEE}
	if err := s.keys().Create(ctx, ik); err != nil {
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
	if again.holderInstance() != "a" {
		t.Fatal("the holder instance wasn't restored")
	}
	if got, err := again.keys().Get(ctx, "tp-k"); err != nil || got.InstanceID != "a" || got.SecurityLevel != wp.SecurityLevelTEE {
		t.Fatalf("reopened instance key = %+v, %v", got, err)
	}

	for name, content := range map[string]string{
		"not JSON":                  "{",
		"from before instance keys": `{"instances":{"a":{"ID":"a","KeyThumbprint":"tp"}}}`,
		"ID mismatch":               `{"version":2,"instances":{"a":{"ID":"b","KeyThumbprint":"tp"}}}`,
		"no thumbprint":             `{"version":2,"instances":{"a":{"ID":"a"}}}`,
		"shared thumbprint":         `{"version":2,"instances":{"a":{"ID":"a","KeyThumbprint":"tp"},"b":{"ID":"b","KeyThumbprint":"tp"}}}`,
		"key thumbprint mismatch":   `{"version":2,"instances":{"a":{"ID":"a","KeyThumbprint":"tp"}},"instance_keys":{"k":{"Thumbprint":"j","InstanceID":"a"}}}`,
		"key of no instance":        `{"version":2,"instances":{"a":{"ID":"a","KeyThumbprint":"tp"}},"instance_keys":{"k":{"Thumbprint":"k","InstanceID":"b"}}}`,
		"registration key as a key": `{"version":2,"instances":{"a":{"ID":"a","KeyThumbprint":"tp"}},"instance_keys":{"tp":{"Thumbprint":"tp","InstanceID":"a"}}}`,
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
// instance, and the shared Key Attestation instance and its key, where
// it left them — same status index, revocation still in force — and
// hands out no index twice.
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
	ka := sharedKeyAttestation(t, c1, &holder.PublicKey)
	kaKept, err := c1.KeyAttestation(ctx, &kept.PublicKey, []*ecdsa.PublicKey{&holder.PublicKey}, "n")
	if err != nil {
		t.Fatal(err)
	}
	if statusIdx(t, kaKept) != statusIdx(t, waKept) {
		t.Fatal("a Key Attestation for an instance key doesn't carry its status")
	}
	if err := s1.lib.Revoke(ctx, instanceOf(t, s1, &revoked.PublicKey), "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := c1.KeyAttestation(ctx, &revoked.PublicKey, []*ecdsa.PublicKey{&holder.PublicKey}, "n"); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("a Key Attestation for a revoked instance's key: %v, want refused as revoked", err)
	}

	s2, c2 := start()
	if n1, n2 := countInstances(t, s1), countInstances(t, s2); n2 != n1 || n1 != 3 || s2.store.holderInstance() != s1.store.holderInstance() || s2.store.holderInstance() == "" {
		t.Fatalf("after a restart: %d instances, holder %q; before: %d, %q", n2, s2.store.holderInstance(), n1, s1.store.holderInstance())
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
	if statusIdx(t, sharedKeyAttestation(t, c2, &holder.PublicKey)) != statusIdx(t, ka) {
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
	if st, err := s2.store.Get(ctx, instanceOf(t, s2, &revoked.PublicKey)); err != nil || st.State != wp.StateRevoked {
		t.Fatalf("revoked instance after a restart: %v, %v", st.State, err)
	}
	if n := countInstances(t, s2); n != 4 {
		t.Fatalf("%d instances after a new instance key, want 4", n)
	}
}

// instanceOf is the instance the instance key key is recorded for.
func instanceOf(t *testing.T, s *service, key *ecdsa.PublicKey) string {
	t.Helper()
	id, err := s.instanceOf(context.Background(), thumbprintOf(t, key))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func countInstances(t *testing.T, s *service) int {
	t.Helper()
	all, err := s.store.List(context.Background(), "", 1000)
	if err != nil {
		t.Fatal(err)
	}
	return len(all)
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
