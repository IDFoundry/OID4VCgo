package walletprovider

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/statefile"
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

// TestFileInstanceStore_DropsExpiredKeys: Create drops the instance
// keys whose RetainUntil is before the new one's CreatedAt, keeping
// those with none, and saves their absence.
func TestFileInstanceStore_DropsExpiredKeys(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "instances.json")
	s, err := openFileInstanceStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, wp.Instance{ID: "a", KeyThumbprint: "tp-a"}); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	for tp, retain := range map[string]time.Time{"expired": at, "unset": {}, "live": at.Add(2 * time.Hour)} {
		if err := s.keys().Create(ctx, wp.InstanceKey{Thumbprint: tp, InstanceID: "a", CreatedAt: at.Add(-time.Hour), RetainUntil: retain}); err != nil {
			t.Fatal(err)
		}
	}
	// Enough keys that a Create sweeps.
	for i := range 64 {
		k := wp.InstanceKey{Thumbprint: fmt.Sprintf("new-%02d", i), InstanceID: "a", CreatedAt: at.Add(time.Hour), RetainUntil: at.Add(time.Hour)}
		if err := s.keys().Create(ctx, k); err != nil {
			t.Fatal(err)
		}
	}
	again, err := openFileInstanceStore(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, store := range []*fileInstanceStore{s, again} {
		if _, err := store.keys().Get(ctx, "expired"); !errors.Is(err, wp.ErrNotFound) {
			t.Fatalf("Get(an expired key) = %v, want ErrNotFound", err)
		}
		for _, tp := range []string{"unset", "live", "new-00"} {
			if _, err := store.keys().Get(ctx, tp); err != nil {
				t.Fatalf("Get(%q): %v", tp, err)
			}
		}
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

	// An instance key saved before keys could move has no Revision: it
	// opens at 1, and moves from there.
	older := filepath.Join(t.TempDir(), "instances.json")
	if err := os.WriteFile(older, []byte(`{"version":2,"instances":{"a":{"ID":"a","KeyThumbprint":"tp","Revision":1}},"instance_keys":{"k":{"Thumbprint":"k","InstanceID":"a"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	opened, err := openFileInstanceStore(older)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := opened.keys().Get(ctx, "k")
	if err != nil || legacy.Revision != 1 {
		t.Fatalf("an instance key without a Revision = %+v, %v; want it at 1", legacy, err)
	}
	if err := opened.keys().Update(ctx, legacy); err != nil {
		t.Fatalf("Update of an instance key without a Revision: %v", err)
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
		srv := httptest.NewTLSServer(s.handler(true))
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

// TestService_SweepsPastStatusLists: the service's Sweep deletes the
// status lists of the periods no longer served, from the status indices
// file too, and keeps the current period's.
func TestService_SweepsPastStatusLists(t *testing.T) {
	ctx := context.Background()
	p, err := New(testIssuer)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	now := time.Now()
	var logged []string
	indicesPath := filepath.Join(t.TempDir(), "status-indices.json")
	s, err := p.NewService(ServiceConfig{
		ClientID: "wallet-1", StatusIndicesPath: indicesPath,
		Logf: func(format string, args ...any) {
			mu.Lock()
			defer mu.Unlock()
			logged = append(logged, fmt.Sprintf(format, args...))
		},
		Now: func() time.Time { mu.Lock(); defer mu.Unlock(); return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(s)
	t.Cleanup(srv.Close)
	c := Client{URL: srv.URL, HTTP: srv.Client()}
	listOf := func(key *ecdsa.PrivateKey) string {
		t.Helper()
		jwt, err := c.WalletAttestation(ctx, "wallet-1", &key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		status, _ := jwtClaims(t, jwt)["status"].(map[string]any)
		list, _ := status["status_list"].(map[string]any)
		uri, _ := list["uri"].(string)
		return uri
	}
	old := listOf(p256(t))
	mu.Lock()
	now = now.Add(4 * wp.DefaultStatusListPeriod)
	mu.Unlock()
	current := listOf(p256(t))

	s.Sweep(ctx)
	indices, err := statefile.OpenIndexStore(indicesPath)
	if err != nil {
		t.Fatal(err)
	}
	for uri, want := range map[string]int{old: 0, current: 1} {
		if n, err := indices.Reserved(ctx, uri); err != nil || n != want {
			t.Fatalf("after Sweep, Reserved(%s) = %d, %v; want %d", uri, n, err, want)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Contains(logged, "wallet provider: deleted 1 status lists of past periods") {
		t.Fatalf("Sweep logged %q", logged)
	}
}
