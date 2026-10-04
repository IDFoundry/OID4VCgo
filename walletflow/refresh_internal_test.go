package walletflow

import (
	"context"
	"errors"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

// A refresh token refused after another refresh stored a newer one
// doesn't take the grant with it: only the token that was refused is.
func TestForgetRefusedGrant_KeepsARotatedToken(t *testing.T) {
	ctx := context.Background()
	keys := NewMemoryKeyStore()
	instance, err := newKey(ctx, keys, KeyPurposeInstance)
	if err != nil {
		t.Fatal(err)
	}
	w, err := New(Config{}, Dependencies{Keys: keys, Credentials: NewMemoryCredentialStore()})
	if err != nil {
		t.Fatal(err)
	}
	sent := RefreshGrant{ID: "g", RefreshToken: fapi.NewSecret("rt1"), InstanceKeyID: instance.ID()}
	rotated := sent
	rotated.RefreshToken = fapi.NewSecret("rt2")
	if err := w.deps.Grants.PutGrant(ctx, rotated); err != nil {
		t.Fatal(err)
	}
	w.forgetRefusedGrant(ctx, sent)
	if _, err := w.deps.Grants.GetGrant(ctx, "g"); err != nil || keys.Len() != 1 {
		t.Errorf("the rotated grant was forgotten: %v, %d keys", err, keys.Len())
	}
	w.forgetRefusedGrant(ctx, rotated)
	if _, err := w.deps.Grants.GetGrant(ctx, "g"); err == nil || keys.Len() != 0 {
		t.Errorf("the refused grant was kept: %d keys", keys.Len())
	}
}

// failingGrants is a GrantStore whose deletes and lists fail.
type failingGrants struct{ *MemoryGrantStore }

func (failingGrants) DeleteGrant(context.Context, string) error { return errors.New("store down") }
func (failingGrants) ListGrants(context.Context) ([]RefreshGrant, error) {
	return nil, errors.New("store down")
}

// revokeGrant is best effort: without a Wallet Provider, an instance
// key, or an issuer it can reach that still lists the Authorization
// Server, it sends nothing.
func TestRevokeGrant_SkipsWhatItCantDo(t *testing.T) {
	ctx := context.Background()
	keys := NewMemoryKeyStore()
	instance, err := newKey(ctx, keys, KeyPurposeInstance)
	if err != nil {
		t.Fatal(err)
	}
	g := RefreshGrant{ID: "g", CredentialIssuer: "https://127.0.0.1:1", AuthorizationServer: "https://127.0.0.1:1", RefreshToken: fapi.NewSecret("rt"), InstanceKeyID: instance.ID()}
	noProvider, err := New(Config{ClientID: "wallet"}, Dependencies{Keys: keys, Credentials: NewMemoryCredentialStore()})
	if err != nil {
		t.Fatal(err)
	}
	noProvider.revokeGrant(ctx, g, "c")
	w, err := New(Config{ClientID: "wallet"}, Dependencies{Keys: keys, Credentials: NewMemoryCredentialStore(), Provider: attestingProvider{}})
	if err != nil {
		t.Fatal(err)
	}
	missing := g
	missing.InstanceKeyID = "missing"
	w.revokeGrant(ctx, missing, "c")
	// Not Development: a loopback issuer isn't fetched.
	w.revokeGrant(ctx, g, "c")
	if keys.Len() != 1 {
		t.Errorf("keys = %d, want the instance key untouched", keys.Len())
	}
}

// unusedGrant reports a grant only when one exists and no credential
// uses it; DeleteCredential reports a grant it couldn't delete.
func TestUnusedGrantAndDeleteErrors(t *testing.T) {
	ctx := context.Background()
	keys := NewMemoryKeyStore()
	grants := failingGrants{NewMemoryGrantStore()}
	creds := NewMemoryCredentialStore()
	w, err := New(Config{}, Dependencies{Keys: keys, Credentials: creds, Grants: grants})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"", "unknown"} {
		if g, err := w.unusedGrant(ctx, id); g != nil || err != nil {
			t.Errorf("unusedGrant(%q) = %v, %v; want none", id, g, err)
		}
	}
	if err := grants.PutGrant(ctx, RefreshGrant{ID: "g", InstanceKeyID: "k"}); err != nil {
		t.Fatal(err)
	}
	if err := creds.Put(ctx, StoredCredential{ID: "c", GrantID: "g", HolderKeyID: "h"}); err != nil {
		t.Fatal(err)
	}
	if err := w.DeleteCredential(ctx, "c"); err == nil {
		t.Error("DeleteCredential with a grant store that can't delete succeeded")
	}
	if err := w.DeleteCredential(ctx, "c"); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleting it again = %v, want ErrNotFound", err)
	}
	if _, err := w.KeysInUse(ctx); err == nil {
		t.Error("KeysInUse with a grant store that can't list succeeded")
	}
}
