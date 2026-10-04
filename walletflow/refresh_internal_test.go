package walletflow

import (
	"context"
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
