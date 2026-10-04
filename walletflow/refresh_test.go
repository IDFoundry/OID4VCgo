package walletflow_test

import (
	"context"
	"errors"
	"testing"

	"github.com/idfoundry/oid4vcgo/wallet"
	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// newRefreshingWallet is a wallet asking for refresh tokens, keeping
// them in grants.
func (f fixture) newRefreshingWallet(t *testing.T, verifiers wallet.VerifierTrust, grants walletflow.GrantStore) *walletflow.Wallet {
	t.Helper()
	w, err := walletflow.New(walletflow.Config{
		ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, IssuerRoots: f.env.IssuerRoots,
		VerifierTrust: verifiers, Development: true, RequestRefresh: true,
	}, walletflow.Dependencies{Keys: f.keys, Credentials: f.store, Provider: f.env.Provider, HTTP: f.env.HTTP, Grants: grants})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// A wallet asking for a refresh token replaces a credential's copies
// with a fresh batch, without the holder: the same credential, new
// copies bound to new keys, the old ones gone.
func TestRefreshCredential(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{BatchSize: 3})
	v := f.env.StartVerifier(t)
	grants := walletflow.NewMemoryGrantStore()
	w := f.newRefreshingWallet(t, v.Trust, grants)
	ctx := context.Background()
	held := receive(t, f, w, walletflowtest.SDJWTConfigurationID, walletflowtest.MdocConfigurationID)
	if len(held) != 2 || held[0].GrantID == "" || held[0].GrantID != held[1].GrantID {
		t.Fatalf("credentials = %+v; want both refreshable by one grant", held)
	}
	if g, _ := grants.ListGrants(ctx); len(g) != 1 || g[0].RefreshToken.Reveal() == "" {
		t.Fatalf("grants = %d; want one with a refresh token", len(g))
	}
	// Three copies of each, and the instance key the grant keeps.
	if f.keys.Len() != 7 {
		t.Fatalf("keys = %d, want 7", f.keys.Len())
	}

	sdjwt := held[0]
	if sdjwt.Format != "dc+sd-jwt" {
		sdjwt = held[1]
	}
	if presentOnce(t, f, v, w, sdjwt.ID).CopiesLeft() != 2 {
		t.Fatal("a presentation didn't use a copy")
	}
	for range 2 { // the refresh token keeps working
		refreshed, deferred, err := w.RefreshCredential(ctx, sdjwt.ID)
		if err != nil || deferred != nil {
			t.Fatalf("RefreshCredential = %v, %v", deferred, err)
		}
		if refreshed.ID != sdjwt.ID || refreshed.GrantID != sdjwt.GrantID || refreshed.CopiesLeft() != 3 || refreshed.Claims["family_name"] != "Doe" {
			t.Fatalf("refreshed = %+v", refreshed)
		}
		assertDistinct(t, append(append([]walletflow.CredentialCopy{}, sdjwt.Copies...), refreshed.Copies...))
		sdjwt = refreshed
	}
	if f.keys.Len() != 7 {
		t.Errorf("keys after refreshing = %d, want 7: the old copies' keys deleted", f.keys.Len())
	}
	if inUse, err := w.KeysInUse(ctx); err != nil || len(inUse) != 7 {
		t.Errorf("KeysInUse = %v, %v; want every copy's key and the instance key", inUse, err)
	}
	if got := presentOnce(t, f, v, w, sdjwt.ID); got.CopiesLeft() != 2 {
		t.Errorf("after presenting a refreshed copy: %d left, want 2", got.CopiesLeft())
	}

	// The grant goes, with its instance key, with the last credential
	// using it.
	if err := w.DeleteCredential(ctx, sdjwt.ID); err != nil {
		t.Fatal(err)
	}
	if g, _ := grants.ListGrants(ctx); len(g) != 1 || f.keys.Len() != 4 {
		t.Errorf("after deleting one: %d grants, %d keys; want the grant kept for the mdoc", len(g), f.keys.Len())
	}
	for _, c := range held {
		if c.ID != sdjwt.ID {
			if err := w.DeleteCredential(ctx, c.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	if g, _ := grants.ListGrants(ctx); len(g) != 0 || f.keys.Len() != 0 {
		t.Errorf("after deleting both: %d grants, %d keys; want none", len(g), f.keys.Len())
	}
}

// A credential can't be refreshed without a refresh token, or once the
// Authorization Server refuses it: ErrReissueRequired.
func TestRefreshCredential_ReissueRequired(t *testing.T) {
	ctx := context.Background()
	t.Run("no refresh token asked for", func(t *testing.T) {
		f := newFixture(t, walletflowtest.Options{})
		c := receive(t, f, f.w, walletflowtest.SDJWTConfigurationID)[0]
		if c.GrantID != "" || f.keys.Len() != 1 {
			t.Fatalf("GrantID %q, %d keys; want none kept", c.GrantID, f.keys.Len())
		}
		if _, _, err := f.w.RefreshCredential(ctx, c.ID); !errors.Is(err, walletflow.ErrReissueRequired) {
			t.Errorf("RefreshCredential = %v, want ErrReissueRequired", err)
		}
	})
	t.Run("the grant revoked", func(t *testing.T) {
		f := newFixture(t, walletflowtest.Options{})
		grants := walletflow.NewMemoryGrantStore()
		w := f.newRefreshingWallet(t, nil, grants)
		c := receive(t, f, w, walletflowtest.SDJWTConfigurationID)[0]
		f.env.RevokeGrants()
		if _, _, err := w.RefreshCredential(ctx, c.ID); !errors.Is(err, walletflow.ErrReissueRequired) {
			t.Fatalf("RefreshCredential = %v, want ErrReissueRequired", err)
		}
		if g, _ := grants.ListGrants(ctx); len(g) != 0 || f.keys.Len() != 1 {
			t.Errorf("%d grants, %d keys; want the grant and its instance key forgotten", len(g), f.keys.Len())
		}
		if kept, err := w.Credentials(ctx); err != nil || len(kept) != 1 || kept[0].CopiesLeft() != 1 {
			t.Errorf("credentials = %+v, %v; want the credential as it was", kept, err)
		}
		if _, _, err := w.RefreshCredential(ctx, c.ID); !errors.Is(err, walletflow.ErrReissueRequired) {
			t.Errorf("RefreshCredential again = %v, want ErrReissueRequired", err)
		}
	})
}
