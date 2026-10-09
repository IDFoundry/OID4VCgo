package walletflow_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

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
		if refreshed.ShownTo(v.ClientID) {
			t.Error("refreshed copies carry the old copies' Verifier history")
		}
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
	if g, _ := grants.ListGrants(ctx); len(g) != 1 || f.keys.Len() != 4 || f.env.Revocations() != 0 {
		t.Errorf("after deleting one: %d grants, %d keys, %d revocations; want the grant kept for the mdoc", len(g), f.keys.Len(), f.env.Revocations())
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
	// The issuer's grant ends with the last credential using it.
	if n := f.env.Revocations(); n != 1 {
		t.Errorf("refresh tokens revoked = %d, want 1", n)
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

// deletingStore deletes the credential victim the second time it's read,
// as the holder deleting it while it's refreshed: the refresh reads it
// when it starts, then again to replace it.
type deletingStore struct {
	*walletflow.MemoryCredentialStore
	victim string
	reads  int
}

func (s *deletingStore) Get(ctx context.Context, id string) (walletflow.StoredCredential, error) {
	if id == s.victim {
		if s.reads++; s.reads == 2 {
			_ = s.Delete(ctx, id)
		}
	}
	return s.MemoryCredentialStore.Get(ctx, id)
}

// A credential deleted while it's refreshed stays deleted: the new
// copies, and their keys, aren't kept.
func TestRefreshCredential_DeletedMeanwhile(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{BatchSize: 2})
	grants := walletflow.NewMemoryGrantStore()
	store := &deletingStore{MemoryCredentialStore: walletflow.NewMemoryCredentialStore()}
	w, err := walletflow.New(walletflow.Config{
		ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, IssuerRoots: f.env.IssuerRoots,
		Development: true, RequestRefresh: true,
	}, walletflow.Dependencies{Keys: f.keys, Credentials: store, Provider: f.env.Provider, HTTP: f.env.HTTP, Grants: grants})
	if err != nil {
		t.Fatal(err)
	}
	c := receive(t, f, w, walletflowtest.SDJWTConfigurationID)[0]
	keysBefore := f.keys.Len()
	store.victim = c.ID
	ctx := context.Background()
	if _, _, err := w.RefreshCredential(ctx, c.ID); !errors.Is(err, walletflow.ErrNotFound) {
		t.Fatalf("RefreshCredential = %v, want ErrNotFound", err)
	}
	if left, _ := store.List(ctx); len(left) != 0 {
		t.Errorf("credentials after the refresh = %d, want the deletion to stand", len(left))
	}
	if f.keys.Len() != keysBefore {
		t.Errorf("keys = %d, want %d: the new copies' keys deleted", f.keys.Len(), keysBefore)
	}
}

// A refresh grant is only used for its own issuer, and only at an
// Authorization Server the issuer lists; one no credential uses is
// forgotten.
func TestRefreshCredential_GrantChecks(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, walletflowtest.Options{})
	grants := walletflow.NewMemoryGrantStore()
	w := f.newRefreshingWallet(t, nil, grants)
	c := receive(t, f, w, walletflowtest.SDJWTConfigurationID)[0]
	g, err := grants.GetGrant(ctx, c.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*walletflow.RefreshGrant){
		"another issuer's":                 func(g *walletflow.RefreshGrant) { g.CredentialIssuer = "https://other.example" },
		"an authorization server unlisted": func(g *walletflow.RefreshGrant) { g.AuthorizationServer = "https://as.other.example" },
	} {
		changed := g
		change(&changed)
		if err := grants.PutGrant(ctx, changed); err != nil {
			t.Fatal(err)
		}
		if _, _, err := w.RefreshCredential(ctx, c.ID); !errors.Is(err, walletflow.ErrReissueRequired) {
			t.Errorf("with %s grant: RefreshCredential = %v, want ErrReissueRequired", name, err)
		}
	}
	if err := grants.PutGrant(ctx, g); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.RefreshCredential(ctx, c.ID); err != nil {
		t.Fatalf("with the grant restored: %v", err)
	}

	// A grant nothing uses, as a failed issuance or deletion leaves.
	orphan := g
	orphan.ID, orphan.InstanceKeyID = "orphan", "orphan-key"
	if err := grants.PutGrant(ctx, orphan); err != nil {
		t.Fatal(err)
	}
	if _, err := w.KeysInUse(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := grants.GetGrant(ctx, "orphan"); !errors.Is(err, walletflow.ErrNotFound) {
		t.Errorf("an orphaned grant survived KeysInUse: %v", err)
	}
	if _, err := grants.GetGrant(ctx, g.ID); err != nil {
		t.Errorf("the grant in use was forgotten: %v", err)
	}
}

// A refresh token is bound to the wallet instance key it was issued
// with (draft-ietf-oauth-attestation-based-client-auth-07 §10.3): an
// attestation for another instance key of the same wallet can't redeem
// it.
func TestRefreshCredential_BoundToTheInstanceKey(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, walletflowtest.Options{})
	grants := walletflow.NewMemoryGrantStore()
	w := f.newRefreshingWallet(t, nil, grants)
	c := receive(t, f, w, walletflowtest.SDJWTConfigurationID)[0]
	g, err := grants.GetGrant(ctx, c.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	other, err := f.keys.NewKey(ctx, walletflow.KeyPurposeInstance)
	if err != nil {
		t.Fatal(err)
	}
	moved := g
	moved.InstanceKeyID = other.ID()
	if err := grants.PutGrant(ctx, moved); err != nil {
		t.Fatal(err)
	}
	_, _, err = w.RefreshCredential(ctx, c.ID)
	if !errors.Is(err, walletflow.ErrReissueRequired) || !strings.Contains(err.Error(), "another client instance") {
		t.Fatalf("RefreshCredential with another instance key = %v, want the server's invalid_grant", err)
	}
}

// A pre-authorized code's issuance keeps the refresh token the
// Authorization Server issues with it, so its credential can be
// refreshed too; a wallet not asking for refresh discards it.
func TestRefreshCredential_PreAuthorizedCode(t *testing.T) {
	ctx := context.Background()
	receivePIN := func(f fixture, w *walletflow.Wallet) walletflow.StoredCredential {
		t.Helper()
		s, err := w.StartIssuance(ctx, f.env.PreAuthorizedOffer(t, "493536", walletflowtest.SDJWTConfigurationID))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s.Close(ctx) }()
		if err := s.RedeemPreAuthorizedCode(ctx, "493536"); err != nil {
			t.Fatal(err)
		}
		result, err := s.RequestCredentials(ctx)
		if err != nil || len(result.Credentials) != 1 {
			t.Fatalf("RequestCredentials = %+v, %v", result, err)
		}
		return result.Credentials[0]
	}

	f := newFixture(t, walletflowtest.Options{BatchSize: 2})
	if c := receivePIN(f, f.w); c.GrantID != "" || f.keys.Len() != 2 {
		t.Errorf("without RequestRefresh: GrantID %q, %d keys; want no grant and only the copies' keys", c.GrantID, f.keys.Len())
	}

	f = newFixture(t, walletflowtest.Options{BatchSize: 2})
	grants := walletflow.NewMemoryGrantStore()
	w := f.newRefreshingWallet(t, nil, grants)
	c := receivePIN(f, w)
	if c.GrantID == "" {
		t.Fatal("the pre-authorized credential isn't refreshable")
	}
	refreshed, _, err := w.RefreshCredential(ctx, c.ID)
	if err != nil || refreshed.ID != c.ID || refreshed.CopiesLeft() != 2 {
		t.Fatalf("RefreshCredential = %+v, %v", refreshed, err)
	}
	assertDistinct(t, append(append([]walletflow.CredentialCopy{}, c.Copies...), refreshed.Copies...))
	f.env.RevokeGrants()
	if _, _, err := w.RefreshCredential(ctx, c.ID); !errors.Is(err, walletflow.ErrReissueRequired) {
		t.Errorf("after the grant was revoked: %v, want ErrReissueRequired", err)
	}
}

// An Authorization Server serving only the pre-authorized code grant
// publishes no authorization or pushed authorization request endpoint:
// its code is redeemed, and the grant refreshed and revoked, from its
// token and revocation endpoints alone.
func TestRefreshCredential_PreAuthorizedCodeOnlyServer(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, walletflowtest.Options{PreAuthorizedCodeOnly: true})
	w := f.newRefreshingWallet(t, nil, walletflow.NewMemoryGrantStore())
	s, err := w.StartIssuance(ctx, f.env.PreAuthorizedOffer(t, "493536", walletflowtest.SDJWTConfigurationID))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RedeemPreAuthorizedCode(ctx, "493536"); err != nil {
		t.Fatalf("RedeemPreAuthorizedCode: %v", err)
	}
	result, err := s.RequestCredentials(ctx)
	if err != nil || len(result.Credentials) != 1 || result.Credentials[0].GrantID == "" {
		t.Fatalf("RequestCredentials = %+v, %v; want one refreshable credential", result, err)
	}
	c := result.Credentials[0]
	if err := s.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.RefreshCredential(ctx, c.ID); err != nil {
		t.Fatalf("RefreshCredential: %v", err)
	}
	if err := w.DeleteCredential(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if n := f.env.Revocations(); n != 1 {
		t.Errorf("refresh tokens revoked = %d, want 1", n)
	}
}

// An Authorization Server with a challenge endpoint gets a fresh
// challenge in every Client Attestation PoP
// (draft-ietf-oauth-attestation-based-client-auth-07 §8): at the pushed
// authorization request and token endpoints of the authorization code
// grant, and the token endpoint of the pre-authorized code grant. It
// refuses any PoP without one.
func TestIssuance_AttestationChallenges(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, walletflowtest.Options{AttestationChallenges: true})
	if held := receive(t, f, f.w, walletflowtest.SDJWTConfigurationID); len(held) != 1 {
		t.Fatalf("authorization code grant: %d credentials, want 1", len(held))
	}

	s, err := f.w.StartIssuance(ctx, f.env.PreAuthorizedOffer(t, "493536", walletflowtest.SDJWTConfigurationID))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close(ctx) }()
	if err := s.RedeemPreAuthorizedCode(ctx, "493536"); err != nil {
		t.Fatalf("pre-authorized code grant: %v", err)
	}
	if result, err := s.RequestCredentials(ctx); err != nil || len(result.Credentials) != 1 {
		t.Fatalf("RequestCredentials = %+v, %v", result, err)
	}
}

// A grant whose instance key is gone can't be used: it's forgotten, and
// the credential has to be received again.
func TestRefreshCredential_InstanceKeyGone(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, walletflowtest.Options{})
	grants := walletflow.NewMemoryGrantStore()
	w := f.newRefreshingWallet(t, nil, grants)
	c := receive(t, f, w, walletflowtest.SDJWTConfigurationID)[0]
	g, err := grants.GetGrant(ctx, c.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.keys.DeleteKey(ctx, g.InstanceKeyID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.RefreshCredential(ctx, c.ID); !errors.Is(err, walletflow.ErrReissueRequired) {
		t.Fatalf("RefreshCredential = %v, want ErrReissueRequired", err)
	}
	if _, err := grants.GetGrant(ctx, g.ID); !errors.Is(err, walletflow.ErrNotFound) {
		t.Errorf("the grant was kept: %v", err)
	}
}

// waitIssued waits for d to settle with the issuer's approval.
func waitIssued(t *testing.T, f fixture, d *walletflow.Deferred) (walletflow.StoredCredential, error) {
	t.Helper()
	f.env.Decide(true)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return d.Wait(ctx)
}

// A credential deferred at issuance keeps its refresh grant, and its
// instance key, while it's pending: once issued it can be refreshed.
func TestRefreshCredential_DeferredAtIssuance(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, walletflowtest.Options{Defer: true})
	grants := walletflow.NewMemoryGrantStore()
	w := f.newRefreshingWallet(t, nil, grants)
	s, err := w.StartIssuance(ctx, f.env.AuthorizationCodeOffer(t, walletflowtest.SDJWTConfigurationID))
	if err != nil {
		t.Fatal(err)
	}
	authorize(t, f, s)
	result, err := s.RequestCredentials(ctx)
	if err != nil || len(result.Deferred) != 1 {
		t.Fatalf("RequestCredentials = %+v, %v", result, err)
	}
	if err := s.Close(ctx); err != nil {
		t.Fatal(err)
	}
	// The pending credential keeps the grant: a sweep doesn't forget it.
	if _, err := w.KeysInUse(ctx); err != nil {
		t.Fatal(err)
	}
	if g, _ := grants.ListGrants(ctx); len(g) != 1 {
		t.Fatalf("grants while deferred = %d, want 1", len(g))
	}
	stored, err := waitIssued(t, f, result.Deferred[0])
	if err != nil || stored.GrantID == "" {
		t.Fatalf("issued = %+v, %v; want it refreshable", stored, err)
	}
	f.env.SetDefer(false)
	if _, _, err := w.RefreshCredential(ctx, stored.ID); err != nil {
		t.Errorf("RefreshCredential = %v", err)
	}
}

// A refresh the issuer defers replaces the credential once issued,
// keeping its ID and grant — unless the holder deleted it meanwhile.
func TestRefreshCredential_Deferred(t *testing.T) {
	ctx := context.Background()
	for _, deleteMeanwhile := range []bool{false, true} {
		f := newFixture(t, walletflowtest.Options{})
		grants := walletflow.NewMemoryGrantStore()
		w := f.newRefreshingWallet(t, nil, grants)
		held := receive(t, f, w, walletflowtest.SDJWTConfigurationID, walletflowtest.MdocConfigurationID)
		c := held[0]
		f.env.SetDefer(true)
		kept, d, err := w.RefreshCredential(ctx, c.ID)
		if err != nil || d == nil || kept.ID != c.ID {
			t.Fatalf("RefreshCredential = %+v, %v, %v; want the old credential and a deferred one", kept, d, err)
		}
		if deleteMeanwhile {
			if err := w.DeleteCredential(ctx, c.ID); err != nil {
				t.Fatal(err)
			}
		}
		stored, err := waitIssued(t, f, d)
		left, _ := w.Credentials(ctx)
		switch {
		case deleteMeanwhile:
			if !errors.Is(err, walletflow.ErrNotFound) || len(left) != 1 {
				t.Errorf("after deleting meanwhile: %v, %d credentials; want the deletion to stand", err, len(left))
			}
		case err != nil || stored.ID != c.ID || stored.GrantID != c.GrantID || len(left) != 2:
			t.Errorf("issued = %+v, %v, %d credentials; want it to replace the old one", stored, err, len(left))
		case stored.Copies[0].Credential == c.Copies[0].Credential:
			t.Error("the refreshed credential is the old one")
		}
	}
}

// A deferred credential abandoned, its grant's only user, takes the
// grant with it: the refresh token is revoked, and no key is left.
func TestRefreshCredential_AbandonedDeferredReleasesTheGrant(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, walletflowtest.Options{Defer: true})
	grants := walletflow.NewMemoryGrantStore()
	w := f.newRefreshingWallet(t, nil, grants)
	s, err := w.StartIssuance(ctx, f.env.AuthorizationCodeOffer(t, walletflowtest.SDJWTConfigurationID))
	if err != nil {
		t.Fatal(err)
	}
	authorize(t, f, s)
	result, err := s.RequestCredentials(ctx)
	if err != nil || len(result.Deferred) != 1 {
		t.Fatalf("RequestCredentials = %+v, %v", result, err)
	}
	if err := s.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := result.Deferred[0].Abandon(ctx); err != nil {
		t.Fatal(err)
	}
	if g, _ := grants.ListGrants(ctx); len(g) != 0 || f.keys.Len() != 0 || f.env.Revocations() != 1 {
		t.Errorf("after abandoning: %d grants, %d keys, %d revocations; want none, none, 1", len(g), f.keys.Len(), f.env.Revocations())
	}
}

// An issuance still open keeps its refresh grant: deleting a credential
// it stored doesn't revoke the grant the issuance may still need.
// Closing the issuance releases a grant nothing uses.
func TestRefreshCredential_OpenIssuanceHoldsItsGrant(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, walletflowtest.Options{})
	grants := walletflow.NewMemoryGrantStore()
	w := f.newRefreshingWallet(t, nil, grants)
	s, err := w.StartIssuance(ctx, f.env.AuthorizationCodeOffer(t, walletflowtest.SDJWTConfigurationID))
	if err != nil {
		t.Fatal(err)
	}
	authorize(t, f, s)
	result, err := s.RequestCredentials(ctx)
	if err != nil || len(result.Credentials) != 1 {
		t.Fatalf("RequestCredentials = %+v, %v", result, err)
	}
	if err := w.DeleteCredential(ctx, result.Credentials[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := w.KeysInUse(ctx); err != nil {
		t.Fatal(err)
	}
	if g, _ := grants.ListGrants(ctx); len(g) != 1 || f.env.Revocations() != 0 {
		t.Fatalf("while the issuance is open: %d grants, %d revocations; want the grant kept", len(g), f.env.Revocations())
	}
	if err := s.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if g, _ := grants.ListGrants(ctx); len(g) != 0 || f.keys.Len() != 0 || f.env.Revocations() != 1 {
		t.Errorf("after Close: %d grants, %d keys, %d revocations; want none, none, 1", len(g), f.keys.Len(), f.env.Revocations())
	}
}

// A refresh token is revoked only by the installation it's bound to: a
// revocation with another instance key's attestation is answered, and
// revokes nothing.
func TestRevocation_BoundToTheInstanceKey(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, walletflowtest.Options{})
	grants := walletflow.NewMemoryGrantStore()
	w := f.newRefreshingWallet(t, nil, grants)
	c := receive(t, f, w, walletflowtest.SDJWTConfigurationID)[0]
	g, err := grants.GetGrant(ctx, c.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	other, err := f.keys.NewKey(ctx, walletflow.KeyPurposeInstance)
	if err != nil {
		t.Fatal(err)
	}
	g.InstanceKeyID = other.ID()
	if err := grants.PutGrant(ctx, g); err != nil {
		t.Fatal(err)
	}
	if err := w.DeleteCredential(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if n := f.env.Revocations(); n != 0 {
		t.Errorf("refresh tokens revoked with another instance key = %d, want 0", n)
	}
}

// A grant whose credential went from the store without DeleteCredential
// (a store cleared or edited outside the wallet) is revoked by the next
// KeysInUse, not only forgotten: its refresh token would otherwise stay
// live at the Authorization Server.
func TestKeysInUse_RevokesAnOrphanedGrant(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, walletflowtest.Options{})
	grants := walletflow.NewMemoryGrantStore()
	w := f.newRefreshingWallet(t, nil, grants)
	c := receive(t, f, w, walletflowtest.SDJWTConfigurationID)[0]
	if err := f.store.Delete(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := w.KeysInUse(ctx); err != nil {
		t.Fatal(err)
	}
	if g, _ := grants.ListGrants(ctx); len(g) != 0 || f.env.Revocations() != 1 {
		t.Errorf("after the sweep: %d grants, %d revocations; want none, 1", len(g), f.env.Revocations())
	}
}
