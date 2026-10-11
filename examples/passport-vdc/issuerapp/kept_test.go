package issuerapp_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demotest"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/issuerapp"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletapp"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// refreshingWallet is a walletflow wallet that asks for refresh tokens,
// as the iOS demo app does.
func refreshingWallet(t *testing.T, env *demotest.Env) *walletflow.Wallet {
	t.Helper()
	cfg := env.WalletConfig()
	w, err := walletflow.New(walletflow.Config{
		ClientID: cfg.ClientID, RedirectURI: cfg.RedirectURI, IssuerRoots: cfg.IssuerRoots, Development: true,
		RequestRefresh: true,
	}, walletflow.Dependencies{
		Keys: walletflow.NewMemoryKeyStore(), Credentials: walletflow.NewMemoryCredentialStore(),
		Grants: walletflow.NewMemoryGrantStore(), Provider: cfg.Provider, HTTP: env.HTTP,
	})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// receive redeems offer — approving it in the issuer's page with its
// confirmation code, or with its PIN — and returns what was stored.
func receive(t *testing.T, env *demotest.Env, w *walletflow.Wallet, offer issuerapp.Offer) []walletflow.StoredCredential {
	t.Helper()
	ctx := context.Background()
	s, err := w.StartIssuance(ctx, offer.URI)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close(ctx) }()
	if offer.PreAuthorized {
		if err := s.RedeemPreAuthorizedCode(ctx, offer.ConfirmationCode); err != nil {
			t.Fatal(err)
		}
	} else {
		authURL, err := s.BeginAuthorization(ctx)
		if err != nil {
			t.Fatal(err)
		}
		loc, err := walletapp.HeadlessApprover{HTTP: env.HTTP, Code: offer.ConfirmationCode}.Redirect(ctx, authURL)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.CompleteAuthorization(ctx, loc.String()); err != nil {
			t.Fatal(err)
		}
	}
	result, err := s.RequestCredentials(ctx)
	if err != nil || len(result.Credentials) != 2 {
		t.Fatalf("RequestCredentials = %d credentials, %v; want both", len(result.Credentials), err)
	}
	return result.Credentials
}

// TestKeepForRefresh_Refreshes: a passport kept for refresh gives the
// wallet a refresh token, in both flows, that fetches fresh copies; it's
// listed as kept until the wallet deletes the credentials, which revokes
// the token and drops the passport.
func TestKeepForRefresh_Refreshes(t *testing.T) {
	for _, preAuthorized := range []bool{false, true} {
		name := map[bool]string{false: "authorization code", true: "pre-authorized code"}[preAuthorized]
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			env := demotest.New(t, nil)
			w := refreshingWallet(t, env)
			offer, err := env.Issuer.CreateOffer(ctx, demotest.SyntheticEvidence(), issuerapp.OfferOptions{PreAuthorized: preAuthorized, KeepForRefresh: true})
			if err != nil {
				t.Fatal(err)
			}
			if !offer.KeptForRefresh {
				t.Error("Offer.KeptForRefresh is false")
			}
			stored := receive(t, env, w, offer)
			if kept := env.Issuer.Kept(); len(kept) != 1 || kept[0].Issued != 2 {
				t.Fatalf("Kept = %+v, want the passport, with 2 credentials issued", kept)
			}

			for _, c := range stored {
				if c.GrantID == "" {
					t.Fatalf("%s has no refresh grant", c.ConfigurationID)
				}
				refreshed, deferred, err := w.RefreshCredential(ctx, c.ID)
				if err != nil || deferred != nil {
					t.Fatalf("RefreshCredential(%s) = %v, deferred %v", c.ConfigurationID, err, deferred)
				}
				if refreshed.Copies[0].Credential == c.Copies[0].Credential {
					t.Errorf("RefreshCredential(%s) returned the same copy", c.ConfigurationID)
				}
			}
			if kept := env.Issuer.Kept(); len(kept) != 1 || kept[0].Issued != 4 {
				t.Fatalf("Kept after refreshing both = %+v, want 4 credentials issued", kept)
			}

			for _, c := range stored {
				if err := w.DeleteCredential(ctx, c.ID); err != nil {
					t.Fatal(err)
				}
			}
			if kept := env.Issuer.Kept(); len(kept) != 0 {
				t.Errorf("Kept after the wallet deleted the credentials = %+v, want none", kept)
			}
		})
	}
}

// TestKeepForRefresh_Forget: forgetting a kept passport revokes its
// refresh token, so the wallet's next refresh says to receive it again.
func TestKeepForRefresh_Forget(t *testing.T) {
	ctx := context.Background()
	env := demotest.New(t, nil)
	w := refreshingWallet(t, env)
	offer, err := env.Issuer.CreateOffer(ctx, demotest.SyntheticEvidence(), issuerapp.OfferOptions{KeepForRefresh: true})
	if err != nil {
		t.Fatal(err)
	}
	stored := receive(t, env, w, offer)
	kept := env.Issuer.Kept()
	if len(kept) != 1 {
		t.Fatalf("Kept = %+v, want the passport", kept)
	}
	if err := env.Issuer.Forget(ctx, kept[0].Ref); err != nil {
		t.Fatal(err)
	}
	if err := env.Issuer.Forget(ctx, kept[0].Ref); err == nil {
		t.Error("forgetting it twice succeeded")
	}
	if len(env.Issuer.Kept()) != 0 {
		t.Error("the forgotten passport is still kept")
	}
	if _, _, err := w.RefreshCredential(ctx, stored[0].ID); !errors.Is(err, walletflow.ErrReissueRequired) {
		t.Errorf("RefreshCredential after Forget: %v, want ErrReissueRequired", err)
	}
}

// TestKeepForRefresh_OptIn: without "Keep for refresh" a wallet asking
// for a refresh token gets none, and the passport is dropped once its
// credentials are issued, as before; a kept passport can't also be held
// for review.
func TestKeepForRefresh_OptIn(t *testing.T) {
	ctx := context.Background()
	env := demotest.New(t, nil)
	w := refreshingWallet(t, env)
	for _, preAuthorized := range []bool{false, true} {
		offer, err := env.Issuer.CreateOffer(ctx, demotest.SyntheticEvidence(), issuerapp.OfferOptions{PreAuthorized: preAuthorized})
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range receive(t, env, w, offer) {
			if c.GrantID != "" {
				t.Errorf("pre-authorized %v: %s got a refresh grant without Keep for refresh", preAuthorized, c.ConfigurationID)
			}
		}
	}
	if kept := env.Issuer.Kept(); len(kept) != 0 {
		t.Errorf("Kept = %+v, want none", kept)
	}
	if _, err := env.Issuer.CreateOffer(ctx, demotest.SyntheticEvidence(), issuerapp.OfferOptions{Review: true, KeepForRefresh: true}); err == nil {
		t.Error("an offer both held for review and kept for refresh was created")
	}
}

// tokenRecorder records the access tokens token responses carry.
type tokenRecorder struct {
	next   http.RoundTripper
	mu     sync.Mutex
	tokens []string
}

func (r *tokenRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.next.RoundTrip(req)
	if err != nil || req.Method != http.MethodPost || !strings.HasSuffix(req.URL.Path, "/token") {
		return resp, err
	}
	body, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	if readErr != nil {
		return resp, err
	}
	var tr struct {
		AccessToken string `json:"access_token"`
	}
	if json.Unmarshal(body, &tr) == nil && tr.AccessToken != "" {
		r.mu.Lock()
		r.tokens = append(r.tokens, tr.AccessToken)
		r.mu.Unlock()
	}
	return resp, err
}

// grantID is a JWT access token's grant_id claim, unverified: the
// token came from the issuer under test.
func grantID(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT access token: %d parts", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		GrantID string `json:"grant_id"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	return claims.GrantID
}

// TestKeepForRefresh_PreAuthorizedTokenNamesItsGrant: the access token
// a pre-authorized code gets names the same grant as the ones its
// refresh token gets, so revoking the grant ends it too, not only the
// refreshed ones.
func TestKeepForRefresh_PreAuthorizedTokenNamesItsGrant(t *testing.T) {
	ctx := context.Background()
	env := demotest.New(t, nil)
	recorder := &tokenRecorder{next: env.HTTP.Transport}
	if recorder.next == nil {
		recorder.next = http.DefaultTransport
	}
	httpClient := *env.HTTP
	httpClient.Transport = recorder
	env.HTTP = &httpClient
	w := refreshingWallet(t, env)
	offer, err := env.Issuer.CreateOffer(ctx, demotest.SyntheticEvidence(), issuerapp.OfferOptions{PreAuthorized: true, KeepForRefresh: true})
	if err != nil {
		t.Fatal(err)
	}
	stored := receive(t, env, w, offer)
	if _, _, err := w.RefreshCredential(ctx, stored[0].ID); err != nil {
		t.Fatal(err)
	}
	recorder.mu.Lock()
	tokens := append([]string(nil), recorder.tokens...)
	recorder.mu.Unlock()
	if len(tokens) < 2 {
		t.Fatalf("recorded %d access tokens, want the pre-authorized one and a refreshed one", len(tokens))
	}
	first, refreshed := grantID(t, tokens[0]), grantID(t, tokens[len(tokens)-1])
	if first == "" || first != refreshed {
		t.Errorf("grant_id: the pre-authorized token's %q, the refreshed one's %q; want the same grant", first, refreshed)
	}
}
