package walletflow_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// anonymousWallet is a wallet with no Wallet Provider, client_id or
// redirect URI: all it needs to receive credentials from an issuer that
// asks for no attestation (OpenID4VCI 1.0, outside HAIP).
func (f fixture) anonymousWallet(t *testing.T, profile walletflow.IssuanceProfile, grants walletflow.GrantStore) *walletflow.Wallet {
	t.Helper()
	w, err := walletflow.New(walletflow.Config{
		IssuerRoots: f.env.IssuerRoots, Development: true, IssuanceProfile: profile, RequestRefresh: grants != nil,
	}, walletflow.Dependencies{Keys: f.keys, Credentials: f.store, HTTP: f.env.HTTP, Grants: grants})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// receivePreAuthorized redeems a pre-authorized offer for configIDs with
// no PIN, and requests its credentials.
func receivePreAuthorized(t *testing.T, f fixture, w *walletflow.Wallet, configIDs ...string) []walletflow.StoredCredential {
	t.Helper()
	ctx := context.Background()
	s, err := w.StartIssuance(ctx, f.env.PreAuthorizedOffer(t, "", configIDs...))
	if err != nil {
		t.Fatalf("StartIssuance: %v", err)
	}
	defer func() { _ = s.Close(ctx) }()
	if err := s.RedeemPreAuthorizedCode(ctx, ""); err != nil {
		t.Fatalf("RedeemPreAuthorizedCode: %v", err)
	}
	result, err := s.RequestCredentials(ctx)
	if err != nil || len(result.Credentials) != len(configIDs) {
		t.Fatalf("RequestCredentials = %+v, %v", result, err)
	}
	return result.Credentials
}

// A wallet with no Wallet Provider receives credentials from an issuer
// outside HAIP, as the in-house mdoc issuer is: a pre-authorized code
// redeemed with no client authentication, at a server with no
// authorization endpoints, and jwt proofs with a c_nonce — or with none,
// from an issuer with no nonce endpoint.
func TestIssuance_AnonymousPreAuthorizedCode(t *testing.T) {
	for _, noNonce := range []bool{false, true} {
		f := newFixture(t, walletflowtest.Options{Anonymous: true, NoNonceEndpoint: noNonce})
		w := f.anonymousWallet(t, walletflow.ProfileOpenID4VCI, nil)
		held := receivePreAuthorized(t, f, w, walletflowtest.MdocConfigurationID, walletflowtest.SDJWTConfigurationID)
		for _, c := range held {
			if c.HolderKeyID == "" {
				t.Errorf("no nonce endpoint %v: %s is bound to no key", noNonce, c.ConfigurationID)
			}
		}
		if n := f.env.Provider.KeyAttestations(); n != 0 {
			t.Errorf("Key Attestations = %d, want none", n)
		}
	}
}

// The same issuer is refused under ProfileHAIP, before the holder sees
// the offer: its Authorization Server takes no Wallet Attestation (HAIP
// 1.0 §4.4.1). And a wallet with no Wallet Provider can't redeem a HAIP
// issuer's offer, which takes nothing else.
func TestIssuance_ClientAuthChoice(t *testing.T) {
	ctx := context.Background()
	anon := newFixture(t, walletflowtest.Options{Anonymous: true})
	haip := walletflow.Config{
		ClientID: walletflowtest.ClientID, IssuerRoots: anon.env.IssuerRoots, Development: true, IssuanceProfile: walletflow.ProfileHAIP,
	}
	w, err := walletflow.New(haip, walletflow.Dependencies{Keys: anon.keys, Credentials: anon.store, HTTP: anon.env.HTTP, Provider: anon.env.Provider})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.StartIssuance(ctx, anon.env.PreAuthorizedOffer(t, "", walletflowtest.MdocConfigurationID)); !errors.Is(err, walletflow.ErrProfileViolation) {
		t.Errorf("HAIP wallet, anonymous issuer: %v, want ErrProfileViolation", err)
	}

	f := newFixture(t, walletflowtest.Options{})
	noProvider := f.anonymousWallet(t, walletflow.ProfileOpenID4VCI, nil)
	if _, err := noProvider.StartIssuance(ctx, f.env.PreAuthorizedOffer(t, "493536", walletflowtest.SDJWTConfigurationID)); !errors.Is(err, walletflow.ErrClientAuthUnsupported) {
		t.Errorf("no provider, HAIP issuer: %v, want ErrClientAuthUnsupported", err)
	}
}

// A HAIP issuer is still redeemed as before under the default profile:
// with a Wallet Attestation and a key attestation.
func TestIssuance_DefaultProfileWithHAIPIssuer(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
	ctx := context.Background()
	s, err := f.w.StartIssuance(ctx, f.env.PreAuthorizedOffer(t, "493536", walletflowtest.SDJWTConfigurationID))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close(ctx) }()
	if err := s.RedeemPreAuthorizedCode(ctx, "493536"); err != nil {
		t.Fatal(err)
	}
	if result, err := s.RequestCredentials(ctx); err != nil || len(result.Credentials) != 1 {
		t.Fatalf("RequestCredentials = %+v, %v", result, err)
	}
	if n := f.env.Provider.KeyAttestations(); n != 1 {
		t.Errorf("Key Attestations = %d, want 1", n)
	}
}

// The PIN is checked against the offer before it's sent: none where the
// offer asks for none, and the length it gives.
func TestIssuance_TxCodeChecked(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, walletflowtest.Options{Anonymous: true})
	w := f.anonymousWallet(t, walletflow.ProfileOpenID4VCI, nil)
	s, err := w.StartIssuance(ctx, f.env.PreAuthorizedOffer(t, "", walletflowtest.MdocConfigurationID))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close(ctx) }()
	if err := s.RedeemPreAuthorizedCode(ctx, "1234"); err == nil {
		t.Error("a PIN for an offer asking for none was sent")
	}

	pin, err := w.StartIssuance(ctx, f.env.PreAuthorizedOffer(t, "493536", walletflowtest.MdocConfigurationID))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pin.Close(ctx) }()
	for _, bad := range []string{"", "12345", "49353a"} {
		if err := pin.RedeemPreAuthorizedCode(ctx, bad); err == nil {
			t.Errorf("PIN %q accepted", bad)
		}
	}
	if err := pin.RedeemPreAuthorizedCode(ctx, "493536"); err != nil {
		t.Errorf("the right PIN: %v", err)
	}
}

// A public client's grant refreshes and revokes with no client
// authentication, bound to its DPoP key (RFC 9449 §5) — or with a Bearer
// access token, which the default profile takes (OpenID4VCI 1.0 §13.2).
func TestRefreshCredential_AnonymousGrant(t *testing.T) {
	for _, bearer := range []bool{false, true} {
		ctx := context.Background()
		f := newFixture(t, walletflowtest.Options{Anonymous: true, AnonymousRefresh: true, BearerTokens: bearer})
		grants := walletflow.NewMemoryGrantStore()
		w := f.anonymousWallet(t, walletflow.ProfileOpenID4VCI, grants)
		c := receivePreAuthorized(t, f, w, walletflowtest.MdocConfigurationID)[0]
		if c.GrantID == "" {
			t.Fatalf("bearer %v: the credential isn't refreshable", bearer)
		}
		g, err := grants.GetGrant(ctx, c.GrantID)
		// The DPoP key is kept even for a Bearer grant: the refresh token
		// is bound to it (RFC 9449 §5).
		if err != nil || g.ClientAuth != walletflow.GrantAuthNone || g.InstanceKeyID != "" || g.DPoPKeyID == "" {
			t.Fatalf("bearer %v: grant = %+v, %v", bearer, g, err)
		}
		refreshed, _, err := w.RefreshCredential(ctx, c.ID)
		if err != nil || refreshed.ID != c.ID {
			t.Fatalf("bearer %v: RefreshCredential = %+v, %v", bearer, refreshed, err)
		}
		if err := w.DeleteCredential(ctx, c.ID); err != nil {
			t.Fatal(err)
		}
		if n := f.env.Revocations(); n != 1 {
			t.Errorf("bearer %v: refresh tokens revoked = %d, want 1", bearer, n)
		}
		if f.keys.Len() != 0 {
			t.Errorf("bearer %v: %d keys left, want none", bearer, f.keys.Len())
		}

		// Under ProfileHAIP, a grant that authenticates no client isn't
		// refreshed, even by a wallet that could attest itself.
		c = receivePreAuthorized(t, f, w, walletflowtest.MdocConfigurationID)[0]
		haip, err := walletflow.New(walletflow.Config{
			ClientID: walletflowtest.ClientID, IssuerRoots: f.env.IssuerRoots, Development: true,
			IssuanceProfile: walletflow.ProfileHAIP, RequestRefresh: true,
		}, walletflow.Dependencies{Keys: f.keys, Credentials: f.store, HTTP: f.env.HTTP, Grants: grants, Provider: f.env.Provider})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := haip.RefreshCredential(ctx, c.ID); !errors.Is(err, walletflow.ErrProfileViolation) {
			t.Errorf("bearer %v: a HAIP wallet refreshing an anonymous grant: %v, want ErrProfileViolation", bearer, err)
		}

		// A refresh token the server has revoked: the credential must be
		// reissued, and the grant and its key are forgotten.
		f.env.RevokeGrants()
		if _, _, err := w.RefreshCredential(ctx, c.ID); !errors.Is(err, walletflow.ErrReissueRequired) {
			t.Errorf("bearer %v: refreshing a revoked public grant: %v, want ErrReissueRequired", bearer, err)
		}
		if _, err := grants.GetGrant(ctx, c.GrantID); !errors.Is(err, walletflow.ErrNotFound) {
			t.Errorf("bearer %v: the revoked grant is kept: %v", bearer, err)
		}
	}
}

// The default profile takes a Bearer access token, as OpenID4VCI 1.0
// allows (§13.2 only RECOMMENDS sender-constrained tokens).
func TestIssuance_BearerToken(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{Anonymous: true, BearerTokens: true})
	w := f.anonymousWallet(t, walletflow.ProfileOpenID4VCI, nil)
	if c := receivePreAuthorized(t, f, w, walletflowtest.MdocConfigurationID); len(c) != 1 {
		t.Fatalf("Bearer: %d credentials, want 1", len(c))
	}
}

// An invalid_nonce is retried with a fresh nonce and fresh keys, once a
// request and at most twice an issuance; one that keeps coming fails
// the credential, and its keys are deleted. (A request may also be
// resent on a DPoP nonce challenge, which isn't counted.)
func TestIssuance_InvalidNonceRetried(t *testing.T) {
	for _, tc := range []struct {
		refusals, wantRefused int
		wantOK                bool
	}{
		{refusals: 1, wantRefused: 1, wantOK: true},
		{refusals: 100, wantRefused: 2},
	} {
		ctx := context.Background()
		f := newFixture(t, walletflowtest.Options{Anonymous: true})
		var mu sync.Mutex
		refused, refusals := 0, tc.refusals
		hc := *f.env.HTTP
		hc.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == "/credential" {
				mu.Lock()
				refuse := refusals > 0
				if refuse {
					refused++
					refusals--
				}
				mu.Unlock()
				if refuse {
					return &http.Response{StatusCode: http.StatusBadRequest, Header: http.Header{"Content-Type": {"application/json"}},
						Body: io.NopCloser(strings.NewReader(`{"error":"invalid_nonce"}`)), Request: r}, nil
				}
			}
			return f.env.HTTP.Transport.RoundTrip(r)
		})
		w, err := walletflow.New(walletflow.Config{IssuerRoots: f.env.IssuerRoots, Development: true},
			walletflow.Dependencies{Keys: f.keys, Credentials: f.store, HTTP: &hc})
		if err != nil {
			t.Fatal(err)
		}
		s, err := w.StartIssuance(ctx, f.env.PreAuthorizedOffer(t, "", walletflowtest.MdocConfigurationID))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.RedeemPreAuthorizedCode(ctx, ""); err != nil {
			t.Fatal(err)
		}
		result, err := s.RequestCredentials(ctx)
		if (err == nil) != tc.wantOK || len(result.Credentials) != map[bool]int{true: 1}[tc.wantOK] {
			t.Errorf("refusals %d: RequestCredentials = %+v, %v", tc.refusals, result, err)
		}
		if refused != tc.wantRefused {
			t.Errorf("refusals %d: %d requests refused, want %d", tc.refusals, refused, tc.wantRefused)
		}
		_ = s.Close(ctx)
		if want := map[bool]int{true: 1}[tc.wantOK]; f.keys.Len() != want {
			t.Errorf("refusals %d: %d keys left, want %d", tc.refusals, f.keys.Len(), want)
		}
	}
}

// A wallet that has dropped its Wallet Provider can't refresh a grant
// that authenticates with a Wallet Attestation: the credential must be
// reissued, not the wallet crash.
func TestRefreshCredential_WithoutProvider(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, walletflowtest.Options{})
	grants := walletflow.NewMemoryGrantStore()
	c := receive(t, f, f.newRefreshingWallet(t, nil, grants), walletflowtest.SDJWTConfigurationID)[0]
	w := f.anonymousWallet(t, walletflow.ProfileOpenID4VCI, grants)
	if _, _, err := w.RefreshCredential(ctx, c.ID); !errors.Is(err, walletflow.ErrReissueRequired) {
		t.Errorf("RefreshCredential = %v, want ErrReissueRequired", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
