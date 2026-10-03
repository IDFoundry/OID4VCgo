package walletflow_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/wallet"
	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

type fixture struct {
	env   testEnv
	w     *walletflow.Wallet
	keys  *walletflow.MemoryKeyStore
	store *walletflow.MemoryCredentialStore
}

func newFixture(t *testing.T, opts walletflowtest.Options) fixture {
	t.Helper()
	env := newEnv(t, opts)
	f := fixture{env: env, keys: walletflow.NewMemoryKeyStore(), store: walletflow.NewMemoryCredentialStore()}
	f.w = f.newWallet(t, env.IssuerRoots)
	return f
}

func (f fixture) newWallet(t *testing.T, roots *x509.CertPool) *walletflow.Wallet {
	t.Helper()
	return f.newWalletTrusting(t, roots, nil)
}

func (f fixture) newWalletTrusting(t *testing.T, roots *x509.CertPool, verifiers wallet.VerifierTrust) *walletflow.Wallet {
	t.Helper()
	w, err := walletflow.New(walletflow.Config{
		ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, IssuerRoots: roots,
		VerifierTrust: verifiers, Development: true,
	}, walletflow.Dependencies{Keys: f.keys, Credentials: f.store, Provider: f.env.Provider, HTTP: f.env.HTTP})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// authorize runs the authorization code grant's two steps.
func authorize(t *testing.T, f fixture, s *walletflow.Issuance) {
	t.Helper()
	ctx := context.Background()
	authURL, err := s.BeginAuthorization(ctx)
	if err != nil {
		t.Fatal(err)
	}
	redirect, err := f.env.Approve(ctx, authURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteAuthorization(ctx, redirect); err != nil {
		t.Fatal(err)
	}
}

func TestIssuance_AuthorizationCode(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
	ctx := context.Background()
	s, err := f.w.StartIssuance(ctx, f.env.AuthorizationCodeOffer(t, walletflowtest.SDJWTConfigurationID, walletflowtest.MdocConfigurationID))
	if err != nil {
		t.Fatal(err)
	}
	offer := s.Offer()
	if offer.Grant != walletflow.GrantAuthorizationCode || offer.CredentialIssuer != f.env.IssuerURL || len(offer.Credentials) != 2 {
		t.Fatalf("Offer = %+v", offer)
	}
	if offer.Credentials[0].Format != "dc+sd-jwt" || offer.Credentials[1].DocType != walletflowtest.DocType {
		t.Fatalf("offered credentials = %+v", offer.Credentials)
	}
	authorize(t, f, s)
	result, err := s.RequestCredentials(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Credentials) != 2 || len(result.Deferred) != 0 {
		t.Fatalf("result = %+v", result)
	}
	if err := s.Close(ctx); err != nil {
		t.Fatal(err)
	}

	held, err := f.w.Credentials(ctx)
	if err != nil || len(held) != 2 {
		t.Fatalf("Credentials = %d, %v", len(held), err)
	}
	for _, c := range held {
		if c.CredentialIssuer != f.env.IssuerURL || c.Credential == "" || c.HolderKeyID == "" {
			t.Errorf("stored credential = %+v", c)
		}
		switch c.Format {
		case "dc+sd-jwt":
			if c.Claims["family_name"] != walletflowtest.FamilyName {
				t.Errorf("SD-JWT VC claims = %v", c.Claims)
			}
		case "mso_mdoc":
			if ns, _ := c.Claims[walletflowtest.NameSpace].(map[string]any); ns["given_name"] != walletflowtest.GivenName {
				t.Errorf("mdoc claims = %v", c.Claims)
			}
		}
		if _, err := f.keys.Key(ctx, c.HolderKeyID); err != nil {
			t.Errorf("holder key: %v", err)
		}
	}
	// Close deleted the instance and DPoP keys: only holder keys remain.
	if f.keys.Len() != 2 {
		t.Errorf("keys held = %d, want the 2 holder keys", f.keys.Len())
	}
	if got := f.env.Notifications(); len(got) != 2 || got[0] != oid4vci.NotificationEventCredentialAccepted {
		t.Errorf("notifications = %v", got)
	}
	if f.env.Provider.KeyAttestations() != 2 {
		t.Errorf("key attestations = %d, want one per credential", f.env.Provider.KeyAttestations())
	}

	if err := f.w.DeleteCredential(ctx, held[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.keys.Key(ctx, held[0].HolderKeyID); !errors.Is(err, walletflow.ErrNotFound) {
		t.Errorf("deleted credential's holder key: %v", err)
	}
	if err := f.w.DeleteCredential(ctx, held[0].ID); !errors.Is(err, walletflow.ErrNotFound) {
		t.Errorf("deleting it again = %v, want ErrNotFound", err)
	}
}

func TestIssuance_PreAuthorizedCodeWithPIN(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
	ctx := context.Background()
	s, err := f.w.StartIssuance(ctx, f.env.PreAuthorizedOffer(t, "493536", walletflowtest.SDJWTConfigurationID))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close(ctx) }()
	if offer := s.Offer(); offer.Grant != walletflow.GrantPreAuthorizedCode || offer.TxCode == nil || offer.TxCode.Length != 6 {
		t.Fatalf("Offer = %+v", offer)
	}
	if _, err := s.BeginAuthorization(ctx); !errors.Is(err, walletflow.ErrWrongStep) {
		t.Fatalf("BeginAuthorization on a pre-authorized offer = %v, want ErrWrongStep", err)
	}
	if err := s.RedeemPreAuthorizedCode(ctx, "000000"); err == nil {
		t.Fatal("a wrong PIN was accepted")
	}
	if err := s.RedeemPreAuthorizedCode(ctx, "493536"); err != nil {
		t.Fatalf("the right PIN after a wrong one: %v", err)
	}
	result, err := s.RequestCredentials(ctx)
	if err != nil || len(result.Credentials) != 1 {
		t.Fatalf("RequestCredentials = %+v, %v", result, err)
	}
}

func TestIssuance_Deferred(t *testing.T) {
	for _, approve := range []bool{true, false} {
		f := newFixture(t, walletflowtest.Options{Defer: true})
		ctx := context.Background()
		s, err := f.w.StartIssuance(ctx, f.env.AuthorizationCodeOffer(t, walletflowtest.MdocConfigurationID))
		if err != nil {
			t.Fatal(err)
		}
		authorize(t, f, s)
		result, err := s.RequestCredentials(ctx)
		if err != nil || len(result.Credentials) != 0 || len(result.Deferred) != 1 {
			t.Fatalf("RequestCredentials = %+v, %v", result, err)
		}
		d := result.Deferred[0]
		if d.ConfigurationID() != walletflowtest.MdocConfigurationID || d.Interval() <= 0 {
			t.Fatalf("deferred = %s, interval %v", d.ConfigurationID(), d.Interval())
		}
		if stored, err := d.Poll(ctx); stored != nil || err != nil {
			t.Fatalf("Poll before a decision = %v, %v", stored, err)
		}
		f.env.Decide(approve)
		waitCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		stored, err := d.Wait(waitCtx)
		cancel()
		if approve {
			if err != nil || stored.DocType != walletflowtest.DocType {
				t.Fatalf("Wait after approval = %+v, %v", stored, err)
			}
		} else if !errors.Is(err, walletflow.ErrCredentialDenied) {
			t.Fatalf("Wait after denial = %v, want ErrCredentialDenied", err)
		}
		if _, err := d.Poll(ctx); !errors.Is(err, walletflow.ErrWrongStep) {
			t.Errorf("Poll once done = %v, want ErrWrongStep", err)
		}
		if err := s.Close(ctx); err != nil {
			t.Fatal(err)
		}
		if want := map[bool]int{true: 1, false: 0}[approve]; f.keys.Len() != want {
			t.Errorf("approve=%v: keys held = %d, want %d", approve, f.keys.Len(), want)
		}
	}
}

func TestIssuance_CloseAbandonsDeferred(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{Defer: true})
	ctx := context.Background()
	s, err := f.w.StartIssuance(ctx, f.env.AuthorizationCodeOffer(t, walletflowtest.SDJWTConfigurationID))
	if err != nil {
		t.Fatal(err)
	}
	authorize(t, f, s)
	result, err := s.RequestCredentials(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(ctx); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if f.keys.Len() != 0 {
		t.Errorf("keys held after Close = %d, want 0", f.keys.Len())
	}
	if _, err := result.Deferred[0].Poll(ctx); !errors.Is(err, walletflow.ErrWrongStep) {
		t.Errorf("Poll after Close = %v, want ErrWrongStep", err)
	}
}

func TestIssuance_RefusesACredentialFromAnUntrustedIssuer(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
	other := newEnv(t, walletflowtest.Options{})
	w := f.newWallet(t, other.IssuerRoots)
	ctx := context.Background()
	s, err := w.StartIssuance(ctx, f.env.AuthorizationCodeOffer(t, walletflowtest.SDJWTConfigurationID))
	if err != nil {
		t.Fatal(err)
	}
	authorize(t, f, s)
	if _, err := s.RequestCredentials(ctx); err == nil {
		t.Fatal("a credential from an untrusted issuer was accepted")
	}
	_ = s.Close(ctx)
	if held, _ := w.Credentials(ctx); len(held) != 0 {
		t.Errorf("stored %d credentials", len(held))
	}
	if f.keys.Len() != 0 {
		t.Errorf("keys held = %d, want 0", f.keys.Len())
	}
	if got := f.env.Notifications(); len(got) != 1 || got[0] != oid4vci.NotificationEventCredentialFailure {
		t.Errorf("notifications = %v", got)
	}
}

func TestIssuance_AuthorizationDenied(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
	ctx := context.Background()
	s, err := f.w.StartIssuance(ctx, f.env.AuthorizationCodeOffer(t, walletflowtest.SDJWTConfigurationID))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close(ctx) }()
	authURL, err := s.BeginAuthorization(ctx)
	if err != nil {
		t.Fatal(err)
	}
	redirect, err := f.env.Approve(ctx, authURL)
	if err != nil {
		t.Fatal(err)
	}
	// The same redirect, but with the holder declining.
	u, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Del("code")
	q.Set("error", "access_denied")
	err = s.CompleteAuthorization(ctx, q.Encode())
	var denied *walletflow.AuthorizationDeniedError
	if !errors.As(err, &denied) || denied.Code != "access_denied" {
		t.Fatalf("CompleteAuthorization = %v, want access_denied", err)
	}
	if _, err := s.RequestCredentials(ctx); !errors.Is(err, walletflow.ErrWrongStep) {
		t.Errorf("RequestCredentials after denial = %v, want ErrWrongStep", err)
	}
}

func TestIssuance_StepsOutOfTurn(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
	ctx := context.Background()
	s, err := f.w.StartIssuance(ctx, f.env.AuthorizationCodeOffer(t, walletflowtest.SDJWTConfigurationID))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteAuthorization(ctx, "code=x"); !errors.Is(err, walletflow.ErrWrongStep) {
		t.Errorf("CompleteAuthorization first = %v", err)
	}
	if err := s.RedeemPreAuthorizedCode(ctx, ""); !errors.Is(err, walletflow.ErrWrongStep) {
		t.Errorf("RedeemPreAuthorizedCode on an authorization code offer = %v", err)
	}
	if _, err := s.RequestCredentials(ctx); !errors.Is(err, walletflow.ErrWrongStep) {
		t.Errorf("RequestCredentials first = %v", err)
	}
	authorize(t, f, s)
	if _, err := s.BeginAuthorization(ctx); !errors.Is(err, walletflow.ErrWrongStep) {
		t.Errorf("BeginAuthorization twice = %v", err)
	}
	if err := s.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RequestCredentials(ctx); !errors.Is(err, walletflow.ErrWrongStep) {
		t.Errorf("RequestCredentials after Close = %v", err)
	}
}

func TestNew_RequiresConfiguration(t *testing.T) {
	deps := walletflow.Dependencies{
		Keys: walletflow.NewMemoryKeyStore(), Credentials: walletflow.NewMemoryCredentialStore(), Provider: &walletflowtest.Provider{},
	}
	good := walletflow.Config{ClientID: "c", RedirectURI: "https://wallet.example/cb", IssuerRoots: x509.NewCertPool()}
	if _, err := walletflow.New(good, deps); err != nil {
		t.Fatalf("New(production config) = %v", err)
	}
	for name, d := range map[string]walletflow.Dependencies{
		"no key store": {Credentials: deps.Credentials},
		"no store":     {Keys: deps.Keys},
	} {
		if _, err := walletflow.New(good, d); err == nil {
			t.Errorf("%s: New succeeded", name)
		}
	}
	// A wallet that only presents needs none of issuance's settings,
	// which StartIssuance asks for.
	for name, mutate := range map[string]func(*walletflow.Config, *walletflow.Dependencies){
		"no client_id":    func(c *walletflow.Config, _ *walletflow.Dependencies) { c.ClientID = "" },
		"no redirect URI": func(c *walletflow.Config, _ *walletflow.Dependencies) { c.RedirectURI = "" },
		"no issuer roots": func(c *walletflow.Config, _ *walletflow.Dependencies) { c.IssuerRoots = nil },
		"no provider":     func(_ *walletflow.Config, d *walletflow.Dependencies) { d.Provider = nil },
	} {
		c, d := good, deps
		mutate(&c, &d)
		w, err := walletflow.New(c, d)
		if err != nil {
			t.Fatalf("%s: New = %v", name, err)
		}
		if _, err := w.StartIssuance(context.Background(), "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Fo"); err == nil || !strings.Contains(err.Error(), "required to receive") {
			t.Errorf("%s: StartIssuance = %v", name, err)
		}
	}
}

// failingProvider refuses every attestation.
type failingProvider struct{}

func (failingProvider) WalletAttestation(context.Context, string, crypto.PublicKey) (string, error) {
	return "", errors.New("no")
}

func (failingProvider) KeyAttestation(context.Context, []*ecdsa.PublicKey, string) (string, error) {
	return "", errors.New("no")
}

// p384Keys hands out P-384 keys, which walletflow refuses.
type p384Keys struct{ *walletflow.MemoryKeyStore }

type p384Key struct{ *ecdsa.PrivateKey }

func (p384Key) ID() string { return "p384" }

func (p384Keys) NewKey(context.Context, walletflow.KeyPurpose) (walletflow.Key, error) {
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	return p384Key{k}, err
}

func TestIssuance_PlatformFailures(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
	ctx := context.Background()
	for name, deps := range map[string]walletflow.Dependencies{
		"provider refuses": {Keys: f.keys, Credentials: f.store, Provider: failingProvider{}, HTTP: f.env.HTTP},
		"not a P-256 key":  {Keys: p384Keys{walletflow.NewMemoryKeyStore()}, Credentials: f.store, Provider: f.env.Provider, HTTP: f.env.HTTP},
	} {
		w, err := walletflow.New(walletflow.Config{
			ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, IssuerRoots: f.env.IssuerRoots, Development: true,
		}, deps)
		if err != nil {
			t.Fatal(err)
		}
		s, err := w.StartIssuance(ctx, f.env.AuthorizationCodeOffer(t, walletflowtest.SDJWTConfigurationID))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.BeginAuthorization(ctx); err == nil {
			t.Errorf("%s: BeginAuthorization succeeded", name)
		}
		_ = s.Close(ctx)
	}
	if _, err := f.w.StartIssuance(ctx, "openid-credential-offer://?credential_offer_uri=https%3A%2F%2F127.0.0.1%3A1%2Fnone"); err == nil {
		t.Error("StartIssuance with an unreachable offer succeeded")
	}
}

func TestAuthorizationDeniedError(t *testing.T) {
	for _, tc := range []struct {
		err  walletflow.AuthorizationDeniedError
		want string
	}{
		{walletflow.AuthorizationDeniedError{Code: "access_denied"}, "walletflow: authorization denied: access_denied"},
		{walletflow.AuthorizationDeniedError{Code: "access_denied", Description: "no"}, "walletflow: authorization denied: access_denied: no"},
	} {
		if got := tc.err.Error(); got != tc.want {
			t.Errorf("Error() = %q, want %q", got, tc.want)
		}
	}
}

// TestIssuance_RefusesAnOfferNamingAnotherAuthorizationServer: someone
// holding a victim's pre-authorized code builds an offer naming the real
// issuer but their own Authorization Server, to have the wallet send
// them the code and the holder's PIN. The offer is refused before the
// holder is shown it, and that server hears nothing.
func TestIssuance_RefusesAnOfferNamingAnotherAuthorizationServer(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
	var hits atomic.Int32
	evil := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer evil.Close()

	genuine, err := url.Parse(f.env.PreAuthorizedOffer(t, "493536", walletflowtest.SDJWTConfigurationID))
	if err != nil {
		t.Fatal(err)
	}
	var offer map[string]any
	if err := json.Unmarshal([]byte(genuine.Query().Get("credential_offer")), &offer); err != nil {
		t.Fatal(err)
	}
	grants := offer["grants"].(map[string]any)
	grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"].(map[string]any)["authorization_server"] = evil.URL
	raw, err := json.Marshal(offer)
	if err != nil {
		t.Fatal(err)
	}
	forged := "openid-credential-offer://?" + url.Values{"credential_offer": {string(raw)}}.Encode()

	if _, err := f.w.StartIssuance(context.Background(), forged); err == nil || !strings.Contains(err.Error(), "names authorization server") {
		t.Fatalf("StartIssuance = %v, want the offer refused", err)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("the offer's authorization server got %d requests", n)
	}
	if f.keys.Len() != 0 {
		t.Errorf("keys held = %d, want none", f.keys.Len())
	}
}

// flakyProvider fails its n-th Key Attestation, once.
type flakyProvider struct {
	walletflow.WalletProvider
	failAt int
	calls  atomic.Int32
}

func (p *flakyProvider) KeyAttestation(ctx context.Context, keys []*ecdsa.PublicKey, nonce string) (string, error) {
	if int(p.calls.Add(1)) == p.failAt {
		return "", errors.New("the Wallet Provider is unavailable")
	}
	return p.WalletProvider.KeyAttestation(ctx, keys, nonce)
}

// TestIssuance_RequestCredentialsRetries: a request failing partway
// returns what was obtained with the error, and a retry requests only the
// rest, returning everything.
func TestIssuance_RequestCredentialsRetries(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
	provider := &flakyProvider{WalletProvider: f.env.Provider, failAt: 2}
	w, err := walletflow.New(walletflow.Config{
		ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, IssuerRoots: f.env.IssuerRoots, Development: true,
	}, walletflow.Dependencies{Keys: f.keys, Credentials: f.store, Provider: provider, HTTP: f.env.HTTP})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	s, err := w.StartIssuance(ctx, f.env.AuthorizationCodeOffer(t, walletflowtest.SDJWTConfigurationID, walletflowtest.MdocConfigurationID))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close(ctx) }()
	authorize(t, f, s)

	first, err := s.RequestCredentials(ctx)
	if err == nil || len(first.Credentials) != 1 {
		t.Fatalf("first RequestCredentials = %d credentials, %v; want 1 and an error", len(first.Credentials), err)
	}
	second, err := s.RequestCredentials(ctx)
	if err != nil || len(second.Credentials) != 2 {
		t.Fatalf("retry = %d credentials, %v; want both", len(second.Credentials), err)
	}
	if second.Credentials[0].ID != first.Credentials[0].ID {
		t.Error("the retry requested the first credential again")
	}
	if held, _ := w.Credentials(ctx); len(held) != 2 {
		t.Errorf("stored %d credentials, want 2", len(held))
	}
	if _, err := s.RequestCredentials(ctx); !errors.Is(err, walletflow.ErrWrongStep) {
		t.Errorf("RequestCredentials after success = %v, want ErrWrongStep", err)
	}
}
