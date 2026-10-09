package walletflow

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/keys"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// durableKeyStore is a MemoryKeyStore declaring durable custody, as a
// production KeyStore (the Secure Enclave's, kept in the Keychain) does.
type durableKeyStore struct{ *MemoryKeyStore }

func (durableKeyStore) KeyCustody() keys.KeyCustody { return keys.KeyCustody{Durable: true} }

// durableAuthorizations is a MemoryAuthorizationStore claiming to be
// Durable, standing in for a persistent one.
type durableAuthorizations struct{ *MemoryAuthorizationStore }

func (durableAuthorizations) Durable() bool { return true }

// attestingProvider is a WalletProvider the client never calls here.
type attestingProvider struct{}

func (attestingProvider) WalletAttestation(context.Context, string, crypto.PublicKey) (string, error) {
	return "", nil
}

func (attestingProvider) KeyAttestation(context.Context, []*ecdsa.PublicKey, string) (string, error) {
	return "", nil
}

// productionWallet is a production wallet over deps' stores.
func productionWallet(t *testing.T, deps Dependencies) *Wallet {
	t.Helper()
	w, err := New(Config{ClientID: "wallet", RedirectURI: "https://wallet.example/cb", IssuerRoots: x509.NewCertPool()}, deps)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// At production assurance, an issuance's fapigo/client builds — over a
// durable AuthorizationStore and KeyStore — and receiving credentials is
// refused, saying why, without them.
func TestProductionAssurance(t *testing.T) {
	ctx := context.Background()
	durable := Dependencies{
		Keys: durableKeyStore{NewMemoryKeyStore()}, Credentials: NewMemoryCredentialStore(),
		Provider: attestingProvider{}, Authorizations: durableAuthorizations{NewMemoryAuthorizationStore()},
	}
	w := productionWallet(t, durable)
	if err := w.checkIssuance(); err != nil {
		t.Fatalf("checkIssuance: %v", err)
	}
	s := &Issuance{w: w, offer: oid4vci.CredentialOffer{CredentialIssuer: "https://issuer.example"}}
	var err error
	if s.instanceKey, err = newKey(ctx, w.deps.Keys, KeyPurposeInstance); err != nil {
		t.Fatal(err)
	}
	if s.dpopKey, err = w.newDPoPKey(ctx); err != nil {
		t.Fatal(err)
	}
	issuer, endpoints, err := wallet.AuthorizationServerMetadata{
		Issuer: "https://as.example", AuthorizationEndpoint: "https://as.example/authorize",
		TokenEndpoint: "https://as.example/token", PushedAuthorizationRequestEndpoint: "https://as.example/par",
	}.ClientEndpoints()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.oauthClient(issuer, endpoints, "https://as.example", client.StaticAttestation("eyJ.attestation.jwt")); err != nil {
		t.Fatalf("the OAuth client doesn't build at production assurance: %v", err)
	}

	for name, change := range map[string]func(*Dependencies){
		"custody":            func(d *Dependencies) { d.Keys = NewMemoryKeyStore() },
		"crypto/rand.Reader": func(d *Dependencies) { d.Random = strings.NewReader("not random") },
	} {
		deps := durable
		change(&deps)
		if err := productionWallet(t, deps).checkIssuance(); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("without %s: checkIssuance = %v", name, err)
		}
	}
	// A Durable Authorizations store is the authorization code grant's
	// alone: nothing else keeps an authorization across a suspension.
	deps := durable
	deps.Authorizations = NewMemoryAuthorizationStore()
	w = productionWallet(t, deps)
	if err := w.checkIssuance(); err != nil {
		t.Errorf("a pre-authorized code wallet without a Durable Authorizations: checkIssuance = %v", err)
	}
	if err := w.checkAuthorizationCode(); err == nil || !strings.Contains(err.Error(), "Durable") {
		t.Errorf("without Durable: checkAuthorizationCode = %v", err)
	}
}

// durableGrants is a MemoryGrantStore claiming to be Durable.
type durableGrants struct{ *MemoryGrantStore }

func (durableGrants) Durable() bool { return true }

// At production assurance, asking for refresh tokens needs a durable
// GrantStore: a refresh token kept only in memory is lost on a restart.
func TestProductionAssurance_RefreshNeedsDurableGrants(t *testing.T) {
	deps := Dependencies{
		Keys: durableKeyStore{NewMemoryKeyStore()}, Credentials: NewMemoryCredentialStore(),
		Provider: attestingProvider{}, Authorizations: durableAuthorizations{NewMemoryAuthorizationStore()},
	}
	refreshing := func(deps Dependencies) *Wallet {
		w, err := New(Config{ClientID: "wallet", RedirectURI: "https://wallet.example/cb", IssuerRoots: x509.NewCertPool(), RequestRefresh: true}, deps)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	if err := refreshing(deps).checkIssuance(); err == nil || !strings.Contains(err.Error(), "Durable Dependencies.Grants") {
		t.Errorf("with a memory GrantStore: checkIssuance = %v", err)
	}
	deps.Grants = durableGrants{NewMemoryGrantStore()}
	if err := refreshing(deps).checkIssuance(); err != nil {
		t.Errorf("with a durable GrantStore: checkIssuance = %v", err)
	}
}
