package haip_test

import (
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/haip"
)

// completeAuthorizationServerConfig fills in what
// RecommendedAuthorizationServerConfig leaves to the caller.
func completeAuthorizationServerConfig(t *testing.T) server.Config {
	t.Helper()
	cfg, err := haip.RecommendedAuthorizationServerConfig()
	if err != nil {
		t.Fatalf("RecommendedAuthorizationServerConfig: %v", err)
	}
	const base = "https://issuer.example.com"
	if cfg.Issuer, err = fapi.ParseIssuerURL(base); err != nil {
		t.Fatal(err)
	}
	for path, dst := range map[string]*fapi.URL{
		"/authorize": &cfg.Endpoints.Authorization, "/token": &cfg.Endpoints.Token,
		"/par": &cfg.Endpoints.PushedAuthorizationRequest, "/jwks": &cfg.Endpoints.JWKS,
	} {
		if *dst, err = fapi.ParseEndpointURL(base + path); err != nil {
			t.Fatal(err)
		}
	}
	cfg.Assurance = server.AssuranceDevelopment
	cfg.Limits.MaxClientAttestationLifetime = 24 * time.Hour
	return cfg
}

func haipServerDependencies(t *testing.T) server.Dependencies {
	t.Helper()
	keyManager, err := ephemeral.NewKeyManager(map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.AccessTokenSigning: fapi.ES256})
	if err != nil {
		t.Fatal(err)
	}
	wallet, err := storage.NewRegisteredClient(func() storage.RegisteredClientConfig {
		c := haip.RecommendedWalletClient("wallet", "https://wallet-provider.example.com")
		c.RedirectURIs = []fapi.RegisteredRedirectURI{"https://wallet.example.com/callback"}
		c.AllowedScopes = []string{"pid"}
		return c
	}())
	if err != nil {
		t.Fatalf("NewRegisteredClient(RecommendedWalletClient): %v", err)
	}
	clientKeys, err := ephemeral.NewClientKeySource(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return server.Dependencies{
		Clients: memstore.NewClientRepository([]storage.RegisteredClient{wallet}), Transactions: memstore.NewTransactionStore(),
		Grants: memstore.NewGrantStore(), Replay: memstore.NewReplayStore(), ClientKeys: clientKeys, Keys: keyManager,
		AccessTokens: server.JWTAccessTokens{Keys: keyManager, Algorithm: fapi.ES256}, Revocation: memstore.NewRevocationStore(),
		Clock: server.SystemClock{}, Random: rand.Reader, ClientCertificateTrust: server.NoClientCertificateChainTrust{},
		AttesterTrust: server.X5CAttesterChain{
			TrustAnchors:  server.StaticAttesterTrustAnchors{Roots: x509.NewCertPool()},
			IssuerBinding: server.AttesterIssuerInCertificate,
		},
	}
}

func TestRecommendedAuthorizationServerConfigWorksWithServerNew(t *testing.T) {
	cfg := completeAuthorizationServerConfig(t)
	if _, err := server.New(cfg, haipServerDependencies(t)); err != nil {
		t.Fatalf("server.New: %v", err)
	}
}

func TestRecommendedAuthorizationServerConfigLeavesAttestationLifetimeToCaller(t *testing.T) {
	cfg := completeAuthorizationServerConfig(t)
	cfg.Limits.MaxClientAttestationLifetime = 0
	if _, err := server.New(cfg, haipServerDependencies(t)); err == nil {
		t.Fatal("server.New accepted a Config without MaxClientAttestationLifetime")
	}
}

func TestRecommendedAuthorizationServerConfigValues(t *testing.T) {
	cfg, err := haip.RecommendedAuthorizationServerConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Profile != server.ProfileFAPISecurity || !cfg.OAuthOnly || !cfg.AttestationBasedClientAuthentication {
		t.Errorf("Profile %v, OAuthOnly %v, AttestationBasedClientAuthentication %v; want FAPI security, true, true",
			cfg.Profile, cfg.OAuthOnly, cfg.AttestationBasedClientAuthentication)
	}
	for name, set := range map[string]server.AlgorithmSet{"ClientAttestation": cfg.Algorithms.ClientAttestation, "ClientAttestationPoP": cfg.Algorithms.ClientAttestationPoP} {
		if len(set) != 1 || set[0] != fapi.ES256 {
			t.Errorf("%s = %v, want [ES256]", name, set)
		}
	}
	if cfg.Limits.MaxClientAttestationPoPAge != cfg.Limits.MaxDPoPProofAge || cfg.Limits.MaxClientAttestationPoPAge == 0 {
		t.Errorf("MaxClientAttestationPoPAge = %v, want MaxDPoPProofAge %v", cfg.Limits.MaxClientAttestationPoPAge, cfg.Limits.MaxDPoPProofAge)
	}
	registered := false
	for _, d := range cfg.Extensions.Definitions() {
		def, ok := d.(extension.Definition[string])
		registered = registered || (ok && def.Name == oid4vci.IssuerStateExtension.Name)
	}
	if !registered {
		t.Error("Extensions doesn't register oid4vci.IssuerStateExtension")
	}
}
