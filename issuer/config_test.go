package issuer_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcigo"
	"github.com/idfoundry/oid4vcigo/internal/cose"
	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/issuer"
)

const (
	testIssuer                     = "https://issuer.example.com"
	testCredentialEndpoint         = "https://issuer.example.com/credential"
	testNonceEndpoint              = "https://issuer.example.com/nonce"
	testCredentialOfferEndpoint    = "https://issuer.example.com/credential-offer"
	testDeferredCredentialEndpoint = "https://issuer.example.com/deferred_credential"
	testNotificationEndpoint       = "https://issuer.example.com/notification"
)

func mustIssuerURL(t *testing.T, raw string) fapi.URL {
	t.Helper()
	u, err := fapi.ParseIssuerURL(raw)
	if err != nil {
		t.Fatalf("ParseIssuerURL(%q): %v", raw, err)
	}
	return u
}

func mustEndpointURL(t *testing.T, raw string) fapi.URL {
	t.Helper()
	u, err := fapi.ParseEndpointURL(raw)
	if err != nil {
		t.Fatalf("ParseEndpointURL(%q): %v", raw, err)
	}
	return u
}

func validCredentialConfigurations() map[string]issuer.CredentialConfiguration {
	return map[string]issuer.CredentialConfiguration{
		"IdentityCredential": {
			Format:                               "dc+sd-jwt",
			Scope:                                "identity_credential",
			VCT:                                  "https://credentials.example.com/identity_credential",
			CryptographicBindingMethodsSupported: []string{"jwk"},
			CredentialSigningAlgValuesSupported:  []string{"ES256"},
			ProofTypesSupported: map[string]issuer.ProofTypeConfiguration{
				oid4vci.ProofTypeJWT: {ProofSigningAlgValuesSupported: []string{"ES256"}},
			},
		},
	}
}

func validConfig(t *testing.T) issuer.Config {
	t.Helper()
	return issuer.Config{
		Issuer: mustIssuerURL(t, testIssuer),
		Endpoints: issuer.Endpoints{
			Credential:         mustEndpointURL(t, testCredentialEndpoint),
			Nonce:              mustEndpointURL(t, testNonceEndpoint),
			DeferredCredential: mustEndpointURL(t, testDeferredCredentialEndpoint),
			Notification:       mustEndpointURL(t, testNotificationEndpoint),
		},
		Limits: issuer.Limits{
			NonceLifetime:                time.Minute,
			CredentialOfferLifetime:      time.Hour,
			DeferredIssuancePollInterval: 10 * time.Second,
		},
		CredentialConfigurationsSupported: validCredentialConfigurations(),
		CredentialOfferEndpoint:           mustEndpointURL(t, testCredentialOfferEndpoint),
	}
}

func testSDJWTSigner(t *testing.T) *issuer.SDJWTSigner {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &issuer.SDJWTSigner{Signer: key, Alg: jose.ES256}
}

func testMdocSigner(t *testing.T) *issuer.MdocSigner {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &issuer.MdocSigner{Signer: key, Alg: cose.ES256, X5Chain: [][]byte{{0x01, 0x02, 0x03}}}
}

func validDependencies(t *testing.T) issuer.Dependencies {
	t.Helper()
	return issuer.Dependencies{
		Nonces:               newFakeNonceStore(),
		Clock:                issuer.ClockFunc(time.Now),
		Random:               rand.Reader,
		SDJWTSigner:          testSDJWTSigner(t),
		CredentialOffers:     newFakeCredentialOfferStore(),
		DeferredTransactions: newFakeDeferredTransactionStore(),
		Notifications:        newFakeNotificationStore(),
	}
}

func TestNewAcceptsValidConfig(t *testing.T) {
	if _, err := issuer.New(validConfig(t), validDependencies(t)); err != nil {
		t.Fatalf("New: %v", err)
	}
}

func TestNewAcceptsNonceEndpointDisabled(t *testing.T) {
	cfg := validConfig(t)
	cfg.Endpoints.Nonce = fapi.URL{}
	cfg.Limits.NonceLifetime = 0
	deps := validDependencies(t)
	deps.Nonces = nil
	if _, err := issuer.New(cfg, deps); err != nil {
		t.Fatalf("New: %v", err)
	}
}

func TestNewAcceptsCredentialOfferEndpointDisabled(t *testing.T) {
	cfg := validConfig(t)
	cfg.CredentialOfferEndpoint = fapi.URL{}
	cfg.Limits.CredentialOfferLifetime = 0
	deps := validDependencies(t)
	deps.CredentialOffers = nil
	if _, err := issuer.New(cfg, deps); err != nil {
		t.Fatalf("New: %v", err)
	}
}

func TestNewAcceptsDeferredCredentialEndpointDisabled(t *testing.T) {
	cfg := validConfig(t)
	cfg.Endpoints.DeferredCredential = fapi.URL{}
	cfg.Limits.DeferredIssuancePollInterval = 0
	deps := validDependencies(t)
	deps.DeferredTransactions = nil
	if _, err := issuer.New(cfg, deps); err != nil {
		t.Fatalf("New: %v", err)
	}
}

func TestNewAcceptsNotificationEndpointDisabled(t *testing.T) {
	cfg := validConfig(t)
	cfg.Endpoints.Notification = fapi.URL{}
	deps := validDependencies(t)
	deps.Notifications = nil
	if _, err := issuer.New(cfg, deps); err != nil {
		t.Fatalf("New: %v", err)
	}
}

func TestNewRejectsMissingNotificationsDependency(t *testing.T) {
	cfg := validConfig(t)
	deps := validDependencies(t)
	deps.Notifications = nil
	if _, err := issuer.New(cfg, deps); err == nil {
		t.Fatalf("New = nil error, want error (endpoints.notification is set but dependencies.notifications is nil)")
	}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	cases := map[string]func(*issuer.Config){
		"zero issuer":                                        func(c *issuer.Config) { c.Issuer = fapi.URL{} },
		"zero credential endpoint":                           func(c *issuer.Config) { c.Endpoints.Credential = fapi.URL{} },
		"empty credential configurations":                    func(c *issuer.Config) { c.CredentialConfigurationsSupported = nil },
		"zero nonce lifetime with endpoint":                  func(c *issuer.Config) { c.Limits.NonceLifetime = 0 },
		"zero credential offer lifetime with endpoint":       func(c *issuer.Config) { c.Limits.CredentialOfferLifetime = 0 },
		"zero deferred issuance poll interval with endpoint": func(c *issuer.Config) { c.Limits.DeferredIssuancePollInterval = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig(t)
			mutate(&cfg)
			if _, err := issuer.New(cfg, validDependencies(t)); err == nil {
				t.Fatalf("New(%s) = nil error, want error", name)
			}
		})
	}
}

func TestNewRejectsInvalidCredentialConfiguration(t *testing.T) {
	cases := map[string]issuer.CredentialConfiguration{
		"empty format": {Format: "", CryptographicBindingMethodsSupported: nil},
		"binding methods without proof types": {
			Format: "dc+sd-jwt", CryptographicBindingMethodsSupported: []string{"jwk"},
		},
		"proof types without binding methods": {
			Format: "dc+sd-jwt",
			ProofTypesSupported: map[string]issuer.ProofTypeConfiguration{
				oid4vci.ProofTypeJWT: {ProofSigningAlgValuesSupported: []string{"ES256"}},
			},
		},
		"proof type with no algorithms": {
			Format: "dc+sd-jwt", CryptographicBindingMethodsSupported: []string{"jwk"},
			ProofTypesSupported: map[string]issuer.ProofTypeConfiguration{
				oid4vci.ProofTypeJWT: {},
			},
		},
		"both JOSE and COSE signing algs set": {
			Format:                                  "mso_mdoc",
			CredentialSigningAlgValuesSupported:     []string{"ES256"},
			CredentialSigningAlgValuesSupportedCOSE: []cose.Alg{cose.ES256},
		},
	}
	for name, cc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig(t)
			cfg.CredentialConfigurationsSupported = map[string]issuer.CredentialConfiguration{"x": cc}
			if _, err := issuer.New(cfg, validDependencies(t)); err == nil {
				t.Fatalf("New(%s) = nil error, want error", name)
			}
		})
	}
}

func TestNewRejectsMissingSignerDependencies(t *testing.T) {
	sdjwtConfig := issuer.CredentialConfiguration{
		Format: "dc+sd-jwt", CryptographicBindingMethodsSupported: []string{"jwk"},
		ProofTypesSupported: map[string]issuer.ProofTypeConfiguration{
			oid4vci.ProofTypeJWT: {ProofSigningAlgValuesSupported: []string{"ES256"}},
		},
	}
	mdocConfig := issuer.CredentialConfiguration{
		Format: "mso_mdoc", CryptographicBindingMethodsSupported: []string{"cose_key"},
		ProofTypesSupported: map[string]issuer.ProofTypeConfiguration{
			oid4vci.ProofTypeJWT: {ProofSigningAlgValuesSupported: []string{"ES256"}},
		},
	}
	attestationConfig := issuer.CredentialConfiguration{
		Format: "dc+sd-jwt", CryptographicBindingMethodsSupported: []string{"jwk"},
		ProofTypesSupported: map[string]issuer.ProofTypeConfiguration{
			oid4vci.ProofTypeAttestation: {ProofSigningAlgValuesSupported: []string{"ES256"}},
		},
	}

	cases := []struct {
		name   string
		cc     issuer.CredentialConfiguration
		mutate func(*issuer.Dependencies)
	}{
		{"missing sdjwt_signer", sdjwtConfig, func(d *issuer.Dependencies) { d.SDJWTSigner = nil }},
		{"sdjwt_signer with nil signer", sdjwtConfig, func(d *issuer.Dependencies) { d.SDJWTSigner = &issuer.SDJWTSigner{Alg: jose.ES256} }},
		{"sdjwt_signer with empty alg", sdjwtConfig, func(d *issuer.Dependencies) {
			d.SDJWTSigner = &issuer.SDJWTSigner{Signer: testP256Key(t)}
		}},
		{"missing mdoc_signer", mdocConfig, func(d *issuer.Dependencies) { d.MdocSigner = nil }},
		{"mdoc_signer with nil signer", mdocConfig, func(d *issuer.Dependencies) {
			d.MdocSigner = &issuer.MdocSigner{Alg: cose.ES256, X5Chain: [][]byte{{1}}}
		}},
		{"mdoc_signer with zero alg", mdocConfig, func(d *issuer.Dependencies) {
			d.MdocSigner = &issuer.MdocSigner{Signer: testP256Key(t), X5Chain: [][]byte{{1}}}
		}},
		{"mdoc_signer with empty x5chain", mdocConfig, func(d *issuer.Dependencies) {
			d.MdocSigner = &issuer.MdocSigner{Signer: testP256Key(t), Alg: cose.ES256}
		}},
		{"missing attestation_verifier", attestationConfig, func(d *issuer.Dependencies) { d.AttestationVerifier = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig(t)
			cfg.CredentialConfigurationsSupported = map[string]issuer.CredentialConfiguration{"x": tc.cc}
			deps := validDependencies(t)
			deps.MdocSigner = testMdocSigner(t)
			tc.mutate(&deps)
			if _, err := issuer.New(cfg, deps); err == nil {
				t.Fatalf("New(%s) = nil error, want error", tc.name)
			}
		})
	}
}

func TestNewRejectsMissingDependencies(t *testing.T) {
	cfg := validConfig(t)
	cases := map[string]func(*issuer.Dependencies){
		"nil nonces (nonce endpoint configured)": func(d *issuer.Dependencies) { d.Nonces = nil },
		"nil clock":                              func(d *issuer.Dependencies) { d.Clock = nil },
		"nil random":                             func(d *issuer.Dependencies) { d.Random = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			deps := validDependencies(t)
			mutate(&deps)
			if _, err := issuer.New(cfg, deps); err == nil {
				t.Fatalf("New(%s) = nil error, want error", name)
			}
		})
	}
}
