package issuer_test

import (
	"crypto/rand"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcigo/internal/cose"
	"github.com/idfoundry/oid4vcigo/issuer"
)

const (
	testIssuer             = "https://issuer.example.com"
	testCredentialEndpoint = "https://issuer.example.com/credential"
	testNonceEndpoint      = "https://issuer.example.com/nonce"
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
				issuer.ProofTypeJWT: {ProofSigningAlgValuesSupported: []string{"ES256"}},
			},
		},
	}
}

func validConfig(t *testing.T) issuer.Config {
	t.Helper()
	return issuer.Config{
		Issuer: mustIssuerURL(t, testIssuer),
		Endpoints: issuer.Endpoints{
			Credential: mustEndpointURL(t, testCredentialEndpoint),
			Nonce:      mustEndpointURL(t, testNonceEndpoint),
		},
		Limits:                            issuer.Limits{NonceLifetime: time.Minute},
		CredentialConfigurationsSupported: validCredentialConfigurations(),
	}
}

func validDependencies() issuer.Dependencies {
	return issuer.Dependencies{
		Nonces: newFakeNonceStore(),
		Clock:  issuer.ClockFunc(time.Now),
		Random: rand.Reader,
	}
}

func TestNewAcceptsValidConfig(t *testing.T) {
	if _, err := issuer.New(validConfig(t), validDependencies()); err != nil {
		t.Fatalf("New: %v", err)
	}
}

func TestNewAcceptsNonceEndpointDisabled(t *testing.T) {
	cfg := validConfig(t)
	cfg.Endpoints.Nonce = fapi.URL{}
	cfg.Limits.NonceLifetime = 0
	deps := validDependencies()
	deps.Nonces = nil
	if _, err := issuer.New(cfg, deps); err != nil {
		t.Fatalf("New: %v", err)
	}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	cases := map[string]func(*issuer.Config){
		"zero issuer":                       func(c *issuer.Config) { c.Issuer = fapi.URL{} },
		"zero credential endpoint":          func(c *issuer.Config) { c.Endpoints.Credential = fapi.URL{} },
		"empty credential configurations":   func(c *issuer.Config) { c.CredentialConfigurationsSupported = nil },
		"zero nonce lifetime with endpoint": func(c *issuer.Config) { c.Limits.NonceLifetime = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig(t)
			mutate(&cfg)
			if _, err := issuer.New(cfg, validDependencies()); err == nil {
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
				issuer.ProofTypeJWT: {ProofSigningAlgValuesSupported: []string{"ES256"}},
			},
		},
		"proof type with no algorithms": {
			Format: "dc+sd-jwt", CryptographicBindingMethodsSupported: []string{"jwk"},
			ProofTypesSupported: map[string]issuer.ProofTypeConfiguration{
				issuer.ProofTypeJWT: {},
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
			if _, err := issuer.New(cfg, validDependencies()); err == nil {
				t.Fatalf("New(%s) = nil error, want error", name)
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
			deps := validDependencies()
			mutate(&deps)
			if _, err := issuer.New(cfg, deps); err == nil {
				t.Fatalf("New(%s) = nil error, want error", name)
			}
		})
	}
}
