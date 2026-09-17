package verifier_test

import (
	"crypto/rand"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/verifier"
)

func TestNewAcceptsValidConfig(t *testing.T) {
	cfg, deps := validConfig(t)
	v, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !strings.HasPrefix(v.ClientID(), "x509_hash:") {
		t.Errorf("ClientID() = %q, want an x509_hash: prefix", v.ClientID())
	}
}

func TestNewRejectsMissingFields(t *testing.T) {
	cases := map[string]func(cfg *verifier.Config, deps *verifier.Dependencies){
		"missing client_certificate": func(cfg *verifier.Config, _ *verifier.Dependencies) {
			cfg.ClientCertificate = nil
		},
		"missing response_uri": func(cfg *verifier.Config, _ *verifier.Dependencies) {
			cfg.ResponseURI = verifier.Config{}.ResponseURI
		},
		"missing signing_alg": func(cfg *verifier.Config, _ *verifier.Dependencies) {
			cfg.SigningAlg = ""
		},
		"missing enc_values_supported": func(cfg *verifier.Config, _ *verifier.Dependencies) {
			cfg.EncValuesSupported = nil
		},
		"missing vp_formats_supported": func(cfg *verifier.Config, _ *verifier.Dependencies) {
			cfg.VPFormatsSupported = nil
		},
		"missing signer": func(_ *verifier.Config, deps *verifier.Dependencies) {
			deps.Signer = nil
		},
		"missing random": func(_ *verifier.Config, deps *verifier.Dependencies) {
			deps.Random = nil
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, deps := validConfig(t)
			mutate(&cfg, &deps)
			if _, err := verifier.New(cfg, deps); err == nil {
				t.Fatalf("New(%s) = nil error, want error", name)
			}
		})
	}
}

func TestNewRejectsSignerCertificateMismatch(t *testing.T) {
	cfg, deps := validConfig(t)
	otherSigner, _ := testSignerAndCert(t)
	deps.Signer = otherSigner
	if _, err := verifier.New(cfg, deps); err == nil {
		t.Fatalf("New = nil error, want error")
	}
}

func TestNewComputesStableClientID(t *testing.T) {
	cfg, deps := validConfig(t)
	v1, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	v2, err := verifier.New(cfg, verifier.Dependencies{Signer: deps.Signer, Random: rand.Reader})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if v1.ClientID() != v2.ClientID() {
		t.Errorf("ClientID() differs across two New calls with the same cert: %q vs %q", v1.ClientID(), v2.ClientID())
	}
}
