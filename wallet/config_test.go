package wallet_test

import (
	"crypto/rand"
	"net/http"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/fapihttp"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/wallet"
)

type fakeHTTPClient struct {
	do func(*http.Request) (*http.Response, error)
}

func (f fakeHTTPClient) Do(req *http.Request) (*http.Response, error) { return f.do(req) }

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

func validConfig() wallet.Config {
	return wallet.Config{
		Assurance:       wallet.AssuranceDevelopment,
		ProofSigningAlg: jose.ES256,
		Fetch: fapihttp.Config{
			MaxResponseBytes: 1 << 20,
			RequestTimeout:   5 * time.Second,
			MaxRedirects:     2,
			// Tests fetch from plain http://localhost URLs (no real
			// network access) rather than a live https:// host.
			AllowLoopbackHTTP: true,
		},
	}
}

func validDependencies() wallet.Dependencies {
	return wallet.Dependencies{
		HTTP:   fakeHTTPClient{do: func(*http.Request) (*http.Response, error) { return nil, nil }},
		Clock:  wallet.ClockFunc(time.Now),
		Random: rand.Reader,
	}
}

func TestNewAcceptsValidConfig(t *testing.T) {
	if _, err := wallet.New(validConfig(), validDependencies()); err != nil {
		t.Fatalf("New: %v", err)
	}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	cases := map[string]func(*wallet.Config, *wallet.Dependencies){
		"missing proof_signing_alg":     func(c *wallet.Config, _ *wallet.Dependencies) { c.ProofSigningAlg = "" },
		"unsupported proof_signing_alg": func(c *wallet.Config, _ *wallet.Dependencies) { c.ProofSigningAlg = jose.Alg("RS256") },
		"missing http":                  func(_ *wallet.Config, d *wallet.Dependencies) { d.HTTP = nil },
		"missing clock":                 func(_ *wallet.Config, d *wallet.Dependencies) { d.Clock = nil },
		"invalid fetch config":          func(c *wallet.Config, _ *wallet.Dependencies) { c.Fetch.MaxResponseBytes = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, deps := validConfig(), validDependencies()
			mutate(&cfg, &deps)
			if _, err := wallet.New(cfg, deps); err == nil {
				t.Fatalf("New(%s) = nil error, want error", name)
			}
		})
	}
}
