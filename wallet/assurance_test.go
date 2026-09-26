package wallet_test

import (
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/wallet"
)

func TestNewRejectsInvalidAssurance(t *testing.T) {
	for _, level := range []wallet.AssuranceLevel{0, 99} {
		cfg := validConfig()
		cfg.Assurance = level
		if _, err := wallet.New(cfg, validDependencies()); err == nil {
			t.Errorf("New(Assurance=%d) = nil error, want error", level)
		}
	}
}

func TestNewProductionRejectsAllowLoopbackHTTP(t *testing.T) {
	cfg := validConfig() // sets Fetch.AllowLoopbackHTTP
	cfg.Assurance = wallet.AssuranceProduction
	_, err := wallet.New(cfg, validDependencies())
	if err == nil || !strings.Contains(err.Error(), "allow_loopback_http") {
		t.Fatalf("New(AssuranceProduction, AllowLoopbackHTTP) error = %v, want an allow_loopback_http rejection", err)
	}
}

func TestNewProductionAcceptsHardenedFetch(t *testing.T) {
	cfg := validConfig()
	cfg.Assurance = wallet.AssuranceProduction
	cfg.Fetch.AllowLoopbackHTTP = false
	// An explicit private-host allow-list is a deployment choice, not a
	// development switch, so it stays permitted.
	cfg.Fetch.AllowedPrivateHosts = []string{"issuer.internal"}
	if _, err := wallet.New(cfg, validDependencies()); err != nil {
		t.Fatalf("New(AssuranceProduction): %v", err)
	}
}
