package issuer_test

import (
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// nonceLessProductionIssuer is productionIssuer without a Nonce
// Endpoint, taking jwt proofs only (production refuses the attestation
// proof type without one).
func nonceLessProductionIssuer(t *testing.T) (issuer.Config, issuer.Dependencies) {
	t.Helper()
	cfg, deps := productionIssuer(t)
	cc := cfg.CredentialConfigurationsSupported["IdentityCredential"]
	delete(cc.ProofTypesSupported, oid4vci.ProofTypeAttestation)
	cfg.CredentialConfigurationsSupported["IdentityCredential"] = cc
	cfg.AllowAttestationProofType = false
	cfg.Endpoints.Nonce = fapi.URL{}
	cfg.Limits.NonceLifetime = 0
	deps.Nonces = nil
	return cfg, deps
}

// TestNewProductionCapsProofAgeWithoutNonceEndpoint: without a Nonce
// Endpoint a jwt proof's iat is its only freshness, and nothing records
// that it was used, so a production issuer takes it for at most
// MaxProductionProofAge (the audit's year-long MaxProofAge PoC,
// inverted). Development assurance takes any positive age, and with a
// Nonce Endpoint MaxProofAge plays no part.
func TestNewProductionCapsProofAgeWithoutNonceEndpoint(t *testing.T) {
	cfg, deps := nonceLessProductionIssuer(t)
	cfg.Limits.MaxProofAge = issuer.MaxProductionProofAge
	if _, err := issuer.New(cfg, deps); err != nil {
		t.Fatalf("New with max_proof_age %s: %v", cfg.Limits.MaxProofAge, err)
	}
	for _, age := range []time.Duration{issuer.MaxProductionProofAge + time.Second, 365 * 24 * time.Hour} {
		cfg.Limits.MaxProofAge = age
		if _, err := issuer.New(cfg, deps); err == nil || !strings.Contains(err.Error(), "max_proof_age") {
			t.Errorf("New with max_proof_age %s = %v, want it refused", age, err)
		}
	}

	dev := cfg
	dev.Assurance = issuer.AssuranceDevelopment
	if _, err := issuer.New(dev, deps); err != nil {
		t.Errorf("New under AssuranceDevelopment with max_proof_age %s: %v", dev.Limits.MaxProofAge, err)
	}

	withNonce, withNonceDeps := productionIssuer(t)
	withNonce.Limits.MaxProofAge = 365 * 24 * time.Hour
	if _, err := issuer.New(withNonce, withNonceDeps); err != nil {
		t.Errorf("New with a Nonce Endpoint and an unused max_proof_age: %v", err)
	}
}

// TestNewProductionCapsDPoPProofAge: where the issuer verifies the
// Token Request's DPoP proof, a production issuer takes it for at most
// MaxProductionDPoPProofAge, as fapigo/server does (the audit's
// year-long MaxDPoPProofAge PoC, inverted). Development assurance is
// unbounded, and under VerifiedPreAuthorizedCode the Authorization
// Server's limit applies.
func TestNewProductionCapsDPoPProofAge(t *testing.T) {
	cfg, deps := preAuthorizedCodeProductionConfig(t)
	deps.DPoPNonces = issuer.NoDPoPNonces{}
	cfg.Limits.MaxDPoPProofAge = issuer.MaxProductionDPoPProofAge
	if _, err := issuer.New(cfg, deps); err != nil {
		t.Fatalf("New with max_dpop_proof_age %s: %v", cfg.Limits.MaxDPoPProofAge, err)
	}
	for _, age := range []time.Duration{issuer.MaxProductionDPoPProofAge + time.Second, 365 * 24 * time.Hour} {
		cfg.Limits.MaxDPoPProofAge = age
		if _, err := issuer.New(cfg, deps); err == nil || !strings.Contains(err.Error(), "max_dpop_proof_age") {
			t.Errorf("New with max_dpop_proof_age %s = %v, want it refused", age, err)
		}
	}

	dev := cfg
	dev.Assurance = issuer.AssuranceDevelopment
	if _, err := issuer.New(dev, deps); err != nil {
		t.Errorf("New under AssuranceDevelopment with max_dpop_proof_age %s: %v", dev.Limits.MaxDPoPProofAge, err)
	}

	verified := cfg
	verified.PreAuthorizedCodeClientAuthentication = issuer.VerifiedPreAuthorizedCode{}
	if _, err := issuer.New(verified, deps); err != nil {
		t.Errorf("New under VerifiedPreAuthorizedCode with max_dpop_proof_age %s: %v", verified.Limits.MaxDPoPProofAge, err)
	}
}

// declaredClock is a Clock declaring issuer.ClockAssurance, as
// fapigo/server.SystemClock does.
type declaredClock struct{ reads bool }

func (declaredClock) Now() time.Time          { return time.Now() }
func (c declaredClock) ReadsSystemTime() bool { return c.reads }

// TestNewProductionRefusesCustomClock: a nil Clock is the system clock;
// a production issuer takes no other, unless it declares
// issuer.ClockAssurance, so a fixed test clock can't ship. Development
// assurance takes any clock.
func TestNewProductionRefusesCustomClock(t *testing.T) {
	cfg, deps := productionIssuer(t)
	for name, clock := range map[string]issuer.Clock{"nil": nil, "declared": declaredClock{reads: true}} {
		deps.Clock = clock
		if _, err := issuer.New(cfg, deps); err != nil {
			t.Errorf("New with a %s clock: %v", name, err)
		}
	}
	// Offset by a minute, so the signer's certificate is still valid.
	offset := issuer.ClockFunc(func() time.Time { return time.Now().Add(time.Minute) })
	for name, clock := range map[string]issuer.Clock{"offset": offset, "time.Now": issuer.ClockFunc(time.Now), "declining": declaredClock{reads: false}} {
		deps.Clock = clock
		if _, err := issuer.New(cfg, deps); err == nil || !strings.Contains(err.Error(), "dependencies.clock") {
			t.Errorf("New with a %s clock = %v, want it refused", name, err)
		}
	}
	cfg.Assurance = issuer.AssuranceDevelopment
	deps.Clock = offset
	if _, err := issuer.New(cfg, deps); err != nil {
		t.Errorf("New under AssuranceDevelopment with an offset clock: %v", err)
	}
}

// TestNewProductionNeedsNoDPoPReplayUnderVerifiedPreAuthorizedCode:
// under VerifiedPreAuthorizedCode the Authorization Server verifies the
// DPoP proof and keeps its replay records, so a production issuer
// doesn't ask for a DPoPReplay store it would never use, nor for one
// declaring StoreAssurance. Where the issuer verifies the proof itself,
// it still does.
func TestNewProductionNeedsNoDPoPReplayUnderVerifiedPreAuthorizedCode(t *testing.T) {
	cfg, deps := preAuthorizedCodeProductionConfig(t)
	cfg.PreAuthorizedCodeClientAuthentication = issuer.VerifiedPreAuthorizedCode{}
	deps.DPoPReplay = nil
	deps.AccessTokens = nil
	if _, err := issuer.New(cfg, deps); err != nil {
		t.Fatalf("New under VerifiedPreAuthorizedCode without DPoPReplay: %v", err)
	}
	deps.DPoPReplay = newFakeDPoPReplayChecker()
	if _, err := issuer.New(cfg, deps); err != nil {
		t.Fatalf("New under VerifiedPreAuthorizedCode with an undeclared DPoPReplay: %v", err)
	}

	cfg.PreAuthorizedCodeClientAuthentication = issuer.AnonymousPreAuthorizedCode{}
	deps.AccessTokens = &fakeAccessTokenIssuer{}
	if _, err := issuer.New(cfg, deps); err == nil || !strings.Contains(err.Error(), "dpop_replay") {
		t.Fatalf("New under AnonymousPreAuthorizedCode with an undeclared DPoPReplay = %v, want it refused", err)
	}
}
