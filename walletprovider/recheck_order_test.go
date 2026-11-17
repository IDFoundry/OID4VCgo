package walletprovider_test

import (
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/walletprovider"
)

// redeploy replaces h's provider with one over the same stores, its
// configuration and dependencies changed by mutate, as an operator
// redeploying does.
func (h *harness) redeploy(mutate func(*walletprovider.Config, *walletprovider.Dependencies)) {
	h.t.Helper()
	cfg, deps := h.cfg, h.deps
	cfg.Policy = policy()
	deps.Evidence = slices.Clone(deps.Evidence)
	mutate(&cfg, &deps)
	p, err := walletprovider.New(cfg, deps)
	if err != nil {
		h.t.Fatalf("New: %v", err)
	}
	h.p, h.cfg, h.deps = p, cfg, deps
}

// raiseMinAppVersion makes the Policy refuse the harness's Android
// evidence, whose app version is 10.
func raiseMinAppVersion(c *walletprovider.Config, _ *walletprovider.Dependencies) {
	pp := c.Policy.Platforms[walletprovider.PlatformAndroid]
	pp.MinAppVersion = 11
	c.Policy.Platforms[walletprovider.PlatformAndroid] = pp
}

// dropStrongBox makes the Policy refuse a StrongBox key.
func dropStrongBox(c *walletprovider.Config, _ *walletprovider.Dependencies) {
	pp := c.Policy.Platforms[walletprovider.PlatformAndroid]
	pp.SecurityLevels = []walletprovider.SecurityLevel{walletprovider.SecurityLevelTEE}
	c.Policy.Platforms[walletprovider.PlatformAndroid] = pp
}

// TestRecheckRevocationOutranksPolicy: the instance's rechecker runs
// though the provider's own Policy has since been tightened to refuse
// the instance, or its instance key, and a verdict that the evidence's
// issuer revoked it wins: the instance is revoked, its keys INVALID,
// and OnRecheckRefused hears of the revocation, not the Policy refusal.
func TestRecheckRevocationOutranksPolicy(t *testing.T) {
	revoked := fmt.Errorf("%w: %w: certificate 1 is REVOKED", walletprovider.ErrEvidenceRejected, walletprovider.ErrEvidenceRevoked)
	for _, tc := range []struct {
		name    string
		tighten func(*walletprovider.Config, *walletprovider.Dependencies)
		refuse  func(*keyRecheckingVerifier)
	}{
		{"registration evidence, app version", raiseMinAppVersion, func(v *keyRecheckingVerifier) { v.refuse(revoked) }},
		{"instance key evidence, security level", dropStrongBox, func(v *keyRecheckingVerifier) { v.refuseKey(revoked) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, log := &keyRecheckingVerifier{recheckingVerifier: &recheckingVerifier{}}, &refusalLog{}
			h := keyRecheckHarness(t, v, log)
			in, _ := h.register(kindTEE)
			key := h.newInstanceKey(in.ID, kindStrongBox)
			h.redeploy(tc.tighten)
			tc.refuse(v)
			if _, err := h.walletAttestation(in.ID, &key.PublicKey, ""); !errors.Is(err, walletprovider.ErrEvidenceRevoked) {
				t.Fatalf("Wallet Attestation = %v, want ErrEvidenceRevoked", err)
			}
			stored := h.stored(in.ID)
			if stored.State != walletprovider.StateRevoked {
				t.Fatalf("the instance is %s, want revoked", stored.State)
			}
			h.expectStatus(statuslist.StatusInvalid, key)
			log.expect(t, 1, stored, walletprovider.ErrEvidenceRevoked)
		})
	}
}

// TestRecheckPolicyRefusalReported: a Policy refusal of an instance the
// rechecker accepts, or can't check, refuses the request, leaves the
// instance active, and is reported to OnRecheckRefused, as a
// rechecker's own refusal is.
func TestRecheckPolicyRefusalReported(t *testing.T) {
	for name, recheck := range map[string]error{
		"accepted":       nil,
		"couldn't check": errors.New("status list unavailable"),
	} {
		t.Run(name, func(t *testing.T) {
			v, log := &recheckingVerifier{}, &refusalLog{}
			h := recheckHarness(t, v, log, nil)
			in, _ := h.register(kindTEE)
			key := h.newInstanceKey(in.ID, kindTEE)
			h.redeploy(raiseMinAppVersion)
			v.refuse(recheck)
			if _, err := h.walletAttestation(in.ID, &key.PublicKey, ""); !errors.Is(err, walletprovider.ErrPolicy) {
				t.Fatalf("Wallet Attestation = %v, want ErrPolicy", err)
			}
			if v.checked == 0 {
				t.Fatal("the rechecker didn't run")
			}
			stored := h.stored(in.ID)
			h.expectState(in.ID, walletprovider.StateActive, "")
			h.expectStatus(statuslist.StatusValid, key)
			log.expect(t, 1, stored, walletprovider.ErrPolicy)
		})
	}
}

// TestRecheckUnconfiguredKind: an instance registered with evidence of
// a Kind no configured verifier checks any more is refused, by policy,
// and reported, rather than attested with its rechecks skipped.
func TestRecheckUnconfiguredKind(t *testing.T) {
	v, log := &recheckingVerifier{}, &refusalLog{}
	h := recheckHarness(t, v, log, nil)
	in, _ := h.register(kindTEE)
	key := h.newInstanceKey(in.ID, kindTEE)
	h.redeploy(func(_ *walletprovider.Config, d *walletprovider.Dependencies) {
		d.Evidence = slices.DeleteFunc(d.Evidence, func(e walletprovider.EvidenceVerifier) bool { return e.Kind() == kindAndroid })
	})
	if _, err := h.walletAttestation(in.ID, &key.PublicKey, ""); !errors.Is(err, walletprovider.ErrPolicy) {
		t.Fatalf("Wallet Attestation = %v, want ErrPolicy", err)
	}
	h.expectState(in.ID, walletprovider.StateActive, "")
	log.expect(t, 1, h.stored(in.ID), walletprovider.ErrPolicy)
}
