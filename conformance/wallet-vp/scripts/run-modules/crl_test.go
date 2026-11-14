package main

import (
	"strings"
	"testing"
)

// TestNewVerifierPKI checks the wallet's config trusts both Verifier
// CAs, publishes both CRLs and checks against both distribution
// points, and the controls each name a reason.
func TestNewVerifierPKI(t *testing.T) {
	var cfg generatedConfig
	pki, err := newVerifierPKI(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfg.VerifierTrustAnchorsPEM, pki.ca.CertPEM) || !strings.Contains(cfg.VerifierTrustAnchorsPEM, pki.stale.CertPEM) {
		t.Error("verifier_trust_anchors_pem lacks a Verifier CA")
	}
	if len(cfg.CRLPublisher.CRLs) != 2 || len(cfg.VerifierCRL.DistributionPoints) != 2 {
		t.Errorf("%d CRLs published, %d distribution points checked; want 2 each", len(cfg.CRLPublisher.CRLs), len(cfg.VerifierCRL.DistributionPoints))
	}
	if _, err := cfg.CRLPublisher.Handler(); err != nil {
		t.Errorf("crl_publisher: %v", err)
	}
	for _, c := range pki.controls() {
		if len(c.refusal) == 0 || len(c.clientJWK.X5C) != 1 {
			t.Errorf("%s: refusal %q, x5c %d", c.name, c.refusal, len(c.clientJWK.X5C))
		}
	}
}
