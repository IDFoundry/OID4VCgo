package conformanceverifier

import (
	"testing"
)

// TestIssuerPKI checks the Verifier's config trusts both issuer CAs,
// publishes both CRLs and checks against both distribution points, and
// the controls are graded by their reasons.
func TestIssuerPKI(t *testing.T) {
	km, err := GenerateKeyMaterial("cn", "ca-cn", "https://conformance-verifier:8443")
	if err != nil {
		t.Fatal(err)
	}
	cfg := km.Config
	if err := km.issuerPKI.configureCRL(&cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.CRLPublisher.CRLs) != 2 || len(cfg.IssuerCRL.DistributionPoints) != 2 {
		t.Errorf("%d CRLs published, %d distribution points checked; want 2 each", len(cfg.CRLPublisher.CRLs), len(cfg.IssuerCRL.DistributionPoints))
	}
	if cfg.CredentialIssuerTrustAnchorsPEM != cfg.StatusListTrustAnchorsPEM {
		t.Error("the status list isn't trusted by the credential issuer's CAs")
	}
	if _, err := cfg.CRLPublisher.Handler(); err != nil {
		t.Errorf("crl_publisher: %v", err)
	}
	controls := km.issuerPKI.controls()
	if len(controls) != 2 {
		t.Fatalf("%d controls, want 2", len(controls))
	}
	want := controls[0].Refusal
	page := want[0] + "\nverifier: verify response: " + want[1] + `: "CN=x"`
	if err := gradeControl(want, outcomeFailed, page); err != nil {
		t.Errorf("a refusal naming the reason: %v", err)
	}
	if err := gradeControl(want, outcomeFailed, "reason: invalid_credential\nsomething else"); err == nil {
		t.Error("a refusal for another reason passed the control")
	}
	if err := gradeControl(want, outcomeVerified, ""); err == nil {
		t.Error("an accepted presentation passed the control")
	}
	if err := gradeControl(nil, outcomeFailed, page); err == nil {
		t.Error("a control naming no refusal passed")
	}
	if RefuseControl.String() == "no expectation" {
		t.Error("RefuseControl has no description")
	}
}
