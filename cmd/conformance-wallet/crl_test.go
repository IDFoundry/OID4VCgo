package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"testing"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
)

// TestWalletCRL checks the run's CAs: the controls' signers are
// refused for their reasons, the run's own credential signer accepted,
// and a control's plan config carries its signing key.
func TestWalletCRL(t *testing.T) {
	crl, err := newWalletCRL()
	if err != nil {
		t.Fatal(err)
	}
	run, err := newWalletRun(runConfig{apiBase: "https://localhost:8443/", scope: "s", credentialConfigurationID: "c"}, crl)
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.start(context.Background()); err != nil {
		t.Fatal(err)
	}
	check := func(leafPEM string, ca *x509.Certificate) error {
		leaf, err := conformancecert.ParseCertificatePEM(leafPEM)
		if err != nil {
			t.Fatal(err)
		}
		return crl.revocation.CheckRevocation(context.Background(), certrevocation.Check{Chain: []*x509.Certificate{leaf, ca}})
	}
	controls := crl.controls()
	if len(controls) != 2 {
		t.Fatalf("%d controls, want 2", len(controls))
	}
	for _, c := range controls {
		ca := crl.credentialCA.Cert
		if c.want == certrevocation.ErrNoCurrentCRL {
			ca = crl.staleCA.Cert
		}
		if err := check(c.signer.leafPEM, ca); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", controlKey(c), err, c.want)
		}
	}
	var plan struct {
		Credential struct {
			SigningJWK map[string]any `json:"signing_jwk"`
		} `json:"credential"`
	}
	if err := json.Unmarshal(run.planConfig, &plan); err != nil || plan.Credential.SigningJWK["x5c"] == nil {
		t.Fatalf("plan config: %v, signing_jwk %v", err, plan.Credential.SigningJWK)
	}
	raw, err := run.planConfigWith(map[string]any{"kid": "control"})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &plan); err != nil || plan.Credential.SigningJWK["kid"] != "control" {
		t.Errorf("control plan config: %v, signing_jwk %v", err, plan.Credential.SigningJWK)
	}
}
