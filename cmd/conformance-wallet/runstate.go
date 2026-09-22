package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
)

// persistedRun is walletRun's on-disk counterpart for -save-run/
// -drive-only: everything a later, separate process needs to
// reconstruct the exact same run — including the private key material
// -dump-config alone throws away the instant it exits. Needed for the
// "create the plan/module yourself through the suite's own
// authenticated web UI, then hand this binary just the resulting
// Credential Offer URL to drive" workflow: the suite's admin API
// (POST /api/plan, POST /api/runner) requires a logged-in session this
// binary has no way to establish against the hosted
// certification.openid.net instance, but the module's own protocol
// endpoints (discovery/PAR/authorize/token/credential) that
// -drive-only actually calls are not behind that login at all — only
// keeping the same keys alive across the two separate invocations
// (rather than each generating its own, which the suite would never
// have been told to trust) was ever the real blocker.
type persistedRun struct {
	Alias                     string `json:"alias"`
	ClientID                  string `json:"client_id"`
	RedirectURI               string `json:"redirect_uri"`
	Scope                     string `json:"scope"`
	CredentialConfigurationID string `json:"credential_configuration_id"`
	ProofType                 string `json:"proof_type"`

	AttesterKeyPEM  string `json:"attester_key_pem"`
	AttesterLeafPEM string `json:"attester_leaf_pem"`

	KeyAttestationKeyPEM  string `json:"key_attestation_key_pem"`
	KeyAttestationLeafPEM string `json:"key_attestation_leaf_pem"`
}

// saveRunState writes run's own private key material and identifiers
// to path as JSON, for a later -drive-only invocation to load via
// loadRunState.
func saveRunState(path string, run *walletRun) error {
	p := persistedRun{
		Alias: run.alias, ClientID: run.clientID, RedirectURI: run.redirectURI,
		Scope: run.scope, CredentialConfigurationID: run.credentialConfigurationID,
		ProofType:             string(run.proofType),
		AttesterKeyPEM:        run.attesterKeyPEM,
		AttesterLeafPEM:       run.attesterLeafPEM,
		KeyAttestationKeyPEM:  run.keyAttestationKeyPEM,
		KeyAttestationLeafPEM: run.keyAttestationLeafPEM,
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal run state: %w", err)
	}
	// 0600: this file carries private key material.
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write run state %s: %w", path, err)
	}
	return nil
}

// loadRunState reads path (written by saveRunState) and reconstructs
// a walletRun ready for driveModule — everything -drive-only needs
// except the module URL/offer, which come from its own flags at drive
// time instead, since they're specific to the module instance created
// out-of-band through the suite's own web UI.
func loadRunState(path string) (*walletRun, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is the operator's own -run-state flag value, not untrusted input
	if err != nil {
		return nil, fmt.Errorf("read run state %s: %w", path, err)
	}
	var p persistedRun
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("decode run state %s: %w", path, err)
	}

	attesterKey, err := conformancecert.ParseECPrivateKeyPEM(p.AttesterKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse attester key: %w", err)
	}
	keyAttestationKey, err := conformancecert.ParseECPrivateKeyPEM(p.KeyAttestationKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse key attestation key: %w", err)
	}

	return &walletRun{
		alias: p.Alias, clientID: p.ClientID, redirectURI: p.RedirectURI,
		scope: p.Scope, credentialConfigurationID: p.CredentialConfigurationID,
		proofType:             proofStrategy(p.ProofType),
		attesterKey:           attesterKey,
		attesterKeyPEM:        p.AttesterKeyPEM,
		attesterLeafPEM:       p.AttesterLeafPEM,
		keyAttestationKey:     keyAttestationKey,
		keyAttestationKeyPEM:  p.KeyAttestationKeyPEM,
		keyAttestationLeafPEM: p.KeyAttestationLeafPEM,
	}, nil
}
