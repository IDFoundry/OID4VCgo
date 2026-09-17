package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcigo/credential/mdoc"
	"github.com/idfoundry/oid4vcigo/internal/conformanceconfig"
	"github.com/idfoundry/oid4vcigo/internal/cose"
)

// mdocTestConfig returns baseTestConfig plus a second, mso_mdoc-format
// CredentialConfiguration (Config.Mdoc) alongside the base config's own
// "dc+sd-jwt" one — this file's own tests exercise driving both formats
// from the one issuer identity wiring.go now builds, matching a real
// multi-format deployment rather than a second throwaway key.
func mdocTestConfig(t *testing.T) Config {
	t.Helper()
	cfg := baseTestConfig(t)
	cfg.Mdoc = &conformanceconfig.MdocConfig{
		CredentialConfigurationID: "MobileDrivingLicense",
		DocType:                   "org.iso.18013.5.1.mDL",
		Namespace:                 "org.iso.18013.5.1",
		Claims:                    map[string]string{"given_name": "Jean", "family_name": "Dupont"},
		Scope:                     "MobileDrivingLicense",
	}
	return cfg
}

// TestFullFlow_MdocCredentialIssuance drives cmd/conformance-issuer's
// entire stack — PAR, consent, token, nonce, and finally the Credential
// Endpoint — end to end against a real newServerMux instance, requesting
// the mso_mdoc CredentialConfiguration instead of the "dc+sd-jwt" one
// every other full-flow test in this package exercises. Decodes and
// fully verifies the returned IssuerSigned structure (signature, digest,
// DocType, disclosed claims, DeviceKey binding, validity window) via
// credential/mdoc's own Verify — not just a shallow "did we get a
// non-empty string back" check — proving wiring.go's new MdocSigner
// wiring and credential.go's new MdocClaims dispatch produce a
// genuinely valid mdoc credential, not just one issuer.RequestCredential
// itself already unit-tests in isolation.
func TestFullFlow_MdocCredentialIssuance(t *testing.T) {
	now := time.Now()
	client, cfg, attesterKey, clientKey := setupFullFlowTestWithConfig(t, mdocTestConfig(t), "mdoc-smoke-test-client", "mdoc-smoke-test-subject")
	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate holder key: %v", err)
	}

	// The access token must carry the mdoc CredentialConfiguration's own
	// scope, not cfg.Scope (the "dc+sd-jwt" one) — issuer.RequestCredential
	// checks the presented token's own granted scope against whichever
	// credential_configuration_id a Credential Request names, the same
	// way it would reject a mismatched scope for the base SD-JWT
	// configuration (confirmed live: driving this with cfg.Scope
	// unchanged gets a real 400 invalid_credential_request, "access
	// token does not grant the scope required for this
	// credential_configuration_id" — not a test bug to route around).
	authCfg := cfg
	authCfg.Scope = cfg.Mdoc.Scope
	accessToken, cNonce := performAuthFlowThroughNonce(t, client, authCfg, attesterKey, clientKey, now)

	proofJWT, err := buildCredentialProofJWT(holderKey, cfg.Client.ID, cfg.Issuer, cNonce, now)
	if err != nil {
		t.Fatalf("buildCredentialProofJWT: %v", err)
	}
	credentialResp := postCredentialRequest(t, client, cfg, clientKey, accessToken, now, map[string]any{
		"credential_configuration_id": cfg.Mdoc.CredentialConfigurationID,
		"proofs":                      map[string][]string{"jwt": {proofJWT}},
	})
	credentials, _ := credentialResp["credentials"].([]any)
	if len(credentials) != 1 {
		t.Fatalf("credential response has %d credentials, want 1: %+v", len(credentials), credentialResp)
	}
	credentialEntry, _ := credentials[0].(map[string]any)
	mdocB64, _ := credentialEntry["credential"].(string)
	if mdocB64 == "" {
		t.Fatalf("credential response entry has no credential string: %+v", credentialEntry)
	}

	raw, err := base64.RawURLEncoding.DecodeString(mdocB64)
	if err != nil {
		t.Fatalf("decode credential as base64url: %v", err)
	}
	signed, err := mdoc.UnmarshalIssuerSigned(raw)
	if err != nil {
		t.Fatalf("UnmarshalIssuerSigned: %v", err)
	}

	issuerCert, err := cfg.credentialIssuerCertificate()
	if err != nil {
		t.Fatalf("credentialIssuerCertificate: %v", err)
	}
	verified, err := mdoc.Verify(signed, issuerCert.PublicKey, cose.ES256, mdoc.VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if verified.DocType != cfg.Mdoc.DocType {
		t.Errorf("DocType = %q, want %q", verified.DocType, cfg.Mdoc.DocType)
	}
	elements, ok := verified.NameSpaces[cfg.Mdoc.Namespace]
	if !ok {
		t.Fatalf("verified credential has no namespace %q: %+v", cfg.Mdoc.Namespace, verified.NameSpaces)
	}
	for name, want := range cfg.Mdoc.Claims {
		got, _ := elements[name].(string)
		if got != want {
			t.Errorf("element %q = %q, want %q", name, got, want)
		}
	}

	deviceKeyECDSA, ok := verified.DeviceKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("DeviceKey has type %T, want *ecdsa.PublicKey", verified.DeviceKey)
	}
	if !deviceKeyECDSA.Equal(&holderKey.PublicKey) {
		t.Error("verified DeviceKey does not match the proof's own holder key")
	}
}
