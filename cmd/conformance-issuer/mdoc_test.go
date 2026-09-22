package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/conformanceconfig"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
)

// TestMdocClaimsForRequestDayRoundedValidity proves
// mdocClaimsForRequest's own anti-linkability rounding: Signed and
// ValidFrom must land exactly on today's own UTC day boundary (not the
// precise call instant), and ValidUntil must be lifetime past that same
// boundary -- see the function's own doc comment for the RFC 9901
// §10.1 reasoning (VCIEnsureCredentialTimeClaimsNotLinkable).
func TestMdocClaimsForRequestDayRoundedValidity(t *testing.T) {
	nameSpaces := map[string]map[string]interface{}{"org.iso.18013.5.1": {"given_name": "Jean"}}
	lifetime := 365 * 24 * time.Hour

	claims := mdocClaimsForRequest("org.iso.18013.5.1.mDL", nameSpaces, lifetime)
	if claims == nil {
		t.Fatal("mdocClaimsForRequest returned nil for non-nil nameSpaces")
	}

	wantDayStart := time.Now().UTC().Truncate(24 * time.Hour)
	if !claims.Signed.Equal(wantDayStart) {
		t.Errorf("Signed = %v, want day-truncated %v", claims.Signed, wantDayStart)
	}
	if !claims.ValidFrom.Equal(wantDayStart) {
		t.Errorf("ValidFrom = %v, want day-truncated %v", claims.ValidFrom, wantDayStart)
	}
	wantValidUntil := wantDayStart.Add(lifetime)
	if !claims.ValidUntil.Equal(wantValidUntil) {
		t.Errorf("ValidUntil = %v, want %v", claims.ValidUntil, wantValidUntil)
	}

	if got := mdocClaimsForRequest("org.iso.18013.5.1.mDL", nil, lifetime); got != nil {
		t.Errorf("mdocClaimsForRequest(nil nameSpaces) = %+v, want nil", got)
	}
}

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
		Claims:                    map[string]any{"given_name": "Jean", "family_name": "Dupont"},
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
	verified, err := mdoc.Verify(signed, cfg.Mdoc.DocType, issuerCert.PublicKey, cose.ES256, mdoc.VerifyOptions{})
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

// TestNewServerMux_KeyAttestationAdvertisedOnBothFormats proves
// addKeyAttestationProofType's own multi-target fix: when both
// cfg.KeyAttestation and cfg.Mdoc are set, the "attestation" proof
// type must appear in credential_issuer metadata for *both*
// CredentialConfigurations, not just the "dc+sd-jwt" one — confirmed
// live as a real gap (the OIDF suite's own
// oid4vci-1_0-issuer-fail-invalid-key-attestation-signature module
// self-SKIPPED against the mso_mdoc CredentialConfiguration until this
// fix, since addKeyAttestationProofType previously only ever mutated
// the "dc+sd-jwt" CredentialConfiguration).
func TestNewServerMux_KeyAttestationAdvertisedOnBothFormats(t *testing.T) {
	cfg := mdocTestConfig(t)
	attestationKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key attestation trust key: %v", err)
	}
	trustedJWK, err := jwk.Marshal(&attestationKey.PublicKey)
	if err != nil {
		t.Fatalf("jwk.Marshal: %v", err)
	}
	trustedJWKRaw, err := json.Marshal(trustedJWK)
	if err != nil {
		t.Fatalf("marshal trusted jwk: %v", err)
	}
	cfg.KeyAttestation = &conformanceconfig.KeyAttestationConfig{TrustedJWK: trustedJWKRaw}

	ts := httptest.NewUnstartedServer(nil)
	cfg.Issuer = "https://" + ts.Listener.Addr().String()
	mux, err := newServerMux(cfg)
	if err != nil {
		t.Fatalf("newServerMux: %v", err)
	}
	ts.Config.Handler = mux
	tlsCert, err := cfg.tlsCertificate()
	if err != nil {
		t.Fatalf("tlsCertificate: %v", err)
	}
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{tlsCert}}
	ts.StartTLS()
	defer ts.Close()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // test-only

	body := getJSON(t, client, ts.URL+"/.well-known/openid-credential-issuer")
	configs, _ := body["credential_configurations_supported"].(map[string]any)

	for _, ccID := range []string{cfg.CredentialConfigurationID, cfg.Mdoc.CredentialConfigurationID} {
		cc, ok := configs[ccID].(map[string]any)
		if !ok {
			t.Fatalf("credential_configurations_supported missing %q: %+v", ccID, configs)
		}
		proofTypes, _ := cc["proof_types_supported"].(map[string]any)
		if _, ok := proofTypes["attestation"]; !ok {
			t.Errorf("%q proof_types_supported missing %q: %+v", ccID, "attestation", proofTypes)
		}
		if _, ok := proofTypes["jwt"]; !ok {
			t.Errorf("%q proof_types_supported missing %q (must stay additive): %+v", ccID, "jwt", proofTypes)
		}
	}
}
