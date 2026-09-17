package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"

	"github.com/idfoundry/oid4vcigo/internal/conformancecert"
)

// run holds everything generated once per invocation: the throwaway
// key material for both cmd/conformance-issuer's own server config and
// the suite's own plan config, built together from the same source so
// the two always agree — see the package doc comment for why this
// replaces the previous manual "copy from the suite's own UI" step.
type run struct {
	alias         string
	issuerBaseURL string

	tlsCertPEM, tlsKeyPEM string

	// attesterKey signs the suite's own dynamically-minted Client
	// Attestation JWTs for both client1 and client2 (one attester
	// identity, shared — confirmed against the suite's own
	// AbstractFAPI2SPFinalServerTestModule.java: client_attestation.attester_jwks/
	// client_attestation.issuer are singular top-level config fields,
	// not per-client). cmd/conformance-issuer's own server config
	// trusts this key's public half for both registered clients.
	// attesterLeafPEM's own x5c must be embedded directly in the JWK
	// entry client_attestation.attester_jwks carries — confirmed live:
	// AbstractSignJWT.java's own "errorIfX5cMissing" path rejects
	// signing the Client Attestation JWT outright ("A x5c entry is
	// required in the client's signing key but isn't present in the
	// configuration") without one, even though cmd/conformance-issuer's
	// own server-side verification (server/client_auth_attestation.go)
	// never looks at x5c at all — this is purely the suite's own
	// HAIP-mandated requirement on what it signs with, independent of
	// what the verifier needs.
	attesterKey     *ecdsa.PrivateKey
	attesterLeafPEM string
	attesterIssuer  string

	client1ID, client2ID                   string
	client1InstanceKey, client2InstanceKey *ecdsa.PrivateKey
	client1RedirectURI, client2RedirectURI string

	credentialIssuerSigningKey  *ecdsa.PrivateKey
	credentialIssuerLeafPEM     string
	credentialIssuerCACertPEM   string
	credentialRequestDecryptPEM string

	// statusListTrustAnchorPEM is required config (HAIP) even though
	// nothing in this battery ever exercises a Status List — confirmed
	// live: "'Status List Trust Anchor' field is missing... It is
	// required for HAIP", the same "required to be present, not to be
	// exercised" pattern as key_attestation_jwks below. Any
	// syntactically valid CA certificate satisfies it.
	statusListTrustAnchorPEM string

	vct                       string
	claims                    map[string]string
	scope                     string
	credentialConfigurationID string
}

func generateRun(alias, issuerBaseURL string) (*run, error) {
	tlsCertPEM, tlsKeyPEM, err := conformancecert.SelfSignedPEM("conformance-issuer", []string{"conformance-issuer", "localhost"})
	if err != nil {
		return nil, fmt.Errorf("generate tls cert: %w", err)
	}

	attesterKey, _, attesterLeafPEM, _, err := conformancecert.GenerateSignerAndCert("run-fapi2sp-battery-attester-leaf", "run-fapi2sp-battery-attester-ca")
	if err != nil {
		return nil, fmt.Errorf("generate attester key: %w", err)
	}

	_, _, statusListTrustAnchorPEM, _, err := conformancecert.GenerateCA("run-fapi2sp-battery-status-list-trust-anchor")
	if err != nil {
		return nil, fmt.Errorf("generate status list trust anchor: %w", err)
	}

	client1InstanceKey, err := generateECKey()
	if err != nil {
		return nil, fmt.Errorf("generate client1 instance key: %w", err)
	}
	client2InstanceKey, err := generateECKey()
	if err != nil {
		return nil, fmt.Errorf("generate client2 instance key: %w", err)
	}

	credentialIssuerSigningKey, _, credentialIssuerLeafPEM, credentialIssuerCACertPEM, err := conformancecert.GenerateSignerAndCert(
		"run-fapi2sp-battery-credential-issuer-leaf", "run-fapi2sp-battery-credential-issuer-ca")
	if err != nil {
		return nil, fmt.Errorf("generate credential issuer key/cert: %w", err)
	}
	credentialRequestDecryptPEM, err := conformancecert.GenerateECKeyPEM()
	if err != nil {
		return nil, fmt.Errorf("generate credential request decryption key: %w", err)
	}

	callback := "https://localhost.emobix.co.uk:8443/test/a/" + alias + "/callback"

	return &run{
		alias:         alias,
		issuerBaseURL: issuerBaseURL,

		tlsCertPEM: tlsCertPEM, tlsKeyPEM: tlsKeyPEM,

		attesterKey:     attesterKey,
		attesterLeafPEM: attesterLeafPEM,
		attesterIssuer:  "https://run-fapi2sp-battery-attester.example.com",

		client1ID: "run-fapi2sp-battery-client-1", client2ID: "run-fapi2sp-battery-client-2",
		client1InstanceKey: client1InstanceKey, client2InstanceKey: client2InstanceKey,
		client1RedirectURI: callback, client2RedirectURI: callback + "?dummy1=lorem&dummy2=ipsum",

		credentialIssuerSigningKey:  credentialIssuerSigningKey,
		credentialIssuerLeafPEM:     credentialIssuerLeafPEM,
		credentialIssuerCACertPEM:   credentialIssuerCACertPEM,
		credentialRequestDecryptPEM: credentialRequestDecryptPEM,

		statusListTrustAnchorPEM: statusListTrustAnchorPEM,

		vct:                       "urn:eudi:pid:1",
		claims:                    map[string]string{"given_name": "Jean", "family_name": "Dupont"},
		scope:                     "IdentityCredential",
		credentialConfigurationID: "IdentityCredential",
	}, nil
}

func generateECKey() (*ecdsa.PrivateKey, error) {
	return conformancecert.ParseECPrivateKeyPEM(mustGenerateECKeyPEM())
}

func mustGenerateECKeyPEM() string {
	pem, err := conformancecert.GenerateECKeyPEM()
	if err != nil {
		panic(err) // conformancecert.GenerateECKeyPEM only fails on rand.Reader exhaustion
	}
	return pem
}

// serverConfig mirrors cmd/conformance-issuer/config.go's own Config/
// ConfigClient JSON shape exactly — duplicated here rather than
// imported, since that binary is package main like this one.
type serverConfig struct {
	ListenAddr                        string             `json:"listen_addr"`
	Issuer                            string             `json:"issuer"`
	TLSCertificatePEM                 string             `json:"tls_certificate_pem"`
	TLSPrivateKeyPEM                  string             `json:"tls_private_key_pem"`
	Client                            serverConfigClient `json:"client"`
	Client2                           serverConfigClient `json:"client2"`
	CredentialIssuerSigningKeyPEM     string             `json:"credential_issuer_signing_key_pem"`
	CredentialIssuerCertificatePEM    string             `json:"credential_issuer_certificate_pem"`
	CredentialRequestDecryptionKeyPEM string             `json:"credential_request_decryption_key_pem"`
	VCT                               string             `json:"vct"`
	Claims                            map[string]string  `json:"claims"`
	Scope                             string             `json:"scope"`
	CredentialConfigurationID         string             `json:"credential_configuration_id"`
	DefaultSubject                    string             `json:"default_subject"`
}

type serverConfigClient struct {
	ID                     string          `json:"id"`
	RedirectURIs           []string        `json:"redirect_uris"`
	ExpectedAttesterIssuer string          `json:"expected_attester_issuer"`
	AttesterJWKS           json.RawMessage `json:"attester_jwks"`
}

// buildServerConfig builds cmd/conformance-issuer's own config.json —
// both registered clients trust the same attester key (see run's own
// doc comment).
func buildServerConfig(r *run) ([]byte, error) {
	attesterPubJWKS, err := conformancecert.JWKSet(&r.attesterKey.PublicKey, "run-fapi2sp-battery-attester-key")
	if err != nil {
		return nil, fmt.Errorf("build attester public jwks: %w", err)
	}

	cfg := serverConfig{
		ListenAddr:        ":8443",
		Issuer:            r.issuerBaseURL,
		TLSCertificatePEM: r.tlsCertPEM,
		TLSPrivateKeyPEM:  r.tlsKeyPEM,
		Client: serverConfigClient{
			ID: r.client1ID, RedirectURIs: []string{r.client1RedirectURI},
			ExpectedAttesterIssuer: r.attesterIssuer, AttesterJWKS: attesterPubJWKS,
		},
		Client2: serverConfigClient{
			ID: r.client2ID, RedirectURIs: []string{r.client2RedirectURI},
			ExpectedAttesterIssuer: r.attesterIssuer, AttesterJWKS: attesterPubJWKS,
		},
		CredentialIssuerSigningKeyPEM:     mustPEMKey(r.credentialIssuerSigningKey),
		CredentialIssuerCertificatePEM:    r.credentialIssuerLeafPEM,
		CredentialRequestDecryptionKeyPEM: r.credentialRequestDecryptPEM,
		VCT:                               r.vct,
		Claims:                            r.claims,
		Scope:                             r.scope,
		CredentialConfigurationID:         r.credentialConfigurationID,
		DefaultSubject:                    "conformance-test-subject",
	}
	return json.MarshalIndent(cfg, "", "  ")
}

func mustPEMKey(key *ecdsa.PrivateKey) string {
	pem, err := conformancecert.ECKeyPEM(key)
	if err != nil {
		panic(err) // ECKeyPEM only fails on malformed input, never on an already-valid *ecdsa.PrivateKey
	}
	return pem
}

// browserBlock/browserTask/overrideEntry mirror the OIDF conformance
// suite's own plan config shape for driving its internal headless
// browser automatically — the exact shape FAPIgo's own
// conformance/server/scripts/setup-config already established and
// proved live against the identical underlying FAPI2SPFinalTestPlan
// module family (see that tool's own writePlanConfig).
type browserTask struct {
	Task     string     `json:"task"`
	Match    string     `json:"match"`
	Optional *bool      `json:"optional,omitempty"`
	Commands [][]string `json:"commands"`
}

type browserBlock struct {
	Match      string        `json:"match"`
	MatchLimit *int          `json:"match-limit,omitempty"`
	Tasks      []browserTask `json:"tasks"`
}

type overrideEntry struct {
	Browser []browserBlock `json:"browser,omitempty"`
}

// buildPlanConfig builds the suite-side plan config for the HAIP
// issuer test plan — see the package doc comment for the overall
// shape, and CreateClientAttestationJwt.java/CreateClientAttestationProofJwt.java
// for exactly which fields each of client.client_instance_key/
// client.client_instance_key_public/client_attestation.attester_jwks/
// client_attestation.issuer feeds.
func buildPlanConfig(r *run) ([]byte, error) {
	client1InstanceKeyPriv, err := privateJWKRaw(r.client1InstanceKey)
	if err != nil {
		return nil, fmt.Errorf("build client1 instance key: %w", err)
	}
	client1InstanceKeyPub, err := publicJWK(&r.client1InstanceKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("build client1 instance public key: %w", err)
	}
	client2InstanceKeyPriv, err := privateJWKRaw(r.client2InstanceKey)
	if err != nil {
		return nil, fmt.Errorf("build client2 instance key: %w", err)
	}
	client2InstanceKeyPub, err := publicJWK(&r.client2InstanceKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("build client2 instance public key: %w", err)
	}
	attesterPrivJWKS, err := privateJWKSet(r.attesterKey, "run-fapi2sp-battery-attester-key", r.attesterLeafPEM)
	if err != nil {
		return nil, fmt.Errorf("build attester private jwks: %w", err)
	}
	// key_attestation_jwks is required config even though nothing in
	// this battery ever presents a Key Attestation proof (HAIP §4.5.1,
	// a distinct requirement from Wallet Attestation client auth) — an
	// empty key set satisfies the suite's own presence check without
	// claiming to support something this battery never exercises.
	keyAttestationJWKS := json.RawMessage(`{"keys":[]}`)

	authorizeURL := "https://conformance-issuer:8443/authorize*"
	trueVal := true
	one := 1
	consentTask := browserTask{
		Task: "Consent", Match: authorizeURL, Optional: &trueVal,
		Commands: [][]string{{"click", "xpath", "//button[@name='decision' and @value='approve']", "optional"}},
	}
	consentBlock := browserBlock{Match: authorizeURL, Tasks: []browserTask{consentTask}}

	plan := map[string]any{
		"alias": r.alias,
		"client": map[string]any{
			"client_id":                  r.client1ID,
			"client_instance_key":        json.RawMessage(client1InstanceKeyPriv),
			"client_instance_key_public": json.RawMessage(client1InstanceKeyPub),
		},
		"client2": map[string]any{
			"client_id":                  r.client2ID,
			"client_instance_key":        json.RawMessage(client2InstanceKeyPriv),
			"client_instance_key_public": json.RawMessage(client2InstanceKeyPub),
		},
		"client_attestation": map[string]any{
			"issuer":               r.attesterIssuer,
			"attester_jwks":        json.RawMessage(attesterPrivJWKS),
			"key_attestation_jwks": keyAttestationJWKS,
		},
		"vci": map[string]any{
			"credential_issuer_url":       r.issuerBaseURL,
			"credential_configuration_id": r.credentialConfigurationID,
			"credential_proof_type_hint":  "jwt",
		},
		"credential": map[string]any{
			"trust_anchor_pem":             r.credentialIssuerCACertPEM,
			"status_list_trust_anchor_pem": r.statusListTrustAnchorPEM,
		},
		"browser": []browserBlock{consentBlock},
		"override": map[string]overrideEntry{
			"fapi2-security-profile-final-user-rejects-authentication": {
				Browser: []browserBlock{{
					Match: authorizeURL,
					Tasks: []browserTask{{
						Task: "Deny", Match: authorizeURL,
						Commands: [][]string{{"click", "xpath", "//button[@name='decision' and @value='deny']", "optional"}},
					}},
				}},
			},
			"fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds": {
				Browser: []browserBlock{
					{Match: authorizeURL, MatchLimit: &one, Tasks: []browserTask{}},
					consentBlock,
				},
			},
		},
		"options": map[string]any{
			"browsercontrol_css_enable": false,
		},
	}
	return json.Marshal(plan)
}
