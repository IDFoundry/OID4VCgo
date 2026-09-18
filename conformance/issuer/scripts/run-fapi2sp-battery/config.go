package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"

	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/internal/conformanceconfig"
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
	// required for HAIP". Any syntactically valid CA certificate
	// satisfies it.
	statusListTrustAnchorPEM string

	// keyAttestationKey signs the suite's own dynamically-minted Key
	// Attestation JWTs (Appendix D.1) — its public half is what
	// cmd/conformance-issuer's own KeyAttestationConfig.TrustedJWK
	// trusts (buildServerConfig), and its private half is what the
	// suite's own key_attestation_jwks plan-config field needs
	// (buildPlanConfig) so it can actually sign one. Used by
	// oid4vci-1_0-issuer-fail-invalid-key-attestation-signature (and,
	// as a positive sanity check, happy-flow under
	// -credential-proof-type-hint=attestation).
	// keyAttestationLeafPEM's own x5c must be embedded in
	// key_attestation_jwks the same way attesterLeafPEM's is for
	// client_attestation.attester_jwks — confirmed live:
	// AbstractSignJWT.java's own "errorIfX5cMissing" path rejects
	// signing a Key Attestation JWT outright too ("A x5c entry is
	// required in the client's signing key but isn't present in the
	// configuration", requirements HAIPA-D.1/OID4VCI-1FINALA-D.1),
	// even though cmd/conformance-issuer's own AttestationVerifier
	// never looks at x5c — this repo's own KeyAttestationConfig.TrustedJWK
	// is a bare public JWK, matching how server-side client-attestation
	// verification already ignores x5c too.
	keyAttestationKey     *ecdsa.PrivateKey
	keyAttestationLeafPEM string

	vct                       string
	claims                    map[string]string
	scope                     string
	credentialConfigurationID string

	// mdoc* mirror vct/claims/scope/credentialConfigurationID above for
	// a second, mso_mdoc-format CredentialConfiguration — always
	// generated and included in the server config (cheap, and keeps
	// cmd/conformance-issuer's own behavior identical for every already-
	// passing sd_jwt_vc-format module), selected via -credential-format
	// mdoc at plan-creation time (buildPlanConfig's own credentialFormat
	// parameter).
	mdocCredentialConfigurationID string
	mdocDocType                   string
	mdocNamespace                 string
	mdocClaims                    map[string]any
	mdocScope                     string

	// mdocSignerKeyPEM/mdocSignerCertPEM/mdocIACACertPEM are the mdoc
	// CredentialConfiguration's own dedicated ISO/IEC 18013-5 Annex B
	// Document Signer identity (internal/conformancecert.GenerateMdocIACA/
	// GenerateMdocDocumentSigner) — separate from
	// credentialIssuerSigningKey/credentialIssuerLeafPEM above, which
	// stays exactly as it was (used only by the sd_jwt_vc-format
	// CredentialConfiguration). mdocIACACertPEM is threaded into
	// buildPlanConfig's own "credential.trust_anchor_pem" field
	// specifically for the mdoc-format invocation (buildPlanConfig's
	// own credentialFormat parameter) — the sd_jwt_vc-format invocation
	// keeps trusting credentialIssuerCACertPEM instead, since it never
	// requests an mdoc credential and so never validates this chain.
	mdocSignerKeyPEM  string
	mdocSignerCertPEM string
	mdocIACACertPEM   string
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

	keyAttestationKey, _, keyAttestationLeafPEM, _, err := conformancecert.GenerateSignerAndCert(
		"run-fapi2sp-battery-key-attestation-leaf", "run-fapi2sp-battery-key-attestation-ca")
	if err != nil {
		return nil, fmt.Errorf("generate key attestation key: %w", err)
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

	mdocIACACert, mdocIACAKey, mdocIACACertPEM, _, err := conformancecert.GenerateMdocIACA(
		"run-fapi2sp-battery-mdoc-iaca", "FR", "https://example.com/run-fapi2sp-battery-mdoc-contact")
	if err != nil {
		return nil, fmt.Errorf("generate mdoc iaca: %w", err)
	}
	_, mdocSignerKeyPEM, mdocSignerCertPEM, err := conformancecert.GenerateMdocDocumentSigner(
		"run-fapi2sp-battery-mdoc-ds", "FR", "https://example.com/run-fapi2sp-battery-mdoc-contact",
		"https://example.com/run-fapi2sp-battery-mdoc.crl", mdocIACACert, mdocIACAKey)
	if err != nil {
		return nil, fmt.Errorf("generate mdoc document signer: %w", err)
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
		keyAttestationKey:        keyAttestationKey,
		keyAttestationLeafPEM:    keyAttestationLeafPEM,

		vct:                       "urn:eudi:pid:1",
		claims:                    map[string]string{"given_name": "Jean", "family_name": "Dupont"},
		scope:                     "IdentityCredential",
		credentialConfigurationID: "IdentityCredential",

		// org.iso.18013.5.1.mDL / org.iso.18013.5.1: a real mDL, not a
		// PID-shaped stand-in — the suite's own
		// EnsureMdocMdlMandatoryDataElementsPresent check applies only
		// to this literal doctype string, and checks it against ISO/IEC
		// 18013-5 §7.2.1 Table 5's own mandatory-element list (confirmed
		// directly against the local draft spec's Table 20, cross-
		// referenced to the same published-edition table number in the
		// spec's own text). All 11 mandatory (Presence=M) elements are
		// populated below so that check now genuinely passes, rather
		// than being sidestepped by a doctype the check doesn't apply
		// to. birth_date/issue_date/expiry_date and portrait need
		// mdocNameSpaceElementsFor's own read-side reinterpretation
		// (full-date CBOR tag, base64 decode) — see that function's own
		// doc comment.
		mdocCredentialConfigurationID: "MobileDrivingLicence",
		mdocDocType:                   "org.iso.18013.5.1.mDL",
		mdocNamespace:                 "org.iso.18013.5.1",
		mdocClaims: map[string]any{
			"family_name":       "Dupont",
			"given_name":        "Jean",
			"birth_date":        "1990-01-01",
			"issue_date":        "2024-01-01",
			"expiry_date":       "2034-01-01",
			"issuing_country":   "FR",
			"issuing_authority": "Prefecture de Police",
			"document_number":   "123456789",
			// Not a real decodable image — a placeholder bstr value,
			// same spirit as the placeholder Jean/Dupont names above.
			"portrait": []byte("run-fapi2sp-battery-placeholder-portrait"),
			"driving_privileges": []map[string]any{
				{"vehicle_category_code": "B"},
			},
			"un_distinguishing_sign": "F",
		},
		mdocScope: "MobileDrivingLicence",

		mdocSignerKeyPEM:  mdocSignerKeyPEM,
		mdocSignerCertPEM: mdocSignerCertPEM,
		mdocIACACertPEM:   mdocIACACertPEM,
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
	ListenAddr                        string                                  `json:"listen_addr"`
	Issuer                            string                                  `json:"issuer"`
	TLSCertificatePEM                 string                                  `json:"tls_certificate_pem"`
	TLSPrivateKeyPEM                  string                                  `json:"tls_private_key_pem"`
	Client                            serverConfigClient                      `json:"client"`
	Client2                           serverConfigClient                      `json:"client2"`
	CredentialIssuerSigningKeyPEM     string                                  `json:"credential_issuer_signing_key_pem"`
	CredentialIssuerCertificatePEM    string                                  `json:"credential_issuer_certificate_pem"`
	CredentialRequestDecryptionKeyPEM string                                  `json:"credential_request_decryption_key_pem"`
	VCT                               string                                  `json:"vct"`
	Claims                            map[string]string                       `json:"claims"`
	Scope                             string                                  `json:"scope"`
	CredentialConfigurationID         string                                  `json:"credential_configuration_id"`
	DefaultSubject                    string                                  `json:"default_subject"`
	Mdoc                              *conformanceconfig.MdocConfig           `json:"mdoc,omitempty"`
	KeyAttestation                    *conformanceconfig.KeyAttestationConfig `json:"key_attestation,omitempty"`
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
	keyAttestationTrustedJWK, err := publicJWK(&r.keyAttestationKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("build key attestation trusted jwk: %w", err)
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
		Mdoc: &conformanceconfig.MdocConfig{
			CredentialConfigurationID: r.mdocCredentialConfigurationID,
			DocType:                   r.mdocDocType,
			Namespace:                 r.mdocNamespace,
			Claims:                    r.mdocClaims,
			Scope:                     r.mdocScope,
			SignerKeyPEM:              r.mdocSignerKeyPEM,
			CertificatePEM:            r.mdocSignerCertPEM,
			TrustAnchorCertificatePEM: r.mdocIACACertPEM,
		},
		KeyAttestation: &conformanceconfig.KeyAttestationConfig{
			TrustedJWK: json.RawMessage(keyAttestationTrustedJWK),
		},
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
// buildPlanConfig builds the suite-side plan config for credentialFormat
// ("sd_jwt_vc" or "mdoc") — the plan's own vci.credential_configuration_id
// selects whichever CredentialConfiguration cmd/conformance-issuer's own
// server config (buildServerConfig, always generated with both) actually
// advertises for that format. proofTypeHint sets vci.credential_proof_type_hint
// ("jwt" for every module except the keyAttestationBattery, which needs
// "attestation" — see main.go's own -credential-proof-type-hint flag).
func buildPlanConfig(r *run, credentialFormat, proofTypeHint string) ([]byte, error) {
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
	// key_attestation_jwks is the suite's own signer for the Key
	// Attestation JWTs it mints when driving under
	// -credential-proof-type-hint=attestation (HAIP §4.5.1, a distinct
	// requirement from Wallet Attestation client auth) —
	// cmd/conformance-issuer's own KeyAttestationConfig.TrustedJWK
	// trusts this same key's public half (buildServerConfig).
	keyAttestationJWKS, err := privateJWKSet(r.keyAttestationKey, "run-fapi2sp-battery-key-attestation-key", r.keyAttestationLeafPEM)
	if err != nil {
		return nil, fmt.Errorf("build key attestation private jwks: %w", err)
	}

	credentialConfigurationID := r.credentialConfigurationID
	trustAnchorPEM := r.credentialIssuerCACertPEM
	if credentialFormat == "mdoc" {
		credentialConfigurationID = r.mdocCredentialConfigurationID
		// The mdoc CredentialConfiguration is signed by a dedicated
		// ISO/IEC 18013-5 Annex B Document Signer identity (run's own
		// mdocSignerKeyPEM/mdocSignerCertPEM doc comment) — the suite
		// must trust that chain's own IACA root, not the shared
		// sd_jwt_vc-format issuer CA, to validate it.
		trustAnchorPEM = r.mdocIACACertPEM
	}

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
			"credential_configuration_id": credentialConfigurationID,
			"credential_proof_type_hint":  proofTypeHint,
		},
		"credential": map[string]any{
			"trust_anchor_pem":             trustAnchorPEM,
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
