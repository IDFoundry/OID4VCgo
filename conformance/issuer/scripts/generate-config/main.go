// Command generate-config writes a throwaway conformance-issuer
// config.json: a fresh self-signed TLS listener cert and a fresh
// EC P-256 credential-issuer signing key. Mirrors
// conformance/verifier(/wallet-vp)/scripts/generate-config.
//
// The one test client's own client_id/redirect_uris/
// expected_attester_issuer/attester_jwks are left as placeholders —
// fill them in from whatever the OIDF suite's own test-configuration
// UI assigns for this plan (see conformance/issuer/README.md).
// attester_jwks is the suite's own attester identity's public key(s)
// — fapigo/server resolves a Client Attestation JWT's own verification
// key this way regardless of ExpectedAttesterIssuer (confirmed against
// server/client_auth_attestation.go's own resolveClientKey call), so
// both fields are required, not just the issuer string.
//
// Usage: go run ./conformance/issuer/scripts/generate-config \
//
//	-issuer=https://conformance-issuer:8443 \
//	-out=conformance/issuer/oidf-config/haip.config.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/idfoundry/oid4vcigo/internal/conformancecert"
)

type generatedConfig struct {
	ListenAddr                    string            `json:"listen_addr"`
	Issuer                        string            `json:"issuer"`
	TLSCertificatePEM             string            `json:"tls_certificate_pem"`
	TLSPrivateKeyPEM              string            `json:"tls_private_key_pem"`
	Client                        generatedClient   `json:"client"`
	CredentialIssuerSigningKeyPEM string            `json:"credential_issuer_signing_key_pem"`
	VCT                           string            `json:"vct"`
	Claims                        map[string]string `json:"claims"`
	Scope                         string            `json:"scope"`
	CredentialConfigurationID     string            `json:"credential_configuration_id"`
	DefaultSubject                string            `json:"default_subject"`
}

type generatedClient struct {
	ID                     string          `json:"id"`
	RedirectURIs           []string        `json:"redirect_uris"`
	ExpectedAttesterIssuer string          `json:"expected_attester_issuer"`
	AttesterJWKS           json.RawMessage `json:"attester_jwks"`
}

func main() {
	issuerURL := flag.String("issuer", "https://conformance-issuer:8443", "this binary's own externally-reachable base URL")
	dnsName := flag.String("dns-name", "conformance-issuer", "DNS name for the TLS listener cert's SAN")
	out := flag.String("out", "", "path to write the generated config.json to (default: stdout)")
	flag.Parse()

	tlsCert, tlsKey, err := conformancecert.SelfSignedPEM("conformance-issuer", []string{*dnsName, "localhost"})
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate tls cert:", err)
		os.Exit(1)
	}
	issuerKeyPEM, err := conformancecert.GenerateECKeyPEM()
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate credential issuer signing key:", err)
		os.Exit(1)
	}

	cfg := generatedConfig{
		ListenAddr:        ":8443",
		Issuer:            *issuerURL,
		TLSCertificatePEM: tlsCert,
		TLSPrivateKeyPEM:  tlsKey,
		Client: generatedClient{
			ID:                     "PLACEHOLDER-fill-in-from-the-suite",
			RedirectURIs:           []string{"https://PLACEHOLDER-fill-in-from-the-suite/callback"},
			ExpectedAttesterIssuer: "https://PLACEHOLDER-fill-in-from-the-suite",
			AttesterJWKS:           json.RawMessage(`{"keys":[]}`),
		},
		CredentialIssuerSigningKeyPEM: issuerKeyPEM,
		VCT:                           "urn:eudi:pid:1",
		Claims:                        map[string]string{"given_name": "Jean", "family_name": "Dupont"},
		Scope:                         "IdentityCredential",
		CredentialConfigurationID:     "IdentityCredential",
		DefaultSubject:                "conformance-test-subject",
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal config:", err)
		os.Exit(1)
	}

	if *out == "" {
		fmt.Println(string(raw))
		return
	}
	if err := os.WriteFile(*out, raw, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "write config:", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "wrote", *out)
}
