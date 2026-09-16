// Command generate-config writes a throwaway conformance-verifier
// config.json: a fresh self-signed TLS listener cert, a fresh
// self-signed OID4VP Client Identifier cert (its SHA-256 hash becomes
// the x509_hash Client ID), and a fresh EC P-256 keypair for the
// "credential issuer" — paste that keypair's public JWK into the OIDF
// suite's own test-configuration UI under "Credential Issuer" >
// "Signing JWK" (matching AbstractCreateSdJwtCredential.createSdJwt's
// own createSdJwt in the suite's source, confirmed against
// gitlab.com/openid/conformance-suite) so the suite signs its emulated
// test credentials with the same key this binary is told to trust.
//
// Usage: go run ./conformance/verifier/scripts/generate-config \
//
//	-base-url=https://conformance-verifier:8443 \
//	-out=conformance/verifier/oidf-config/haip.config.json
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/idfoundry/oid4vcigo/internal/conformancecert"
	"github.com/idfoundry/oid4vcigo/internal/jwk"
)

// privateJWK embeds jwk.Marshal's own public-only shape plus the "d"
// (private key) member the OIDF suite's own "Credential Issuer" >
// "Signing JWK" field needs — internal/jwk deliberately never
// marshals a private key itself (nothing in the shipped packages needs
// to), so this stays local to this one throwaway generator, the same
// "embed jwk.JWK + extra fields locally" pattern
// verifier/authorization_request.go's own responseEncryptionJWK
// already establishes.
type privateJWK struct {
	jwk.JWK
	D   string `json:"d"`
	Alg string `json:"alg"`
}

type generatedConfig struct {
	ListenAddr           string          `json:"listen_addr"`
	BaseURL              string          `json:"base_url"`
	TLSCertificatePEM    string          `json:"tls_certificate_pem"`
	TLSPrivateKeyPEM     string          `json:"tls_private_key_pem"`
	ClientCertificatePEM string          `json:"client_certificate_pem"`
	ClientPrivateKeyPEM  string          `json:"client_private_key_pem"`
	CredentialIssuerJWK  json.RawMessage `json:"credential_issuer_jwk"`
	VCT                  string          `json:"vct"`
	Claims               []string        `json:"claims"`
}

func main() {
	baseURL := flag.String("base-url", "https://conformance-verifier:8443", "this binary's own externally-reachable base URL")
	dnsNames := flag.String("dns-name", "conformance-verifier", "DNS name for the TLS listener cert's SAN (repeat -dns-name for more than one)")
	out := flag.String("out", "", "path to write the generated config.json to (default: stdout)")
	flag.Parse()

	tlsCert, tlsKey, err := conformancecert.SelfSignedPEM("conformance-verifier", []string{*dnsNames, "localhost"})
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate tls cert:", err)
		os.Exit(1)
	}
	clientCert, clientKey, err := conformancecert.SelfSignedPEM("conformance-verifier-client", nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate client cert:", err)
		os.Exit(1)
	}

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate credential issuer key:", err)
		os.Exit(1)
	}
	issuerJWK, err := jwk.Marshal(&issuerKey.PublicKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal credential issuer jwk:", err)
		os.Exit(1)
	}
	issuerJWKRaw, err := json.Marshal(issuerJWK)
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal credential issuer jwk:", err)
		os.Exit(1)
	}
	issuerKeyBytes, err := issuerKey.Bytes()
	if err != nil {
		fmt.Fprintln(os.Stderr, "encode credential issuer private key:", err)
		os.Exit(1)
	}
	issuerPrivateJWK := privateJWK{JWK: issuerJWK, D: base64.RawURLEncoding.EncodeToString(issuerKeyBytes), Alg: "ES256"}
	issuerPrivateJWKRaw, err := json.MarshalIndent(issuerPrivateJWK, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal credential issuer private jwk:", err)
		os.Exit(1)
	}

	cfg := generatedConfig{
		ListenAddr:           ":8443",
		BaseURL:              *baseURL,
		TLSCertificatePEM:    tlsCert,
		TLSPrivateKeyPEM:     tlsKey,
		ClientCertificatePEM: clientCert,
		ClientPrivateKeyPEM:  clientKey,
		CredentialIssuerJWK:  issuerJWKRaw,
		VCT:                  "urn:eudi:pid:1",
		Claims:               []string{"given_name", "family_name"},
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal config:", err)
		os.Exit(1)
	}

	if *out == "" {
		fmt.Println(string(raw))
	} else {
		if err := os.WriteFile(*out, raw, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "write config:", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "wrote", *out)
	}

	fmt.Fprintln(os.Stderr, "\nPaste this JWK into the OIDF suite's own \"Credential Issuer\" >")
	fmt.Fprintln(os.Stderr, "\"Signing JWK\" test-configuration field (it signs the suite's own")
	fmt.Fprintln(os.Stderr, "emulated test credentials with it) — its public half is already")
	fmt.Fprintln(os.Stderr, "embedded in the generated config.json as credential_issuer_jwk:")
	fmt.Fprintln(os.Stderr, string(issuerPrivateJWKRaw))
}
