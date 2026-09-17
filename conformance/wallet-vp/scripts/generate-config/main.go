// Command generate-config writes a throwaway conformance-wallet-vp
// config.json: a fresh self-signed TLS listener cert, a fresh EC
// P-256 credential-issuer key plus a leaf certificate wrapping it
// issued under a fresh throwaway CA (the CA's own PEM is what to paste
// into the OIDF suite's own credential-trust test configuration,
// "credential.trust_anchor_pem" — confirmed live: the suite's own SD-
// JWT VC x5c check rejects a self-signed leaf outright, "Leaf
// certificate in x5c chain must not be self-signed"), and a fresh EC
// P-256 Holder Binding key. Mirrors
// conformance/verifier/scripts/generate-config.
//
// Usage: go run ./conformance/wallet-vp/scripts/generate-config \
//
//	-out=conformance/wallet-vp/oidf-config/haip.config.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
)

type generatedConfig struct {
	ListenAddr                     string            `json:"listen_addr"`
	TLSCertificatePEM              string            `json:"tls_certificate_pem"`
	TLSPrivateKeyPEM               string            `json:"tls_private_key_pem"`
	CredentialIssuerPrivateKeyPEM  string            `json:"credential_issuer_private_key_pem"`
	CredentialIssuerCertificatePEM string            `json:"credential_issuer_certificate_pem"`
	HolderPrivateKeyPEM            string            `json:"holder_private_key_pem"`
	VCT                            string            `json:"vct"`
	Claims                         map[string]string `json:"claims"`
}

func main() {
	dnsName := flag.String("dns-name", "conformance-wallet-vp", "DNS name for the TLS listener cert's SAN")
	out := flag.String("out", "", "path to write the generated config.json to (default: stdout)")
	flag.Parse()

	tlsCert, tlsKey, err := conformancecert.SelfSignedPEM("conformance-wallet-vp", []string{*dnsName, "localhost"})
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate tls cert:", err)
		os.Exit(1)
	}
	_, issuerKeyPEM, issuerCertPEM, caCertPEM, err := conformancecert.GenerateSignerAndCert(
		"conformance-wallet-vp-credential-issuer", "conformance-wallet-vp-credential-issuer-ca")
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate credential issuer key/certificate:", err)
		os.Exit(1)
	}
	holderKeyPEM, err := conformancecert.GenerateECKeyPEM()
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate holder key:", err)
		os.Exit(1)
	}

	cfg := generatedConfig{
		ListenAddr:                     ":8443",
		TLSCertificatePEM:              tlsCert,
		TLSPrivateKeyPEM:               tlsKey,
		CredentialIssuerPrivateKeyPEM:  issuerKeyPEM,
		CredentialIssuerCertificatePEM: issuerCertPEM,
		HolderPrivateKeyPEM:            holderKeyPEM,
		VCT:                            "urn:eudi:pid:1",
		Claims:                         map[string]string{"given_name": "Jean", "family_name": "Dupont"},
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

	fmt.Fprintln(os.Stderr, "\nPaste this CA certificate into the OIDF suite's own")
	fmt.Fprintln(os.Stderr, "\"credential.trust_anchor_pem\" test-configuration field — it signed")
	fmt.Fprintln(os.Stderr, "the leaf certificate embedded in this binary's own fixture SD-JWT")
	fmt.Fprintln(os.Stderr, "VC's own \"x5c\" header (the leaf itself must not be self-signed):")
	fmt.Fprint(os.Stderr, caCertPEM)
}
