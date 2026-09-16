// Command generate-config writes a throwaway conformance-wallet-vp
// config.json: a fresh self-signed TLS listener cert, a fresh EC
// P-256 credential-issuer key (signs the fixture SD-JWT VC — see
// conformance/wallet-vp/README.md for what to paste into the OIDF
// suite's own credential-trust test configuration, not yet confirmed
// against a live suite instance), and a fresh EC P-256 Holder Binding
// key. Mirrors conformance/verifier/scripts/generate-config.
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

	"github.com/idfoundry/oid4vcigo/internal/conformancecert"
)

type generatedConfig struct {
	ListenAddr                    string            `json:"listen_addr"`
	TLSCertificatePEM             string            `json:"tls_certificate_pem"`
	TLSPrivateKeyPEM              string            `json:"tls_private_key_pem"`
	CredentialIssuerPrivateKeyPEM string            `json:"credential_issuer_private_key_pem"`
	HolderPrivateKeyPEM           string            `json:"holder_private_key_pem"`
	VCT                           string            `json:"vct"`
	Claims                        map[string]string `json:"claims"`
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
	issuerKeyPEM, err := conformancecert.GenerateECKeyPEM()
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate credential issuer key:", err)
		os.Exit(1)
	}
	holderKeyPEM, err := conformancecert.GenerateECKeyPEM()
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate holder key:", err)
		os.Exit(1)
	}

	cfg := generatedConfig{
		ListenAddr:                    ":8443",
		TLSCertificatePEM:             tlsCert,
		TLSPrivateKeyPEM:              tlsKey,
		CredentialIssuerPrivateKeyPEM: issuerKeyPEM,
		HolderPrivateKeyPEM:           holderKeyPEM,
		VCT:                           "urn:eudi:pid:1",
		Claims:                        map[string]string{"given_name": "Jean", "family_name": "Dupont"},
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
