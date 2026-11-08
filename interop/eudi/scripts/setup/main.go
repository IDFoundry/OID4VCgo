// Command setup writes the throwaway key material and configs for
// interop/eudi/run-verifier.sh: cmd/conformance-wallet-vp configs for
// an SD-JWT VC and an mdoc fixture credential, the EUDI Verifier
// Endpoint's Access Certificate (its Request Object signing key, a
// leaf under a CA the wallet is told to trust), the verifier's TLS
// listener certificate, and unrelated CAs for the controls.
//
// Usage: go run ./interop/eudi/scripts/setup -out DIR
//
// DIR receives:
//
//	wallet-sdjwt.json, wallet-mdoc.json  the wallet's configs
//	issuer-ca.pem, iaca.pem              the credentials' trust anchors
//	other-ca.pem                         an unrelated CA
//	verifier-key.pem, verifier-chain.pem the Access Certificate's key and chain (leaf first)
//	verifier-ca.pem                      the CA the wallet trusts for the verifier
//	tls-cert.pem, tls-key.pem            the verifier's TLS listener
//	registration-certificate.jws         a Relying Party registration certificate for the verifier
package main

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// walletConfig is the subset of cmd/conformance-wallet-vp's Config
// this run sets.
type walletConfig struct {
	ListenAddr                     string         `json:"listen_addr"`
	TLSCertificatePEM              string         `json:"tls_certificate_pem"`
	TLSPrivateKeyPEM               string         `json:"tls_private_key_pem"`
	VerifierTrustAnchorsPEM        string         `json:"verifier_trust_anchors_pem"`
	HolderPrivateKeyPEM            string         `json:"holder_private_key_pem"`
	CredentialIssuerPrivateKeyPEM  string         `json:"credential_issuer_private_key_pem,omitempty"`
	CredentialIssuerCertificatePEM string         `json:"credential_issuer_certificate_pem,omitempty"`
	VCT                            string         `json:"vct,omitempty"`
	Claims                         map[string]any `json:"claims,omitempty"`
	CredentialFormat               string         `json:"credential_format,omitempty"`
	MdocIssuerPrivateKeyPEM        string         `json:"mdoc_issuer_private_key_pem,omitempty"`
	MdocIssuerCertificatePEM       string         `json:"mdoc_issuer_certificate_pem,omitempty"`
	MdocDocType                    string         `json:"mdoc_doc_type,omitempty"`
	MdocNamespace                  string         `json:"mdoc_namespace,omitempty"`
	MdocClaims                     map[string]any `json:"mdoc_claims,omitempty"`
}

// The EUDI PID, in both formats: the type the EUDI verifier's own
// examples ask for.
const (
	pidVCT       = "urn:eudi:pid:1"
	pidDocType   = "eu.europa.ec.eudi.pid.1"
	pidNamespace = "eu.europa.ec.eudi.pid.1"
	contactURI   = "https://example.com/oid4vcgo-eudi-interop"
)

var pidClaims = map[string]any{
	"given_name":        "Jean",
	"family_name":       "Dupont",
	"birth_date":        "1990-01-01",
	"nationalities":     []any{"FR"},
	"issuing_country":   "FR",
	"issuing_authority": "OID4VCgo interop test authority",
}

func main() {
	out := flag.String("out", "", "directory to write into")
	flag.Parse()
	if *out == "" {
		fail("-out is required")
	}
	if err := run(*out); err != nil {
		fail(err.Error())
	}
}

func run(dir string) error {
	files := map[string]string{}

	// The verifier's Access Certificate: EUDI refuses a self-signed one.
	verifierKey, verifierKeyPEM, verifierCertPEM, verifierCAPEM, err := conformancecert.GenerateSignerAndCert(
		"oid4vcgo-eudi-interop-verifier", "oid4vcgo-eudi-interop-verifier-ca")
	if err != nil {
		return fmt.Errorf("verifier access certificate: %w", err)
	}
	files["verifier-key.pem"] = verifierKeyPEM
	files["verifier-chain.pem"] = verifierCertPEM + verifierCAPEM
	files["verifier-ca.pem"] = verifierCAPEM
	rc, err := registrationCertificate(verifierKey, verifierCertPEM)
	if err != nil {
		return fmt.Errorf("registration certificate: %w", err)
	}
	files["registration-certificate.jws"] = rc

	tlsCertPEM, tlsKeyPEM, err := conformancecert.SelfSignedPEM("localhost", []string{"localhost"})
	if err != nil {
		return fmt.Errorf("verifier tls certificate: %w", err)
	}
	files["tls-cert.pem"] = tlsCertPEM
	files["tls-key.pem"] = tlsKeyPEM

	_, _, otherCAPEM, _, err := conformancecert.GenerateCA("oid4vcgo-eudi-interop-unrelated-ca")
	if err != nil {
		return fmt.Errorf("unrelated ca: %w", err)
	}
	files["other-ca.pem"] = otherCAPEM

	base, err := baseWalletConfig(verifierCAPEM)
	if err != nil {
		return err
	}

	sdjwt := base
	_, issuerKeyPEM, issuerCertPEM, issuerCAPEM, err := conformancecert.GenerateSignerAndCert(
		"oid4vcgo-eudi-interop-issuer", "oid4vcgo-eudi-interop-issuer-ca")
	if err != nil {
		return fmt.Errorf("credential issuer: %w", err)
	}
	sdjwt.CredentialIssuerPrivateKeyPEM = issuerKeyPEM
	sdjwt.CredentialIssuerCertificatePEM = issuerCertPEM
	sdjwt.VCT = pidVCT
	sdjwt.Claims = pidClaims
	files["issuer-ca.pem"] = issuerCAPEM

	mdoc := base
	iacaCert, iacaKey, iacaPEM, _, err := conformancecert.GenerateMdocIACA("oid4vcgo-eudi-interop-iaca", "FR", contactURI)
	if err != nil {
		return fmt.Errorf("mdoc iaca: %w", err)
	}
	_, dsKeyPEM, dsCertPEM, err := conformancecert.GenerateMdocDocumentSigner("oid4vcgo-eudi-interop-ds", "FR", contactURI,
		contactURI+"/crl", iacaCert, iacaKey)
	if err != nil {
		return fmt.Errorf("mdoc document signer: %w", err)
	}
	mdoc.CredentialFormat = "mso_mdoc"
	mdoc.MdocIssuerPrivateKeyPEM = dsKeyPEM
	mdoc.MdocIssuerCertificatePEM = dsCertPEM
	mdoc.MdocDocType = pidDocType
	mdoc.MdocNamespace = pidNamespace
	mdoc.MdocClaims = pidClaims
	files["iaca.pem"] = iacaPEM

	for name, cfg := range map[string]walletConfig{"wallet-sdjwt.json": sdjwt, "wallet-mdoc.json": mdoc} {
		raw, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return err
		}
		files[name] = string(raw)
	}
	for name, content := range files {
		// Throwaway material, read by containers running as other users.
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil { // #nosec G306 -- throwaway, per-run key material
			return err
		}
	}
	return nil
}

// registrationCertificate is a Wallet Relying Party Registration
// Certificate (an rc-wrp+jwt) for the verifier, signed with its Access
// Certificate's key: the EUDI verifier puts one in every request and
// refuses a transaction without one. Its contents are illustrative.
func registrationCertificate(key *ecdsa.PrivateKey, certPEM string) (string, error) {
	cert, err := conformancecert.ParseCertificatePEM(certPEM)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(map[string]any{
		"name":         "OID4VCgo EUDI interop verifier",
		"sub":          "LEIXG-OID4VCGO-INTEROP",
		"country":      "EU",
		"entitlements": []string{"https://uri.etsi.org/19475/Entitlement/Service_Provider"},
		"purpose":      []map[string]string{{"lang": "en", "value": "Interoperability testing"}},
		"credentials": []map[string]any{
			{"format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []string{pidVCT}}},
			{"format": "mso_mdoc", "meta": map[string]any{"doctype_value": pidDocType}},
		},
		"iat": time.Now().Unix(),
	})
	if err != nil {
		return "", err
	}
	return jose.Sign(jose.ES256, key, map[string]any{
		"typ": "rc-wrp+jwt",
		"x5c": []string{base64.StdEncoding.EncodeToString(cert.Raw)},
	}, payload)
}

// baseWalletConfig is what both wallet configs share: the listener,
// the holder key and the verifier's trust anchor.
func baseWalletConfig(verifierCAPEM string) (walletConfig, error) {
	tlsCertPEM, tlsKeyPEM, err := conformancecert.SelfSignedPEM("conformance-wallet-vp", []string{"localhost"})
	if err != nil {
		return walletConfig{}, fmt.Errorf("wallet tls certificate: %w", err)
	}
	holderKeyPEM, err := conformancecert.GenerateECKeyPEM()
	if err != nil {
		return walletConfig{}, fmt.Errorf("holder key: %w", err)
	}
	return walletConfig{
		ListenAddr:              "127.0.0.1:8443",
		TLSCertificatePEM:       tlsCertPEM,
		TLSPrivateKeyPEM:        tlsKeyPEM,
		VerifierTrustAnchorsPEM: verifierCAPEM,
		HolderPrivateKeyPEM:     holderKeyPEM,
	}, nil
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "setup:", msg)
	os.Exit(1)
}
