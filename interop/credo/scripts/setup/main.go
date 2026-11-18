// Command setup writes the throwaway key material for
// interop/credo/run.sh: the run's CA, which Credo's TLS certificate,
// its SD-JWT VC signer and its Verifier's x509_hash Access Certificate
// chain to; an mdoc IACA and the Document Signer under it, which signs
// Credo's mdocs; and another CA, which nothing trusts, for the
// controls. Credo's keys go to the driver as private JWKs
// (credo.json), as its key management imports them.
//
// Usage: go run ./interop/credo/scripts/setup -out DIR -issuer-url URL
//
// DIR receives:
//
//	ca.pem                        the run's CA: TLS, the SD-JWT VC signer, the Access Certificate
//	iaca.pem                      the IACA Credo's Document Signer chains to
//	other-ca.pem                  a CA nothing trusts
//	tls-cert.pem, tls-key.pem     the TLS certificate for localhost
//	verifier-key.pem              the Access Certificate's key, for the wallet's negative presentations
//	credo.json                    the driver's keys, chains and trust (interop/credo/driver)
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
)

// country is the issuer's certificates': an mdoc's Document Signer
// names its IACA's country (ISO/IEC 18013-5 Annex B).
const country = "AT"

// authority is a CA: its certificate and key.
type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// signer is a key and its certificate chain, leaf first, as the driver
// takes them: a private JWK and base64 DER certificates.
type signer struct {
	Key jwk.JWK  `json:"key"`
	X5C []string `json:"x5c"`
}

// driverConfig is credo.json: the driver's TLS certificate, its
// signers, and the anchors its Verifier trusts credentials to.
type driverConfig struct {
	TLSCertPEM string `json:"tls_cert_pem"`
	TLSKeyPEM  string `json:"tls_key_pem"`
	// Issuer signs SD-JWT VCs, MdocSigner mdocs, and Verifier its
	// request objects (x509_hash).
	Issuer     signer `json:"issuer"`
	MdocSigner signer `json:"mdoc_signer"`
	Verifier   signer `json:"verifier"`
	// CredentialAnchors are what Credo's Verifier trusts credentials
	// to, base64 DER: the run's CA and the IACA.
	CredentialAnchors []string `json:"credential_anchors"`
}

func main() {
	out := flag.String("out", "", "directory to write into")
	issuerURL := flag.String("issuer-url", "", "Credo's Credential Issuer Identifier, which its SD-JWT VC signer's certificate names (Credo requires an SD-JWT VC's iss to match the leaf's SAN)")
	flag.Parse()
	if *out == "" || *issuerURL == "" {
		fail("-out and -issuer-url are required")
	}
	if err := run(*out, *issuerURL); err != nil {
		fail(err.Error())
	}
}

func run(dir, issuerURL string) error {
	issuerURI, err := url.Parse(issuerURL)
	if err != nil {
		return fmt.Errorf("-issuer-url: %w", err)
	}
	files := map[string]string{}
	ca, err := newCA("OID4VCgo Credo interop CA")
	if err != nil {
		return err
	}
	other, err := newCA("OID4VCgo Credo interop other CA")
	if err != nil {
		return err
	}
	files["ca.pem"], files["other-ca.pem"] = certPEM(ca.cert.Raw), certPEM(other.cert.Raw)

	tlsKey, tlsDER, err := leaf(ca, x509.Certificate{
		Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return err
	}
	files["tls-cert.pem"] = certPEM(tlsDER)
	if files["tls-key.pem"], err = conformancecert.ECKeyPEM(tlsKey); err != nil {
		return err
	}

	issuerKey, issuerDER, err := leaf(ca, x509.Certificate{
		Subject:  pkix.Name{CommonName: "Credo issuer", Country: []string{country}},
		DNSNames: []string{issuerURI.Hostname()}, URIs: []*url.URL{issuerURI},
	})
	if err != nil {
		return err
	}
	verifierKey, verifierDER, err := leaf(ca, x509.Certificate{Subject: pkix.Name{CommonName: "Credo verifier"}})
	if err != nil {
		return err
	}
	if files["verifier-key.pem"], err = conformancecert.ECKeyPEM(verifierKey); err != nil {
		return err
	}

	iaca, iacaKey, iacaPEM, _, err := conformancecert.GenerateMdocIACA("OID4VCgo Credo interop IACA", country, "https://localhost/")
	if err != nil {
		return err
	}
	files["iaca.pem"] = iacaPEM
	dsKey, _, dsPEM, err := conformancecert.GenerateMdocDocumentSigner("Credo document signer", country, "https://localhost/",
		"https://localhost/iaca.crl", iaca, iacaKey)
	if err != nil {
		return err
	}
	ds, _ := pem.Decode([]byte(dsPEM))

	cfg := driverConfig{TLSCertPEM: files["tls-cert.pem"], TLSKeyPEM: files["tls-key.pem"]}
	for _, sg := range []struct {
		to  *signer
		key *ecdsa.PrivateKey
		der []byte
	}{{&cfg.Issuer, issuerKey, issuerDER}, {&cfg.MdocSigner, dsKey, ds.Bytes}, {&cfg.Verifier, verifierKey, verifierDER}} {
		if *sg.to, err = newSigner(sg.key, sg.der); err != nil {
			return err
		}
	}
	for _, anchor := range []*x509.Certificate{ca.cert, iaca} {
		cfg.CredentialAnchors = append(cfg.CredentialAnchors, base64.StdEncoding.EncodeToString(anchor.Raw))
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	files["credo.json"] = string(raw)

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			return err
		}
	}
	return nil
}

// newCA is a fresh CA (conformancecert.GenerateCA).
func newCA(commonName string) (authority, error) {
	cert, key, _, _, err := conformancecert.GenerateCA(commonName)
	return authority{cert: cert, key: key}, err
}

// leaf is a fresh P-256 signing key and its certificate under ca, DER,
// valid for a day, with tmpl's names.
func leaf(ca authority, tmpl x509.Certificate) (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	if tmpl.SerialNumber, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64)); err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl.NotBefore, tmpl.NotAfter, tmpl.KeyUsage = now.Add(-time.Hour), now.Add(24*time.Hour), x509.KeyUsageDigitalSignature
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, ca.cert, key.Public(), ca.key)
	return key, der, err
}

func certPEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// newSigner is key and its certificate as the driver takes them.
func newSigner(key *ecdsa.PrivateKey, der []byte) (signer, error) {
	j, err := jwk.MarshalPrivate(key)
	return signer{Key: j, X5C: []string{base64.StdEncoding.EncodeToString(der)}}, err
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "setup:", msg)
	os.Exit(1)
}
