// Command setup writes the throwaway key material for
// interop/protocolsoup/run.sh: the run's CA, which every TLS
// certificate of the run chains to, as do ProtocolSoup's Verifier's
// request object signer (its x509_san_dns and x509_hash client) and
// OID4VCgo's verifiers' Access Certificates; and another CA, which
// nothing trusts, for the controls.
//
// It also writes what ProtocolSoup's wallet harness signs its Wallet
// Attestations and Key Attestations with, as it takes them: private
// JWKs carrying their certificate (x5c), under a CA of the harness's
// own, which OID4VCgo's issuer trusts; the attester's certificate
// names -attester, the attester OID4VCgo's issuer expects of its
// client, as a URI. And one under other-ca.pem, for the controls.
//
// Usage: go run ./interop/protocolsoup/scripts/setup -out DIR -host HOST -attester URL
//
// DIR receives:
//
//	ca.pem, other-ca.pem            the run's CA, and a CA nothing trusts
//	tls-cert.pem, tls-key.pem       TLS for localhost and HOST, under ca.pem
//	verifier-chain.pem              ProtocolSoup's request object signer, for localhost, and ca.pem
//	verifier-key.pem                its key, for the wallet's negative presentations too
//	our-verifier-cert.pem, our-verifier-key.pem              OID4VCgo's verifiers' Access Certificate, under ca.pem
//	untrusted-verifier-cert.pem, untrusted-verifier-key.pem  one under other-ca.pem
//	harness-ca.pem                  the harness's attester CA
//	harness-attester.json           its Wallet Attestation key, naming -attester
//	harness-key-attester.json       its Key Attestation key
//	untrusted-harness-attester.json a Wallet Attestation key under other-ca.pem, naming -attester
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

// authority is a CA: its certificate and key.
type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func main() {
	out := flag.String("out", "", "directory to write into")
	host := flag.String("host", "", "the name ProtocolSoup's containers reach this host by")
	attester := flag.String("attester", "", "the attester the harness's Wallet Attestations name")
	flag.Parse()
	if *out == "" || *host == "" || *attester == "" {
		fail("-out, -host and -attester are required")
	}
	attesterURI, err := url.Parse(*attester)
	if err != nil {
		fail("-attester: " + err.Error())
	}
	if err := run(*out, *host, attesterURI); err != nil {
		fail(err.Error())
	}
}

func run(dir, host string, attester *url.URL) error {
	files := map[string]string{}
	ca, err := newCA("OID4VCgo ProtocolSoup interop CA")
	if err != nil {
		return err
	}
	other, err := newCA("OID4VCgo ProtocolSoup interop other CA")
	if err != nil {
		return err
	}
	files["ca.pem"], files["other-ca.pem"] = certPEM(ca.cert.Raw), certPEM(other.cert.Raw)

	for _, l := range []struct {
		name string
		ca   authority
		tmpl x509.Certificate
	}{
		{"tls", ca, x509.Certificate{
			Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost", host},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}},
		// ProtocolSoup's x509_san_dns client is its base URL's host;
		// its x509_hash client the same certificate's hash.
		{"verifier", ca, x509.Certificate{
			Subject:  pkix.Name{CommonName: "ProtocolSoup Verifier", Organization: []string{"OID4VCgo interop"}},
			DNSNames: []string{"localhost"},
		}},
		{"our-verifier", ca, x509.Certificate{Subject: pkix.Name{CommonName: "OID4VCgo verifier"}}},
		{"untrusted-verifier", other, x509.Certificate{Subject: pkix.Name{CommonName: "OID4VCgo untrusted verifier"}}},
	} {
		key, der, err := leaf(l.ca, l.tmpl)
		if err != nil {
			return err
		}
		files[l.name+"-cert.pem"] = certPEM(der)
		if files[l.name+"-key.pem"], err = conformancecert.ECKeyPEM(key); err != nil {
			return err
		}
	}
	if err := harnessFiles(files, other, attester); err != nil {
		return err
	}
	// ProtocolSoup takes its signer's chain whole, leaf first, and
	// leaves the self-signed CA out of the x5c it sends.
	files["verifier-chain.pem"] = files["verifier-cert.pem"] + files["ca.pem"]
	delete(files, "verifier-cert.pem")

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

// harnessFiles adds the wallet harness's attester CA and keys to
// files: as WALLET_CLIENT_ATTESTATION_ATTESTER_JWK_JSON and
// WALLET_CLIENT_ATTESTATION_KEY_ATTESTATION_JWK_JSON take them, a
// private JWK whose x5c is its certificate alone (the harness sends no
// self-signed one).
func harnessFiles(files map[string]string, other authority, attester *url.URL) error {
	harness, err := newCA("ProtocolSoup wallet harness interop attester CA")
	if err != nil {
		return err
	}
	files["harness-ca.pem"] = certPEM(harness.cert.Raw)
	for _, k := range []struct {
		name string
		ca   authority
		tmpl x509.Certificate
	}{
		{"harness-attester", harness, x509.Certificate{Subject: pkix.Name{CommonName: "ProtocolSoup wallet harness attester"}, URIs: []*url.URL{attester}}},
		{"harness-key-attester", harness, x509.Certificate{Subject: pkix.Name{CommonName: "ProtocolSoup wallet harness key attester"}}},
		{"untrusted-harness-attester", other, x509.Certificate{Subject: pkix.Name{CommonName: "untrusted attester"}, URIs: []*url.URL{attester}}},
	} {
		key, der, err := leaf(k.ca, k.tmpl)
		if err != nil {
			return err
		}
		priv, err := jwk.MarshalPrivate(key)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(struct {
			jwk.JWK
			X5C []string `json:"x5c"`
		}{priv, []string{base64.StdEncoding.EncodeToString(der)}})
		if err != nil {
			return err
		}
		files[k.name+".json"] = string(raw)
	}
	return nil
}

// newCA is a fresh CA (conformancecert.GenerateCA).
func newCA(commonName string) (authority, error) {
	cert, key, _, _, err := conformancecert.GenerateCA(commonName)
	return authority{cert: cert, key: key}, err
}

// leaf is a fresh P-256 key and its certificate under ca, DER, with
// tmpl's subject, names (DNS and URI) and extended key usage, valid from an hour ago
// for a day.
func leaf(ca authority, tmpl x509.Certificate) (*ecdsa.PrivateKey, []byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return nil, nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	start := time.Now().Add(-time.Hour)
	cert := x509.Certificate{
		SerialNumber: serial, Subject: tmpl.Subject, DNSNames: tmpl.DNSNames, URIs: tmpl.URIs, ExtKeyUsage: tmpl.ExtKeyUsage,
		NotBefore: start, NotAfter: start.Add(25 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, &cert, ca.cert, &key.PublicKey, ca.key)
	return key, der, err
}

func certPEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "setup:", msg)
	os.Exit(1)
}
