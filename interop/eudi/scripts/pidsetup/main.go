// Command pidsetup writes the throwaway key material and documents for
// interop/eudi/run-pid-issuer.sh, where OID4VCgo's wallet obtains PIDs
// from the EUDI reference PID Issuer (eudi-srv-pid-issuer):
//
//   - a TLS CA and, under it, the certificates of the stack's HAProxy
//     (localhost, where the wallet reaches the issuer and its Keycloak),
//     of Keycloak's own listener (keycloak, where the issuer reaches it),
//     and of interop/eudi/scripts/serve (host.docker.internal, where
//     Keycloak and the issuer fetch the Wallet Provider's status list);
//   - the issuer's keys: an IACA, with a Document Signer under it for
//     mdocs and an SD-JWT VC signer naming the Credential Issuer; an
//     Access Certificate for signed metadata, under a CA of its own; the
//     credential request and nonce encryption keys; the status list
//     service's signer, under the IACA, naming its Status Issuer; and a
//     Wallet Relying Party Registration Certificate, under a registrar
//     CA of its own;
//   - a Wallet Provider: a CA, the Wallet Attestation and Key
//     Attestation signers under it, and the Status List Token their
//     client_status and key_storage_status point at (index 0 valid, 1
//     invalid), which serve serves at /statuslists/jwt;
//   - an unrelated CA, for the controls.
//
// Usage:
//
//	go run ./interop/eudi/scripts/pidsetup -out DIR -issuer-url URL -serve-url URL
//
// Every certificate, and the key the script's keystore is built from,
// is per run. Keys are written as PKCS #8 PEM.
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
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// contactURI is the IACA's and Document Signer's Issuer Alternative
// Name.
const contactURI = "https://example.com/oid4vcgo-eudi-interop"

// issuingCountry is the countryName of the issuer's certificates: the
// issuer's own default ISSUER_PID_ISSUINGCOUNTRY, which an mdoc PID's
// issuing_country must match (ISO/IEC 18013-5 Annex B).
const issuingCountry = "GR"

// statusListPath is where serve serves the Wallet Provider's Status
// List Token.
const statusListPath = "/statuslists/jwt"

// walletAttestationEntry names the Wallet Attestation signer's files,
// which also signs the Wallet Provider's status list.
const walletAttestationEntry = "wallet-attestation"

// tlsLifetime bounds the TLS certificates and the Wallet Provider's
// Status List Token: a run takes minutes.
const tlsLifetime = 48 * time.Hour

// files is what the run writes, by name.
type files map[string][]byte

func (f files) put(name, content string) { f[name] = []byte(content) }

func main() {
	out := flag.String("out", "", "directory to write into")
	issuerURL := flag.String("issuer-url", "", "the Credential Issuer Identifier (https://localhost:PORT/pid-issuer)")
	serveURL := flag.String("serve-url", "", "where Keycloak and the issuer reach serve (https://host.docker.internal:PORT)")
	flag.Parse()
	if *out == "" || *issuerURL == "" || *serveURL == "" {
		fail("-out, -issuer-url and -serve-url are required")
	}
	f, err := generate(*issuerURL, strings.TrimSuffix(*serveURL, "/"))
	if err != nil {
		fail(err.Error())
	}
	for name, content := range f {
		// Throwaway material, read by containers running as other users.
		if err := os.WriteFile(filepath.Join(*out, name), content, 0o644); err != nil { // #nosec G306 -- throwaway, per-run key material
			fail(err.Error())
		}
	}
}

// generate makes every file the run needs. issuerURL is the Credential
// Issuer Identifier; serveURL is where the containers reach serve.
func generate(issuerURL, serveURL string) (files, error) {
	issuer, err := url.Parse(issuerURL)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" {
		return nil, fmt.Errorf("-issuer-url %q isn't an https URL", issuerURL)
	}
	serve, err := url.Parse(serveURL)
	if err != nil || serve.Scheme != "https" || serve.Hostname() == "" {
		return nil, fmt.Errorf("-serve-url %q isn't an https URL", serveURL)
	}
	f := files{}
	if err := tlsFiles(f, serve.Hostname()); err != nil {
		return nil, err
	}
	if err := issuerFiles(f, issuer); err != nil {
		return nil, err
	}
	if err := walletProviderFiles(f, serveURL+statusListPath); err != nil {
		return nil, err
	}
	_, _, otherCAPEM, _, err := conformancecert.GenerateCA("oid4vcgo-eudi-pid-unrelated-ca")
	if err != nil {
		return nil, fmt.Errorf("unrelated ca: %w", err)
	}
	f.put("other-ca.pem", otherCAPEM)
	return f, nil
}

// tlsFiles makes the TLS CA and the stack's three listeners'
// certificates under it.
func tlsFiles(f files, serveHost string) error {
	ca, caKey, caPEM, _, err := conformancecert.GenerateCA("oid4vcgo-eudi-pid-tls-ca")
	if err != nil {
		return fmt.Errorf("tls ca: %w", err)
	}
	f.put("tls-ca.pem", caPEM)
	for _, l := range []struct {
		name  string
		hosts []string
	}{
		{"haproxy", []string{"localhost"}},
		{"keycloak", []string{"keycloak"}},
		{"serve", []string{serveHost, "localhost"}},
	} {
		certPEM, keyPEM, err := tlsLeaf(l.hosts, ca, caKey)
		if err != nil {
			return fmt.Errorf("%s tls certificate: %w", l.name, err)
		}
		f.put(l.name+"-cert.pem", certPEM)
		f.put(l.name+"-key.pem", keyPEM)
	}
	// HAProxy takes its certificate and key in one file.
	f.put("haproxy.pem", string(f["haproxy-cert.pem"])+string(f["haproxy-key.pem"]))
	return nil
}

// tlsLeaf issues a TLS server certificate for hosts under ca.
func tlsLeaf(hosts []string, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (certPEM, keyPEM string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: hosts[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(tlsLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return "", "", err
	}
	keyPEM, err = pkcs8PEM(key)
	if err != nil {
		return "", "", err
	}
	return certPEM0(der), keyPEM, nil
}

// issuerFiles makes the PID issuer's keys and certificates. Each
// keystore entry is written as NAME.key.pem and NAME.chain.pem (leaf
// first, its CA after it: the issuer leaves the CA out of every x5c it
// sends).
func issuerFiles(f files, issuer *url.URL) error {
	iaca, iacaKey, iacaPEM, _, err := conformancecert.GenerateMdocIACA("oid4vcgo-eudi-pid-iaca", issuingCountry, contactURI)
	if err != nil {
		return fmt.Errorf("iaca: %w", err)
	}
	f.put("iaca.pem", iacaPEM)

	dsKey, _, dsPEM, err := conformancecert.GenerateMdocDocumentSigner("oid4vcgo-eudi-pid-ds", issuingCountry, contactURI, contactURI+"/crl", iaca, iacaKey)
	if err != nil {
		return fmt.Errorf("document signer: %w", err)
	}
	if err := putEntry(f, "pid-mdoc", dsKey, dsPEM, iacaPEM); err != nil {
		return err
	}

	// The SD-JWT VC signer names the Credential Issuer, so the wallet
	// can require its iss be named by its certificate.
	if err := leafEntry(f, "pid-sdjwt", "oid4vcgo-eudi-pid-sdjwt", iaca, iacaKey, iacaPEM, issuer); err != nil {
		return err
	}

	// The status list service signs for the issuer's credentials of
	// both formats: under the IACA, as ISO/IEC 18013-5 §12.3.6 has an
	// mdoc's revocation list signed under the CA that signed its
	// Document Signer, and naming its Status Issuer identifier, which
	// the wallet's SD-JWT VC checks accept for the issuer.
	statusIssuer := &url.URL{Scheme: "https", Host: issuer.Host, Path: "/token_status_list"}
	slKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	slDER, err := leafDER("oid4vcgo-eudi-pid-status-list", slKey, iaca, iacaKey, statusIssuer)
	if err != nil {
		return fmt.Errorf("status list signer: %w", err)
	}
	slKeyPEM, err := pkcs8PEM(slKey)
	if err != nil {
		return err
	}
	f["statuslist-signer.cert.der"] = slDER
	f.put("statuslist-signer.key.pem", slKeyPEM)
	f.put("status-issuer.txt", statusIssuer.String())

	// Signed metadata's Access Certificate, under a CA that anchors
	// nothing else, naming the Credential Issuer.
	metadataCA, metadataCAKey, metadataCAPEM, _, err := conformancecert.GenerateCA("oid4vcgo-eudi-pid-metadata-ca")
	if err != nil {
		return fmt.Errorf("metadata ca: %w", err)
	}
	f.put("metadata-ca.pem", metadataCAPEM)
	if err := leafEntry(f, "access-certificate", "oid4vcgo-eudi-pid-metadata", metadataCA, metadataCAKey, metadataCAPEM, issuer); err != nil {
		return err
	}

	// The encryption keys need a certificate only to sit in the
	// keystore: the issuer reads the key's use (enc) from its key
	// usage.
	for _, name := range []string{"request-encryption", "nonce-encryption"} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		tmpl := &x509.Certificate{
			SerialNumber: serial(),
			Subject:      pkix.Name{CommonName: "oid4vcgo-eudi-pid-" + name},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageKeyAgreement,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if err := putEntry(f, name, key, certPEM0(der), ""); err != nil {
			return err
		}
	}

	wrprc, err := registrationCertificate(issuer.String())
	if err != nil {
		return fmt.Errorf("registration certificate: %w", err)
	}
	f.put("wrprc.jws", wrprc)
	return nil
}

// leafEntry issues a leaf for a fresh key under ca, naming uri, and
// writes it as the keystore entry name.
func leafEntry(f files, name, commonName string, ca *x509.Certificate, caKey *ecdsa.PrivateKey, caPEM string, uri *url.URL) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := leafDER(commonName, key, ca, caKey, uri)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return putEntry(f, name, key, certPEM0(der), caPEM)
}

// leafDER issues a signing leaf for key under ca, naming uri.
func leafDER(commonName string, key *ecdsa.PrivateKey, ca *x509.Certificate, caKey *ecdsa.PrivateKey, uri *url.URL) ([]byte, error) {
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{Country: []string{issuingCountry}, CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		URIs:         []*url.URL{uri},
	}
	if uri.Hostname() != "" {
		tmpl.DNSNames = []string{uri.Hostname()}
	}
	return x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
}

// putEntry writes key and its chain (certPEM, then caPEM) as the
// keystore entry name.
func putEntry(f files, name string, key *ecdsa.PrivateKey, certPEM, caPEM string) error {
	keyPEM, err := pkcs8PEM(key)
	if err != nil {
		return err
	}
	f.put(name+".key.pem", keyPEM)
	f.put(name+".chain.pem", certPEM+caPEM)
	return nil
}

// registrationCertificate is a Wallet Relying Party Registration
// Certificate (an rc-wrp+jwt) for the issuer, signed under a registrar
// CA: the issuer publishes it in its metadata's issuer_info, and
// refuses to start without one. Its contents are illustrative.
func registrationCertificate(issuer string) (string, error) {
	key, _, certPEM, _, err := conformancecert.GenerateSignerAndCert("oid4vcgo-eudi-pid-registrar-leaf", "oid4vcgo-eudi-pid-registrar-ca")
	if err != nil {
		return "", err
	}
	cert, err := conformancecert.ParseCertificatePEM(certPEM)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(map[string]any{
		"name":         "OID4VCgo EUDI interop PID issuer",
		"sub":          "LEIXG-OID4VCGO-PID-INTEROP",
		"country":      issuingCountry,
		"entitlements": []string{"https://uri.etsi.org/19475/Entitlement/PID_Provider"},
		"srv_description": []map[string]string{
			{"lang": "en", "value": "Interoperability testing"},
		},
		"info_uri": issuer,
		"provides_attestations": []map[string]any{
			{"format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []string{"urn:eudi:pid:1"}}},
			{"format": "mso_mdoc", "meta": map[string]any{"doctype_value": "eu.europa.ec.eudi.pid.1"}},
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

// walletProviderFiles makes the Wallet Provider's CA, the Wallet
// Attestation and Key Attestation signers under it, and its Status List
// Token, served at statusListURI: index 0 valid, 1 invalid. The Wallet
// Attestation signer signs it.
func walletProviderFiles(f files, statusListURI string) error {
	ca, caKey, caPEM, _, err := conformancecert.GenerateCA("oid4vcgo-eudi-pid-wallet-provider-ca")
	if err != nil {
		return fmt.Errorf("wallet provider ca: %w", err)
	}
	f.put("wallet-provider-ca.pem", caPEM)
	provider := &url.URL{Scheme: "https", Host: "wallet-provider.oid4vcgo.example"}
	keys := map[string]*ecdsa.PrivateKey{}
	certs := map[string]*x509.Certificate{}
	for _, name := range []string{walletAttestationEntry, "key-attestation"} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		der, err := leafDER("oid4vcgo-eudi-pid-"+name, key, ca, caKey, provider)
		if err != nil {
			return fmt.Errorf("%s signer: %w", name, err)
		}
		if certs[name], err = x509.ParseCertificate(der); err != nil {
			return err
		}
		keys[name] = key
		if err := putEntry(f, name, key, certPEM0(der), ""); err != nil {
			return err
		}
	}
	f.put("wallet-provider-status-list.txt", statusListURI)

	list, err := statuslist.New(statuslist.Bits1, []uint8{uint8(statuslist.StatusValid), uint8(statuslist.StatusInvalid)}, "")
	if err != nil {
		return fmt.Errorf("status list: %w", err)
	}
	now := time.Now()
	exp := now.Add(tlsLifetime).Unix()
	ttl := int64(300)
	token, err := statuslist.IssueTokenX5C(keys[walletAttestationEntry], oid4vci.ES256,
		statuslist.TokenClaims{Sub: statusListURI, Iat: now.Unix(), Exp: &exp, TTL: &ttl, StatusList: list},
		[]*x509.Certificate{certs[walletAttestationEntry]})
	if err != nil {
		return fmt.Errorf("status list token: %w", err)
	}
	f.put("statuslist.jwt", token)
	return nil
}

// pkcs8PEM PEM-encodes key as PKCS #8, which every component reads.
func pkcs8PEM(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// certPEM0 PEM-encodes a certificate.
func certPEM0(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// serial is a random positive certificate serial number.
func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		panic(errors.Join(errors.New("pidsetup: random serial"), err))
	}
	return n.Add(n, big.NewInt(1))
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "pidsetup:", msg)
	os.Exit(1)
}
