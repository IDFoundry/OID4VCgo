// Command setup-issuer writes the throwaway key material and configs
// for interop/eudi/run-issuer.sh: cmd/conformance-issuer's config (a
// Credential Issuer and Authorization Server for an SD-JWT VC PID and
// an mdoc PID, issuing pre-authorized code offers too) and the EUDI
// wallet driver's (interop/eudi/issuance), which holds what a Wallet
// Provider would give a wallet: a Wallet Attestation key under an
// attester CA the issuer trusts, and a key attestation key the issuer
// trusts. Unrelated keys for the controls come with them.
//
// Usage: go run ./interop/eudi/scripts/setup-issuer -out DIR -port PORT -offers-port PORT
//
// DIR receives:
//
//	issuer.json   cmd/conformance-issuer's config, listening on loopback, at PORT
//	driver.json   the wallet driver's config
//	tls-ca.pem    the CA the driver trusts for the issuer's TLS listener
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
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/internal/conformanceconfig"
)

// The EUDI PID, in both formats, as interop/eudi/scripts/setup issues
// it for the verifier run.
const (
	pidVCT       = "urn:eudi:pid:1"
	pidDocType   = "eu.europa.ec.eudi.pid.1"
	pidNamespace = "eu.europa.ec.eudi.pid.1"
	contactURI   = "https://example.com/oid4vcgo-eudi-interop"

	sdjwtConfigurationID = "eu.europa.ec.eudi.pid_vc_sd_jwt"
	mdocConfigurationID  = "eu.europa.ec.eudi.pid_mso_mdoc"
	sdjwtScope           = "eu.europa.ec.eudi.pid_vc_sd_jwt"
	mdocScope            = "eu.europa.ec.eudi.pid_mso_mdoc"

	clientID    = "oid4vcgo-eudi-interop-wallet"
	redirectURI = "https://wallet.example.com/callback"
	subject     = "eudi-interop-subject"

	attesterIssuer = "https://wallet-provider.example.com"
)

// The PID claims the issuer issues, in both formats: the SD-JWT VC's
// are strings, so these are too.
var pidClaims = map[string]string{
	"given_name":        "Jean",
	"family_name":       "Dupont",
	"birth_date":        "1990-01-01",
	"issuing_country":   "FR",
	"issuing_authority": "OID4VCgo interop test authority",
}

// issuerConfig is the subset of cmd/conformance-issuer's Config this
// run sets.
type issuerConfig struct {
	ListenAddr                        string                                  `json:"listen_addr"`
	Issuer                            string                                  `json:"issuer"`
	TLSCertificatePEM                 string                                  `json:"tls_certificate_pem"`
	TLSPrivateKeyPEM                  string                                  `json:"tls_private_key_pem"`
	Client                            issuerClient                            `json:"client"`
	CredentialIssuerSigningKeyPEM     string                                  `json:"credential_issuer_signing_key_pem"`
	CredentialIssuerCertificatePEM    string                                  `json:"credential_issuer_certificate_pem"`
	CredentialRequestDecryptionKeyPEM string                                  `json:"credential_request_decryption_key_pem"`
	VCT                               string                                  `json:"vct"`
	Claims                            map[string]string                       `json:"claims"`
	Scope                             string                                  `json:"scope"`
	CredentialConfigurationID         string                                  `json:"credential_configuration_id"`
	DefaultSubject                    string                                  `json:"default_subject"`
	Mdoc                              *conformanceconfig.MdocConfig           `json:"mdoc"`
	KeyAttestation                    *conformanceconfig.KeyAttestationConfig `json:"key_attestation"`
	Offers                            offersConfig                            `json:"offers"`
	AuthorizationDetails              bool                                    `json:"authorization_details"`
}

type issuerClient struct {
	ID                      string   `json:"id"`
	RedirectURIs            []string `json:"redirect_uris"`
	ExpectedAttesterIssuer  string   `json:"expected_attester_issuer"`
	AttesterTrustAnchorsPEM string   `json:"attester_trust_anchors_pem"`
}

type offersConfig struct {
	ListenAddr string `json:"listen_addr"`
}

// driverConfig is interop/eudi/issuance's Config.
type driverConfig struct {
	CredentialIssuer string `json:"credential_issuer"`
	OffersURL        string `json:"offers_url"`
	TLSTrustPEM      string `json:"tls_trust_pem"`
	ClientID         string `json:"client_id"`
	RedirectURI      string `json:"redirect_uri"`
	Subject          string `json:"subject"`

	// The Wallet Attestation the issuer trusts: its attester's key and
	// certificate (x5c, leaf first), naming AttesterIssuer.
	AttesterIssuer   string   `json:"attester_issuer"`
	AttesterKey      jwk      `json:"attester_key"`
	AttesterX5C      []string `json:"attester_x5c"`
	OtherAttesterKey jwk      `json:"other_attester_key"`
	OtherAttesterX5C []string `json:"other_attester_x5c"`

	// The key attestation key the issuer trusts, and one it doesn't.
	KeyAttestationKey      jwk `json:"key_attestation_key"`
	OtherKeyAttestationKey jwk `json:"other_key_attestation_key"`

	// What the issuer issues, and the trust anchors it's verified by.
	SDJWTConfigurationID string            `json:"sdjwt_configuration_id"`
	MdocConfigurationID  string            `json:"mdoc_configuration_id"`
	VCT                  string            `json:"vct"`
	DocType              string            `json:"doctype"`
	Namespace            string            `json:"namespace"`
	Claims               map[string]string `json:"claims"`
	IssuerCAPEM          string            `json:"issuer_ca_pem"`
	IACAPEM              string            `json:"iaca_pem"`
	OtherCAPEM           string            `json:"other_ca_pem"`
}

// jwk is a private EC P-256 JWK (RFC 7518 §6.2).
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d,omitempty"`
}

func privateJWK(k *ecdsa.PrivateKey) jwk {
	key := ecJWK(&k.PublicKey)
	d, err := k.Bytes()
	if err != nil {
		fail(err.Error())
	}
	key.D = base64.RawURLEncoding.EncodeToString(d)
	return key
}

func publicJWK(k *ecdsa.PublicKey) (json.RawMessage, error) {
	return json.Marshal(ecJWK(k))
}

// ecJWK is a P-256 public key's JWK, from its uncompressed point
// (0x04 || X || Y).
func ecJWK(k *ecdsa.PublicKey) jwk {
	point, err := k.Bytes()
	if err != nil || len(point) != 65 {
		fail("not a P-256 public key")
	}
	b := base64.RawURLEncoding.EncodeToString
	return jwk{Kty: "EC", Crv: "P-256", X: b(point[1:33]), Y: b(point[33:])}
}

// loopback is where the issuer listens: built from its bytes, not
// written out.
var loopback = net.IPv4(127, 0, 0, 1).String()

func main() {
	out := flag.String("out", "", "directory to write into")
	port := flag.Int("port", 18446, "the issuer's TLS port, on loopback")
	offersPort := flag.Int("offers-port", 18447, "the issuer's offer-minting port, on loopback")
	flag.Parse()
	if *out == "" {
		fail("-out is required")
	}
	if err := run(*out, *port, *offersPort); err != nil {
		fail(err.Error())
	}
}

func run(dir string, port, offersPort int) error {
	files := map[string][]byte{}
	issuerURL := "https://localhost:" + strconv.Itoa(port)

	tlsCertPEM, tlsKeyPEM, tlsCAPEM, err := tlsListener()
	if err != nil {
		return err
	}
	files["tls-ca.pem"] = []byte(tlsCAPEM)

	_, issuerKeyPEM, issuerCertPEM, issuerCAPEM, err := conformancecert.GenerateSignerAndCert(
		"oid4vcgo-eudi-interop-issuer", "oid4vcgo-eudi-interop-issuer-ca")
	if err != nil {
		return fmt.Errorf("credential issuer: %w", err)
	}
	requestDecryptionKeyPEM, err := conformancecert.GenerateECKeyPEM()
	if err != nil {
		return err
	}
	iacaCert, iacaKey, iacaPEM, _, err := conformancecert.GenerateMdocIACA("oid4vcgo-eudi-interop-iaca", "FR", contactURI)
	if err != nil {
		return fmt.Errorf("mdoc iaca: %w", err)
	}
	_, dsKeyPEM, dsCertPEM, err := conformancecert.GenerateMdocDocumentSigner("oid4vcgo-eudi-interop-ds", "FR", contactURI,
		contactURI+"/crl", iacaCert, iacaKey)
	if err != nil {
		return fmt.Errorf("mdoc document signer: %w", err)
	}

	attesterURL, err := url.Parse(attesterIssuer)
	if err != nil {
		return err
	}
	attesterKey, _, attesterLeafPEM, attesterCAPEM, err := conformancecert.GenerateSignerAndCert(
		"oid4vcgo-eudi-interop-wallet-provider", "oid4vcgo-eudi-interop-wallet-provider-ca", attesterURL)
	if err != nil {
		return fmt.Errorf("attester: %w", err)
	}
	// An attester naming the same issuer, under a CA the issuer doesn't
	// trust.
	otherAttesterKey, _, otherAttesterLeafPEM, _, err := conformancecert.GenerateSignerAndCert(
		"oid4vcgo-eudi-interop-other-wallet-provider", "oid4vcgo-eudi-interop-other-wallet-provider-ca", attesterURL)
	if err != nil {
		return fmt.Errorf("other attester: %w", err)
	}
	keyAttestationKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	otherKeyAttestationKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	trustedKeyAttestationJWK, err := publicJWK(&keyAttestationKey.PublicKey)
	if err != nil {
		return err
	}
	_, _, otherCAPEM, _, err := conformancecert.GenerateCA("oid4vcgo-eudi-interop-unrelated-ca")
	if err != nil {
		return err
	}

	mdocClaims := map[string]any{}
	for k, v := range pidClaims {
		mdocClaims[k] = v
	}
	issuer := issuerConfig{
		ListenAddr: net.JoinHostPort(loopback, strconv.Itoa(port)), Issuer: issuerURL,
		TLSCertificatePEM: tlsCertPEM, TLSPrivateKeyPEM: tlsKeyPEM,
		Client: issuerClient{
			ID: clientID, RedirectURIs: []string{redirectURI},
			ExpectedAttesterIssuer: attesterIssuer, AttesterTrustAnchorsPEM: attesterCAPEM,
		},
		CredentialIssuerSigningKeyPEM:     issuerKeyPEM,
		CredentialIssuerCertificatePEM:    issuerCertPEM,
		CredentialRequestDecryptionKeyPEM: requestDecryptionKeyPEM,
		VCT:                               pidVCT, Claims: pidClaims, Scope: sdjwtScope,
		CredentialConfigurationID: sdjwtConfigurationID,
		DefaultSubject:            subject,
		Mdoc: &conformanceconfig.MdocConfig{
			CredentialConfigurationID: mdocConfigurationID, DocType: pidDocType, Namespace: pidNamespace,
			Claims: mdocClaims, Scope: mdocScope,
			SignerKeyPEM: dsKeyPEM, CertificatePEM: dsCertPEM, TrustAnchorCertificatePEM: iacaPEM,
		},
		KeyAttestation:       &conformanceconfig.KeyAttestationConfig{TrustedJWK: trustedKeyAttestationJWK},
		Offers:               offersConfig{ListenAddr: net.JoinHostPort(loopback, strconv.Itoa(offersPort))},
		AuthorizationDetails: true,
	}
	driver := driverConfig{
		CredentialIssuer: issuerURL,
		// Plain HTTP: the offers listener is loopback-only.
		OffersURL:   (&url.URL{Scheme: "http", Host: net.JoinHostPort(loopback, strconv.Itoa(offersPort)), Path: "/offers"}).String(),
		TLSTrustPEM: tlsCAPEM,
		ClientID:    clientID, RedirectURI: redirectURI, Subject: subject,
		AttesterIssuer: attesterIssuer,
		AttesterKey:    privateJWK(attesterKey), AttesterX5C: []string{derBase64(attesterLeafPEM)},
		OtherAttesterKey: privateJWK(otherAttesterKey), OtherAttesterX5C: []string{derBase64(otherAttesterLeafPEM)},
		KeyAttestationKey:      privateJWK(keyAttestationKey),
		OtherKeyAttestationKey: privateJWK(otherKeyAttestationKey),
		SDJWTConfigurationID:   sdjwtConfigurationID, MdocConfigurationID: mdocConfigurationID,
		VCT: pidVCT, DocType: pidDocType, Namespace: pidNamespace, Claims: pidClaims,
		IssuerCAPEM: issuerCAPEM, IACAPEM: iacaPEM, OtherCAPEM: otherCAPEM,
	}
	for name, v := range map[string]any{"issuer.json": issuer, "driver.json": driver} {
		raw, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
		files[name] = raw
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// tlsListener makes the issuer's TLS certificate, a leaf for localhost
// under a CA the driver trusts, so the driver verifies it as any
// wallet would.
func tlsListener() (certPEM, keyPEM, caPEM string, err error) {
	ca, caKey, caPEM, _, err := conformancecert.GenerateCA("oid4vcgo-eudi-interop-issuer-tls-ca")
	if err != nil {
		return "", "", "", fmt.Errorf("tls ca: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return "", "", "", fmt.Errorf("tls certificate: %w", err)
	}
	if keyPEM, err = conformancecert.ECKeyPEM(key); err != nil {
		return "", "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), keyPEM, caPEM, nil
}

// derBase64 is a PEM certificate's DER, base64-encoded as an x5c entry
// is (RFC 7515 §4.1.6).
func derBase64(certPEM string) string {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		fail("not a PEM certificate")
	}
	return base64.StdEncoding.EncodeToString(block.Bytes)
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "setup-issuer:", msg)
	os.Exit(1)
}
