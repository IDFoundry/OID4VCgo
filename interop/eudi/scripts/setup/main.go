// Command setup writes the throwaway key material, configs and served
// documents for interop/eudi/run-verifier.sh: cmd/conformance-wallet-vp
// configs for an SD-JWT VC and an mdoc fixture credential, each with a
// Token Status List reference; the status lists themselves, as a JWT
// and a CWT Status List Token; the PID's SD-JWT VC Type Metadata, which
// the SD-JWT VC names by its integrity; the EUDI Verifier Endpoint's
// Access Certificate (its Request Object signing key, a leaf under a CA
// the wallet is told to trust); the verifier's TLS listener; the TLS
// certificate interop/eudi/scripts/serve serves the documents with,
// under a CA the verifier is told to trust; and unrelated CAs for the
// controls.
//
// Usage: go run ./interop/eudi/scripts/setup -out DIR -serve-url URL [-verifier-curve P-521]
//
// URL is where the verifier reaches serve (https://host:port), whose
// host must be one of -serve-hosts. -verifier-curve P-521 makes the
// Access Certificate a P-521 key's, for the EUDI verifier signing ES512
// (run-verifier.sh); P-256, the default, signs ES256, as
// cmd/conformance-verifier does (run-wallet.sh).
//
// DIR receives:
//
//	wallet-sdjwt.json, wallet-mdoc.json  the wallet's configs, at status list index 0 (valid)
//	issuer-ca.pem, iaca.pem              the credentials' trust anchors
//	other-ca.pem                         an unrelated CA
//	verifier-key.pem, verifier-chain.pem the Access Certificate's key and chain (leaf first)
//	verifier-ca.pem                      the CA the wallet trusts for the verifier
//	tls-cert.pem, tls-key.pem            the verifier's TLS listener
//	registration-certificate.jws         a Relying Party registration certificate for the verifier
//	serve-cert.pem, serve-key.pem        serve's TLS listener
//	serve-ca.pem                         the CA the verifier trusts for serve
//	statuslist.jwt, statuslist.cwt       the Status List Tokens: index 0 valid, 1 invalid
//	type-metadata.json                   the PID's Type Metadata
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
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
	"strings"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/statuslist"
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
	VCTIntegrity                   string         `json:"vct_integrity,omitempty"`
	Claims                         map[string]any `json:"claims,omitempty"`
	CredentialFormat               string         `json:"credential_format,omitempty"`
	MdocIssuerPrivateKeyPEM        string         `json:"mdoc_issuer_private_key_pem,omitempty"`
	MdocIssuerCertificatePEM       string         `json:"mdoc_issuer_certificate_pem,omitempty"`
	MdocDocType                    string         `json:"mdoc_doc_type,omitempty"`
	MdocNamespace                  string         `json:"mdoc_namespace,omitempty"`
	MdocClaims                     map[string]any `json:"mdoc_claims,omitempty"`
	StatusListURI                  string         `json:"status_list_uri"`
	StatusListIdx                  uint64         `json:"status_list_idx"`
}

// The EUDI PID, in both formats: the type the EUDI verifier's own
// examples ask for.
const (
	pidVCT       = "urn:eudi:pid:1"
	pidDocType   = "eu.europa.ec.eudi.pid.1"
	pidNamespace = "eu.europa.ec.eudi.pid.1"
	contactURI   = "https://example.com/oid4vcgo-eudi-interop"
)

// The paths interop/eudi/scripts/serve serves the Status List Tokens
// at.
const (
	statusListJWTPath = "/statuslists/jwt"
	statusListCWTPath = "/statuslists/cwt"
)

// statusListLifetime bounds the Status List Tokens: a run takes minutes.
const statusListLifetime = 24 * time.Hour

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
	serveURL := flag.String("serve-url", "", "the base URL the verifier reaches serve at")
	serveHosts := flag.String("serve-hosts", "localhost,host.docker.internal", "comma-separated DNS names for serve's TLS certificate")
	verifierCurve := flag.String("verifier-curve", "P-256", "the Access Certificate key's curve: P-256, signing ES256, or P-521, signing ES512")
	flag.Parse()
	if *out == "" || *serveURL == "" {
		fail("-out and -serve-url are required")
	}
	if err := run(*out, strings.TrimSuffix(*serveURL, "/"), strings.Split(*serveHosts, ","), *verifierCurve); err != nil {
		fail(err.Error())
	}
}

func run(dir, serveURL string, serveHosts []string, verifierCurve string) error {
	if u, err := url.Parse(serveURL); err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("-serve-url %q isn't an https URL", serveURL)
	}
	files := map[string][]byte{}
	put := func(name, content string) { files[name] = []byte(content) }

	if err := verifierFiles(put, verifierCurve); err != nil {
		return err
	}
	if err := serveFiles(put, serveHosts); err != nil {
		return err
	}
	_, _, otherCAPEM, _, err := conformancecert.GenerateCA("oid4vcgo-eudi-interop-unrelated-ca")
	if err != nil {
		return fmt.Errorf("unrelated ca: %w", err)
	}
	put("other-ca.pem", otherCAPEM)

	base, err := baseWalletConfig(string(files["verifier-ca.pem"]))
	if err != nil {
		return err
	}
	sdjwt, err := sdjwtFiles(put, base, serveURL)
	if err != nil {
		return err
	}
	mdoc, err := mdocFiles(files, base, serveURL)
	if err != nil {
		return err
	}
	for name, cfg := range map[string]walletConfig{"wallet-sdjwt.json": sdjwt, "wallet-mdoc.json": mdoc} {
		raw, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return err
		}
		files[name] = raw
	}
	for name, content := range files {
		// Throwaway material, read by containers running as other users.
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o644); err != nil { // #nosec G306 -- throwaway, per-run key material
			return err
		}
	}
	return nil
}

// verifierFiles makes the verifier's Access Certificate, registration
// certificate and TLS listener. The Access Certificate's key is on
// curve: P-521 for the EUDI verifier, which signs ES512 as its own
// docker-compose configures it, and P-256 for cmd/conformance-verifier,
// which signs ES256.
func verifierFiles(put func(name, content string), curve string) error {
	var c elliptic.Curve
	switch curve {
	case "P-256":
		c = elliptic.P256()
	case "P-521":
		c = elliptic.P521()
	default:
		return fmt.Errorf("-verifier-curve %q isn't P-256 or P-521", curve)
	}
	// EUDI refuses a self-signed Access Certificate.
	verifierKey, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return err
	}
	verifierKeyPEM, err := conformancecert.ECKeyPEM(verifierKey)
	if err != nil {
		return err
	}
	verifierCA, verifierCAKey, verifierCAPEM, _, err := conformancecert.GenerateCA("oid4vcgo-eudi-interop-verifier-ca")
	if err != nil {
		return fmt.Errorf("verifier access certificate: %w", err)
	}
	verifierCertPEM, err := conformancecert.IssueLeafCertPEM("oid4vcgo-eudi-interop-verifier", verifierKey, verifierCA, verifierCAKey)
	if err != nil {
		return fmt.Errorf("verifier access certificate: %w", err)
	}
	put("verifier-key.pem", verifierKeyPEM)
	put("verifier-chain.pem", verifierCertPEM+verifierCAPEM)
	put("verifier-ca.pem", verifierCAPEM)
	rc, err := registrationCertificate(verifierKey, verifierCertPEM)
	if err != nil {
		return fmt.Errorf("registration certificate: %w", err)
	}
	put("registration-certificate.jws", rc)

	tlsCertPEM, tlsKeyPEM, err := conformancecert.SelfSignedPEM("localhost", []string{"localhost"})
	if err != nil {
		return fmt.Errorf("verifier tls certificate: %w", err)
	}
	put("tls-cert.pem", tlsCertPEM)
	put("tls-key.pem", tlsKeyPEM)
	return nil
}

// serveFiles makes serve's TLS certificate, a leaf for hosts under a
// CA the verifier trusts.
func serveFiles(put func(name, content string), hosts []string) error {
	ca, caKey, caPEM, _, err := conformancecert.GenerateCA("oid4vcgo-eudi-interop-serve-ca")
	if err != nil {
		return fmt.Errorf("serve ca: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: hosts[0]},
		DNSNames:     hosts,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(statusListLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("serve tls certificate: %w", err)
	}
	keyPEM, err := conformancecert.ECKeyPEM(key)
	if err != nil {
		return err
	}
	put("serve-cert.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	put("serve-key.pem", keyPEM)
	put("serve-ca.pem", caPEM)
	return nil
}

// sdjwtFiles makes the SD-JWT VC issuer, its JWT Status List Token and
// the PID's Type Metadata, and returns the SD-JWT VC wallet config.
func sdjwtFiles(put func(name, content string), base walletConfig, serveURL string) (walletConfig, error) {
	issuerKey, issuerKeyPEM, issuerCertPEM, issuerCAPEM, err := conformancecert.GenerateSignerAndCert(
		"oid4vcgo-eudi-interop-issuer", "oid4vcgo-eudi-interop-issuer-ca")
	if err != nil {
		return walletConfig{}, fmt.Errorf("credential issuer: %w", err)
	}
	put("issuer-ca.pem", issuerCAPEM)
	issuerCert, err := conformancecert.ParseCertificatePEM(issuerCertPEM)
	if err != nil {
		return walletConfig{}, err
	}
	uri := serveURL + statusListJWTPath
	claims, err := statusListClaims(uri)
	if err != nil {
		return walletConfig{}, err
	}
	token, err := statuslist.IssueTokenX5C(issuerKey, oid4vci.ES256, claims, []*x509.Certificate{issuerCert})
	if err != nil {
		return walletConfig{}, fmt.Errorf("jwt status list token: %w", err)
	}
	put("statuslist.jwt", token)

	metadata, err := typeMetadata()
	if err != nil {
		return walletConfig{}, err
	}
	put("type-metadata.json", string(metadata))
	digest := sha256.Sum256(metadata)

	cfg := base
	cfg.CredentialIssuerPrivateKeyPEM = issuerKeyPEM
	cfg.CredentialIssuerCertificatePEM = issuerCertPEM
	cfg.VCT = pidVCT
	cfg.VCTIntegrity = "sha256-" + base64.StdEncoding.EncodeToString(digest[:])
	cfg.Claims = pidClaims
	cfg.StatusListURI = uri
	return cfg, nil
}

// mdocFiles makes the mdoc IACA and Document Signer and the CWT Status
// List Token, and returns the mdoc wallet config.
func mdocFiles(files map[string][]byte, base walletConfig, serveURL string) (walletConfig, error) {
	iacaCert, iacaKey, iacaPEM, _, err := conformancecert.GenerateMdocIACA("oid4vcgo-eudi-interop-iaca", "FR", contactURI)
	if err != nil {
		return walletConfig{}, fmt.Errorf("mdoc iaca: %w", err)
	}
	dsKey, dsKeyPEM, dsCertPEM, err := conformancecert.GenerateMdocDocumentSigner("oid4vcgo-eudi-interop-ds", "FR", contactURI,
		contactURI+"/crl", iacaCert, iacaKey)
	if err != nil {
		return walletConfig{}, fmt.Errorf("mdoc document signer: %w", err)
	}
	files["iaca.pem"] = []byte(iacaPEM)
	dsCert, err := conformancecert.ParseCertificatePEM(dsCertPEM)
	if err != nil {
		return walletConfig{}, err
	}
	uri := serveURL + statusListCWTPath
	claims, err := statusListClaims(uri)
	if err != nil {
		return walletConfig{}, err
	}
	token, err := statuslist.IssueTokenCWTX5Chain(dsKey, oid4vci.COSEES256, claims, []*x509.Certificate{dsCert})
	if err != nil {
		return walletConfig{}, fmt.Errorf("cwt status list token: %w", err)
	}
	files["statuslist.cwt"] = token

	cfg := base
	cfg.CredentialFormat = "mso_mdoc"
	cfg.MdocIssuerPrivateKeyPEM = dsKeyPEM
	cfg.MdocIssuerCertificatePEM = dsCertPEM
	cfg.MdocDocType = pidDocType
	cfg.MdocNamespace = pidNamespace
	cfg.MdocClaims = pidClaims
	cfg.StatusListURI = uri
	return cfg, nil
}

// statusListClaims is a Status List Token served at uri, where index 0
// is valid and index 1 invalid.
func statusListClaims(uri string) (statuslist.TokenClaims, error) {
	list, err := statuslist.New(statuslist.Bits1, []uint8{uint8(statuslist.StatusValid), uint8(statuslist.StatusInvalid)}, "")
	if err != nil {
		return statuslist.TokenClaims{}, fmt.Errorf("status list: %w", err)
	}
	now := time.Now()
	exp := now.Add(statusListLifetime).Unix()
	return statuslist.TokenClaims{Sub: uri, Iat: now.Unix(), Exp: &exp, StatusList: list}, nil
}

// typeMetadata is the PID's Type Metadata: every claim the fixture
// carries, each always selectively disclosable, as the fixture issues
// them, and the two the query asks for mandatory.
func typeMetadata() ([]byte, error) {
	md := sdjwtvc.TypeMetadata{
		VCT:  pidVCT,
		Name: "OID4VCgo interop PID",
	}
	for _, name := range []string{"family_name", "given_name", "birth_date", "nationalities", "issuing_country", "issuing_authority"} {
		md.Claims = append(md.Claims, sdjwtvc.ClaimMetadata{
			Path:      sdjwtvc.ClaimPath(name),
			Mandatory: name == "family_name" || name == "given_name",
			SD:        sdjwtvc.SDAlways,
		})
	}
	return json.Marshal(md)
}

// registrationCertificate is a Wallet Relying Party Registration
// Certificate (an rc-wrp+jwt) for the verifier, signed with its
// Access Certificate's key (ES512 on P-521, ES256 on P-256): the EUDI
// verifier puts one in every request
// and refuses a transaction without one. Its contents are illustrative.
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
	header := map[string]any{
		"typ": "rc-wrp+jwt",
		"x5c": []string{base64.StdEncoding.EncodeToString(cert.Raw)},
	}
	if key.Curve == elliptic.P521() {
		return signES512(key, header, payload)
	}
	return jose.Sign(jose.ES256, key, header, payload)
}

// signES512 signs payload as a compact JWS under header, ES512 (RFC
// 7518 §3.4) with key, a P-521 key: internal/jose verifies ES512 but
// signs only ES256 and EdDSA.
func signES512(key *ecdsa.PrivateKey, header map[string]any, payload []byte) (string, error) {
	header["alg"] = "ES512"
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha512.Sum512([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 2*66)
	r.FillBytes(sig[:66])
	s.FillBytes(sig[66:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
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
