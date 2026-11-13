// Command setup writes the throwaway key material and configs for
// interop/waltid/run.sh: one test CA the run's parties trust, the TLS
// certificate every party serves under, walt.id Issuer2's credential
// signer and Verifier2's x509_hash Access Certificate under it, the
// HOCON blocks run.sh appends to walt.id's pinned config files, and
// cmd/conformance-verifier's configs for walt.id's Wallet to present
// to. Another CA, which nothing trusts, makes the controls' material.
//
// Two names: Issuer2 and Verifier2, which only OID4VCgo's wallet calls,
// from this host, are localhost (its fetcher reaches loopback in
// development only for a loopback name); everything walt.id's Wallet
// calls from its container (OID4VCgo's issuer and verifiers, the
// attester) is HOST, which the container maps to this host.
//
// Usage: go run ./interop/waltid/scripts/setup -out DIR -host HOST -bind ADDR -issuer-ca FILE -iaca FILE [ports]
//
// DIR receives:
//
//	ca.pem                        the test CA: TLS, Access Certificates, credential signers
//	other-ca.pem                  a CA nothing trusts
//	tls-cert.pem, tls-key.pem     the TLS certificate for HOST
//	issuer2-profiles.conf         appended to Issuer2's issuer2-profiles.conf: its signing key and chains
//	issuer2-service.conf          appended to issuer-service.conf: its base URL, anonymous pre-authorized code
//	verifier2-service.conf        appended to Verifier2's verifier-service.conf: x509_hash client, key, base URL
//	verifier2-key.pem             that key, for the wallet's negative presentations to sign Verifier2's request again
//	wallet2-service.conf          appended to Wallet2's wallet-service.conf: the CA, the attester
//	wallet2-features.conf         appended to Wallet2's _features.conf: no login, no database
//	verifier-sdjwt.json           cmd/conformance-verifier: an SD-JWT VC PID
//	verifier-mdoc.json            cmd/conformance-verifier: an mdoc PID
//	verifier-untrusted-access.json  the SD-JWT VC verifier, its Access Certificate under other-ca.pem
//	verifier-untrusted-issuer.json  the SD-JWT VC verifier, trusting only other-ca.pem's issuers
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
)

// country is every certificate's: an mdoc's document signer must name
// its IACA's country (ISO/IEC 18013-5 Annex B).
const country = "AT"

// authority is a CA: its certificate, its key and the certificate as
// PEM.
type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

// ports are where each party listens; HOST names them all.
type ports struct {
	issuer2, verifier2, attester, verifier int
}

func main() {
	out := flag.String("out", "", "directory to write into")
	host := flag.String("host", "waltid.test", "the name every party is reached by")
	bind := flag.String("bind", "", "the address the verifiers listen on")
	issuerCA := flag.String("issuer-ca", "", "the CA OID4VCgo's issuer's SD-JWT VCs chain to")
	iaca := flag.String("iaca", "", "the IACA OID4VCgo's issuer's mdocs chain to")
	var p ports
	flag.IntVar(&p.issuer2, "issuer2-port", 21411, "Issuer2's TLS port")
	flag.IntVar(&p.verifier2, "verifier2-port", 21412, "Verifier2's TLS port")
	flag.IntVar(&p.attester, "attester-port", 21426, "the attester's TLS port")
	flag.IntVar(&p.verifier, "verifier-port", 21431, "the first of the four verifiers' ports")
	flag.Parse()
	if *out == "" || *bind == "" || *issuerCA == "" || *iaca == "" {
		fail("-out, -bind, -issuer-ca and -iaca are required")
	}
	anchors, err := readAnchors(*issuerCA, *iaca)
	if err != nil {
		fail(err.Error())
	}
	if err := run(*out, *host, *bind, p, anchors); err != nil {
		fail(err.Error())
	}
}

// anchors are what OID4VCgo's issuer's credentials chain to, which the
// verifiers trust.
type anchors struct{ issuerCA, iaca string }

func readAnchors(issuerCA, iaca string) (anchors, error) {
	a, err := os.ReadFile(issuerCA) // #nosec G304 -- the operator's own file
	if err != nil {
		return anchors{}, err
	}
	b, err := os.ReadFile(iaca) // #nosec G304 -- the operator's own file
	if err != nil {
		return anchors{}, err
	}
	return anchors{issuerCA: string(a), iaca: string(b)}, nil
}

func run(dir, host, bind string, p ports, trust anchors) error {
	files := map[string]string{}
	put := func(name, content string) { files[name] = content }

	ca, err := newCA("OID4VCgo walt.id interop CA")
	if err != nil {
		return err
	}
	other, err := newCA("OID4VCgo walt.id interop other CA")
	if err != nil {
		return err
	}
	put("ca.pem", ca.pem)
	put("other-ca.pem", other.pem)

	tlsKey, tlsCert, err := leaf(ca, &x509.Certificate{
		Subject: pkix.Name{CommonName: host}, DNSNames: []string{host, "localhost"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return err
	}
	put("tls-cert.pem", tlsCert)
	if files["tls-key.pem"], err = conformancecert.ECKeyPEM(tlsKey); err != nil {
		return err
	}

	if err := issuer2Files(put, ca, p); err != nil {
		return err
	}
	if err := verifier2File(put, ca, p); err != nil {
		return err
	}
	put("wallet2-service.conf", hocon(
		"attestationConfig.attesterUrl", httpsURL(host, p.attester)+"/attest",
	)+"clientIdTrust.x509TrustAnchors = ["+quote(ca.pem)+"]\n")
	// Wallet2 keeps its wallets in memory and needs no login: the run's
	// wallets are its own, for minutes.
	put("wallet2-features.conf", "enabledFeatures = []\ndisabledFeatures = [auth, wallet2-persistence]\n")

	at := func(i int) (string, string) {
		return net.JoinHostPort(bind, strconv.Itoa(p.verifier+i)), httpsURL(host, p.verifier+i)
	}
	if err := verifierFiles(put, ca, other, trust, files["tls-cert.pem"], files["tls-key.pem"], at); err != nil {
		return err
	}

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

// issuer2Files are Issuer2's: one signing key, its SD-JWT VC chain and
// its mdoc document signer chain under the CA, which every profile
// takes by substitution; its base URL; and the pre-authorized code
// redeemable with no client authentication.
func issuer2Files(put func(name, content string), ca authority, p ports) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	sdjwt, err := leafFor(ca, &key.PublicKey, &x509.Certificate{Subject: pkix.Name{CommonName: "walt.id Issuer2", Country: []string{country}}})
	if err != nil {
		return err
	}
	ds, err := leafFor(ca, &key.PublicKey, &x509.Certificate{
		Subject:            pkix.Name{CommonName: "walt.id Issuer2 document signer", Country: []string{country}},
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{mdoc.MDLDocumentSignerEKU},
	})
	if err != nil {
		return err
	}
	keyJSON, err := json.Marshal(map[string]any{"type": "jwk", "jwk": privateJWK(key)})
	if err != nil {
		return err
	}
	// A key set to null first is replaced, not merged with the one the
	// pinned file sets (HOCON object merging).
	put("issuer2-profiles.conf", "defaultIssuerKey = null\ndefaultIssuerKey = "+string(keyJSON)+"\n"+
		"defaultIssuerX5chain = ["+quote(sdjwt)+"]\n"+
		"defaultMdocIssuerX5chain = ["+quote(ds)+"]\n")
	put("issuer2-service.conf", hocon("baseUrl", httpsURL("localhost", p.issuer2))+
		"clientAuthenticationConfig = null\nclientAuthenticationConfig { supportedMethods = [{ type = \"preauth-anonymous\" }] }\n")
	return nil
}

// verifier2File is Verifier2's: an Access Certificate under the CA, its
// x509_hash Client Identifier, and its base URL.
func verifier2File(put func(name, content string), ca authority, p ports) error {
	key, cert, err := leaf(ca, &x509.Certificate{Subject: pkix.Name{CommonName: "walt.id Verifier2"}})
	if err != nil {
		return err
	}
	block, _ := pem.Decode([]byte(cert))
	hash := sha256.Sum256(block.Bytes)
	keyJSON, err := json.Marshal(map[string]any{"type": "jwk", "jwk": privateJWK(key)})
	if err != nil {
		return err
	}
	// The wallet's negative presentations (scripts/wallet's -tamper)
	// sign Verifier2's request again with it.
	keyPEM, err := conformancecert.ECKeyPEM(key)
	if err != nil {
		return err
	}
	put("verifier2-key.pem", keyPEM)
	put("verifier2-service.conf", hocon(
		"clientId", "x509_hash:"+base64.RawURLEncoding.EncodeToString(hash[:]),
		"urlPrefix", httpsURL("localhost", p.verifier2)+"/verification-session",
	)+"key = null\nkey = "+string(keyJSON)+"\n"+
		"x5c = ["+quote(base64.StdEncoding.EncodeToString(block.Bytes))+"]\n")
	return nil
}

// verifierConfig is cmd/conformance-verifier's Config, as far as the
// run uses it.
type verifierConfig struct {
	ListenAddr                      string   `json:"listen_addr"`
	BaseURL                         string   `json:"base_url"`
	TLSCertificatePEM               string   `json:"tls_certificate_pem"`
	TLSPrivateKeyPEM                string   `json:"tls_private_key_pem"`
	ClientCertificatePEM            string   `json:"client_certificate_pem"`
	ClientPrivateKeyPEM             string   `json:"client_private_key_pem"`
	CredentialFormat                string   `json:"credential_format,omitempty"`
	CredentialIssuerTrustAnchorsPEM string   `json:"credential_issuer_trust_anchors_pem,omitempty"`
	VCT                             string   `json:"vct,omitempty"`
	Claims                          []string `json:"claims,omitempty"`
	Doctype                         string   `json:"doctype,omitempty"`
	Namespace                       string   `json:"namespace,omitempty"`
	MdocClaims                      []string `json:"mdoc_claims,omitempty"`
	MdocTrustAnchorPEM              string   `json:"mdoc_trust_anchor_pem,omitempty"`
}

// verifierFiles are the four cmd/conformance-verifier configs, the ith
// listening and reached at at(i), for OID4VCgo's issuer's PIDs: the SD-JWT
// VC's, the mdoc's, and two controls, the first with an Access
// Certificate walt.id's Wallet doesn't trust, the second trusting no
// issuer of the run's.
func verifierFiles(put func(name, content string), ca, other authority, trust anchors, tlsCert, tlsKey string,
	at func(i int) (addr, baseURL string)) error {
	accessKey, accessCert, err := leaf(ca, &x509.Certificate{Subject: pkix.Name{CommonName: "OID4VCgo verifier"}})
	if err != nil {
		return err
	}
	untrustedKey, untrustedCert, err := leaf(other, &x509.Certificate{Subject: pkix.Name{CommonName: "OID4VCgo untrusted verifier"}})
	if err != nil {
		return err
	}
	keyPEM := func(k *ecdsa.PrivateKey) string {
		s, err := conformancecert.ECKeyPEM(k)
		if err != nil {
			fail(err.Error())
		}
		return s
	}
	sdjwt := func(i int) verifierConfig {
		addr, base := at(i)
		return verifierConfig{
			ListenAddr: addr, BaseURL: base, TLSCertificatePEM: tlsCert, TLSPrivateKeyPEM: tlsKey,
			ClientCertificatePEM: accessCert, ClientPrivateKeyPEM: keyPEM(accessKey),
			CredentialIssuerTrustAnchorsPEM: trust.issuerCA, VCT: "urn:eudi:pid:1", Claims: []string{"family_name", "given_name"},
		}
	}
	addr, base := at(1)
	mdl := verifierConfig{
		ListenAddr: addr, BaseURL: base, TLSCertificatePEM: tlsCert, TLSPrivateKeyPEM: tlsKey,
		ClientCertificatePEM: accessCert, ClientPrivateKeyPEM: keyPEM(accessKey),
		CredentialFormat: mdoc.CredentialFormat, Doctype: "eu.europa.ec.eudi.pid.1", Namespace: "eu.europa.ec.eudi.pid.1",
		MdocClaims: []string{"family_name", "given_name"}, MdocTrustAnchorPEM: trust.iaca,
	}
	untrustedAccess := sdjwt(2)
	untrustedAccess.ClientCertificatePEM, untrustedAccess.ClientPrivateKeyPEM = untrustedCert, keyPEM(untrustedKey)
	untrustedIssuer := sdjwt(3)
	untrustedIssuer.CredentialIssuerTrustAnchorsPEM = other.pem
	for name, cfg := range map[string]verifierConfig{
		"verifier-sdjwt.json": sdjwt(0), "verifier-mdoc.json": mdl,
		"verifier-untrusted-access.json": untrustedAccess, "verifier-untrusted-issuer.json": untrustedIssuer,
	} {
		raw, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return err
		}
		put(name, string(raw))
	}
	return nil
}

// newCA is a self-signed P-256 CA naming country, as an mdoc IACA must
// (ISO/IEC 18013-5 Annex B), valid for a day.
func newCA(commonName string) (authority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return authority{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: commonName, Country: []string{country}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return authority{}, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return authority{}, err
	}
	return authority{cert: cert, key: key, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}, nil
}

// httpsURL is the https origin of host and port.
func httpsURL(host string, port int) string {
	return "https://" + net.JoinHostPort(host, strconv.Itoa(port))
}

// leaf is a fresh P-256 key and its certificate from tmpl under ca, as
// PEM.
func leaf(ca authority, tmpl *x509.Certificate) (*ecdsa.PrivateKey, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	cert, err := leafFor(ca, &key.PublicKey, tmpl)
	return key, cert, err
}

// leafFor is pub's certificate from tmpl under ca, for a day, as PEM:
// a signing key, never a CA.
func leafFor(ca authority, pub *ecdsa.PublicKey, tmpl *x509.Certificate) (string, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return "", err
	}
	tmpl.SerialNumber = serial
	tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		return "", fmt.Errorf("certificate %q: %w", tmpl.Subject.CommonName, err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}

// privateJWK is a P-256 private key's JWK.
func privateJWK(k *ecdsa.PrivateKey) map[string]string {
	point, err := k.PublicKey.Bytes()
	if err != nil || len(point) != 65 {
		fail("not a P-256 key")
	}
	d, err := k.Bytes()
	if err != nil {
		fail(err.Error())
	}
	b := base64.RawURLEncoding.EncodeToString
	return map[string]string{"kty": "EC", "crv": "P-256", "x": b(point[1:33]), "y": b(point[33:]), "d": b(d)}
}

// hocon is "key = value" lines from pairs of key and string value.
func hocon(pairs ...string) string {
	var b strings.Builder
	for i := 0; i+1 < len(pairs); i += 2 {
		fmt.Fprintf(&b, "%s = %s\n", pairs[i], quote(pairs[i+1]))
	}
	return b.String()
}

// quote is s as a JSON string, which HOCON reads as one.
func quote(s string) string {
	raw, err := json.Marshal(s)
	if err != nil {
		fail(err.Error())
	}
	return string(raw)
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "setup:", msg)
	os.Exit(1)
}
