// Command setup writes the throwaway key material and EUDIPLO's config
// folder for interop/eudiplo/run.sh: the run's CA, the TLS certificate
// EUDIPLO and the tap in front of OID4VCgo's issuer serve, EUDIPLO's
// Access Certificate under the CA, and one EUDIPLO tenant, imported at
// startup, whose trust lists name OID4VCgo's issuer's CAs and, for the
// controls, a CA that issued nothing.
//
// It also writes EUDIPLO's issuer, in that tenant and in a second one
// requiring Credential Request and Response encryption (issuer.go):
// its signing keys under CAs of the run's, and a trust list naming
// OID4VCgo's Wallet Provider's CA (-wallet-provider-ca) as a wallet
// provider.
//
// Usage: go run ./interop/eudiplo/scripts/setup -out DIR -host HOST -issuer-ca FILE -iaca FILE -wallet-provider-ca FILE -public-url URL
//
// DIR receives:
//
//	ca.pem, other-ca.pem          the run's CA, and a CA nothing was issued under
//	tls-cert.pem, tls-key.pem     TLS for localhost and HOST, under ca.pem
//	verifier-key.pem              EUDIPLO's Access Certificate key, for the wallet's negative presentations
//	client.json                   the tenant's API client: {"id", "secret"}
//	enc-client.json               the encrypting tenant's
//	eudiplo-issuer-ca.pem         the CA EUDIPLO's SD-JWT VCs and status lists chain to
//	eudiplo-iaca.pem              the IACA its mdocs chain to
//	eudiplo/config/TENANT/...     EUDIPLO's config folder (CONFIG_FOLDER), eudiplo/ its FOLDER
//
// The tenant holds: its API client; the Access Certificate's key chain
// (standalone, leaf only) and a key chain that signs its trust lists;
// the trust lists oid4vcgo-issuers (OID4VCgo's issuer's SD-JWT VC CA
// and IACA, each its own issuer and revocation certificate, as the
// issuer signs its status lists with its credential signers) and
// other-issuers (other-ca.pem alone); and the presentation configs
// pid-sdjwt, pid-mdoc (both trusting oid4vcgo-issuers) and
// pid-sdjwt-untrusted (trusting other-issuers), status checked
// strictly, EUDIPLO's default; and pid-mdoc-annexc, pid-mdoc's query
// for ISO/IEC TS 18013-7 Annex C requests, which the Access
// Certificate signs (readerAuth).
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
)

// tenant is the EUDIPLO tenant's id, its config folder's name.
const tenant = "oid4vcgo"

// The PID OID4VCgo's issuer issues (interop/eudi/scripts/setup-issuer).
const (
	pidVCT       = "urn:eudi:pid:1"
	pidDocType   = "eu.europa.ec.eudi.pid.1"
	pidNamespace = "eu.europa.ec.eudi.pid.1"
)

// Each config document's $schema, as EUDIPLO 10.1 publishes them.
const (
	schemaBase         = "https://eudiplo.dev/schemas/"
	tenantSchema       = schemaBase + "v4/TenantConfigFile.schema.json"
	clientSchema       = schemaBase + "v2/ClientConfigFile.schema.json"
	keyChainSchema     = schemaBase + "v4/KeyChainConfigFile.schema.json"
	trustListSchema    = schemaBase + "v2/TrustListConfigFile.schema.json"
	presentationSchema = schemaBase + "v5/PresentationConfigFile.schema.json"
)

// Key chain ids in the tenant.
const (
	accessKeyChain    = "oid4vcgo-access"
	trustListKeyChain = "oid4vcgo-trust-list"
)

// keyChainsDir is the tenant's folder of key chain documents.
const keyChainsDir = "key-chains"

// issuersTrustList is the id of the trust list of OID4VCgo's issuer's
// CAs, which the presentation configs' queries name.
const issuersTrustList = "oid4vcgo-issuers"

func main() {
	out := flag.String("out", "", "directory to write into")
	host := flag.String("host", "", "the name EUDIPLO's container reaches this host by")
	issuerCA := flag.String("issuer-ca", "", "the CA OID4VCgo's issuer's SD-JWT VCs chain to")
	iaca := flag.String("iaca", "", "the IACA OID4VCgo's issuer's mdocs chain to")
	wpCA := flag.String("wallet-provider-ca", "", "the CA OID4VCgo's Wallet Provider's attestations chain to, which EUDIPLO's issuer trusts")
	publicURL := flag.String("public-url", "", "EUDIPLO's PUBLIC_URL, the iss of its status lists")
	flag.Parse()
	if *out == "" || *host == "" || *issuerCA == "" || *iaca == "" || *wpCA == "" || *publicURL == "" {
		fail("-out, -host, -issuer-ca, -iaca, -wallet-provider-ca and -public-url are required")
	}
	if err := run(*out, *host, *issuerCA, *iaca, *wpCA, *publicURL); err != nil {
		fail(err.Error())
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "setup:", msg)
	os.Exit(1)
}

// files is what setup writes, by path below the output directory.
type files map[string]string

func (f files) json(name string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	f[name] = string(raw) + "\n"
	return nil
}

// doc is an EUDIPLO config document: its schema, and its spec.
func doc(schema string, spec any) map[string]any {
	return map[string]any{"$schema": schema, "metadata": map[string]any{"generation": 1}, "spec": spec}
}

func run(dir, host, issuerCAFile, iacaFile, wpCAFile, publicURL string) error {
	issuerCA, err := os.ReadFile(issuerCAFile) // #nosec G304 -- the operator's own file
	if err != nil {
		return err
	}
	iaca, err := os.ReadFile(iacaFile) // #nosec G304 -- the operator's own file
	if err != nil {
		return err
	}
	wpCA, err := os.ReadFile(wpCAFile) // #nosec G304 -- the operator's own file
	if err != nil {
		return err
	}
	f := files{}
	ca, caKey, caPEM, _, err := conformancecert.GenerateCA("OID4VCgo EUDIPLO interop CA")
	if err != nil {
		return err
	}
	_, _, otherPEM, _, err := conformancecert.GenerateCA("OID4VCgo EUDIPLO interop other CA")
	if err != nil {
		return err
	}
	f["ca.pem"], f["other-ca.pem"] = caPEM, otherPEM

	tlsKey, tlsCert, err := issue(ca, caKey, &x509.Certificate{
		Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost", host},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return err
	}
	f["tls-cert.pem"] = tlsCert
	if f["tls-key.pem"], err = conformancecert.ECKeyPEM(tlsKey); err != nil {
		return err
	}
	// The Access Certificate: EUDIPLO's x509_hash client, under the run's
	// CA, which OID4VCgo's wallet trusts for Verifiers.
	accessKey, accessCert, err := issue(ca, caKey, &x509.Certificate{
		Subject:  pkix.Name{CommonName: "OID4VCgo EUDIPLO interop Verifier", Organization: []string{"OID4VCgo interop"}},
		DNSNames: []string{"localhost"}, KeyUsage: x509.KeyUsageDigitalSignature,
	})
	if err != nil {
		return err
	}
	if f["verifier-key.pem"], err = conformancecert.ECKeyPEM(accessKey); err != nil {
		return err
	}
	listKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	secret, err := client(f, "client.json", tenant)
	if err != nil {
		return err
	}
	if err := tenantFiles(f, secret, accessKey, accessCert, listKey, string(issuerCA), string(iaca), f["other-ca.pem"]); err != nil {
		return err
	}
	keys, err := newIssuerKeys(f, publicURL)
	if err != nil {
		return err
	}
	if err := issuerFiles(f, tenant, keys, listKey, string(wpCA), false); err != nil {
		return err
	}
	encSecret, err := client(f, "enc-client.json", encTenant)
	if err != nil {
		return err
	}
	if err := encTenantFiles(f, encSecret); err != nil {
		return err
	}
	if err := issuerFiles(f, encTenant, keys, listKey, string(wpCA), true); err != nil {
		return err
	}
	for name, content := range f {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		// EUDIPLO's image runs as root, which reads them as they are.
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			return err
		}
	}
	return nil
}

// tenantFiles adds the tenant's config folder to f.
func tenantFiles(f files, secret string, accessKey *ecdsa.PrivateKey, accessCert string, listKey *ecdsa.PrivateKey,
	issuerCA, iaca, otherCA string) error {
	at := func(parts ...string) string {
		return filepath.Join(append([]string{"eudiplo", "config", tenant}, parts...)...)
	}
	docs := map[string]any{
		at("info.json"): doc(tenantSchema, map[string]any{
			"name": "OID4VCgo interop", "description": "OID4VCgo's wallet presents to this tenant's Verifier, and receives from its issuer",
		}),
		at("clients", "run.json"): clientDoc(tenant, secret),
		at(keyChainsDir, "access.json"): doc(keyChainSchema, map[string]any{
			"id": accessKeyChain, "description": "Access Certificate", "usageType": "access", "type": "standalone",
			"keySource":   map[string]any{"type": "private-jwk", "jwk": privateJWK(accessKey, accessKeyChain)},
			"kmsProvider": "db", "crt": []string{accessCert},
		}),
		at(keyChainsDir, "trust-list.json"): doc(keyChainSchema, map[string]any{
			"id": trustListKeyChain, "description": "signs the tenant's trust lists", "usageType": "trustList",
			"keySource":   map[string]any{"type": "private-jwk", "jwk": privateJWK(listKey, trustListKeyChain)},
			"kmsProvider": "db",
		}),
		at("trust-lists", issuersTrustList+".json"): trustList(issuersTrustList, "OID4VCgo's issuer's CAs",
			entity("OID4VCgo issuer, SD-JWT VC", issuerCA), entity("OID4VCgo issuer, mdoc", iaca)),
		at("trust-lists", "other-issuers.json"): trustList("other-issuers", "a CA that issued nothing presented",
			entity("Unrelated issuer", otherCA)),
		at("presentation", "pid-sdjwt.json"):           presentation("pid-sdjwt", sdjwtQuery(issuersTrustList)),
		at("presentation", "pid-sdjwt-untrusted.json"): presentation("pid-sdjwt-untrusted", sdjwtQuery("other-issuers")),
		at("presentation", "pid-mdoc.json"):            presentation("pid-mdoc", mdocQuery(issuersTrustList)),
		at("presentation", "pid-mdoc-annexc.json"):     readerAuth(presentation("pid-mdoc-annexc", mdocQuery(issuersTrustList))),
	}
	for name, v := range docs {
		if err := f.json(name, v); err != nil {
			return err
		}
	}
	return nil
}

// client adds to f, as name, a fresh API client of tenant t, returning
// its secret.
func client(f files, name, t string) (string, error) {
	secret, err := randomHex(32)
	if err != nil {
		return "", err
	}
	return secret, f.json(name, map[string]string{"id": t + "-run", "secret": secret})
}

// clientDoc is tenant t's API client, for the Verifier's sessions and
// the issuer's offers and credentials' statuses.
func clientDoc(t, secret string) map[string]any {
	return doc(clientSchema, map[string]any{
		"clientId": t + "-run", "secret": secret, "description": "interop/eudiplo/run.sh",
		"roles": []string{"presentation:manage", "presentation:request", "sessions:read", "issuance:offer", "credentials:status"},
	})
}

// encTenantFiles adds the encrypting tenant's info and client to f.
func encTenantFiles(f files, secret string) error {
	at := func(parts ...string) string {
		return filepath.Join(append([]string{"eudiplo", "config", encTenant}, parts...)...)
	}
	if err := f.json(at("info.json"), doc(tenantSchema, map[string]any{
		"name": "OID4VCgo interop, encrypted", "description": "an issuer requiring Credential Request and Response encryption",
	})); err != nil {
		return err
	}
	return f.json(at("clients", "run.json"), clientDoc(encTenant, secret))
}

// trustList is a managed trust list, signed by the tenant's trust list
// key chain.
func trustList(id, description string, entities ...map[string]any) map[string]any {
	return doc(trustListSchema, map[string]any{
		"id": id, "description": description, "keyChainId": trustListKeyChain, "entities": entities,
	})
}

// entity is an external trusted entity whose credentials and status
// lists are both signed under the CA certificate caPEM.
func entity(name, caPEM string) map[string]any {
	return map[string]any{
		"type": "external", "issuerCertPem": caPEM, "revocationCertPem": caPEM,
		"info": map[string]any{
			"name": name, "country": "AT", "contactUri": "interop@example.com", "website": "https://example.com/",
		},
	}
}

// presentation is a presentation config for query.
func presentation(id string, query map[string]any) map[string]any {
	return doc(presentationSchema, map[string]any{
		"id": id, "description": "interop/eudiplo/run.sh: " + id, "accessKeyChainId": accessKeyChain,
		"statusCheckMode": "strict", "dcql_query": query,
	})
}

// readerAuth has an ISO/IEC TS 18013-7 Annex C request of config d
// signed by its Access Certificate (readerAuth).
func readerAuth(d map[string]any) map[string]any {
	d["spec"].(map[string]any)["readerAuth"] = true
	return d
}

func trusted(list string) []map[string]any {
	return []map[string]any{{"type": "etsi_tl", "values": []map[string]string{{"trustListId": list}}}}
}

// sdjwtQuery asks for the PID's family_name and birth_date, both
// selectively disclosable.
func sdjwtQuery(list string) map[string]any {
	return map[string]any{"credentials": []map[string]any{{
		"id": "pid", "format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []string{pidVCT}},
		"claims":              []map[string]any{{"path": []string{"family_name"}}, {"path": []string{"birth_date"}}},
		"trusted_authorities": trusted(list),
	}}}
}

// mdocQuery asks for the mdoc PID's family_name.
func mdocQuery(list string) map[string]any {
	return map[string]any{"credentials": []map[string]any{{
		"id": "pid", "format": "mso_mdoc", "meta": map[string]any{"doctype_value": pidDocType},
		"claims":              []map[string]any{{"path": []string{pidNamespace, "family_name"}}},
		"trusted_authorities": trusted(list),
	}}}
}

// issue is a fresh P-256 key and its certificate from tmpl under ca,
// for a day, as PEM.
func issue(ca *x509.Certificate, caKey *ecdsa.PrivateKey, tmpl *x509.Certificate) (*ecdsa.PrivateKey, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	if tmpl.SerialNumber, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64)); err != nil {
		return nil, "", err
	}
	tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, "", fmt.Errorf("certificate %q: %w", tmpl.Subject.CommonName, err)
	}
	return key, pemCert(der), nil
}

func pemCert(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// privateJWK is k's private JWK, as EUDIPLO's private-jwk key source
// takes it: P-256, its coordinates and d each 32 bytes.
func privateJWK(k *ecdsa.PrivateKey, kid string) map[string]string {
	enc := base64.RawURLEncoding.EncodeToString
	jwk := map[string]string{"kty": "EC", "crv": "P-256", "alg": "ES256", "kid": kid}
	if uncompressed, err := k.PublicKey.Bytes(); err == nil && len(uncompressed) == 65 {
		jwk["x"], jwk["y"] = enc(uncompressed[1:33]), enc(uncompressed[33:])
	}
	if d, err := k.Bytes(); err == nil {
		jwk["d"] = enc(d)
	}
	return jwk
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
