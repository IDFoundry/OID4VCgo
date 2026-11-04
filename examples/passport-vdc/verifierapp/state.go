package verifierapp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/democert"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/statefile"
	"github.com/idfoundry/oid4vcgo/mdocdcapi"
)

// identities are the verifier's request-signing identities: one per
// scenario, each a key and a certificate naming the scenario's relying
// party, issued by the verifier CA wallets trust, or for an untrusted
// scenario by a CA they don't (HAIP 1.0 §5: the certificate signing a
// request must not be self-signed); a certificate's hash is its
// scenario's x509_hash client identifier. The CAs wallets trust — the
// verifier, registrar and mdoc reader CAs — keep their keys, to sign
// the CRLs their certificates name (crl.go); the untrusted CA's key is
// discarded once its certificates are made.
type identities struct {
	ca, untrustedCA *x509.Certificate
	caKey           *ecdsa.PrivateKey
	signers         map[Scenario]signer
	// registrar registers the trusted scenarios' relying parties
	// (registrations), under registrarCA, which wallets trust for that.
	registrarCA    *x509.Certificate
	registrarCAKey *ecdsa.PrivateKey
	registrar      signer
	// readerCA issues the trusted scenarios' mdoc reader authentication
	// certificates, which sign their org-iso-mdoc requests; an untrusted
	// scenario's is the untrusted CA's. Each has the ISO/IEC 18013-5
	// reader authentication extended key usage, and none is an OpenID4VP
	// request signer's.
	readerCA    *x509.Certificate
	readerCAKey *ecdsa.PrivateKey
	readers     map[Scenario]signer
}

// readerAuthenticationEKU is ISO/IEC 18013-5 Annex B's mdoc reader
// authentication extended key usage (mdocdcapi.ReaderAuthenticationEKU).
var readerAuthenticationEKU = mdocdcapi.ReaderAuthenticationEKU

type signer struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

// demoOrganization is the organization every demo certificate names.
const demoOrganization = "IDFoundry demo"

// identityFile is the file a verifier keeps its identities in, in
// Config.StateDir.
const identityFile = "verifier-identity.pem"

// PEM block roles in identityFile: the CAs, and "signer:" + a scenario.
const (
	roleHeader      = "Role"
	roleCA          = "ca"
	roleUntrustedCA = "untrusted-ca"
	roleRegistrarCA = "registrar-ca"
	roleRegistrar   = "registrar"
	roleSignerPre   = "signer:"
	roleReaderCA    = "reader-ca"
	roleReaderPre   = "reader:"
)

// renewBefore is how long before a signing certificate expires saved
// identities are replaced with new ones.
const renewBefore = 30 * 24 * time.Hour

// loadIdentities returns the verifier's identities, their trusted CAs'
// certificates naming CRL distribution points under base (the
// VerifierURL): kept in dir when set, so wallets that trust its CA
// still do after a restart; generated afresh otherwise. Saved ones are
// replaced, all together, when any scenario's is missing or names
// another relying party, a certificate expires within renewBefore, or
// a trusted CA has no key or names no distribution point under base —
// for identities from before the CAs published CRLs, a one-time
// migration, logged.
func loadIdentities(dir string, now time.Time, base string) (identities, error) {
	if dir == "" {
		return newIdentities(now, base)
	}
	path := filepath.Join(dir, identityFile)
	data, err := os.ReadFile(path) // #nosec G304 -- operator-supplied state directory
	switch {
	case err == nil:
		ids, err := parseIdentities(data)
		if err != nil {
			return identities{}, fmt.Errorf("verifierapp: %s: %w", path, err)
		}
		if !ids.current(now) {
			break
		}
		if ids.publishesCRLs(base) {
			return ids, nil
		}
		log.Printf("verifierapp: %s: its CAs have no keys or don't name CRL distribution points under %s (from before the demo verifier published CRLs); replacing them with new CAs: wallets that trust the old ones need the new verifier-ca.pem, mdoc-reader-ca.pem and registrar-ca.pem", path, base)
	case !errors.Is(err, fs.ErrNotExist):
		return identities{}, fmt.Errorf("verifierapp: read %s: %w", path, err)
	}
	ids, err := newIdentities(now, base)
	if err != nil {
		return identities{}, err
	}
	encoded, err := ids.encode()
	if err != nil {
		return identities{}, err
	}
	if err := statefile.WriteAtomic(path, encoded); err != nil {
		return identities{}, fmt.Errorf("verifierapp: %w", err)
	}
	return ids, nil
}

// current reports whether ids has an identity for every scenario, named
// for its relying party, none expiring within renewBefore.
func (ids identities) current(now time.Time) bool {
	if ids.ca == nil || ids.untrustedCA == nil || ids.registrarCA == nil || ids.registrar.key == nil || !ids.registrar.cert.NotAfter.After(now.Add(renewBefore)) {
		return false
	}
	// A registrar certificate from before its iss was bound to it.
	if !slices.ContainsFunc(ids.registrar.cert.URIs, func(u *url.URL) bool { return u.String() == registrarID }) {
		return false
	}
	if ids.readerCA == nil {
		return false
	}
	for _, s := range Scenarios {
		info, _ := s.Info()
		sg, ok := ids.signers[s]
		if !ok || sg.cert.Subject.CommonName != info.Verifier || !sg.cert.NotAfter.After(now.Add(renewBefore)) {
			return false
		}
		rd, ok := ids.readers[s]
		if !ok || rd.cert.Subject.CommonName != info.Verifier || !rd.cert.NotAfter.After(now.Add(renewBefore)) ||
			!slices.ContainsFunc(rd.cert.UnknownExtKeyUsage, readerAuthenticationEKU.Equal) {
			return false
		}
	}
	return true
}

// publishesCRLs reports whether each of ids' trusted CAs has its key,
// to sign its CRL with, and names its distribution point under base.
func (ids identities) publishesCRLs(base string) bool {
	for path, ca := range map[string]signer{
		VerifierCRLPath:  {cert: ids.ca, key: ids.caKey},
		ReaderCRLPath:    {cert: ids.readerCA, key: ids.readerCAKey},
		RegistrarCRLPath: {cert: ids.registrarCA, key: ids.registrarCAKey},
	} {
		if ca.key == nil || ca.cert.KeyUsage&x509.KeyUsageCRLSign == 0 || !slices.Equal(ca.cert.CRLDistributionPoints, []string{base + path}) {
			return false
		}
	}
	return true
}

// newIdentities generates a trusted and an untrusted CA, and an identity
// for each scenario under the one its trust calls for. The trusted CAs
// name distribution points under base for their CRLs.
func newIdentities(now time.Time, base string) (identities, error) {
	ids := identities{signers: map[Scenario]signer{}, readers: map[Scenario]signer{}}
	ca, caKey, err := newCA(now, "passport-vdc demo verifier CA", base+VerifierCRLPath)
	if err != nil {
		return identities{}, err
	}
	untrustedCA, untrustedKey, err := newCA(now, "passport-vdc demo untrusted verifier CA", "")
	if err != nil {
		return identities{}, err
	}
	ids.ca, ids.caKey, ids.untrustedCA = ca, caKey, untrustedCA
	registrarCA, registrarCAKey, err := newCA(now, "passport-vdc demo registrar CA", base+RegistrarCRLPath)
	if err != nil {
		return identities{}, err
	}
	ids.registrarCA, ids.registrarCAKey = registrarCA, registrarCAKey
	if ids.registrar, err = newSigner(now, "passport-vdc demo registrar", registrarCA, registrarCAKey, registrarID); err != nil {
		return identities{}, err
	}
	readerCA, readerCAKey, err := newCA(now, "passport-vdc demo mdoc reader CA", base+ReaderCRLPath)
	if err != nil {
		return identities{}, err
	}
	ids.readerCA, ids.readerCAKey = readerCA, readerCAKey
	for _, s := range Scenarios {
		info, _ := s.Info()
		parent, parentKey := ca, caKey
		readerParent, readerParentKey := readerCA, readerCAKey
		if !info.Trusted {
			parent, parentKey = untrustedCA, untrustedKey
			readerParent, readerParentKey = untrustedCA, untrustedKey
		}
		sg, err := newSigner(now, info.Verifier, parent, parentKey, "")
		if err != nil {
			return identities{}, err
		}
		ids.signers[s] = sg
		if ids.readers[s], err = newReader(now, info.Verifier, readerParent, readerParentKey); err != nil {
			return identities{}, err
		}
	}
	return ids, nil
}

// newReader generates an mdoc reader authentication key and certificate
// naming name, issued by parent, with the reader authentication
// extended key usage, and parent's CRL distribution points (those of
// its CRL), if any.
func newReader(now time.Time, name string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return signer{}, fmt.Errorf("verifierapp: key: %w", err)
	}
	cert, err := democert.Create(&x509.Certificate{
		Subject:   pkix.Name{CommonName: name, Organization: []string{demoOrganization}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, UnknownExtKeyUsage: []asn1.ObjectIdentifier{readerAuthenticationEKU},
		CRLDistributionPoints: parent.CRLDistributionPoints,
	}, parent, &key.PublicKey, parentKey)
	if err != nil {
		return signer{}, fmt.Errorf("verifierapp: %w", err)
	}
	return signer{key: key, cert: cert}, nil
}

// newSigner generates a signing key and a certificate naming name,
// issued by parent, with uri as its URI subject alternative name when
// set (a registrar's identifier, which its registrations' iss must
// match), and parent's CRL distribution points, if any.
func newSigner(now time.Time, name string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, uri string) (signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return signer{}, fmt.Errorf("verifierapp: key: %w", err)
	}
	tmpl := &x509.Certificate{
		Subject:   pkix.Name{CommonName: name, Organization: []string{demoOrganization}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		CRLDistributionPoints: parent.CRLDistributionPoints,
	}
	if uri != "" {
		u, err := url.Parse(uri)
		if err != nil {
			return signer{}, fmt.Errorf("verifierapp: %w", err)
		}
		tmpl.URIs = []*url.URL{u}
	}
	cert, err := democert.Create(tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		return signer{}, fmt.Errorf("verifierapp: %w", err)
	}
	return signer{key: key, cert: cert}, nil
}

// newCA generates a self-signed CA certificate naming name and its key.
// With crlURL set, the CA signs a CRL served there, which its
// certificate names as its distribution point.
func newCA(now time.Time, name, crlURL string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("verifierapp: CA key: %w", err)
	}
	tmpl := &x509.Certificate{
		Subject:   pkix.Name{CommonName: name, Organization: []string{demoOrganization}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
	}
	if crlURL != "" {
		tmpl.KeyUsage |= x509.KeyUsageCRLSign
		tmpl.CRLDistributionPoints = []string{crlURL}
	}
	cert, err := democert.Create(tmpl, nil, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("verifierapp: %w", err)
	}
	return cert, key, nil
}

func (ids identities) encode() ([]byte, error) {
	var out []byte
	for _, ca := range []struct {
		role string
		key  *ecdsa.PrivateKey
	}{{roleCA, ids.caKey}, {roleRegistrarCA, ids.registrarCAKey}, {roleReaderCA, ids.readerCAKey}} {
		der, err := x509.MarshalECPrivateKey(ca.key)
		if err != nil {
			return nil, fmt.Errorf("verifierapp: encode %s key: %w", ca.role, err)
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Headers: map[string]string{roleHeader: ca.role}, Bytes: der})...)
	}
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{roleHeader: roleCA}, Bytes: ids.ca.Raw})...)
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{roleHeader: roleUntrustedCA}, Bytes: ids.untrustedCA.Raw})...)
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{roleHeader: roleRegistrarCA}, Bytes: ids.registrarCA.Raw})...)
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{roleHeader: roleReaderCA}, Bytes: ids.readerCA.Raw})...)
	signers := []struct {
		role string
		sg   signer
	}{{roleRegistrar, ids.registrar}}
	for _, s := range Scenarios {
		signers = append(signers, struct {
			role string
			sg   signer
		}{roleSignerPre + string(s), ids.signers[s]}, struct {
			role string
			sg   signer
		}{roleReaderPre + string(s), ids.readers[s]})
	}
	for _, e := range signers {
		der, err := x509.MarshalECPrivateKey(e.sg.key)
		if err != nil {
			return nil, fmt.Errorf("verifierapp: encode %s key: %w", e.role, err)
		}
		role := map[string]string{roleHeader: e.role}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Headers: role, Bytes: der})...)
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: role, Bytes: e.sg.cert.Raw})...)
	}
	return out, nil
}

// parseIdentities reads an identityFile: the CA certificates, with the
// trusted CAs' keys (missing in a file from before they kept them, for
// publishesCRLs to catch, but each there must be its CA's), and for
// each scenario a key with its certificate, which must be for that key
// and issued by the CA the scenario's trust calls for. A scenario with
// no identity in it is left out, for current to catch.
func parseIdentities(data []byte) (identities, error) {
	certs, keys, err := decodeBlocks(data)
	if err != nil {
		return identities{}, err
	}
	ids := identities{
		signers: map[Scenario]signer{}, readers: map[Scenario]signer{},
		ca: certs[roleCA], untrustedCA: certs[roleUntrustedCA], registrarCA: certs[roleRegistrarCA], readerCA: certs[roleReaderCA],
		caKey: keys[roleCA], registrarCAKey: keys[roleRegistrarCA], readerCAKey: keys[roleReaderCA],
	}
	if ids.ca == nil || ids.untrustedCA == nil {
		// An older layout (one CA, one request signer): not current, so
		// replaced, rather than an error.
		return identities{signers: map[Scenario]signer{}}, nil
	}
	for _, ca := range []signer{{cert: ids.ca, key: ids.caKey}, {cert: ids.registrarCA, key: ids.registrarCAKey}, {cert: ids.readerCA, key: ids.readerCAKey}} {
		if ca.key != nil && (ca.cert == nil || !ca.key.PublicKey.Equal(ca.cert.PublicKey)) {
			return identities{}, errors.New("a CA key isn't its CA certificate's")
		}
	}
	if ids.registrarCA != nil || certs[roleRegistrar] != nil {
		r := signer{key: keys[roleRegistrar], cert: certs[roleRegistrar]}
		if ids.registrarCA == nil || checkSigner(r, ids.registrarCA) != nil {
			return identities{}, errors.New("the registrar's identity is incomplete or doesn't chain to its CA")
		}
		ids.registrar = r
	}
	for _, s := range Scenarios {
		if err := ids.parseScenario(s, certs, keys); err != nil {
			return identities{}, err
		}
	}
	return ids, nil
}

// parseScenario adds s's request signer and mdoc reader from an
// identityFile's blocks to ids, each checked against the CA s's trust
// calls for. One missing is left out, for current to catch.
func (ids identities) parseScenario(s Scenario, certs map[string]*x509.Certificate, keys map[string]*ecdsa.PrivateKey) error {
	info, _ := s.Info()
	parent, readerParent := ids.ca, ids.readerCA
	if !info.Trusted {
		parent, readerParent = ids.untrustedCA, ids.untrustedCA
	}
	role := roleSignerPre + string(s)
	if certs[role] == nil {
		return nil
	}
	sg := signer{key: keys[role], cert: certs[role]}
	if err := checkSigner(sg, parent); err != nil {
		return fmt.Errorf("%s: %w", s, err)
	}
	ids.signers[s] = sg
	readerRole := roleReaderPre + string(s)
	if certs[readerRole] == nil || ids.readerCA == nil {
		return nil
	}
	rd := signer{key: keys[readerRole], cert: certs[readerRole]}
	if err := checkSigner(rd, readerParent); err != nil {
		return fmt.Errorf("%s reader: %w", s, err)
	}
	ids.readers[s] = rd
	return nil
}

// decodeBlocks reads an identityFile's certificates and keys, by role.
func decodeBlocks(data []byte) (map[string]*x509.Certificate, map[string]*ecdsa.PrivateKey, error) {
	certs := map[string]*x509.Certificate{}
	keys := map[string]*ecdsa.PrivateKey{}
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		role := block.Headers[roleHeader]
		switch block.Type {
		case "CERTIFICATE":
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("%s certificate: %w", role, err)
			}
			certs[role] = c
		case "EC PRIVATE KEY":
			k, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("%s key: %w", role, err)
			}
			keys[role] = k
		}
	}
	return certs, keys, nil
}

// checkSigner checks sg's certificate is for its key and issued by
// parent.
func checkSigner(sg signer, parent *x509.Certificate) error {
	if sg.key == nil || sg.cert == nil || !sg.key.PublicKey.Equal(sg.cert.PublicKey) {
		return errors.New("the signing certificate isn't for its key")
	}
	if err := sg.cert.CheckSignatureFrom(parent); err != nil {
		return fmt.Errorf("the signing certificate isn't its CA's: %w", err)
	}
	return nil
}
