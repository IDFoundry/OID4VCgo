package mobile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func ekuCert(t *testing.T, standard []x509.ExtKeyUsage, custom []asn1.ObjectIdentifier) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "eku test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: standard, UnknownExtKeyUsage: custom,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// The leaf's extended key usage extension is read as is, so a standard
// usage (which Go files under ExtKeyUsage) and a private one (under
// UnknownExtKeyUsage) both match.
func TestRequireEKU(t *testing.T) {
	private := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}
	for name, tc := range map[string]struct {
		cert   *x509.Certificate
		oid    string
		wantOK bool
	}{
		"standard (clientAuth)": {ekuCert(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil), "1.3.6.1.5.5.7.3.2", true},
		"private":               {ekuCert(t, nil, []asn1.ObjectIdentifier{private}), "1.3.6.1.4.1.99999.1", true},
		"another usage":         {ekuCert(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil), "1.3.6.1.5.5.7.3.2", false},
		"no usage at all":       {ekuCert(t, nil, nil), "1.3.6.1.5.5.7.3.2", false},
	} {
		policy, err := roleEKU("verifier_require_eku", tc.oid)
		if err != nil {
			t.Fatal(err)
		}
		if err := policy(tc.cert, nil); (err == nil) != tc.wantOK {
			t.Errorf("%s: %v, want ok = %v", name, err, tc.wantOK)
		}
	}
	for _, bad := range []string{"1", "1.x.3", "-1.2"} {
		if _, err := roleEKU("verifier_require_eku", bad); err == nil {
			t.Errorf("%q accepted as an OID", bad)
		}
	}
}

// Outside development, any role's roots sharing an anchor with another
// role's need that role's EKU, the issuer's and mdoc reader's included.
func TestCheckRoleRoots(t *testing.T) {
	shared := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ekuCert(t, nil, nil).Raw}))
	other := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ekuCert(t, nil, nil).Raw}))
	for name, tc := range map[string]struct {
		cfg     config
		refused string
	}{
		"separate anchors":               {cfg: config{IssuerRoots: other, VerifierRoots: shared}},
		"verifier shares with issuer":    {cfg: config{IssuerRoots: shared, VerifierRoots: shared}, refused: "verifier_require_eku"},
		"registrar shares with verifier": {cfg: config{VerifierRoots: shared, VerifierRequireEKU: "1.2.3", RegistrarRoots: shared}, refused: "registrar_require_eku"},
		"both have EKUs":                 {cfg: config{VerifierRoots: shared, VerifierRequireEKU: "1.2.3", RegistrarRoots: shared, RegistrarRequireEKU: "1.2.4"}},
		"issuer shares with verifier":    {cfg: config{IssuerRoots: shared, VerifierRoots: shared, VerifierRequireEKU: "1.2.3"}, refused: "issuer_require_eku"},
		"issuer and verifier have EKUs":  {cfg: config{IssuerRoots: shared, IssuerRequireEKU: "1.2.5", VerifierRoots: shared, VerifierRequireEKU: "1.2.3"}},
		"mdoc reader shares with issuer": {cfg: config{IssuerRoots: shared, IssuerRequireEKU: "1.2.5", MdocReaderRoots: shared}, refused: "mdoc_reader_require_eku"},
		"mdoc reader has its EKU":        {cfg: config{IssuerRoots: shared, IssuerRequireEKU: "1.2.5", MdocReaderRoots: shared, MdocReaderRequireEKU: true}},
		"development":                    {cfg: config{IssuerRoots: shared, VerifierRoots: shared, Development: true}},
		"the same EKU for both":          {cfg: config{IssuerRoots: shared, IssuerRequireEKU: "1.2.3", VerifierRoots: shared, VerifierRequireEKU: "1.2.3"}, refused: "same extended key usage"},
		"issuer EKU is the reader's":     {cfg: config{IssuerRoots: shared, IssuerRequireEKU: mdocReaderAuthEKU, MdocReaderRoots: shared, MdocReaderRequireEKU: true}, refused: "same extended key usage"},
		"metadata shares with issuer":    {cfg: config{IssuerRoots: shared, IssuerRequireEKU: "1.2.5", IssuerMetadataRoots: shared}, refused: "issuer_metadata_require_eku"},
		"metadata has its EKU":           {cfg: config{IssuerRoots: shared, IssuerRequireEKU: "1.2.5", IssuerMetadataRoots: shared, IssuerMetadataRequireEKU: "1.2.6"}},
		"issuers of both formats share":  {cfg: config{IssuerRoots: shared, MdocIssuerRoots: shared, MdocIssuerRootsByDocType: map[string]string{"a": shared}}},
		"the same EKU for both formats":  {cfg: config{IssuerRoots: shared, IssuerRequireEKU: "1.2.5", MdocIssuerRoots: shared, MdocIssuerRequireEKU: "1.2.5"}},
		"mdoc issuer shares with verifier": {cfg: config{IssuerRoots: other, MdocIssuerRoots: shared, VerifierRoots: shared, VerifierRequireEKU: "1.2.3"},
			refused: "mdoc_issuer_require_eku"},
		"mdoc issuer has its EKU": {cfg: config{MdocIssuerRoots: shared, MdocIssuerRequireEKU: "1.0.18013.5.1.2", VerifierRoots: shared, VerifierRequireEKU: "1.2.3"}},
		"a document type's roots share with a reader": {cfg: config{MdocIssuerRootsByDocType: map[string]string{"a": shared}, MdocReaderRoots: shared, MdocReaderRequireEKU: true},
			refused: "mdoc_issuer_require_eku"},
		"mdoc EKU under issuer_roots is the verifier's": {cfg: config{IssuerRoots: shared, IssuerRequireEKU: "1.2.5", MdocIssuerRequireEKU: "1.2.3", VerifierRoots: shared, VerifierRequireEKU: "1.2.3"},
			refused: "mdoc_issuer_require_eku"},
		"mdoc and SD-JWT EKUs under issuer_roots": {cfg: config{IssuerRoots: shared, IssuerRequireEKU: "1.2.5", MdocIssuerRequireEKU: "1.0.18013.5.1.2", VerifierRoots: shared, VerifierRequireEKU: "1.2.3"}},
	} {
		err := checkRoleRoots(tc.cfg)
		switch {
		case tc.refused == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.refused != "" && (err == nil || !strings.Contains(err.Error(), tc.refused)):
			t.Errorf("%s: %v, want refused naming %s", name, err, tc.refused)
		}
	}
}

// Roots overlap not only when they're the same certificate: an
// intermediate under the other role's root, a reissued root with the
// same key and subject, or one certified through others in the sets
// all let a certificate chain to both.
func TestCheckRoleRoots_OverlapBeyondEqualCertificates(t *testing.T) {
	newKey := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	issue := func(name string, pub *ecdsa.PublicKey, parent *x509.Certificate, signer *ecdsa.PrivateKey) *x509.Certificate {
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		}
		if parent == nil {
			parent = tmpl
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	asPEM := func(certs ...*x509.Certificate) string {
		var b strings.Builder
		for _, c := range certs {
			b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
		}
		return b.String()
	}
	rootKey, intKey, subKey, otherKey := newKey(), newKey(), newKey(), newKey()
	root := issue("shared root", &rootKey.PublicKey, nil, rootKey)
	reissued := issue("shared root", &rootKey.PublicKey, nil, rootKey)
	intermediate := issue("issuer intermediate", &intKey.PublicKey, root, rootKey)
	sub := issue("issuing CA", &subKey.PublicKey, intermediate, intKey)
	unrelated := issue("unrelated root", &otherKey.PublicKey, nil, otherKey)

	for name, tc := range map[string]struct {
		verifierRoots, issuerRoots string
		refused                    bool
	}{
		"issuer roots are an intermediate of the verifier root": {asPEM(root), asPEM(intermediate), true},
		"verifier roots are an intermediate of the issuer root": {asPEM(intermediate), asPEM(root), true},
		"a reissued root, same key and subject":                 {asPEM(root), asPEM(reissued), true},
		"two levels below, through a CA in the sets":            {asPEM(root, intermediate), asPEM(sub), true},
		"unrelated": {asPEM(root), asPEM(unrelated), false},
		// The intermediate between them is configured nowhere: whether
		// sub chains to root can't be told, so it may.
		"an intermediate whose root is unknown": {asPEM(root), asPEM(sub), true},
		"an unrelated root and an intermediate": {asPEM(unrelated), asPEM(sub), true},
	} {
		err := checkRoleRoots(config{VerifierRoots: tc.verifierRoots, IssuerRoots: tc.issuerRoots})
		if tc.refused != (err != nil) {
			t.Errorf("%s: %v, want refused = %v", name, err, tc.refused)
		}
	}
}

// anyExtendedKeyUsage names no role, so it's refused as one's.
func TestRoleEKU_RefusesAnyExtendedKeyUsage(t *testing.T) {
	if _, err := roleEKU("issuer_require_eku", "2.5.29.37.0"); err == nil {
		t.Error("anyExtendedKeyUsage accepted as a role's EKU")
	}
}

// An object identifier has one spelling: an arc with a sign or a
// leading zero is refused, so two spellings of one role's EKU can't
// pass for two roles'.
func TestParseOID_Canonical(t *testing.T) {
	for _, ok := range []string{"1.2.3.4", "0.0", "2.5.29.37.0", mdocReaderAuthEKU, "1.2.10"} {
		if _, err := parseOID(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"1.2.3.04", "+1.2.3.4", "01.2.3.4", "1.-2.3", "1..2", "1.2.", "1", "", "1.2. 3", "1.0x2", "1.2.99999999999999999999"} {
		if _, err := parseOID(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// Two roles sharing an anchor are refused the same EKU however it's
// spelled.
func TestCheckRoleRoots_SameEKUSpelledDifferently(t *testing.T) {
	shared := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ekuCert(t, nil, nil).Raw}))
	for _, spelled := range []string{"1.2.3.04", "+1.2.3.4", "01.2.3.4"} {
		cfg := config{IssuerRoots: shared, VerifierRoots: shared, IssuerRequireEKU: "1.2.3.4", VerifierRequireEKU: spelled}
		if err := checkRoleRoots(cfg); err == nil {
			t.Errorf("verifier_require_eku %q accepted beside issuer_require_eku 1.2.3.4", spelled)
		}
	}
	cfg := config{MdocReaderRoots: shared, MdocReaderRequireEKU: true, VerifierRoots: shared, VerifierRequireEKU: "1.0.18013.5.1.06"}
	if err := checkRoleRoots(cfg); err == nil {
		t.Error("verifier_require_eku 1.0.18013.5.1.06 accepted beside mdoc_reader_require_eku")
	}
}
