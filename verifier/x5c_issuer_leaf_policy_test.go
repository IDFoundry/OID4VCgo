package verifier_test

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"runtime"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// Without a LeafPolicy, X5CIssuerKeyResolver refuses a certificate
// whose key usage denotes another role — a TLS server's under an
// ecosystem CA that also issues those — and accepts one with no key
// usage, or with any purpose that may be an issuer's.
func TestX5CIssuerKeyResolver_DefaultLeafPolicy(t *testing.T) {
	ca, caKey := testcert.CA(t, "ecosystem CA")
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	resolver := verifier.X5CIssuerKeyResolver{Roots: roots, Revocation: certrevocation.NoCheck{}}
	issue := func(tmpl x509.Certificate) *x509.Certificate {
		tmpl.Subject = pkix.Name{CommonName: "leaf"}
		cert, _ := testcert.Issue(t, &tmpl, ca, caKey)
		return cert
	}
	private := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}
	for name, tc := range map[string]struct {
		cert   *x509.Certificate
		refuse bool
	}{
		"a TLS server's": {issue(x509.Certificate{
			DNSNames: []string{"attacker.example"}, KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}), true},
		"TLS client and server": {issue(x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}), true},
		"code signing":          {issue(x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}), true},
		"email and time stamping": {issue(x509.Certificate{
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageTimeStamping},
		}), true},
		"an OCSP signer's":          {issue(x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning, x509.ExtKeyUsageAny}}), true},
		"no digital signature":      {issue(x509.Certificate{KeyUsage: x509.KeyUsageKeyEncipherment}), true},
		"no key usage":              {issue(x509.Certificate{}), false},
		"digital signature only":    {issue(x509.Certificate{KeyUsage: x509.KeyUsageDigitalSignature}), false},
		"any purpose":               {issue(x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}), false},
		"a private purpose":         {issue(x509.Certificate{UnknownExtKeyUsage: []asn1.ObjectIdentifier{private}}), false},
		"TLS and a private purpose": {issue(x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, UnknownExtKeyUsage: []asn1.ObjectIdentifier{private}}), false},
		"an mdoc reader's": {issue(x509.Certificate{
			KeyUsage: x509.KeyUsageDigitalSignature, UnknownExtKeyUsage: []asn1.ObjectIdentifier{readerAuthEKU},
		}), true},
		"an mdoc reader's and a private purpose": {issue(x509.Certificate{UnknownExtKeyUsage: []asn1.ObjectIdentifier{readerAuthEKU, private}}), true},
		"an mDL document signer's":               {issue(x509.Certificate{UnknownExtKeyUsage: []asn1.ObjectIdentifier{mdoc.MDLDocumentSignerEKU}}), false},
	} {
		_, _, err := resolver.ResolveIssuerKey(context.Background(), x5cHeader(tc.cert), nil)
		if tc.refuse != (err != nil) {
			t.Errorf("%s: %v, want refused %v", name, err, tc.refuse)
		}
		if policyErr := verifier.DefaultSDJWTIssuerLeafPolicy(tc.cert, nil); tc.refuse != (policyErr != nil) {
			t.Errorf("%s: DefaultSDJWTIssuerLeafPolicy: %v, want refused %v", name, policyErr, tc.refuse)
		}
	}

	// A LeafPolicy that's set replaces it; AnyIssuerLeaf opts out.
	tls := issue(x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	resolver.LeafPolicy = verifier.AnyIssuerLeaf
	if _, _, err := resolver.ResolveIssuerKey(context.Background(), x5cHeader(tls), nil); err != nil {
		t.Errorf("AnyIssuerLeaf: %v", err)
	}
}

// readerAuthEKU is ISO/IEC 18013-5's mdoc reader authentication
// extended key usage (Annex B).
var readerAuthEKU = asn1.ObjectIdentifier{1, 0, 18013, 5, 1, 6}

// DefaultSDJWTIssuerLeafPolicy refuses a leaf whose every verified path
// runs through an intermediate CA restricted to other roles' purposes,
// and accepts one with a path through an unrestricted one.
func TestX5CIssuerKeyResolver_DefaultLeafPolicyIntermediates(t *testing.T) {
	ca, caKey := testcert.CA(t, "ecosystem CA")
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	resolver := verifier.X5CIssuerKeyResolver{Roots: roots, Revocation: certrevocation.NoCheck{}}
	private := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}
	for name, tc := range map[string]struct {
		eku     []x509.ExtKeyUsage
		unknown []asn1.ObjectIdentifier
		refuse  bool
	}{
		"TLS server only":         {eku: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, refuse: true},
		"TLS client and server":   {eku: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, refuse: true},
		"mdoc reader auth only":   {unknown: []asn1.ObjectIdentifier{readerAuthEKU}, refuse: true},
		"unrestricted":            {},
		"any purpose":             {eku: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}},
		"a private purpose":       {unknown: []asn1.ObjectIdentifier{private}},
		"TLS and an mDL signer's": {eku: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, unknown: []asn1.ObjectIdentifier{mdoc.MDLDocumentSignerEKU}},
	} {
		intermediate, intermediateKey := testcert.Issue(t, &x509.Certificate{
			Subject: pkix.Name{CommonName: "issuing CA"}, IsCA: true, BasicConstraintsValid: true,
			KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
			ExtKeyUsage: tc.eku, UnknownExtKeyUsage: tc.unknown,
		}, ca, caKey)
		leaf, _ := testcert.Issue(t, &x509.Certificate{
			Subject: pkix.Name{CommonName: "issuer"}, KeyUsage: x509.KeyUsageDigitalSignature,
		}, intermediate, intermediateKey)
		_, _, err := resolver.ResolveIssuerKey(context.Background(), x5cHeader(leaf, intermediate), nil)
		if tc.refuse != (err != nil) {
			t.Errorf("under an intermediate with %s: %v, want refused %v", name, err, tc.refuse)
		}
		if tc.refuse && !strings.Contains(err.Error(), "intermediate") {
			t.Errorf("under an intermediate with %s: %v, want the intermediate named", name, err)
		}
		// With no paths, only the leaf is checked.
		if err := verifier.DefaultSDJWTIssuerLeafPolicy(leaf, nil); err != nil {
			t.Errorf("%s: the leaf alone: %v", name, err)
		}
	}
}

// Under AssuranceProduction, issuer roots that are the system root
// pool, which anchors every public CA's certificates, are refused.
// systemPoolHoldsCertificates reports whether the system root pool is a
// set of certificates (Linux and the other Unix systems), not deferred
// to the platform verifier (macOS, Windows).
func systemPoolHoldsCertificates() bool {
	switch runtime.GOOS {
	case "darwin", "ios", "windows":
		return false
	}
	return true
}

func TestNewTransactions_RefusesSystemPoolIssuerRoots(t *testing.T) {
	system, err := x509.SystemCertPool()
	if err != nil {
		t.Skipf("no system root pool: %v", err)
	}
	cfg, deps := validConfig(t)
	caIssuedClientCert(t, &cfg, &deps)
	cfg.Assurance = verifier.AssuranceProduction
	prod, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatal(err)
	}
	store := assuredTransactionStore{nil}
	cases := map[string]verifier.VerifyResponseRequest{
		"issuer_keys":                      {IssuerKeys: verifier.X5CIssuerKeyResolver{Roots: system, Revocation: certrevocation.NoCheck{}}},
		"issuer_keys (pointer)":            {IssuerKeys: &verifier.X5CIssuerKeyResolver{Roots: system, Revocation: certrevocation.NoCheck{}}},
		"issuer_keys RootsByVCT":           {IssuerKeys: verifier.X5CIssuerKeyResolver{RootsByVCT: map[string]*x509.CertPool{"urn:pid:1": system}, Revocation: certrevocation.NoCheck{}}},
		"mdoc_issuer_keys":                 {MdocIssuerKeys: verifier.X5ChainIssuerKeyResolver{Roots: system, Revocation: certrevocation.NoCheck{}}},
		"mdoc_issuer_keys (pointer)":       {MdocIssuerKeys: &verifier.X5ChainIssuerKeyResolver{Roots: system, Revocation: certrevocation.NoCheck{}}},
		"mdoc_issuer_keys (wrapped)":       {MdocIssuerKeys: wrappingResolver{verifier.X5ChainIssuerKeyResolver{Roots: system, Revocation: certrevocation.NoCheck{}}}},
		"mdoc_issuer_keys RootsByDocType":  {MdocIssuerKeys: verifier.X5ChainIssuerKeyResolver{RootsByDocType: map[string]*x509.CertPool{"org.iso.18013.5.1.mDL": system}, Revocation: certrevocation.NoCheck{}}},
		"mdoc_issuer_keys (twice wrapped)": {MdocIssuerKeys: wrappingResolver{wrappingResolver{&verifier.X5ChainIssuerKeyResolver{RootsByDocType: map[string]*x509.CertPool{"org.iso.18013.5.1.mDL": system}, Revocation: certrevocation.NoCheck{}}}}},
	}
	if systemPoolHoldsCertificates() {
		// The system pool with a private CA added: the usual way to
		// trust one on top of the Web PKI, which it still anchors.
		// Detected only where the system pool is a set of certificates.
		extended := system.Clone()
		extraCA, _ := testcert.CA(t, "private CA")
		extended.AddCert(extraCA)
		cases["issuer_keys (system plus a CA)"] = verifier.VerifyResponseRequest{IssuerKeys: verifier.X5CIssuerKeyResolver{Roots: extended, Revocation: certrevocation.NoCheck{}}}
		cases["mdoc_issuer_keys (system plus a CA)"] = verifier.VerifyResponseRequest{MdocIssuerKeys: &verifier.X5ChainIssuerKeyResolver{Roots: extended, Revocation: certrevocation.NoCheck{}}}
	}
	for name, verify := range cases {
		verify.AnyIssuerForAnyType = true
		_, err := verifier.NewTransactions(prod, store, verifier.TransactionsConfig{RequestURIBase: txBase, Verify: verify, NoStatusCheck: true})
		if err == nil || !strings.Contains(err.Error(), "system root pool") {
			t.Errorf("%s: %v, want the system root pool refused", name, err)
		}
	}
	own := x509.NewCertPool()
	ca, _ := testcert.CA(t, "issuer CA")
	own.AddCert(ca)
	verify := verifier.VerifyResponseRequest{IssuerKeys: verifier.X5CIssuerKeyResolver{Roots: own, Revocation: certrevocation.NoCheck{}}, AnyIssuerForAnyType: true}
	if _, err := verifier.NewTransactions(prod, store, verifier.TransactionsConfig{RequestURIBase: txBase, Verify: verify, NoStatusCheck: true}); err != nil {
		t.Errorf("the issuers' own CA: %v", err)
	}
}
