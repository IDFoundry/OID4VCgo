package mobile

import (
	"crypto/x509"
	"encoding/asn1"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// documentSignerCerts are a document signer certificate without an
// extended key usage, one with the mDL document signer's, and a reader
// authentication certificate.
func documentSignerCerts(t *testing.T) (noEKU, mdl, reader *x509.Certificate) {
	t.Helper()
	return ekuCert(t, nil, nil), ekuCert(t, nil, []asn1.ObjectIdentifier{mdoc.MDLDocumentSignerEKU}),
		ekuCert(t, nil, []asn1.ObjectIdentifier{{1, 0, 18013, 5, 1, 6}})
}

// A wallet refuses a document signer without the mDL document signer
// extended key usage by default (walletflow then applies
// mdoc.DefaultDocumentSignerPolicy), and accepts one with
// accept_mdl_signer_without_eku, which no other mdoc issuer policy may
// be set with.
func TestWallet_AcceptMDLSignerWithoutEKU(t *testing.T) {
	noEKU, mdl, reader := documentSignerCerts(t)
	var strict walletflow.Config
	if err := mdocIssuerTrust(config{}, &strict); err != nil || strict.MdocIssuerLeafPolicy != nil {
		t.Fatalf("default: policy set %v, %v; want walletflow's default", strict.MdocIssuerLeafPolicy != nil, err)
	}
	if mdoc.DefaultDocumentSignerPolicy(noEKU, nil) == nil {
		t.Error("the default accepted a document signer without an extended key usage")
	}

	var cfg config
	if err := decodeConfig(`{"accept_mdl_signer_without_eku":true}`, &cfg); err != nil || !cfg.AcceptMDLSignerWithoutEKU {
		t.Fatalf("decode: %v", err)
	}
	var lenient walletflow.Config
	if err := mdocIssuerTrust(cfg, &lenient); err != nil || lenient.MdocIssuerLeafPolicy == nil {
		t.Fatalf("accept_mdl_signer_without_eku: policy set %v, %v", lenient.MdocIssuerLeafPolicy != nil, err)
	}
	for name, tc := range map[string]struct {
		cert *x509.Certificate
		ok   bool
	}{"no EKU": {noEKU, true}, "mDL document signer": {mdl, true}, "reader": {reader, false}} {
		if err := lenient.MdocIssuerLeafPolicy(tc.cert, nil); tc.ok != (err == nil) {
			t.Errorf("%s: %v, want ok %v", name, err, tc.ok)
		}
	}

	for name, c := range map[string]config{
		"with mdoc_issuer_require_eku":           {AcceptMDLSignerWithoutEKU: true, MdocIssuerRequireEKU: "1.2.3"},
		"with issuer_require_eku, no mdoc roots": {AcceptMDLSignerWithoutEKU: true, IssuerRequireEKU: "1.2.3"},
	} {
		var w walletflow.Config
		if err := mdocIssuerTrust(c, &w); err == nil || !strings.Contains(err.Error(), "accept_mdl_signer_without_eku") {
			t.Errorf("%s: %v, want refused", name, err)
		}
	}
}

// A proximity reader keeps proximity's default document signer check
// unless asked otherwise: require_mdl_signer_eku, or
// accept_mdl_signer_without_eku, but not both.
func TestProximityReader_AcceptMDLSignerWithoutEKU(t *testing.T) {
	noEKU, mdl, _ := documentSignerCerts(t)
	if policy, err := readerDocumentSignerPolicy(proximityReaderConfig{}); err != nil || policy != nil {
		t.Errorf("default: policy set %v, %v; want proximity's default", policy != nil, err)
	}
	var cfg proximityReaderConfig
	if err := decodeConfig(`{"accept_mdl_signer_without_eku":true}`, &cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	policy, err := readerDocumentSignerPolicy(cfg)
	if err != nil || policy == nil {
		t.Fatalf("accept_mdl_signer_without_eku: %v", err)
	}
	if err := policy(noEKU, nil); err != nil {
		t.Errorf("accept_mdl_signer_without_eku, no EKU: %v", err)
	}
	strict, err := readerDocumentSignerPolicy(proximityReaderConfig{RequireMDLSignerEKU: true})
	if err != nil || strict(noEKU, nil) == nil || strict(mdl, nil) != nil {
		t.Errorf("require_mdl_signer_eku: %v", err)
	}
	if _, err := readerDocumentSignerPolicy(proximityReaderConfig{RequireMDLSignerEKU: true, AcceptMDLSignerWithoutEKU: true}); err == nil {
		t.Error("require_mdl_signer_eku with accept_mdl_signer_without_eku accepted")
	}
}
