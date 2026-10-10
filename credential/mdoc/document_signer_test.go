package mdoc_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
)

// signerChain is a document signer certificate under an IACA, with the
// given subjects' countryName and stateOrProvinceName.
func signerChain(t *testing.T, iacaCountry, iacaState, dsCountry, dsState string) []*x509.Certificate {
	t.Helper()
	name := func(cn, country, state string) pkix.Name {
		n := pkix.Name{CommonName: cn}
		if country != "" {
			n.Country = []string{country}
		}
		if state != "" {
			n.Province = []string{state}
		}
		return n
	}
	now := time.Now()
	iacaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	iacaTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: name("IACA", iacaCountry, iacaState),
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	iacaDER, err := x509.CreateCertificate(rand.Reader, iacaTmpl, iacaTmpl, &iacaKey.PublicKey, iacaKey)
	if err != nil {
		t.Fatal(err)
	}
	iaca, _ := x509.ParseCertificate(iacaDER)
	dsKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	dsDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: name("DS", dsCountry, dsState),
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}, iaca, &dsKey.PublicKey, iacaKey)
	if err != nil {
		t.Fatal(err)
	}
	ds, _ := x509.ParseCertificate(dsDER)
	return []*x509.Certificate{ds, iaca}
}

func TestCheckDocumentSigner(t *testing.T) {
	now := time.Now()
	mdl := func(elements map[string]any) mdoc.VerifiedMSO {
		return mdoc.VerifiedMSO{
			ValidityInfo: mdoc.ValidityInfo{Signed: now},
			NameSpaces:   map[string]map[string]any{mdoc.MDLNameSpace: elements},
		}
	}
	for _, tc := range []struct {
		name     string
		chain    []*x509.Certificate
		verified mdoc.VerifiedMSO
		wantErr  string
	}{
		{"matching", signerChain(t, "US", "US-CA", "US", "US-CA"), mdl(map[string]any{"issuing_country": "US", "issuing_jurisdiction": "US-CA"}), ""},
		{"no issuing elements", signerChain(t, "US", "", "US", ""), mdl(map[string]any{"age_over_18": true}), ""},
		{"jurisdiction without a DS state", signerChain(t, "US", "", "US", ""), mdl(map[string]any{"issuing_jurisdiction": "US-NY"}), ""},
		{"another country", signerChain(t, "SG", "", "SG", ""), mdl(map[string]any{"issuing_country": "US"}), "issuing_country"},
		{"another jurisdiction", signerChain(t, "US", "US-CA", "US", "US-CA"), mdl(map[string]any{"issuing_jurisdiction": "US-NY"}), "issuing_jurisdiction"},
		{"country not a string", signerChain(t, "US", "", "US", ""), mdl(map[string]any{"issuing_country": 840}), "issuing_country"},
		{"DS country differs from the IACA's", signerChain(t, "SG", "", "US", ""), mdl(nil), "countryName"},
		{"no countries", signerChain(t, "", "", "", ""), mdl(nil), "countryName"},
		{"DS state differs from the IACA's", signerChain(t, "US", "US-CA", "US", "US-NY"), mdl(nil), "stateOrProvinceName"},
		{"signed outside the DS validity", signerChain(t, "US", "", "US", ""), mdoc.VerifiedMSO{ValidityInfo: mdoc.ValidityInfo{Signed: now.Add(-48 * time.Hour)}}, "validity"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := mdoc.CheckDocumentSigner(tc.verified, [][]*x509.Certificate{tc.chain})
			switch {
			case tc.wantErr == "" && err != nil:
				t.Errorf("err = %v, want accepted", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Errorf("err = %v, want one naming %s", err, tc.wantErr)
			}
		})
	}
	// Another doctype's issuing_country isn't the mDL's: not checked here.
	other := mdoc.VerifiedMSO{ValidityInfo: mdoc.ValidityInfo{Signed: now}, NameSpaces: map[string]map[string]any{"org.iso.23220.1": {"issuing_country": "SG"}}}
	if _, err := mdoc.CheckDocumentSigner(other, [][]*x509.Certificate{signerChain(t, "ZZ", "", "ZZ", "")}); err != nil {
		t.Errorf("a non-mDL namespace's issuing_country: %v", err)
	}
}
