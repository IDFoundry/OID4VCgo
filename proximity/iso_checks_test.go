package proximity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
)

// issueUnder issues a fixture mdoc under an IACA and document signer
// with the given subjects, its MSO signed at signed.
func issueUnder(t *testing.T, iaca, ds pkix.Name, signed time.Time) fixture {
	t.Helper()
	now := time.Now()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: iaca,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	dsKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	dsDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: ds,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}, ca, &dsKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuerSigned, err := mdoc.Issue(dsKey, cose.ES256, mdoc.Claims{
		DocType:    mDL,
		NameSpaces: map[string]map[string]interface{}{mDLNS: {"age_over_18": true}},
		DeviceKey:  &deviceKey.PublicKey,
		Signed:     signed, ValidFrom: signed, ValidUntil: now.Add(time.Hour),
	}, mdoc.IssueOptions{X5Chain: [][]byte{dsDER}})
	if err != nil {
		t.Fatalf("mdoc.Issue: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return fixture{docType: mDL, issuerSigned: issuerSigned, deviceKey: deviceKey, roots: roots}
}

func verifyFixture(t *testing.T, fx fixture) error {
	t.Helper()
	f := establish(t, mDL, map[string][]string{mDLNS: {"age_over_18"}})
	_, err := f.reader.Verify(f.respond(t, fx, [][2]string{{mDLNS, "age_over_18"}}), fx.roots, time.Now())
	return err
}

// TestIACASubjectChecks: §9.3.3's countryName and stateOrProvinceName
// checks between the IACA and the document signer.
func TestIACASubjectChecks(t *testing.T) {
	signed := time.Now().Add(-time.Minute)
	name := func(cn, c, st string) pkix.Name {
		n := pkix.Name{CommonName: cn}
		if c != "" {
			n.Country = []string{c}
		}
		if st != "" {
			n.Province = []string{st}
		}
		return n
	}
	tests := []struct {
		name     string
		iaca, ds pkix.Name
		want     string // "" for accepted
	}{
		{"same country", name("IACA", "SG", ""), name("DS", "SG", ""), ""},
		{"different country", name("IACA", "SG", ""), name("DS", "US", ""), "countryName"},
		{"same state", name("IACA", "US", "CA"), name("DS", "US", "CA"), ""},
		{"different state", name("IACA", "US", "CA"), name("DS", "US", "NY"), "stateOrProvinceName"},
		{"state on one side only", name("IACA", "US", ""), name("DS", "US", "NY"), ""},
		{"neither has a country", name("IACA", "", ""), name("DS", "", ""), "countryName"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyFixture(t, issueUnder(t, tt.iaca, tt.ds, signed))
			switch {
			case tt.want == "" && err != nil:
				t.Errorf("Verify: %v", err)
			case tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)):
				t.Errorf("Verify = %v, want one containing %q", err, tt.want)
			}
		})
	}
}

// TestMSOSignedOutsideCertificate: §9.3.1 step 5, the MSO's signed date
// is within the document signer certificate's validity (here, before
// its NotBefore).
func TestMSOSignedOutsideCertificate(t *testing.T) {
	sg := pkix.Name{CommonName: "x", Country: []string{"SG"}}
	fx := issueUnder(t, sg, sg, time.Now().Add(-2*time.Hour))
	if err := verifyFixture(t, fx); err == nil || !strings.Contains(err.Error(), "outside the document signer certificate's validity") {
		t.Errorf("Verify = %v", err)
	}
}

// TestReaderPrefersCentralClient: §8.3.3.1.1.1, a reader offered both
// BLE modes should select mdoc central client mode.
func TestReaderPrefersCentralClient(t *testing.T) {
	holder, err := NewDeviceSession(nil)
	if err != nil {
		t.Fatal(err)
	}
	pe, _ := parseDeviceEngagement(holder.DeviceEngagementBytes())
	coseKey, _ := encodeCoseKey(pe.eDeviceKey)
	keyBytes, _ := wrapTag24(coseKey)
	peripheral, central := make([]byte, 16), make([]byte, 16)
	central[0] = 1
	de := mustMarshal(t, map[int]any{
		0: "1.0",
		1: []any{1, cbor.RawMessage(keyBytes)},
		2: []any{[]any{2, 1, map[int]any{0: true, 1: true, 10: peripheral, 11: central}}},
	})
	r, err := NewReaderSession("mdoc:" + base64.RawURLEncoding.EncodeToString(de))
	if err != nil {
		t.Fatal(err)
	}
	if r.BLEMode() != CentralClient || r.ServiceUUID() != formatUUID(central) {
		t.Errorf("BLEMode %v, UUID %s; want central client with its UUID", r.BLEMode(), r.ServiceUUID())
	}
}
