package credential

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/passport"
	"github.com/idfoundry/oid4vcgo/haip"
)

const testVCT = "https://issuer.example.com/vct/passport/1"

var now = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

func date(s string) time.Time {
	d, err := time.Parse(time.DateOnly, s)
	if err != nil {
		panic(err)
	}
	return d
}

// adult is an adult's passport whose birth year the MRZ alone settles.
func adult() passport.Evidence {
	return passport.Evidence{
		Identity: passport.Identity{
			FamilyName: "DOE", GivenNames: "JANE", NamesFromMRZ: true,
			BirthDate: passport.BirthDate{
				Resolution: passport.BirthDateInferred, Date: date("1980-01-01"), Youngest: date("1980-01-01"),
			},
			Sex: "F", Nationality: "SGP", IssuingCountry: "SGP", DocumentNumber: "K0000000A",
			ExpiryDate: date("2031-01-01"),
		},
		Raw: passport.RawDataGroups{
			SOD: []byte("sod-bytes"), DG1: []byte("dg1-bytes"), DG2: bytes.Repeat([]byte{0xFF}, 16<<10),
		},
	}
}

// child is a child's passport without DG11: 2014 (12) or 1914 (112).
func child() passport.Evidence {
	e := adult()
	e.Identity.BirthDate = passport.BirthDate{Resolution: passport.BirthDateAmbiguous, Youngest: date("2014-06-15")}
	return e
}

func testIssuer(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "passport-vdc test issuer"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(10, 0, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return key, der
}

func TestValidUntil(t *testing.T) {
	cases := []struct {
		name string
		e    passport.Evidence
		o    Options
		want time.Time
	}{
		{name: "default one-year cap", e: adult(), o: Options{Now: now}, want: now.Add(365 * 24 * time.Hour)},
		{
			name: "passport expiry wins", e: adult(), o: Options{Now: now, MaxValidity: 10 * 365 * 24 * time.Hour},
			want: date("2031-01-01").Add(24*time.Hour - time.Second),
		},
		// The child turns 13 on 2027-06-15, when age_over_13 = false
		// would become wrong.
		{name: "next age threshold wins", e: child(), o: Options{Now: now}, want: date("2027-06-15")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidUntil(tc.e, tc.o)
			if err != nil {
				t.Fatalf("ValidUntil: %v", err)
			}
			if !got.Equal(tc.want) {
				t.Errorf("ValidUntil = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestValidUntilRejectsExpiredPassport(t *testing.T) {
	e := adult()
	e.Identity.ExpiryDate = date("2020-01-01")
	if _, err := ValidUntil(e, Options{Now: now}); !errors.Is(err, ErrNoValidity) {
		t.Errorf("ValidUntil error = %v, want ErrNoValidity", err)
	}
}

func TestAgeClaimsUseYoungestReading(t *testing.T) {
	ages := ageClaims(child(), Options{Now: now})
	for threshold, want := range map[int]bool{13: false, 16: false, 18: false, 21: false, 65: false} {
		if ages[threshold] != want {
			t.Errorf("age_over_%d = %v, want %v (youngest reading: age 12)", threshold, ages[threshold], want)
		}
	}
	ages = ageClaims(adult(), Options{Now: now})
	for threshold, want := range map[int]bool{13: true, 18: true, 21: true, 65: false} {
		if ages[threshold] != want {
			t.Errorf("adult age_over_%d = %v, want %v", threshold, ages[threshold], want)
		}
	}
}

// issueAndVerifyMdoc signs claims as the issuer package would and
// verifies the result, returning the verified namespaces.
func issueAndVerifyMdoc(t *testing.T, claims *mdoc.Claims) map[string]map[string]interface{} {
	t.Helper()
	issuerKey, cert := testIssuer(t)
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	claims.DeviceKey = &deviceKey.PublicKey

	signed, err := mdoc.Issue(issuerKey, haip.RecommendedCOSEAlgorithm, *claims, mdoc.IssueOptions{X5Chain: [][]byte{cert}})
	if err != nil {
		t.Fatalf("mdoc.Issue: %v", err)
	}
	wire, err := signed.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	parsed, err := mdoc.UnmarshalIssuerSigned(wire)
	if err != nil {
		t.Fatalf("UnmarshalIssuerSigned: %v", err)
	}
	verified, err := mdoc.Verify(parsed, DocType, &issuerKey.PublicKey, haip.RecommendedCOSEAlgorithm, mdoc.VerifyOptions{
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("mdoc.Verify: %v", err)
	}
	return verified.NameSpaces
}

func TestMdocClaims_Adult(t *testing.T) {
	claims, err := MdocClaims(adult(), Options{Now: now})
	if err != nil {
		t.Fatalf("MdocClaims: %v", err)
	}
	ns := issueAndVerifyMdoc(t, claims)

	identity := ns[IdentityNamespace]
	if identity[FamilyName] != "DOE" || identity[DocumentNumber] != "K0000000A" || identity[NamesFromMRZ] != true {
		t.Errorf("identity = %v", identity)
	}
	if bd, ok := identity[BirthDate].(cbor.Tag); !ok || bd.Number != fullDateTag || bd.Content != "1980-01-01" {
		t.Errorf("birth_date = %#v, want tag 1004 \"1980-01-01\"", identity[BirthDate])
	}
	if identity["age_over_18"] != true || identity["age_over_65"] != false {
		t.Errorf("age_over_18/65 = %v/%v", identity["age_over_18"], identity["age_over_65"])
	}

	icao := ns[ICAONamespace]
	for name, want := range map[string][]byte{ICAOSOD: adult().Raw.SOD, ICAODG1: adult().Raw.DG1, ICAODG2: adult().Raw.DG2} {
		if got, _ := icao[name].([]byte); !bytes.Equal(got, want) {
			t.Errorf("%s did not round-trip byte-for-byte", name)
		}
	}
	if _, ok := icao[ICAODG11]; ok {
		t.Error("icao_dg11 present without DG11 in the evidence")
	}
}

func TestMdocClaims_ChildOmitsBirthDate(t *testing.T) {
	claims, err := MdocClaims(child(), Options{Now: now})
	if err != nil {
		t.Fatalf("MdocClaims: %v", err)
	}
	identity := issueAndVerifyMdoc(t, claims)[IdentityNamespace]
	if _, ok := identity[BirthDate]; ok {
		t.Error("birth_date issued for an ambiguous MRZ birth year")
	}
	if identity["age_over_18"] != false || identity["age_over_13"] != false {
		t.Errorf("age_over_13/18 = %v/%v, want false/false", identity["age_over_13"], identity["age_over_18"])
	}
	if !claims.ValidUntil.Equal(date("2027-06-15")) {
		t.Errorf("ValidUntil = %v, want the 13th birthday", claims.ValidUntil)
	}
}

// issueAndVerifySDJWT signs claims as the issuer package would and
// verifies the result, returning the fully disclosed payload.
func issueAndVerifySDJWT(t *testing.T, claims *sdjwtvc.Claims) map[string]any {
	t.Helper()
	issuerKey, _ := testIssuer(t)
	sdjwt, _, err := sdjwtvc.Issue(issuerKey, oid4vci.ES256, *claims, sdjwtvc.IssueOptions{})
	if err != nil {
		t.Fatalf("sdjwtvc.Issue: %v", err)
	}
	payload, _, err := sdjwtvc.Verify(sdjwt, &issuerKey.PublicKey, oid4vci.ES256, sdjwtvc.VerifyOptions{
		RequireKeyBinding: sdjwtvc.KeyBindingNotRequired, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("sdjwtvc.Verify: %v", err)
	}
	return payload
}

func TestSDJWTClaims_Adult(t *testing.T) {
	claims, err := SDJWTClaims(adult(), testVCT, Options{Now: now, Issuer: "https://issuer.example.com"})
	if err != nil {
		t.Fatalf("SDJWTClaims: %v", err)
	}
	payload := issueAndVerifySDJWT(t, claims)

	if payload["iss"] != "https://issuer.example.com" {
		t.Errorf("iss = %v", payload["iss"])
	}
	if iat, _ := payload["iat"].(float64); int64(iat) != now.Unix() {
		t.Errorf("iat = %v, want %d", payload["iat"], now.Unix())
	}
	if payload["vct"] != testVCT || payload[FamilyName] != "DOE" || payload[SDJWTBirthDate] != "1980-01-01" {
		t.Errorf("payload = %v", payload)
	}
	nats, _ := payload[SDJWTNationalities].([]any)
	if len(nats) != 1 || nats[0] != "SGP" {
		t.Errorf("nationalities = %v", payload[SDJWTNationalities])
	}
	ages, _ := payload[SDJWTAgeEqualOrOver].(map[string]any)
	if ages["18"] != true || ages["65"] != false {
		t.Errorf("age_equal_or_over = %v", ages)
	}
	for name, want := range map[string][]byte{ICAOSOD: adult().Raw.SOD, ICAODG1: adult().Raw.DG1, ICAODG2: adult().Raw.DG2} {
		s, _ := payload[name].(string)
		got, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s did not round-trip byte-for-byte", name)
		}
	}
}

// TestSDJWTClaims_IssAndIatAlwaysDisclosed checks iss and iat are plain
// claims, not disclosures a holder could withhold.
func TestSDJWTClaims_IssAndIatAlwaysDisclosed(t *testing.T) {
	claims, err := SDJWTClaims(adult(), testVCT, Options{Now: now, Issuer: "https://issuer.example.com"})
	if err != nil {
		t.Fatalf("SDJWTClaims: %v", err)
	}
	if claims.Iss != "https://issuer.example.com" {
		t.Errorf("Claims.Iss = %q", claims.Iss)
	}
	if iat, ok := claims.Additional["iat"].(int64); !ok || iat != now.Unix() {
		t.Errorf("Additional[iat] = %#v, want a plain %d", claims.Additional["iat"], now.Unix())
	}
	noIssuer, err := SDJWTClaims(adult(), testVCT, Options{Now: now})
	if err != nil || noIssuer.Iss != "" {
		t.Errorf("without Options.Issuer: Iss = %q, err %v; want no iss", noIssuer.Iss, err)
	}
}

func TestSDJWTClaims_ChildOmitsBirthDate(t *testing.T) {
	claims, err := SDJWTClaims(child(), testVCT, Options{Now: now})
	if err != nil {
		t.Fatalf("SDJWTClaims: %v", err)
	}
	payload := issueAndVerifySDJWT(t, claims)
	if _, ok := payload[SDJWTBirthDate]; ok {
		t.Error("birthdate issued for an ambiguous MRZ birth year")
	}
	ages, _ := payload[SDJWTAgeEqualOrOver].(map[string]any)
	if ages["18"] != false {
		t.Errorf("age_equal_or_over.18 = %v, want false", ages["18"])
	}
	if exp, _ := payload["exp"].(float64); int64(exp) != date("2027-06-15").Unix() {
		t.Errorf("exp = %v, want the 13th birthday", payload["exp"])
	}
}

func TestEncodersRequireSODAndDG1(t *testing.T) {
	e := adult()
	e.Raw.SOD = nil
	if _, err := MdocClaims(e, Options{Now: now}); err == nil {
		t.Error("MdocClaims without SOD = nil error")
	}
	if _, err := SDJWTClaims(e, testVCT, Options{Now: now}); err == nil {
		t.Error("SDJWTClaims without SOD = nil error")
	}
	if _, err := SDJWTClaims(adult(), "", Options{Now: now}); err == nil {
		t.Error("SDJWTClaims without vct = nil error")
	}
}
