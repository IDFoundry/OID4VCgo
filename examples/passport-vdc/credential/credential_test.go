package credential

import (
	"bytes"
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
		File:     bytes.Repeat([]byte{0xA5}, 20<<10),
		Portrait: testPortrait,
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
			name: "passport expiry doesn't limit it", e: adult(), o: Options{Now: now, MaxValidity: 10 * 365 * 24 * time.Hour},
			want: now.Add(10 * 365 * 24 * time.Hour),
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

// TestExpiredPassportStillIssues: an expired passport's data is still
// authentic, so its credential gets the ordinary validity and carries
// the expiry date for a verifier to judge.
func TestExpiredPassportStillIssues(t *testing.T) {
	e := adult()
	e.Identity.ExpiryDate = date("2020-01-01")
	got, err := ValidUntil(e, Options{Now: now})
	if err != nil || !got.Equal(now.Add(365*24*time.Hour)) {
		t.Fatalf("ValidUntil = %v, %v; want the default one-year validity", got, err)
	}
	claims, err := MdocClaims(e, Options{Now: now})
	if err != nil {
		t.Fatalf("MdocClaims: %v", err)
	}
	if exp, _ := claims.NameSpaces[DemoNamespace][PassportExpiryDate].(cbor.Tag); exp.Content != "2020-01-01" {
		t.Errorf("passport_expiry_date = %v, want 2020-01-01", claims.NameSpaces[DemoNamespace][PassportExpiryDate])
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

	identity := ns[ISONamespace]
	if identity[FamilyName] != "DOE" || identity[GivenName] != "JANE" || identity[IssuingAuthority] != IssuingAuthorityName {
		t.Errorf("org.iso.23220.1 = %v", identity)
	}
	// ISO/IEC 5218 sex, alpha-2 issuing country, alpha-3 nationality.
	if identity[Sex] != uint64(2) || identity[IssuingCountry] != "SG" || identity[Nationality] != "SGP" {
		t.Errorf("sex/issuing_country/nationality = %v/%v/%v, want 2/SG/SGP", identity[Sex], identity[IssuingCountry], identity[Nationality])
	}
	// The mobile document's own issue and expiry dates: the credential's
	// validity, not the passport's.
	if iss, _ := identity[IssueDate].(cbor.Tag); iss.Content != now.Format(time.DateOnly) {
		t.Errorf("issue_date = %v, want %s", identity[IssueDate], now.Format(time.DateOnly))
	}
	if bd := birthDateOf(t, identity); bd.date != "1980-01-01" || bd.mask != "" {
		t.Errorf("birth_date = %+v, want 1980-01-01 with no mask", bd)
	}
	if ns[PhotoIDNamespace][TravelDocumentNumber] != "K0000000A" {
		t.Errorf("travel_document_number = %v", ns[PhotoIDNamespace][TravelDocumentNumber])
	}
	if ns[DemoNamespace][NamesFromMRZ] != true {
		t.Errorf("names_from_mrz = %v", ns[DemoNamespace][NamesFromMRZ])
	}
	if identity["age_over_18"] != true || identity["age_over_65"] != false {
		t.Errorf("age_over_18/65 = %v/%v", identity["age_over_18"], identity["age_over_65"])
	}

	if got, _ := ns[FileNamespace][PassportFile].([]byte); !bytes.Equal(got, adult().File) {
		t.Error("the passport file did not round-trip byte-for-byte")
	}
}

// A child's ambiguous MRZ birth year is the youngest reading, with its
// century masked (ISO/IEC TS 23220-2's approximate_mask).
func TestMdocClaims_ChildMasksTheCentury(t *testing.T) {
	claims, err := MdocClaims(child(), Options{Now: now})
	if err != nil {
		t.Fatalf("MdocClaims: %v", err)
	}
	identity := issueAndVerifyMdoc(t, claims)[ISONamespace]
	if bd := birthDateOf(t, identity); !strings.HasPrefix(bd.date, "2014-") || bd.mask != "11000000" {
		t.Errorf("birth_date = %+v, want the youngest reading with the century masked", bd)
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
	claims, err := SDJWTClaims(adult(), testVCT, Options{Now: now})
	if err != nil {
		t.Fatalf("SDJWTClaims: %v", err)
	}
	payload := issueAndVerifySDJWT(t, claims)

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
	s, _ := payload[PassportFile].(string)
	if got, err := base64.RawURLEncoding.DecodeString(s); err != nil || !bytes.Equal(got, adult().File) {
		t.Error("the passport file did not round-trip byte-for-byte")
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

func TestEncodersRequireThePassportFile(t *testing.T) {
	e := adult()
	e.File = nil
	if _, err := MdocClaims(e, Options{Now: now}); err == nil {
		t.Error("MdocClaims without the passport file = nil error")
	}
	if _, err := SDJWTClaims(e, testVCT, Options{Now: now}); err == nil {
		t.Error("SDJWTClaims without the passport file = nil error")
	}
	if _, err := SDJWTClaims(adult(), "", Options{Now: now}); err == nil {
		t.Error("SDJWTClaims without vct = nil error")
	}
}

type birthDateValue struct{ date, mask string }

// birthDateOf reads ISO/IEC TS 23220-2's birth_date structure.
func birthDateOf(t *testing.T, ns map[string]interface{}) birthDateValue {
	t.Helper()
	raw, err := cbor.Marshal(ns[BirthDate])
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Date cbor.Tag `cbor:"birth_date"`
		Mask string   `cbor:"approximate_mask"`
	}
	if err := cbor.Unmarshal(raw, &v); err != nil {
		t.Fatalf("birth_date %#v isn't the structure: %v", ns[BirthDate], err)
	}
	if v.Date.Number != fullDateTag {
		t.Errorf("birth_date's date is tag %d, want %d", v.Date.Number, fullDateTag)
	}
	s, _ := v.Date.Content.(string)
	return birthDateValue{date: s, mask: v.Mask}
}

// MRZ codes map to ISO/IEC 23220-2's encodings: countries to ISO 3166-1
// alpha-2 (ICAO's own codes included, a code with no alpha-2 kept), sex
// to ISO/IEC 5218.
func TestISOEncodings(t *testing.T) {
	for mrz, want := range map[string]string{
		"DEU": "DE", "D": "DE", "D<<": "DE", "GBR": "GB", "GBD": "GB", "SGP": "SG", "RKS": "XK", "UTO": "UTO", "UNO": "UNO",
	} {
		if got := alpha2(mrz); got != want {
			t.Errorf("alpha2(%q) = %q, want %q", mrz, got, want)
		}
	}
	for mrz, want := range map[string]uint{"M": 1, "F": 2, "X": 0, "<": 0, "": 0} {
		if got := isoSex(mrz); got != want {
			t.Errorf("isoSex(%q) = %d, want %d", mrz, got, want)
		}
	}
}
