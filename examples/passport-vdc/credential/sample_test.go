package credential

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/gmrtd/gmrtd/cms"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/passport"
)

// TestSample_BothFormats runs a real gmrtd portable passport file
// through Verify, both encoders and real signing/verification, when
// PASSPORT_VDC_SAMPLE points at one (see passport.TestVerifySample for
// why that file must stay outside this repository). Logs nothing from
// the passport.
func TestSample_BothFormats(t *testing.T) {
	path := os.Getenv("PASSPORT_VDC_SAMPLE")
	if path == "" {
		t.Skip("PASSPORT_VDC_SAMPLE not set")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}
	pool, err := cms.DefaultMasterList()
	if err != nil {
		t.Fatalf("DefaultMasterList: %v", err)
	}
	issuedAt := time.Now().Truncate(time.Second).UTC()
	e, err := passport.Verify(data, pool, issuedAt)
	if errors.Is(err, passport.ErrExpired) {
		t.Skip("sample passport has expired")
	}
	if err != nil {
		t.Fatal("Verify failed on the sample (error not printed: it could embed the MRZ)")
	}
	o := Options{Now: issuedAt}

	mdocClaims, err := MdocClaims(e, o)
	if err != nil {
		t.Fatalf("MdocClaims: %v", err)
	}
	restore := now
	now = issuedAt // issueAndVerify* verify against the package-level now
	defer func() { now = restore }()
	if ns := issueAndVerifyMdoc(t, mdocClaims); len(ns[ICAONamespace][ICAOSOD].([]byte)) == 0 {
		t.Error("icao_sod missing from the verified mdoc")
	}

	sdClaims, err := SDJWTClaims(e, testVCT, o)
	if err != nil {
		t.Fatalf("SDJWTClaims: %v", err)
	}
	if payload := issueAndVerifySDJWT(t, sdClaims); payload[ICAOSOD] == nil {
		t.Error("icao_sod missing from the verified SD-JWT")
	}
}
