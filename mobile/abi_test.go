package mobile

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

// The Swift and Kotlin sources refuse a framework whose ABIVersion isn't
// the one they were written for (OID4VC.expectedABIVersion): an ABI
// change here must be made there too, with both sides updated to match.
func TestWrappersExpectThisABI(t *testing.T) {
	for _, src := range []string{
		"ios/OID4VCWallet/Sources/OID4VCWallet/OID4VC.swift",
		"android/OID4VCWallet/src/main/kotlin/dev/idfoundry/oid4vcwallet/OID4VC.kt",
	} {
		text, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		m := regexp.MustCompile(`expectedABIVersion(?:: Int)? = (\d+)`).FindSubmatch(text)
		if m == nil {
			t.Errorf("%s declares no expectedABIVersion", src)
			continue
		}
		if got, _ := strconv.Atoi(string(m[1])); got != ABIVersion {
			t.Errorf("%s: expectedABIVersion = %d, ABIVersion = %d", src, got, ABIVersion)
		}
	}
}
