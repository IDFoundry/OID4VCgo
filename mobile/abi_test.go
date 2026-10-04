package mobile

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

// The Swift sources refuse a framework whose ABIVersion isn't the one
// they were written for (OID4VC.expectedABIVersion): an ABI change here
// must be made there too, with the Swift side updated to match.
func TestSwiftExpectsThisABI(t *testing.T) {
	src, err := os.ReadFile("ios/OID4VCWallet/Sources/OID4VCWallet/OID4VC.swift")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`expectedABIVersion = (\d+)`).FindSubmatch(src)
	if m == nil {
		t.Fatal("OID4VC.swift declares no expectedABIVersion")
	}
	if got, _ := strconv.Atoi(string(m[1])); got != ABIVersion {
		t.Errorf("OID4VC.expectedABIVersion = %d, ABIVersion = %d", got, ABIVersion)
	}
}
