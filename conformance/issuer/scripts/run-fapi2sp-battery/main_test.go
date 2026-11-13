package main

import (
	"slices"
	"strings"
	"testing"
)

// TestPlanFor_VCIBattery checks -credential-format mdoc and -deferred,
// alone and together, drive every oid4vci-1_0-issuer-* module the HAIP
// plan lists and no fapi2-security-profile-final-* module.
func TestPlanFor_VCIBattery(t *testing.T) {
	for _, tc := range []struct {
		name     string
		format   string
		deferred bool
	}{
		{"mdoc", "mdoc", false},
		{"deferred", "sd_jwt_vc", true},
		{"mdoc deferred", "mdoc", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			planName, battery, variant := planFor(tc.format, "jwt", "plain", tc.deferred, false, false)
			if planName != "oid4vci-1_0-issuer-haip-test-plan" {
				t.Errorf("plan = %q", planName)
			}
			if variant["credential_format"] != tc.format {
				t.Errorf("credential_format = %q, want %q", variant["credential_format"], tc.format)
			}
			if len(battery) != 21 {
				t.Errorf("battery has %d modules, want the plan's 21 OID4VCI-specific ones", len(battery))
			}
			for _, name := range battery {
				if !strings.HasPrefix(name, vciIssuerTestNamePrefix) {
					t.Errorf("battery holds %s", name)
				}
			}
			for _, name := range []string{happyFlowTestName, multipleClientsTestName, "oid4vci-1_0-issuer-batch-issuance", keyAttestationSignatureTestName} {
				if !slices.Contains(battery, name) {
					t.Errorf("battery lacks %s", name)
				}
			}
		})
	}
}

// TestPlanFor_DefaultBatteries checks the runs vciBattery doesn't
// change keep their batteries.
func TestPlanFor_DefaultBatteries(t *testing.T) {
	if _, b, _ := planFor("sd_jwt_vc", "jwt", "plain", false, false, false); len(b) != 60 {
		t.Errorf("haip battery has %d modules, want 60", len(b))
	}
	if _, b, _ := planFor("sd_jwt_vc", "jwt", "plain", false, false, true); len(b) != 61 {
		t.Errorf("production battery has %d modules, want 61", len(b))
	}
	if _, b, _ := planFor("sd_jwt_vc", "attestation", "plain", false, false, false); !slices.Equal(b, keyAttestationBattery) {
		t.Errorf("attestation battery = %v", b)
	}
}

func TestOnSuite(t *testing.T) {
	got, err := onSuite("https://localhost:8463/", "https://localhost.emobix.co.uk:8443/test/a/alias/credential_offer?x=1")
	if err != nil {
		t.Fatal(err)
	}
	if want := "https://localhost:8463/test/a/alias/credential_offer?x=1"; got != want {
		t.Errorf("onSuite = %q, want %q", got, want)
	}
	if _, err := onSuite("https://localhost:8463/", ""); err == nil {
		t.Error("an empty endpoint was accepted")
	}
	if _, err := onSuite("https://localhost:8463/", "://bad"); err == nil {
		t.Error("an unparseable endpoint was accepted")
	}
}
