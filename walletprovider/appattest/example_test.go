package appattest_test

import (
	"os"

	"github.com/idfoundry/oid4vcgo/walletprovider"
	"github.com/idfoundry/oid4vcgo/walletprovider/appattest"
)

// A Wallet Provider taking iOS wallets' App Attest evidence. The App ID
// is the app's team ID and bundle ID; the Policy accepts the
// registration, instance and holder keys a genuine app vouches for, and
// claims no key_storage for them (no KeyStorageRule names
// KeyBindingAppAssertion): App Attest proves the app, not its keys.
func ExampleEvidenceVerifier() {
	v := &appattest.Verifier{
		Apps: []string{os.Getenv("TEAM_ID") + ".com.example.wallet"},
		// Only for a provider that development builds register with.
		AllowDevelopment: os.Getenv("APP_ATTEST_ENVIRONMENT") == "development",
	}
	deps := walletprovider.Dependencies{
		Evidence: []walletprovider.EvidenceVerifier{appattest.EvidenceVerifier{Verifier: v}},
		// … the stores, Signer and Chain, as walletprovider.ExampleNew.
	}
	policy := walletprovider.Policy{
		Platforms: map[walletprovider.Platform]walletprovider.PlatformPolicy{
			walletprovider.PlatformIOS: {SecurityLevels: []walletprovider.SecurityLevel{walletprovider.SecurityLevelSecureEnclave}},
		},
	}
	_, _ = deps, policy
}
