package mobile

import "testing"

// proof_key_by_index reaches walletflow.Config.ProofKeyByIndex, and is
// off unless set.
func TestWalletflowConfig_ProofKeyByIndex(t *testing.T) {
	for raw, want := range map[string]bool{`{"development":true}`: false, `{"development":true,"proof_key_by_index":true}`: true} {
		var cfg config
		if err := decodeConfig(raw, &cfg); err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		wcfg, err := walletConfig(cfg)
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if wcfg.ProofKeyByIndex != want {
			t.Errorf("%s: ProofKeyByIndex = %v, want %v", raw, wcfg.ProofKeyByIndex, want)
		}
	}
}
