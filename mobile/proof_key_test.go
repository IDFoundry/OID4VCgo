package mobile

import (
	"errors"
	"testing"
)

// proof_key_by_jwk reaches walletflow.Config.ProofKeyByJWK, and is off
// unless set; proof_key_by_index, now the default, still decodes, and
// is invalid_input with proof_key_by_jwk.
func TestWalletflowConfig_ProofKey(t *testing.T) {
	for raw, want := range map[string]bool{
		`{"development":true}`:                           false,
		`{"development":true,"proof_key_by_jwk":true}`:   true,
		`{"development":true,"proof_key_by_index":true}`: false,
	} {
		var cfg config
		if err := decodeConfig(raw, &cfg); err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		wcfg, err := walletConfig(cfg)
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if wcfg.ProofKeyByJWK != want {
			t.Errorf("%s: ProofKeyByJWK = %v, want %v", raw, wcfg.ProofKeyByJWK, want)
		}
	}

	var cfg config
	if err := decodeConfig(`{"development":true,"proof_key_by_jwk":true,"proof_key_by_index":true}`, &cfg); err != nil {
		t.Fatal(err)
	}
	var e *Error
	if _, err := walletConfig(cfg); !errors.As(err, &e) || e.Code != CodeInvalidInput {
		t.Errorf("proof_key_by_jwk with proof_key_by_index: %v, want %s", err, CodeInvalidInput)
	}
}
