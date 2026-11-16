//go:build mobiletest

package mobile

import (
	"errors"
	"sync/atomic"
	"testing"
)

// markingProvider is a native Wallet Provider that, while refusal is
// set, refuses Wallet Attestations with it, marked as the Swift and
// Kotlin adapters mark a WalletProviderRefusedError.
type markingProvider struct {
	WalletProvider
	refusal atomic.Pointer[string]
}

func (p *markingProvider) WalletAttestation(clientID string, instanceKeyJWK []byte) ([]byte, error) {
	if code := p.refusal.Load(); code != nil {
		return nil, errors.New("[refused:" + *code + "] the Wallet Provider refused /v1/wallet-attestation: HTTP 403 " + *code)
	}
	return p.WalletProvider.WalletAttestation(clientID, instanceKeyJWK)
}

// A native provider's refusal to attest a refresh grant's instance key
// again — instance_key_expired, or instance_key_registered once it
// registered again after registration_expired — makes the refresh
// reissue_required, and the grant goes with its instance key: the next
// refresh doesn't ask the provider again, and receiving the credentials
// again works, with a new instance key. A refusal that doesn't retire
// the key (instance_not_active) keeps the grant.
func TestSessions_RefreshRefusedByNativeProvider(t *testing.T) {
	for _, refusal := range []string{"instance_key_expired", "instance_key_registered", "registration_expired"} {
		t.Run(refusal, func(t *testing.T) {
			env, err := StartBatchTestEnv(false, 1)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(env.Close)
			provider := &markingProvider{WalletProvider: env.Provider()}
			h := harness{env: env, keys: newGoKeyStore(), creds: newGoCredentialStore()}
			if h.w, err = NewWallet(env.ConfigJSON(), h.keys, h.creds, provider); err != nil {
				t.Fatal(err)
			}
			id := h.receive(t)[0].ID
			keys := len(h.keys.keys)

			suspended := "instance_not_active"
			provider.refusal.Store(&suspended)
			if _, err := h.w.RefreshCredential(NewOperation(0), id); code(err) != CodePlatform || providerDetail(err) != suspended {
				t.Fatalf("refused as suspended: %v, want platform instance_not_active", err)
			}
			if len(h.keys.keys) != keys {
				t.Fatalf("keys after a suspension = %d, want %d: the grant's instance key kept", len(h.keys.keys), keys)
			}

			provider.refusal.Store(&refusal)
			if _, err := h.w.RefreshCredential(NewOperation(0), id); code(err) != CodeReissueRequired {
				t.Fatalf("RefreshCredential = %v, want reissue_required", err)
			}
			if len(h.keys.keys) != keys-1 {
				t.Errorf("keys = %d, want %d: the grant's instance key deleted", len(h.keys.keys), keys-1)
			}
			provider.refusal.Store(nil)
			if _, err := h.w.RefreshCredential(NewOperation(0), id); code(err) != CodeReissueRequired {
				t.Errorf("RefreshCredential again = %v, want reissue_required: the grant is gone", err)
			}
			h.receive(t)
		})
	}
}
