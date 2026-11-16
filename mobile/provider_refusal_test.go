//go:build mobiletest

package mobile

import (
	"errors"
	"sync/atomic"
	"testing"
)

// markingProvider is a native Wallet Provider that, while refusal is
// set, refuses Wallet Attestations with it, and while keyRefusal is,
// Key Attestations, marked as the Swift and Kotlin adapters mark a
// WalletProviderRefusedError.
type markingProvider struct {
	WalletProvider
	refusal, keyRefusal atomic.Pointer[string]
}

func refusedWith(code, path string) error {
	return errors.New("[refused:" + code + "] the Wallet Provider refused " + path + ": HTTP 403 " + code)
}

func (p *markingProvider) WalletAttestation(clientID string, instanceKeyJWK []byte) ([]byte, error) {
	if code := p.refusal.Load(); code != nil {
		return nil, refusedWith(*code, "/v1/wallet-attestation")
	}
	return p.WalletProvider.WalletAttestation(clientID, instanceKeyJWK)
}

func (p *markingProvider) KeyAttestation(instanceKeyJWK, keysJWK []byte, nonce string) ([]byte, error) {
	if code := p.keyRefusal.Load(); code != nil {
		return nil, refusedWith(*code, "/v1/key-attestation")
	}
	return p.WalletProvider.KeyAttestation(instanceKeyJWK, keysJWK, nonce)
}

// A native provider's refusal to attest a refresh grant's instance key
// again — instance_key_expired, or instance_key_registered once it
// registered again after registration_expired — makes the refresh
// reissue_required, and the grant goes with its instance key: the next
// refresh doesn't ask the provider again, and receiving the credentials
// again works, with a new instance key. A refusal that doesn't retire
// the key (instance_not_active) keeps the grant. That holds at the
// refresh's Wallet Attestation, and, once that passed, at the Key
// Attestation of its new holder keys, which is for the same instance
// key.
func TestSessions_RefreshRefusedByNativeProvider(t *testing.T) {
	stages := map[string]func(*markingProvider) *atomic.Pointer[string]{
		"wallet attestation": func(p *markingProvider) *atomic.Pointer[string] { return &p.refusal },
		"key attestation":    func(p *markingProvider) *atomic.Pointer[string] { return &p.keyRefusal },
	}
	for stage, refusing := range stages {
		for _, refusal := range []string{"instance_key_expired", "instance_key_registered", "registration_expired"} {
			t.Run(stage+"/"+refusal, func(t *testing.T) {
				testRefreshRefusedByNativeProvider(t, refusal, refusing)
			})
		}
	}
}

func testRefreshRefusedByNativeProvider(t *testing.T, refusal string, refusing func(*markingProvider) *atomic.Pointer[string]) {
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
	refused := refusing(provider)

	suspended := "instance_not_active"
	refused.Store(&suspended)
	if _, err := h.w.RefreshCredential(NewOperation(0), id); code(err) != CodePlatform || providerDetail(err) != suspended {
		t.Fatalf("refused as suspended: %v, want platform instance_not_active", err)
	}
	if len(h.keys.keys) != keys {
		t.Fatalf("keys after a suspension = %d, want %d: the grant's instance key kept", len(h.keys.keys), keys)
	}

	refused.Store(&refusal)
	if _, err := h.w.RefreshCredential(NewOperation(0), id); code(err) != CodeReissueRequired {
		t.Fatalf("RefreshCredential = %v, want reissue_required", err)
	}
	if len(h.keys.keys) != keys-1 {
		t.Errorf("keys = %d, want %d: the grant's instance key deleted", len(h.keys.keys), keys-1)
	}
	refused.Store(nil)
	if _, err := h.w.RefreshCredential(NewOperation(0), id); code(err) != CodeReissueRequired {
		t.Errorf("RefreshCredential again = %v, want reissue_required: the grant is gone", err)
	}
	h.receive(t)
}
