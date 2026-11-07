package mobile

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/attestation"
)

// promptingKeyStore is a goKeyStore whose keys, while prompting is set,
// wait in Sign and Agree for the holder, as a key store showing a
// biometric prompt does: until answer is closed, or CancelKeyUse
// dismisses the prompt. It's the app's CallbackCanceller too, as the
// Swift and Kotlin libraries' key stores are behind theirs.
type promptingKeyStore struct {
	*goKeyStore
	agreement *goKeyAgreement
	// delay passes before a prompt shows, so a cancel can come first.
	delay  time.Duration
	answer chan struct{}

	mu        sync.Mutex
	prompting bool
	prompts   map[string]chan struct{}
	shown     chan string
	cancelled []string
	providers [][]byte
}

func newPromptingKeyStore() *promptingKeyStore {
	s := &promptingKeyStore{goKeyStore: newGoKeyStore(), answer: make(chan struct{}), prompts: map[string]chan struct{}{}, shown: make(chan string, 16), prompting: true}
	s.agreement = &goKeyAgreement{s: s.goKeyStore}
	return s
}

var errDismissed = errors.New("the holder wasn't authenticated: cancelled")

// prompt waits for the holder, when prompting, for key id.
func (s *promptingKeyStore) prompt(id string) error {
	s.mu.Lock()
	prompting := s.prompting
	s.mu.Unlock()
	if !prompting {
		return nil
	}
	time.Sleep(s.delay)
	dismissed := make(chan struct{})
	s.mu.Lock()
	s.prompts[id] = dismissed
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.prompts, id)
		s.mu.Unlock()
	}()
	s.shown <- id
	select {
	case <-dismissed:
		return errDismissed
	case <-s.answer:
		return nil
	}
}

func (s *promptingKeyStore) Sign(id string, digest []byte) ([]byte, error) {
	if err := s.prompt(id); err != nil {
		return nil, err
	}
	return s.goKeyStore.Sign(id, digest)
}

func (s *promptingKeyStore) Agree(id string, peer []byte) ([]byte, error) {
	if err := s.prompt(id); err != nil {
		return nil, err
	}
	return s.agreement.Agree(id, peer)
}

func (s *promptingKeyStore) CancelKeyUse(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cancelled = append(s.cancelled, id)
	if dismissed, ok := s.prompts[id]; ok {
		close(dismissed)
		delete(s.prompts, id)
	}
}

func (s *promptingKeyStore) CancelProvider(instanceKeyJWK []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.providers = append(s.providers, instanceKeyJWK)
}

func (s *promptingKeyStore) cancels() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.cancelled)
}

// key makes a key in s and loads it for ctx's call, with s as the
// CallbackCanceller when withCanceller.
func (s *promptingKeyStore) key(t *testing.T, ctx context.Context, withCanceller bool) *platformKey {
	t.Helper()
	ks := keyStore{ks: s, ka: &agreement{}, cc: &canceller{}}
	if withCanceller {
		var c CallbackCanceller = s
		ks.cc.c.Store(&c)
	}
	var ka KeyAgreement = s
	ks.ka.ka.Store(&ka)
	s.mu.Lock()
	s.prompting = false
	s.mu.Unlock()
	k, err := ks.NewKey(context.Background(), "holder")
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.prompting = true
	s.mu.Unlock()
	key, err := ks.Key(ctx, k.ID())
	if err != nil {
		t.Fatal(err)
	}
	return key.(*platformKey)
}

func digest() []byte {
	d := sha256.Sum256([]byte("oid4vcgo"))
	return d[:]
}

// Cancelling a call while its holder key's prompt shows dismisses the
// prompt, and the signature fails as cancelled at once.
func TestCallbackCanceller_SignDismissesPrompt(t *testing.T) {
	s := newPromptingKeyStore()
	ctx, cancel := context.WithCancel(context.Background())
	key := s.key(t, ctx, true)
	go func() {
		<-s.shown
		cancel()
	}()
	start := time.Now()
	_, err := key.Sign(rand.Reader, digest(), crypto.SHA256)
	if code(classify(err)) != CodeCancelled || code(err) != CodeCancelled {
		t.Errorf("Sign = %v (classified %v)", err, classify(err))
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("Sign returned after %v", time.Since(start))
	}
	if got := s.cancels(); len(got) == 0 || got[0] != key.ID() {
		t.Errorf("CancelKeyUse calls = %v, want %q", got, key.ID())
	}
}

// An Operation's timeout ends the prompt too, and is network, as the
// call's other timeouts are.
func TestCallbackCanceller_TimeoutDismissesPrompt(t *testing.T) {
	s := newPromptingKeyStore()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	key := s.key(t, ctx, true)
	_, err := key.Sign(rand.Reader, digest(), crypto.SHA256)
	if code(classify(err)) != CodeNetwork || code(err) != CodeNetwork {
		t.Errorf("Sign = %v (classified %v)", err, classify(err))
	}
}

// A cancel that comes before the prompt shows is repeated, so the
// prompt is dismissed once it does.
func TestCallbackCanceller_PromptShownAfterCancel(t *testing.T) {
	s := newPromptingKeyStore()
	s.delay = 3 * cancelRetryInterval
	ctx, cancel := context.WithCancel(context.Background())
	key := s.key(t, ctx, true)
	go func() {
		time.Sleep(cancelRetryInterval / 5)
		cancel()
	}()
	if _, err := key.Sign(rand.Reader, digest(), crypto.SHA256); code(classify(err)) != CodeCancelled {
		t.Errorf("Sign = %v", err)
	}
	if got := s.cancels(); len(got) < 2 {
		t.Errorf("CancelKeyUse calls = %v, want it repeated", got)
	}
}

// Agreeing a key (deviceMac) is dismissed as signing is.
func TestCallbackCanceller_AgreeDismissesPrompt(t *testing.T) {
	s := newPromptingKeyStore()
	ctx, cancel := context.WithCancel(context.Background())
	key := s.key(t, ctx, true)
	peer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		<-s.shown
		cancel()
	}()
	if _, err := key.Agree(&peer.PublicKey); code(classify(err)) != CodeCancelled {
		t.Errorf("Agree = %v", err)
	}
	if got := s.cancels(); len(got) == 0 || got[0] != key.ID() {
		t.Errorf("CancelKeyUse calls = %v", got)
	}
}

// A call that isn't cancelled signs when the holder answers, and the
// canceller hears nothing.
func TestCallbackCanceller_Answered(t *testing.T) {
	s := newPromptingKeyStore()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	key := s.key(t, ctx, true)
	go func() {
		<-s.shown
		close(s.answer)
	}()
	sig, err := key.Sign(rand.Reader, digest(), crypto.SHA256)
	if err != nil || !ecdsa.VerifyASN1(key.pub, digest(), sig) {
		t.Fatalf("Sign = %x, %v", sig, err)
	}
	if got := s.cancels(); len(got) != 0 {
		t.Errorf("CancelKeyUse calls = %v, want none", got)
	}
}

// A key loaded by a call that has since ended — a session's DPoP key,
// loaded at its start — still signs for a later call: its old call's
// end isn't taken for this one's.
func TestCallbackCanceller_KeyFromEndedCall(t *testing.T) {
	s := newPromptingKeyStore()
	close(s.answer)
	ctx, cancel := context.WithCancel(context.Background())
	key := s.key(t, ctx, true)
	cancel()
	if _, err := key.Sign(rand.Reader, digest(), crypto.SHA256); err != nil {
		t.Errorf("Sign = %v", err)
	}
	if got := s.cancels(); len(got) != 0 {
		t.Errorf("CancelKeyUse calls = %v, want none", got)
	}
}

// Without a CallbackCanceller, a cancelled call waits for the holder,
// as before, and the prompt's own failure is platform.
func TestCallbackCanceller_None(t *testing.T) {
	s := newPromptingKeyStore()
	ctx, cancel := context.WithCancel(context.Background())
	key := s.key(t, ctx, false)
	go func() {
		<-s.shown
		cancel()
		time.Sleep(2 * cancelRetryInterval)
		s.mu.Lock()
		for _, dismissed := range s.prompts {
			close(dismissed)
		}
		s.prompts = map[string]chan struct{}{}
		s.mu.Unlock()
	}()
	if _, err := key.Sign(rand.Reader, digest(), crypto.SHA256); code(err) != CodePlatform {
		t.Errorf("Sign = %v", err)
	}
	if got := s.cancels(); len(got) != 0 {
		t.Errorf("CancelKeyUse calls = %v, want none", got)
	}
}

// A cancelled Wallet Provider call is told to stop, with the instance
// key it was given, until it returns.
func TestCallbackCanceller_Provider(t *testing.T) {
	s := newPromptingKeyStore()
	var c CallbackCanceller = s
	cc := &canceller{}
	cc.c.Store(&c)
	release := make(chan struct{})
	p := walletProvider{&blockingProvider{release: release}, cc}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	instance, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.WalletAttestation(ctx, "client", &instance.PublicKey); !errors.Is(err, context.Canceled) {
		t.Errorf("WalletAttestation = %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		s.mu.Lock()
		n := len(s.providers)
		var first []byte
		if n > 0 {
			first = s.providers[0]
		}
		s.mu.Unlock()
		if n > 0 {
			if want, _ := attestation.AttestedKey(&instance.PublicKey); string(first) != string(want) {
				t.Errorf("CancelProvider(%s), want %s", first, want)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("CancelProvider wasn't called")
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(release)
}

// Wallet.SetCallbackCanceller sets the wallet's, and nil removes it.
func TestWallet_SetCallbackCanceller(t *testing.T) {
	w := &Wallet{cc: &canceller{}}
	s := newPromptingKeyStore()
	w.SetCallbackCanceller(s)
	if w.cc.get() != CallbackCanceller(s) {
		t.Error("SetCallbackCanceller didn't set it")
	}
	w.SetCallbackCanceller(nil)
	if w.cc.get() != nil {
		t.Error("SetCallbackCanceller(nil) didn't remove it")
	}
	var none *canceller
	if none.get() != nil {
		t.Error("a nil canceller has a CallbackCanceller")
	}
}

// blockingProvider is a WalletProvider whose calls wait for release.
type blockingProvider struct{ release chan struct{} }

func (p *blockingProvider) WalletAttestation(string, []byte) ([]byte, error) {
	<-p.release
	return []byte("jwt"), nil
}

func (p *blockingProvider) KeyAttestation([]byte, []byte, string) ([]byte, error) {
	<-p.release
	return []byte("jwt"), nil
}
