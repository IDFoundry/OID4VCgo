package mobile

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/idfoundry/oid4vcgo/proximity"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// goKeyStore is a KeyStore over in-memory keys, as the app's would be,
// with ways to misbehave.
type goKeyStore struct {
	mu       sync.Mutex
	keys     map[string]*ecdsa.PrivateKey
	purposes []string
	n        int

	newKeyErr  error
	signErr    error
	wrongKey   bool // signs with another key
	noID       bool // CreateKey returns no ID
	lose       bool // CreateKey's key isn't there afterwards
	keepOnDrop bool // DeleteKey keeps the key
	pubErr     error
}

func newGoKeyStore() *goKeyStore { return &goKeyStore{keys: map[string]*ecdsa.PrivateKey{}} }

func (s *goKeyStore) Durable() bool { return true }

func (s *goKeyStore) CreateKey(purpose string) (string, error) {
	if s.newKeyErr != nil {
		return "", s.newKeyErr
	}
	if s.noID {
		return "", nil
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	id := fmt.Sprintf("%s-%d", purpose, s.n)
	s.purposes = append(s.purposes, purpose)
	if !s.lose {
		s.keys[id] = k
	}
	return id, nil
}

func (s *goKeyStore) PublicKey(id string) ([]byte, error) {
	if s.pubErr != nil {
		return nil, s.pubErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		return nil, nil
	}
	return k.PublicKey.Bytes()
}

func (s *goKeyStore) Sign(id string, digest []byte) ([]byte, error) {
	if s.signErr != nil {
		return nil, s.signErr
	}
	s.mu.Lock()
	k, ok := s.keys[id]
	s.mu.Unlock()
	if !ok {
		return nil, errors.New("no such key")
	}
	if s.wrongKey {
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		k = other
	}
	return k.Sign(rand.Reader, digest, crypto.SHA256)
}

func (s *goKeyStore) DeleteKey(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.keepOnDrop {
		delete(s.keys, id)
	}
	return nil
}

// goKeyAgreement is a KeyAgreement over a goKeyStore's keys, as the
// app's would be, with ways to misbehave.
type goKeyAgreement struct {
	s        *goKeyStore
	signOnly bool // reports the key can't agree keys
	wrong    bool // agrees with another key
	err      error
	n        int
}

func (a *goKeyAgreement) Agree(id string, peerPublicKey []byte) ([]byte, error) {
	a.n++
	if a.signOnly {
		return nil, errors.New("[no_key_agreement] created for signing only")
	}
	if a.err != nil {
		return nil, a.err
	}
	a.s.mu.Lock()
	k, ok := a.s.keys[id]
	a.s.mu.Unlock()
	if !ok {
		return nil, errors.New("no such key")
	}
	if a.wrong {
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		k = other
	}
	priv, err := k.ECDH()
	if err != nil {
		return nil, err
	}
	peer, err := ecdh.P256().NewPublicKey(peerPublicKey)
	if err != nil {
		return nil, err
	}
	return priv.ECDH(peer)
}

func TestCheckKeyAgreement(t *testing.T) {
	for name, tc := range map[string]struct {
		ka   func(*goKeyStore) *goKeyAgreement
		want string
		code string
	}{
		"supported":   {func(s *goKeyStore) *goKeyAgreement { return &goKeyAgreement{s: s} }, "supported", ""},
		"sign only":   {func(s *goKeyStore) *goKeyAgreement { return &goKeyAgreement{s: s, signOnly: true} }, "unsupported", ""},
		"another key": {func(s *goKeyStore) *goKeyAgreement { return &goKeyAgreement{s: s, wrong: true} }, "", CodePlatform},
		"fails":       {func(s *goKeyStore) *goKeyAgreement { return &goKeyAgreement{s: s, err: errors.New("keystore busy")} }, "", CodePlatform},
	} {
		s := newGoKeyStore()
		out, err := CheckKeyAgreement(s, tc.ka(s))
		if tc.code != "" {
			if code(err) != tc.code {
				t.Errorf("%s: CheckKeyAgreement = %v, want %s", name, err, tc.code)
			}
		} else if err != nil {
			t.Errorf("%s: %v", name, err)
		} else {
			var report struct {
				ABI          int    `json:"abi"`
				KeyAgreement string `json:"key_agreement"`
			}
			if err := json.Unmarshal([]byte(out), &report); err != nil || report.ABI != ABIVersion || report.KeyAgreement != tc.want {
				t.Errorf("%s: report = %s (%v)", name, out, err)
			}
		}
		if len(s.keys) != 0 {
			t.Errorf("%s: %d keys left behind", name, len(s.keys))
		}
		if strings.Join(s.purposes, ",") != "holder" {
			t.Errorf("%s: purposes asked for = %v", name, s.purposes)
		}
	}
	if _, err := CheckKeyAgreement(newGoKeyStore(), nil); code(err) != CodeInvalidInput {
		t.Errorf("no key agreement: %v", err)
	}
}

// A platform key agrees keys only through a KeyAgreement; without one,
// or for a sign-only key, it reports proximity.ErrNoKeyAgreement.
func TestPlatformKeyAgree(t *testing.T) {
	s := newGoKeyStore()
	ka := &agreement{}
	ks := keyStore{ks: s, ka: ka}
	key, err := ks.NewKey(context.Background(), walletflow.KeyPurposeHolder)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	agreer := key.(proximity.KeyAgreer)
	if _, err := agreer.Agree(&peer.PublicKey); !errors.Is(err, proximity.ErrNoKeyAgreement) {
		t.Errorf("no KeyAgreement: %v", err)
	}
	var sign KeyAgreement = &goKeyAgreement{s: s, signOnly: true}
	ka.ka.Store(&sign)
	if _, err := agreer.Agree(&peer.PublicKey); !errors.Is(err, proximity.ErrNoKeyAgreement) {
		t.Errorf("sign-only key: %v", err)
	}
	var good KeyAgreement = &goKeyAgreement{s: s}
	ka.ka.Store(&good)
	z, err := agreer.Agree(&peer.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	peerPriv, _ := peer.ECDH()
	holderPub, _ := key.Public().(*ecdsa.PublicKey).ECDH()
	if want, _ := peerPriv.ECDH(holderPub); string(z) != string(want) {
		t.Error("the agreed secret isn't the peer's")
	}
}

func TestCheckKeyStore(t *testing.T) {
	s := newGoKeyStore()
	out, err := CheckKeyStore(s)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		ABI     int      `json:"abi"`
		Checked []string `json:"checked"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if report.ABI != ABIVersion || strings.Join(report.Checked, ",") != "instance,dpop,holder" {
		t.Errorf("report = %s", out)
	}
	if len(s.keys) != 0 {
		t.Errorf("%d keys left behind", len(s.keys))
	}
	if strings.Join(s.purposes, ",") != "instance,dpop,holder" {
		t.Errorf("purposes asked for = %v", s.purposes)
	}
}

func TestCheckKeyStore_FindsMisbehaviour(t *testing.T) {
	for name, s := range map[string]*goKeyStore{
		"CreateKey fails":          {newKeyErr: errors.New("no enclave")},
		"no key ID":                {noID: true},
		"key lost after CreateKey": {lose: true},
		"signs with another key":   {wrongKey: true},
		"signing fails":            {signErr: errors.New("the user cancelled Face ID")},
		"DeleteKey keeps it":       {keepOnDrop: true},
	} {
		s.keys = map[string]*ecdsa.PrivateKey{}
		if _, err := CheckKeyStore(s); code(err) != CodePlatform {
			t.Errorf("%s: CheckKeyStore = %v, want a platform error", name, err)
		}
		if name != "DeleteKey keeps it" && len(s.keys) != 0 {
			t.Errorf("%s: %d keys left behind", name, len(s.keys))
		}
	}
	if _, err := CheckKeyStore(nil); code(err) != CodeInvalidInput {
		t.Errorf("no store: %v", err)
	}
}

// TestKeyStoreIsAWalletflowKeyStore: walletflow sees the app's keys,
// and a missing one as walletflow.ErrNotFound.
func TestKeyStoreIsAWalletflowKeyStore(t *testing.T) {
	ctx := context.Background()
	ks := keyStore{ks: newGoKeyStore()}
	if _, err := walletflow.New(walletflow.Config{}, walletflow.Dependencies{Keys: ks, Credentials: walletflow.NewMemoryCredentialStore()}); err != nil {
		t.Fatal(err)
	}
	k, err := ks.NewKey(ctx, walletflow.KeyPurposeHolder)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Sign(rand.Reader, make([]byte, 20), crypto.SHA256); err == nil {
		t.Error("signed a digest of the wrong length")
	}
	if _, err := k.Sign(rand.Reader, make([]byte, 48), crypto.SHA384); err == nil {
		t.Error("signed a SHA-384 digest")
	}
	if err := ks.DeleteKey(ctx, k.ID()); err != nil {
		t.Fatal(err)
	}
	_, err = ks.Key(ctx, k.ID())
	if !errors.Is(err, walletflow.ErrNotFound) || code(err) != CodeNotFound || !strings.HasPrefix(err.Error(), "[not_found] ") {
		t.Errorf("a deleted key: %v", err)
	}
}

// TestKeyStore_DeletesAKeyItCantLoad: a key the store creates but can't
// return the public key of is deleted, not left behind.
func TestKeyStore_DeletesAKeyItCantLoad(t *testing.T) {
	s := newGoKeyStore()
	s.pubErr = errors.New("keychain unavailable")
	if _, err := (keyStore{ks: s}).NewKey(context.Background(), walletflow.KeyPurposeHolder); code(err) != CodePlatform {
		t.Fatalf("NewKey = %v", err)
	}
	if len(s.keys) != 0 {
		t.Errorf("%d keys left behind", len(s.keys))
	}
}

// TestKeyStore_CreateKeyNetworkFailure: a CreateKey error marked as a
// network failure (a Wallet Provider challenge the store couldn't fetch)
// is reported as network, retryable; any other as platform.
func TestKeyStore_CreateKeyNetworkFailure(t *testing.T) {
	s := newGoKeyStore()
	s.newKeyErr = errors.New("[network] challenge: offline")
	_, err := (keyStore{ks: s}).NewKey(context.Background(), walletflow.KeyPurposeHolder)
	if code(err) != CodeNetwork || !strings.Contains(err.Error(), "new holder key: challenge: offline") {
		t.Errorf("NewKey = %v", err)
	}
	s.newKeyErr = errors.New("keystore broken")
	if _, err := (keyStore{ks: s}).NewKey(context.Background(), walletflow.KeyPurposeHolder); code(err) != CodePlatform {
		t.Errorf("NewKey = %v", err)
	}
}
