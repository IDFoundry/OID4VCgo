package mobile

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

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
}

func newGoKeyStore() *goKeyStore { return &goKeyStore{keys: map[string]*ecdsa.PrivateKey{}} }

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
	ks := keyStore{newGoKeyStore()}
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
