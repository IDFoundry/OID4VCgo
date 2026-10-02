package walletapp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/idfoundry/oid4vcgo/walletflow"
)

// softwareKeys is a walletflow.KeyStore of ordinary in-memory keys whose
// private halves the demo reads back, to keep each holder key with its
// credential in the Store.
type softwareKeys struct {
	mu   sync.Mutex
	keys map[string]*ecdsa.PrivateKey
}

func newSoftwareKeys() *softwareKeys {
	return &softwareKeys{keys: map[string]*ecdsa.PrivateKey{}}
}

type softwareKey struct {
	*ecdsa.PrivateKey
	id string
}

func (k softwareKey) ID() string { return k.id }

// NewKey implements walletflow.KeyStore.
func (s *softwareKeys) NewKey(context.Context, walletflow.KeyPurpose) (walletflow.Key, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	id := base64.RawURLEncoding.EncodeToString(b[:])
	s.add(id, priv)
	return softwareKey{priv, id}, nil
}

// Key implements walletflow.KeyStore.
func (s *softwareKeys) Key(_ context.Context, id string) (walletflow.Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		return nil, fmt.Errorf("walletapp: key %q: %w", id, walletflow.ErrNotFound)
	}
	return softwareKey{k, id}, nil
}

// DeleteKey implements walletflow.KeyStore.
func (s *softwareKeys) DeleteKey(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.keys, id)
	return nil
}

func (s *softwareKeys) add(id string, k *ecdsa.PrivateKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[id] = k
}

// received is c with its holder key, as the demo keeps it.
func (s *softwareKeys) received(c walletflow.StoredCredential) Received {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Received{
		ConfigurationID: c.ConfigurationID, Format: c.Format, DocType: c.DocType,
		Credential: c.Credential, HolderKey: s.keys[c.HolderKeyID],
	}
}
