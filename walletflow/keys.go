package walletflow

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"
)

// KeyPurpose says what a key is for, so a KeyStore can apply the right
// protection: for example, user presence for holder keys.
type KeyPurpose string

const (
	// KeyPurposeInstance is the wallet instance key a Wallet Attestation
	// binds; it signs the Client Attestation PoP at the Pushed
	// Authorization Request and Token Endpoints. One per issuance.
	KeyPurposeInstance KeyPurpose = "instance"
	// KeyPurposeDPoP signs DPoP proofs; the access token is bound to
	// it. One per issuance.
	KeyPurposeDPoP KeyPurpose = "dpop"
	// KeyPurposeHolder is the key a credential is bound to: it signs
	// the Key Binding JWT or mdoc DeviceAuth when presenting. One per
	// credential. A KeyStore may require user presence to sign with it;
	// walletflow signs with a holder key only when presenting.
	KeyPurposeHolder KeyPurpose = "holder"
)

// Key is a P-256 key held by a KeyStore. Sign is called with a SHA-256
// digest and crypto.SHA256 and must return an ASN.1 DER ECDSA signature,
// as an *ecdsa.PrivateKey would; the private key never needs to leave
// the store.
type Key interface {
	crypto.Signer
	// ID identifies the key in its KeyStore.
	ID() string
}

// KeyStore creates and holds the wallet's keys. On a phone it's backed
// by secure hardware (the Secure Enclave, Android Keystore).
type KeyStore interface {
	// NewKey creates a P-256 key for purpose.
	NewKey(ctx context.Context, purpose KeyPurpose) (Key, error)
	// Key returns the key id names, or an error wrapping ErrNotFound.
	Key(ctx context.Context, id string) (Key, error)
	// DeleteKey deletes the key id names. Deleting a key that doesn't
	// exist isn't an error.
	DeleteKey(ctx context.Context, id string) error
}

// newKey creates a key for purpose and checks it's a P-256 key.
func newKey(ctx context.Context, store KeyStore, purpose KeyPurpose) (Key, error) {
	k, err := store.NewKey(ctx, purpose)
	if err != nil {
		return nil, fmt.Errorf("walletflow: new %s key: %w", purpose, err)
	}
	if _, err := p256(k); err != nil {
		_ = store.DeleteKey(ctx, k.ID())
		return nil, err
	}
	return k, nil
}

// p256 returns k's public key, which must be P-256.
func p256(k Key) (*ecdsa.PublicKey, error) {
	pub, ok := k.Public().(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("walletflow: key %q isn't a P-256 key", k.ID())
	}
	return pub, nil
}

// MemoryKeyStore is a KeyStore of ordinary in-memory keys, for tests and
// development. A real wallet keeps its keys in secure hardware.
type MemoryKeyStore struct {
	mu   sync.Mutex
	keys map[string]*memoryKey
}

// NewMemoryKeyStore returns an empty MemoryKeyStore.
func NewMemoryKeyStore() *MemoryKeyStore {
	return &MemoryKeyStore{keys: make(map[string]*memoryKey)}
}

type memoryKey struct {
	*ecdsa.PrivateKey
	id string
}

func (k *memoryKey) ID() string { return k.id }

// NewKey implements KeyStore.
func (s *MemoryKeyStore) NewKey(_ context.Context, _ KeyPurpose) (Key, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	id, err := randomID(rand.Reader)
	if err != nil {
		return nil, err
	}
	k := &memoryKey{PrivateKey: priv, id: id}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[id] = k
	return k, nil
}

// Key implements KeyStore.
func (s *MemoryKeyStore) Key(_ context.Context, id string) (Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		return nil, fmt.Errorf("walletflow: key %q: %w", id, ErrNotFound)
	}
	return k, nil
}

// DeleteKey implements KeyStore.
func (s *MemoryKeyStore) DeleteKey(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.keys, id)
	return nil
}

// Len returns how many keys s holds.
func (s *MemoryKeyStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.keys)
}

// randomID returns a random 128-bit identifier.
func randomID(r io.Reader) (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", errors.New("walletflow: random identifier: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
