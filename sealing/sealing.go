// Package sealing seals records at rest: the Sealer interface every
// store of this library that keeps holders' data outside the process
// takes (github.com/idfoundry/oid4vcgo/sqlstore's Options.Sealer, the
// verifier's TransactionCodec.Sealer), AESGCMSealer to make one from a
// key, and Store, by which a store declares whether it seals what it
// holds, so a role's production assurance can refuse one that doesn't.
package sealing

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
)

// Sealer seals and opens a record's secret data — an AEAD, such as
// AESGCMSealer, or a call to a key management service. Open must
// refuse sealed data altered in any way, or sealed with other
// additionalData: that's what binds each sealed value to the record
// it belongs to. It protects only what it seals: whatever a store
// keeps beside it stays as the store keeps it.
type Sealer interface {
	Seal(plaintext, additionalData []byte) ([]byte, error)
	Open(sealed, additionalData []byte) ([]byte, error)
}

// Store is implemented by a store that says whether it seals the
// records it holds where they're kept (a database's rows, its
// backups). Under production assurance the issuer refuses a durable
// store holding holders' data that doesn't declare it seals them, as
// the verifier refuses an unsealed TransactionStore.
type Store interface {
	// SealsRecords reports whether the store seals its records with a
	// Sealer.
	SealsRecords() bool
}

// AESGCMSealer is a Sealer that seals with AES-256-GCM under key (32
// bytes, from a cryptographically secure source, kept outside the
// store), with a random nonce for each seal. Random nonces allow about
// 2^32 seals per key, so rotate the key before then. Changing the key
// makes the records sealed under the previous one unreadable; to rotate
// it, open with both until those records expire, with a Sealer of your
// own or github.com/idfoundry/fapigo/sqlstore's RotatingSealer, which
// seals with the first sealer it's given and opens with any of them.
// Under a rolling deploy, give every instance RotatingSealer(old, new)
// before any gets RotatingSealer(new, old), so none is handed a record
// sealed under a key it can't open.
//
// Each value it seals is the 12-byte random nonce followed by the
// AES-GCM ciphertext and its 16-byte tag, sealed with the
// additionalData Seal is given: a Sealer of your own can open it, with
// crypto/cipher's NewGCM, under a key this one refuses.
//
// It refuses a key that's one byte repeated (all zeros, say: a
// placeholder), or all printable text (a passphrase, or a hex or base64
// key not yet decoded), as fapigo/sqlstore's AESGCMSealer does: neither
// is random, and 32 random bytes are all printable with probability
// about 4e-14.
func AESGCMSealer(key []byte) (Sealer, error) {
	switch {
	case len(key) != 32:
		return nil, fmt.Errorf("sealing: AES-GCM sealer: key is %d bytes, want 32 (AES-256)", len(key))
	case bytes.Count(key, key[:1]) == len(key):
		return nil, errors.New("sealing: AES-GCM sealer: key is one byte repeated, not a random key")
	case !slices.ContainsFunc(key, func(c byte) bool { return (c < 0x20 || c > 0x7e) && c != '\t' && c != '\n' && c != '\r' }):
		return nil, errors.New("sealing: AES-GCM sealer: key is all printable text (a passphrase, or a hex or base64 key not yet decoded), not 32 random bytes: generate it with crypto/rand, and decode an encoded key before passing it")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("sealing: AES-GCM sealer: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("sealing: AES-GCM sealer: %w", err)
	}
	return gcmSealer{aead}, nil
}

type gcmSealer struct{ aead cipher.AEAD }

func (s gcmSealer) Seal(plaintext, additionalData []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, plaintext, additionalData), nil
}

func (s gcmSealer) Open(sealed, additionalData []byte) ([]byte, error) {
	if len(sealed) < s.aead.NonceSize() {
		return nil, errors.New("sealed data is too short")
	}
	nonce, ciphertext := sealed[:s.aead.NonceSize()], sealed[s.aead.NonceSize():]
	return s.aead.Open(nil, nonce, ciphertext, additionalData)
}
