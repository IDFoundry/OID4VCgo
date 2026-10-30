package sqlstore

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/idfoundry/fapigo/keys"

	"github.com/idfoundry/oid4vcgo/walletflow"
)

// keyRecord is a key as a KeyStore keeps it, always sealed.
type keyRecord struct {
	Purpose walletflow.KeyPurpose `json:"purpose"`
	// PKCS8 is the private key, PKCS #8 DER.
	PKCS8 []byte `json:"pkcs8"`
}

// KeyStore is a walletflow.KeyStore of software P-256 keys, each kept
// in the database sealed by the DB's Sealer: Dependencies.Keys for a
// wallet running on a server, where the keys' protection is the
// Sealer's key and whatever holds it (a KMS, say). A wallet on a phone
// belongs with the platform's secure hardware instead (the Secure
// Enclave, Android Keystore), which never lets a key out.
type KeyStore struct {
	t *table[keyRecord]
}

// Keys returns d's walletflow.KeyStore. It needs the DB to have a
// Sealer: private keys are never stored unsealed.
func (d *DB) Keys() (*KeyStore, error) {
	if d.sealer == nil {
		return nil, errors.New("sqlstore: a KeyStore needs Options.Sealer: private keys are never stored unsealed")
	}
	return &KeyStore{&table[keyRecord]{d: d, name: "wallet_keys", sql: tableSQL{insert: d.sql.keyInsert, get: d.sql.keyGet, delete: d.sql.keyDelete}, rowOf: func(keyRecord) row { return row{} }}}, nil
}

// storedKey is a KeyStore's walletflow.Key.
type storedKey struct {
	*ecdsa.PrivateKey
	id string
}

func (k storedKey) ID() string { return k.id }

// NewKey implements walletflow.KeyStore.
func (s *KeyStore) NewKey(ctx context.Context, purpose walletflow.KeyPurpose) (walletflow.Key, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: new key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: new key: %w", err)
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("sqlstore: new key: %w", err)
	}
	id := base64.RawURLEncoding.EncodeToString(b)
	if err := s.t.insert(ctx, id, keyRecord{Purpose: purpose, PKCS8: der}); err != nil {
		return nil, fmt.Errorf("sqlstore: new key: %w", err)
	}
	return storedKey{priv, id}, nil
}

// Key implements walletflow.KeyStore.
func (s *KeyStore) Key(ctx context.Context, id string) (walletflow.Key, error) {
	r, err := s.t.get(ctx, id)
	if err != nil {
		return nil, notFound("key", id, err)
	}
	priv, err := x509.ParsePKCS8PrivateKey(r.PKCS8)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: key %q: %w: %v", id, ErrRecordFormat, err)
	}
	ec, ok := priv.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, fmt.Errorf("sqlstore: key %q: %w: not a P-256 key", id, ErrRecordFormat)
	}
	return storedKey{ec, id}, nil
}

// DeleteKey implements walletflow.KeyStore.
func (s *KeyStore) DeleteKey(ctx context.Context, id string) error {
	_, err := s.t.remove(ctx, id)
	return notFound("delete key", id, err)
}

// KeyCustody implements keys.KeyCustodyAssurance: the keys survive a
// restart, and every process sharing the database uses the same ones.
// It says nothing of how well they're protected, which is the Sealer's
// key's to provide.
func (s *KeyStore) KeyCustody() keys.KeyCustody {
	return keys.KeyCustody{Durable: true, CrossInstanceConsistent: true}
}
