package walletflow

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcgo/statuslist"
)

// StoredCredential is a credential the wallet holds.
type StoredCredential struct {
	// ID identifies it in the CredentialStore.
	ID string
	// CredentialIssuer is the Credential Issuer that issued it.
	CredentialIssuer string
	// ConfigurationID is the issuer's credential configuration it was
	// issued under.
	ConfigurationID string
	// Format is "dc+sd-jwt" or "mso_mdoc".
	Format string
	// VCT is an SD-JWT VC's type; DocType an mdoc's.
	VCT     string
	DocType string
	// Credential is the credential as the issuer returned it: a compact
	// SD-JWT VC, or base64url-encoded mdoc IssuerSigned CBOR.
	Credential string
	// HolderKeyID names the key the credential is bound to, in the
	// wallet's KeyStore.
	HolderKeyID string
	// Claims are the credential's claims, as the wallet checked them
	// on receipt (wallet.VerifyIssuedCredential), for display: an SD-JWT
	// VC's processed payload with every disclosure resolved, or an
	// mdoc's namespace → element identifier → value. They're personal
	// data, like the credential itself.
	Claims map[string]any
	// ReceivedAt is when the wallet received it.
	ReceivedAt time.Time

	// Display is how to show the credential, from the issuer's metadata
	// when it was received.
	Display Display
	// ValidUntil is when the credential expires, or zero when it doesn't
	// say.
	ValidUntil time.Time
	// StatusList is where the issuer publishes the credential's
	// revocation status, nil when it has none; StatusListCWT is whether
	// that list is a CWT. Status is what Wallet.CheckStatus last found
	// there.
	StatusList    *statuslist.StatusListRef
	StatusListCWT bool
	Status        CredentialStatus
}

// CredentialStore holds the wallet's credentials. They carry personal
// data: on a phone, keep them under the platform's data protection.
type CredentialStore interface {
	// Put stores c, replacing any credential with the same ID.
	Put(ctx context.Context, c StoredCredential) error
	// Get returns the credential id names, or an error wrapping
	// ErrNotFound.
	Get(ctx context.Context, id string) (StoredCredential, error)
	// List returns every stored credential.
	List(ctx context.Context) ([]StoredCredential, error)
	// Delete deletes the credential id names. Deleting one that doesn't
	// exist isn't an error.
	Delete(ctx context.Context, id string) error
}

// MemoryCredentialStore is a CredentialStore in memory, for tests and
// development.
type MemoryCredentialStore struct {
	mu          sync.Mutex
	credentials map[string]StoredCredential
}

// NewMemoryCredentialStore returns an empty MemoryCredentialStore.
func NewMemoryCredentialStore() *MemoryCredentialStore {
	return &MemoryCredentialStore{credentials: make(map[string]StoredCredential)}
}

// Put implements CredentialStore.
func (s *MemoryCredentialStore) Put(_ context.Context, c StoredCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.credentials[c.ID] = c
	return nil
}

// Get implements CredentialStore.
func (s *MemoryCredentialStore) Get(_ context.Context, id string) (StoredCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.credentials[id]
	if !ok {
		return StoredCredential{}, fmt.Errorf("walletflow: credential %q: %w", id, ErrNotFound)
	}
	return c, nil
}

// List implements CredentialStore, oldest first.
func (s *MemoryCredentialStore) List(context.Context) ([]StoredCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]StoredCredential, 0, len(s.credentials))
	for _, c := range s.credentials {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].ReceivedAt.Equal(out[j].ReceivedAt) {
			return out[i].ReceivedAt.Before(out[j].ReceivedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// Delete implements CredentialStore.
func (s *MemoryCredentialStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.credentials, id)
	return nil
}
