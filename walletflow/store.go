package walletflow

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"slices"
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
	// wallet's KeyStore. Credential and HolderKeyID are the first of
	// Copies.
	HolderKeyID string
	// Copies are every copy the issuer issued in one batch: the same
	// claims, each bound to its own key, so each presentation can use
	// one no Verifier has seen (unlinkability). nil for a credential
	// stored before copies were kept: its one copy is Credential.
	Copies []CredentialCopy
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

	// GrantID names the RefreshGrant Wallet.RefreshCredential refreshes
	// it with, when its issuance kept one (Config.RequestRefresh); ""
	// when it can't be refreshed, only received again.
	GrantID string
}

// CredentialCopy is one copy of a credential: the credential, the key
// it's bound to, whether it's been presented, and to which Verifiers.
type CredentialCopy struct {
	Credential  string
	HolderKeyID string
	Presented   bool
	// ShownTo are the Verifiers it's been presented to, each as a hash of
	// its client_id (VerifierHash), not the client_id itself: the wallet
	// can tell whether a Verifier has seen it without keeping a readable
	// list of where the holder has shown their credentials.
	ShownTo []string
}

// VerifierHash is how a CredentialCopy's ShownTo records the Verifier
// whose client_id is clientID.
func VerifierHash(clientID string) string {
	sum := sha256.Sum256([]byte("walletflow verifier " + clientID))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ShownTo reports whether a copy of c has been presented to the Verifier
// whose client_id is clientID (Presentation.Verifier().ClientID).
func (c StoredCredential) ShownTo(clientID string) bool {
	h := VerifierHash(clientID)
	return slices.ContainsFunc(c.AllCopies(), func(cp CredentialCopy) bool { return slices.Contains(cp.ShownTo, h) })
}

// copyFor is the copy to present to the Verifier verifierHash names
// under policy, and whether it's one that Verifier has seen already.
// Per Verifier, that's the copy it has seen, if any; otherwise, as per
// presentation, the next copy (nextCopy).
func (c StoredCredential) copyFor(policy CopyPolicy, verifierHash string) (int, CredentialCopy, bool) {
	copies := c.AllCopies()
	if policy == CopyPerVerifier {
		for i, cp := range copies {
			if slices.Contains(cp.ShownTo, verifierHash) {
				return i, cp, true
			}
		}
	}
	i, cp := c.nextCopy()
	return i, cp, false
}

// AllCopies are c's copies: Copies, or its one copy when it has none.
func (c StoredCredential) AllCopies() []CredentialCopy {
	if len(c.Copies) > 0 {
		return c.Copies
	}
	return []CredentialCopy{{Credential: c.Credential, HolderKeyID: c.HolderKeyID}}
}

// CopiesLeft is how many of c's copies no Verifier has seen.
func (c StoredCredential) CopiesLeft() int {
	n := 0
	for _, cp := range c.AllCopies() {
		if !cp.Presented {
			n++
		}
	}
	return n
}

// nextCopy is the copy to present next: the first not yet presented,
// else — every copy has been — the one shown to the fewest Verifiers,
// which Verifiers may link to earlier presentations: reusing the least
// shown keeps each set of Verifiers that can link the holder small.
func (c StoredCredential) nextCopy() (int, CredentialCopy) {
	copies := c.AllCopies()
	least := 0
	for i, cp := range copies {
		if !cp.Presented {
			return i, cp
		}
		if len(cp.ShownTo) < len(copies[least].ShownTo) {
			least = i
		}
	}
	return least, copies[least]
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
