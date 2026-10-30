package walletflow

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
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
	// CredentialIdentifier is the credential_identifier it was requested
	// by: the Credential Dataset it holds, of those its grant covers
	// (OpenID4VCI 1.0 §6.2); "" when it was requested by its
	// configuration, or stored before this was kept. A refresh asks for
	// the same dataset.
	CredentialIdentifier string
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
	// say: the earliest of its copies' (CredentialCopy.ValidUntil), so a
	// copy the wallet may present is never past it.
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

	// CopiesCorrelated is whether the issuer gave two of its copies the
	// same jti, sub, status list or mdoc identifier list entry, disclosure
	// digest (an SD-JWT VC's _sd or array element digest, an mdoc's
	// valueDigests entry) or validity timestamp to the second (an
	// SD-JWT VC's iat, nbf or
	// exp, an mdoc's validityInfo; one rounded to a UTC day, as
	// sdjwtvc.RoundedExp and mdoc.RoundedValidity do, is shared with
	// every credential the issuer issued that day, so it doesn't
	// count): Verifiers shown different
	// copies can link them all the same, so a copy another Verifier has
	// seen of any of them makes a presentation linkable (Linkable). False
	// for a credential stored before this was kept.
	CopiesCorrelated bool
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
	// list of where the holder has shown their credentials. It keeps the
	// list from a casual reader, not from one who can read the store:
	// the hash is unkeyed, so hashing candidate client_ids — a
	// Verifier's is public — finds which ones are there. Protect the
	// store as the credentials beside it already need.
	ShownTo []string

	// StatusList is where the issuer publishes this copy's status, and
	// ValidUntil when it expires (zero when it doesn't say): each copy
	// of a batch has its own (HAIP 1.0 §6.1), and a copy stored before
	// they were kept has neither, the credential's own applying.
	StatusList *statuslist.StatusListRef
	ValidUntil time.Time

	// Reservation identifies the latest presentation that reserved this
	// copy and may still undo it: one that isn't sent undoes its
	// reservation only while it's still the latest, so what a later one
	// recorded, sent or not, stands — whichever Wallet sharing the store
	// made it. It's random, walletflow's own, and "" once undone, or for
	// a copy no presentation has reserved since it was kept.
	Reservation string
}

// VerifierHash is how a CredentialCopy's ShownTo records the Verifier
// whose client_id is clientID.
func VerifierHash(clientID string) string {
	sum := sha256.Sum256([]byte("walletflow verifier " + clientID))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ShownTo reports whether a copy of c has been presented to the Verifier
// whose client_id is clientID (Presentation.Verifier().ClientID); over
// the Digital Credentials API, ask Presentation.ShownTo, which knows
// how a Verifier there is identified.
func (c StoredCredential) ShownTo(clientID string) bool {
	h := VerifierHash(clientID)
	return slices.ContainsFunc(c.AllCopies(), func(cp CredentialCopy) bool { return slices.Contains(cp.ShownTo, h) })
}

// Linkable reports whether presentations of c can already be linked: a
// copy has been presented to more than one Verifier, so those Verifiers
// hold the same credential — or, its copies correlated
// (CopiesCorrelated), copies have between them. Refreshing
// (Wallet.RefreshCredential) gives it copies no Verifier has seen.
func (c StoredCredential) Linkable() bool {
	if c.CopiesCorrelated {
		shown := map[string]bool{}
		for _, cp := range c.AllCopies() {
			for _, h := range cp.ShownTo {
				shown[h] = true
			}
		}
		return len(shown) > 1
	}
	return slices.ContainsFunc(c.AllCopies(), func(cp CredentialCopy) bool { return len(cp.ShownTo) > 1 })
}

// linkableTo reports whether presenting cp, one of c's copies, to the
// Verifier verifierHash names would let it link the holder with another
// Verifier: one has seen cp, or, c's copies correlated, any copy.
func (c StoredCredential) linkableTo(cp CredentialCopy, verifierHash string) bool {
	other := func(h string) bool { return h != verifierHash }
	if c.CopiesCorrelated {
		return slices.ContainsFunc(c.AllCopies(), func(o CredentialCopy) bool { return slices.ContainsFunc(o.ShownTo, other) })
	}
	return slices.ContainsFunc(cp.ShownTo, other)
}

// copyFor is the copy to present to the Verifier verifierHash names
// under policy at now, and whether it's one that Verifier has seen
// already. Per Verifier, that's the copy it has seen, if any still
// valid; otherwise, as per presentation, the next copy (nextCopy).
func (c StoredCredential) copyFor(policy CopyPolicy, verifierHash string, now time.Time) (int, CredentialCopy, bool) {
	copies := c.AllCopies()
	if policy == CopyPerVerifier {
		for i, cp := range copies {
			if slices.Contains(cp.ShownTo, verifierHash) && !c.copyExpired(cp, now) {
				return i, cp, true
			}
		}
	}
	i, cp := c.nextCopy(verifierHash, now)
	return i, cp, false
}

// copyExpired reports whether cp, one of c's copies, has expired at
// now: by its own ValidUntil, or c's for a copy stored without one.
func (c StoredCredential) copyExpired(cp CredentialCopy, now time.Time) bool {
	until := cp.ValidUntil
	if until.IsZero() {
		until = c.ValidUntil
	}
	return !until.IsZero() && !now.Before(until)
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

// nextCopy is the copy to present next, to the Verifier verifierHash
// names, at now: the first not yet presented, else (every copy has
// been) one only that Verifier has seen, which links it to nothing it
// can't link already, else the one shown to the fewest Verifiers, which
// Verifiers may link to earlier presentations: reusing the least shown
// keeps each set of Verifiers that can link the holder small. A copy
// still valid comes before an expired one, which a Verifier would refuse
// after the holder disclosed its claims.
func (c StoredCredential) nextCopy(verifierHash string, now time.Time) (int, CredentialCopy) {
	copies := c.AllCopies()
	onlyThis := func(cp CredentialCopy) bool {
		return !slices.ContainsFunc(cp.ShownTo, func(h string) bool { return h != verifierHash })
	}
	better := func(i, j int) bool { // i before j
		ei, ej := c.copyExpired(copies[i], now), c.copyExpired(copies[j], now)
		if ei != ej {
			return !ei
		}
		if copies[i].Presented != copies[j].Presented {
			return !copies[i].Presented
		}
		if oi, oj := onlyThis(copies[i]), onlyThis(copies[j]); oi != oj {
			return oi
		}
		return len(copies[i].ShownTo) < len(copies[j].ShownTo)
	}
	best := 0
	for i := range copies {
		if better(i, best) {
			best = i
		}
	}
	return best, copies[best]
}

// CredentialStore holds the wallet's credentials. They carry personal
// data: on a phone, keep them under the platform's data protection.
//
// Several Wallets — in several processes: an app and its extension, or
// a server's replicas — may share one store. walletflow changes a stored
// credential only through Update, which the store makes atomic across
// all of them.
type CredentialStore interface {
	// Put stores c, replacing any credential with the same ID.
	Put(ctx context.Context, c StoredCredential) error
	// Get returns the credential id names, or an error wrapping
	// ErrNotFound.
	Get(ctx context.Context, id string) (StoredCredential, error)
	// List returns every stored credential.
	List(ctx context.Context) ([]StoredCredential, error)
	// Update loads the credential id names, calls fn on it, and stores
	// the result, atomically: across every Wallet sharing the store,
	// concurrent Updates of one credential take effect one after
	// another, and none is lost to a Put or Delete in between — a
	// database transaction reading it FOR UPDATE, say, or a conditional
	// UPDATE. It returns an error wrapping ErrNotFound for a credential
	// the store doesn't hold. fn's error aborts the update, storing
	// nothing, and is returned. A store may call fn more than once, each
	// time on the credential as it is then, when another update got in
	// first: fn changes only the record it's given, and never its ID.
	Update(ctx context.Context, id string, fn func(*StoredCredential) error) error
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
	s.credentials[c.ID] = cloneCredential(c)
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
	return cloneCredential(c), nil
}

// Update implements CredentialStore, calling fn once.
func (s *MemoryCredentialStore) Update(_ context.Context, id string, fn func(*StoredCredential) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return updateRecord(s.credentials, id, "credential", cloneCredential, func(c StoredCredential) string { return c.ID }, fn)
}

// List implements CredentialStore, oldest first.
func (s *MemoryCredentialStore) List(context.Context) ([]StoredCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]StoredCredential, 0, len(s.credentials))
	for _, c := range s.credentials {
		out = append(out, cloneCredential(c))
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

// errUnchanged aborts an Update that finds nothing to change.
var errUnchanged = errors.New("walletflow: nothing to change")

// cloneCredential is c sharing no copy with it, so neither a caller's
// changes nor an aborted Update reach what a MemoryCredentialStore
// holds. Claims, which walletflow never changes, are shared.
func cloneCredential(c StoredCredential) StoredCredential {
	if c.Copies != nil {
		c.Copies = slices.Clone(c.Copies)
		for i := range c.Copies {
			c.Copies[i].ShownTo = slices.Clone(c.Copies[i].ShownTo)
		}
	}
	return c
}

// updateRecord is a memory store's Update of the record id names in
// records, called with the store's lock held: fn changes a clone, which
// is stored only when fn succeeds and leaves its ID as it was. what
// names the kind of record in errors.
func updateRecord[T any](records map[string]T, id, what string, clone func(T) T, idOf func(T) string, fn func(*T) error) error {
	cur, ok := records[id]
	if !ok {
		return fmt.Errorf("walletflow: %s %q: %w", what, id, ErrNotFound)
	}
	next := clone(cur)
	if err := fn(&next); err != nil {
		return err
	}
	if idOf(next) != id {
		return fmt.Errorf("walletflow: an update changed %s %q's ID", what, id)
	}
	records[id] = clone(next)
	return nil
}
