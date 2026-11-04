package walletprovider

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// Purpose is what a challenge may be used for. A challenge is consumed
// by the first use of it, and refused for any other purpose.
type Purpose string

const (
	// PurposeInstance: registering an instance (Provider.Register); its
	// evidence covers the instance key.
	PurposeInstance Purpose = "instance"

	// PurposeHolder: attesting holder keys (Provider.KeyAttestation);
	// its evidence covers the holder keys.
	PurposeHolder Purpose = "holder"

	// PurposeRequest: a signed request (Provider.VerifyRequest).
	PurposeRequest Purpose = "request"
)

func (p Purpose) valid() bool {
	return p == PurposeInstance || p == PurposeHolder || p == PurposeRequest
}

// challengeBytes is how many random bytes a challenge has.
const challengeBytes = 32

// Challenge is a challenge the provider issued.
type Challenge struct {
	// Value is the challenge as the wallet sends it back: base64url
	// (no padding) of 32 random bytes. Evidence binds the raw bytes
	// (EvidenceInput.Challenge).
	Value string

	Purpose   Purpose
	ExpiresAt time.Time
}

// ChallengeRecord is a challenge as a ChallengeStore keeps it.
type ChallengeRecord struct {
	Value     string
	Purpose   Purpose
	CreatedAt time.Time
	ExpiresAt time.Time
}

// ChallengeStore keeps issued challenges until they're used. A
// production store is shared by every process serving the provider,
// and its Consume is one atomic read-and-delete, so two concurrent
// requests can't both use one challenge: in SQL, a DELETE ...
// RETURNING.
type ChallengeStore interface {
	// Create stores rec, or returns an error wrapping ErrExists if a
	// challenge with its Value is stored. A store may drop records
	// whose ExpiresAt is before rec.CreatedAt.
	Create(ctx context.Context, rec ChallengeRecord) error

	// Consume atomically removes the challenge with value and returns
	// it — expired or not: the provider checks its expiry and purpose
	// — or returns an error wrapping ErrNotFound if none is stored.
	Consume(ctx context.Context, value string) (ChallengeRecord, error)
}

// Challenge issues a challenge for purpose, valid for Config.ChallengeTTL.
func (p *Provider) Challenge(ctx context.Context, purpose Purpose) (Challenge, error) {
	if !purpose.valid() {
		return Challenge{}, fmt.Errorf("%w: unknown challenge purpose %q", ErrInvalidRequest, purpose)
	}
	raw := make([]byte, challengeBytes)
	if _, err := io.ReadFull(p.deps.Random, raw); err != nil {
		return Challenge{}, fmt.Errorf("walletprovider: generating a challenge: %w", err)
	}
	now := p.now()
	rec := ChallengeRecord{
		Value: base64.RawURLEncoding.EncodeToString(raw), Purpose: purpose,
		CreatedAt: now, ExpiresAt: now.Add(p.cfg.ChallengeTTL),
	}
	if err := p.deps.Challenges.Create(ctx, rec); err != nil {
		return Challenge{}, fmt.Errorf("walletprovider: storing a challenge: %w", err)
	}
	return Challenge{Value: rec.Value, Purpose: purpose, ExpiresAt: rec.ExpiresAt}, nil
}

// consumeChallenge uses up the challenge value, issued for purpose, and
// returns its raw bytes. The challenge is gone whether or not it's
// accepted, so a refused attempt can't be retried with it.
func (p *Provider) consumeChallenge(ctx context.Context, value string, purpose Purpose) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) != challengeBytes {
		return nil, fmt.Errorf("%w: malformed", ErrChallenge)
	}
	rec, err := p.deps.Challenges.Consume(ctx, value)
	switch {
	case errors.Is(err, ErrNotFound):
		return nil, fmt.Errorf("%w: unknown or already used", ErrChallenge)
	case err != nil:
		return nil, fmt.Errorf("walletprovider: consuming a challenge: %w", err)
	case rec.Purpose != purpose:
		return nil, fmt.Errorf("%w: issued for %q, not %q", ErrChallenge, rec.Purpose, purpose)
	case !p.now().Before(rec.ExpiresAt):
		return nil, fmt.Errorf("%w: expired", ErrChallenge)
	}
	return raw, nil
}

// MemoryChallengeStore is a ChallengeStore held in memory, safe for
// concurrent use; its zero value is ready to use. It isn't shared
// between processes, so it serves a provider running as one process
// only. Create drops expired challenges, so it holds no more than the
// challenges issued within one ChallengeTTL; rate-limit issuing them.
type MemoryChallengeStore struct {
	mu      sync.Mutex
	records map[string]ChallengeRecord
	// swept is how many records were left by the last sweep: the next
	// runs once there are twice as many, so sweeping costs O(1) per
	// Create, amortized.
	swept int
}

var _ ChallengeStore = (*MemoryChallengeStore)(nil)

// Create implements ChallengeStore.
func (s *MemoryChallengeStore) Create(ctx context.Context, rec ChallengeRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.records == nil {
		s.records = make(map[string]ChallengeRecord)
	}
	if len(s.records) >= 2*s.swept+64 {
		for v, r := range s.records {
			if r.ExpiresAt.Before(rec.CreatedAt) {
				delete(s.records, v)
			}
		}
		s.swept = len(s.records)
	}
	if _, ok := s.records[rec.Value]; ok {
		return ErrExists
	}
	s.records[rec.Value] = rec
	return nil
}

// Consume implements ChallengeStore.
func (s *MemoryChallengeStore) Consume(ctx context.Context, value string) (ChallengeRecord, error) {
	if err := ctx.Err(); err != nil {
		return ChallengeRecord{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[value]
	if !ok {
		return ChallengeRecord{}, ErrNotFound
	}
	delete(s.records, value)
	return rec, nil
}
