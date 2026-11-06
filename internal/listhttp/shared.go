package listhttp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// LeaseSlack is how long past SignTimeout a replica's lease on signing
// a list's token lasts: a replica that took the lease and stopped is
// replaced once SignTimeout plus LeaseSlack have passed.
const LeaseSlack = 5 * time.Second

// Stored is a token in a Store: its bytes (nil in a Head), the list
// version it was signed from, when it was signed, when it expires, and
// who signed it (SignerOf).
type Stored struct {
	Bytes         []byte
	Version       int64
	SignedAt, Exp time.Time
	Signer        []byte
}

// SignerOf names the signer of a token whose chain's leaf certificate
// is leaf (its DER): the certificate's SHA-256. A stored token is served
// only by a replica whose signer it names, so a replica with a new key
// or certificate signs its own rather than serve a token another key
// signed.
func SignerOf(leaf []byte) []byte {
	sum := sha256.Sum256(leaf)
	return sum[:]
}

// Head is what a Store holds for one list and form, without the
// token's bytes: the list's version, and the stored token, if any.
type Head struct {
	Version int64
	Stored  bool
	Token   Stored
}

// Store is one list's form in the store that the replicas serving it
// share: a Tokens with its uri and form fixed (StoreOf).
type Store interface {
	Head(ctx context.Context) (Head, error)
	Token(ctx context.Context) (Stored, bool, error)
	Claim(ctx context.Context, holder string, now, until time.Time) (bool, error)
	Put(ctx context.Context, holder string, token Stored) error
}

// Tokens is statuslist.TokenStore, its Form being F.
type Tokens[F any] interface {
	Head(ctx context.Context, uri string, form F) (Head, error)
	Token(ctx context.Context, uri string, form F) (Stored, bool, error)
	Claim(ctx context.Context, uri string, form F, holder string, now, until time.Time) (bool, error)
	Put(ctx context.Context, uri string, form F, holder string, token Stored) error
}

// StoreOf is t's Store for the list at uri, in form.
func StoreOf[F any](t Tokens[F], uri string, form F) Store {
	return formStore[F]{t, uri, form}
}

type formStore[F any] struct {
	tokens Tokens[F]
	uri    string
	form   F
}

func (s formStore[F]) Head(ctx context.Context) (Head, error) {
	return s.tokens.Head(ctx, s.uri, s.form)
}

func (s formStore[F]) Token(ctx context.Context) (Stored, bool, error) {
	return s.tokens.Token(ctx, s.uri, s.form)
}

func (s formStore[F]) Claim(ctx context.Context, holder string, now, until time.Time) (bool, error) {
	return s.tokens.Claim(ctx, s.uri, s.form, holder, now, until)
}

func (s formStore[F]) Put(ctx context.Context, holder string, token Stored) error {
	return s.tokens.Put(ctx, s.uri, s.form, holder, token)
}

// Holder names one replica to a Store's lease: random, so no two
// replicas share a name. Its zero value is ready to use.
type Holder struct {
	once sync.Once
	name string
}

// Name returns h's name, made on first use.
func (h *Holder) Name() string {
	h.once.Do(func() {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		h.name = hex.EncodeToString(b)
	})
	return h.name
}

// Shared is how GetShared shares tokens through Store.
type Shared struct {
	// Store is where the replicas' tokens are.
	Store Store

	// Holder names this replica to Store's lease.
	Holder string

	// Fresh is how long a token is served before one is signed anew,
	// by whichever replica takes the lease.
	Fresh time.Duration

	// Check is how often this replica asks Store whether there's a
	// newer token: at most Fresh.
	Check time.Duration

	// Signer is this replica's signer (SignerOf): a stored token
	// another signer signed is never served here.
	Signer []byte
}

// GetShared is Get, for a list served by several replicas that share
// one token at a time through sh.Store. At most every sh.Check, it
// reads the Store: a token signed from the list's current version, in
// the last sh.Fresh, is served as it is; otherwise this replica takes
// the Store's lease, signs one and stores it for the others. While
// another replica holds the lease, the stored token is served for as
// long as waitable allows — within sh.Fresh of its signing when the
// list has changed since, otherwise one lease longer — and signed here
// once that's passed, when there's none, or when another signer signed
// it (sh.Signer): a lease's holder that can't sign doesn't keep the
// others serving its token. Replicas whose keys differ, as while a new key is
// rolled out, each sign their own and the Store keeps the newer, so
// the token changes hands about once per sh.Check until they agree.
// A call after Invalidate
// signs here, whatever the Store holds. With sh.Fresh not positive,
// it's Get with a token per call.
func (c *Cache) GetShared(ctx context.Context, sh Shared, clock func() time.Time, sign SignFunc) (Served, error) {
	if sh.Fresh <= 0 {
		return c.Get(ctx, 0, clock, sign)
	}
	return c.get(ctx, min(sh.Check, sh.Fresh), clock, func(ctx context.Context, now time.Time, prev *Token) (*Token, error) {
		return c.produceShared(ctx, sh, now.Truncate(time.Millisecond), prev, sign)
	})
}

// produceShared is GetShared's produceFunc, at now: what a Store keeps
// of a time is milliseconds.
func (c *Cache) produceShared(ctx context.Context, sh Shared, now time.Time, prev *Token, sign SignFunc) (*Token, error) {
	c.mu.Lock()
	forced := c.forced
	c.forced = false
	c.mu.Unlock()
	head, err := sh.Store.Head(ctx)
	if err != nil {
		c.reforce(forced)
		return nil, fmt.Errorf("listhttp: reading the stored token: %w", err)
	}
	mine := head.Stored && bytes.Equal(head.Token.Signer, sh.Signer)
	if !forced && mine && current(head, now, sh.Fresh) {
		return stored(ctx, sh.Store, head, now, prev, sh.Signer)
	}
	claimed, err := sh.Store.Claim(ctx, sh.Holder, now, now.Add(SignTimeout+LeaseSlack))
	if err != nil {
		c.reforce(forced)
		return nil, fmt.Errorf("listhttp: taking the lease on signing the token: %w", err)
	}
	if !claimed && !forced && mine && waitable(head, now, sh.Fresh) {
		// Another replica is signing: its token comes in a later check.
		return stored(ctx, sh.Store, head, now, prev, sh.Signer)
	}
	// The version read before the statuses are: a status set after it
	// bumps the version again, and the token is signed anew.
	token, err := signToken(ctx, now, sign)
	if err != nil {
		c.reforce(forced)
		return nil, err
	}
	token.version = head.Version
	if err := sh.Store.Put(ctx, sh.Holder, Stored{Bytes: token.Bytes, Version: token.version, SignedAt: token.SignedAt, Exp: token.Exp, Signer: sh.Signer}); err != nil {
		// Served here all the same; the others sign their own once
		// the lease runs out.
		return token, fmt.Errorf("listhttp: storing the token: %w", err)
	}
	return token, nil
}

// reforce restores Invalidate's request to sign when a produceShared
// that took it failed.
func (c *Cache) reforce(forced bool) {
	if forced {
		c.mu.Lock()
		c.forced = true
		c.mu.Unlock()
	}
}

// current reports whether head's token is one to serve at now: signed
// from the list's version or a later one, within fresh, and not
// expired. A SignedAt as far as fresh ahead of now is another replica's
// clock; one further ahead isn't trusted.
func current(head Head, now time.Time, fresh time.Duration) bool {
	t := head.Token
	age := now.Sub(t.SignedAt)
	return t.Version >= head.Version && age < fresh && age > -fresh && now.Before(t.Exp)
}

// waitable reports whether head's token is one to serve at now while
// another replica holds the lease to sign its successor, rather than
// sign one here. A token signed from an earlier version than the
// list's is served only within fresh of its signing, as a replica
// sharing nothing serves its own; one from the list's version, only
// within fresh plus a lease, the time the lease's holder has to store
// a new one. So a holder that can't sign, and keeps taking its own
// lease, holds the others to its token no longer than that: they then
// sign their own. A SignedAt as far as fresh ahead of now is another
// replica's clock; one further ahead isn't trusted.
func waitable(head Head, now time.Time, fresh time.Duration) bool {
	t := head.Token
	age := now.Sub(t.SignedAt)
	limit := fresh + SignTimeout + LeaseSlack
	if t.Version < head.Version {
		limit = fresh
	}
	return age < limit && age > -fresh && now.Before(t.Exp)
}

// stored returns the token head describes: prev when it's that token,
// otherwise read from s, provided signer signed it.
func stored(ctx context.Context, s Store, head Head, now time.Time, prev *Token, signer []byte) (*Token, error) {
	if prev != nil && prev.version == head.Token.Version && prev.SignedAt.Equal(head.Token.SignedAt) && prev.Exp.Equal(head.Token.Exp) {
		return prev, nil
	}
	st, ok, err := s.Token(ctx)
	switch {
	case err != nil:
		return nil, fmt.Errorf("listhttp: reading the stored token: %w", err)
	case !ok || len(st.Bytes) == 0:
		return nil, errors.New("listhttp: the stored token is gone")
	case !bytes.Equal(st.Signer, signer):
		return nil, errors.New("listhttp: the stored token was replaced by one another signer signed")
	case !now.Before(st.Exp):
		return nil, errors.New("listhttp: the stored token has expired")
	}
	return &Token{Bytes: st.Bytes, SignedAt: st.SignedAt, Exp: st.Exp, version: st.Version, etag: etag(st.Bytes)}, nil
}
