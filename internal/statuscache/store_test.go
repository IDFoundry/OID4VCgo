package statuscache

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// memStore is a Store in memory, standing for one that outlives a
// process.
type memStore struct {
	mu      sync.Mutex
	records map[string][]byte
	failing bool
}

func newMemStore() *memStore { return &memStore{records: map[string][]byte{}} }

func (s *memStore) Load(name string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failing {
		return nil, errors.New("store down")
	}
	return s.records[name], nil
}

func (s *memStore) Save(name string, record []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failing {
		return errors.New("store down")
	}
	s.records[name] = record
	return nil
}

func (s *memStore) Remove(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, name)
	return nil
}

func (s *memStore) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

// tokenVerify is a Verify that passes only the token want.
func tokenVerify(n *counter, want string, v Verified) Verify {
	return func(token []byte) (Verified, error) {
		n.mu.Lock()
		defer n.mu.Unlock()
		n.verifies++
		if string(token) != want {
			return Verified{}, errors.New("refused")
		}
		return v, nil
	}
}

// A Cache over a Store another process filled revalidates the token it
// kept rather than downloading it, and verifies it in full on the 304.
func TestStore_RevalidatedAcrossProcesses(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	clock := func() time.Time { return now }
	store := newMemStore()
	s := &server{token: "v1"}
	ctx := context.Background()
	v := Verified{Iat: now.Unix(), Exp: ptr(now.Unix() + 3600)}
	var n counter
	first := New(Options{Now: clock, Store: store})
	if err := first.Check(ctx, "u", "m", "", s.fetch, tokenVerify(&n, "v1", v), n.rechecks(nil)); err != nil {
		t.Fatal(err)
	}
	if store.len() != 1 {
		t.Fatalf("%d records kept, want the verified token", store.len())
	}

	second := New(Options{Now: clock, Store: store})
	if err := second.Check(ctx, "u", "m", "", s.fetch, tokenVerify(&n, "v1", v), n.rechecks(nil)); err != nil {
		t.Fatal(err)
	}
	if len(s.fetches) != 2 || s.fetches[1].ETag != `"v1"` {
		t.Fatalf("fetches %v, want the kept token revalidated", s.fetches)
	}
	n.want(t, 2, 0, "after a 304 for a kept token")
	// Kept in memory now, as a fetched token.
	if err := second.Check(ctx, "u", "m", "", s.fetch, tokenVerify(&n, "v1", v), n.rechecks(nil)); err != nil || len(s.fetches) != 2 {
		t.Errorf("Check = %v after %d fetches, want the revalidated token used", err, len(s.fetches))
	}

	// A changed list is downloaded, and kept in its place.
	s.token = "v2"
	third := New(Options{Now: clock, Store: store})
	if err := third.Check(ctx, "u", "m", "", s.fetch, tokenVerify(&n, "v2", v), n.rechecks(nil)); err != nil {
		t.Fatal(err)
	}
	r := third.load(key{"u", "m"})
	if r == nil || string(r.Token) != "v2" || r.ETag != `"v2"` {
		t.Errorf("record %+v, want v2's", r)
	}
}

// A kept token is never used without its server: a fetch that fails
// fails the check, as without a Store.
func TestStore_NotTrustedOffline(t *testing.T) {
	store := newMemStore()
	s := &server{token: "v1"}
	ctx := context.Background()
	var n counter
	v := Verified{Iat: time.Now().Unix()}
	if err := New(Options{Store: store}).Check(ctx, "u", "m", "", s.fetch, tokenVerify(&n, "v1", v), n.rechecks(nil)); err != nil {
		t.Fatal(err)
	}
	down := errors.New("offline")
	fail := func(context.Context, Validators) (Fetched, error) { return Fetched{}, down }
	if err := New(Options{Store: store}).Check(ctx, "u", "m", "", fail, tokenVerify(&n, "v1", v), n.rechecks(nil)); !errors.Is(err, down) {
		t.Errorf("Check = %v offline, want the fetch's error", err)
	}
}

// Kept bytes a check refuses on a 304 — damaged on disk, say — are
// removed, and the next check downloads the token.
func TestStore_RefusedRecordRemoved(t *testing.T) {
	store := newMemStore()
	s := &server{token: "v1"}
	ctx := context.Background()
	var n counter
	v := Verified{Iat: time.Now().Unix()}
	if err := New(Options{Store: store}).Check(ctx, "u", "m", "", s.fetch, tokenVerify(&n, "v1", v), n.rechecks(nil)); err != nil {
		t.Fatal(err)
	}
	name := recordName(key{"u", "m"})
	store.records[name] = []byte(`{"uri":"u","media_type":"m","etag":"\"v1\"","token":"ZGFtYWdlZA=="}`) // "damaged"
	c := New(Options{Store: store})
	if err := c.Check(ctx, "u", "m", "", s.fetch, tokenVerify(&n, "v1", v), n.rechecks(nil)); err == nil {
		t.Fatal("damaged kept bytes passed")
	}
	if store.len() != 0 {
		t.Fatal("the refused record was kept")
	}
	if err := c.Check(ctx, "u", "m", "", s.fetch, tokenVerify(&n, "v1", v), n.rechecks(nil)); err != nil {
		t.Fatal(err)
	}
	if got := s.fetches[len(s.fetches)-1]; got != (Validators{}) {
		t.Errorf("fetch after a refused record revalidated %v, want a download", got)
	}
}

// Only a token whose response gave validators is kept; a record for
// another key, or one that doesn't parse, isn't used; and a failing
// store costs a download, not the check.
func TestStore_WhatIsKept(t *testing.T) {
	ctx := context.Background()
	var n counter
	v := Verified{Iat: time.Now().Unix()}
	plainFetch := func(context.Context, Validators) (Fetched, error) { return Fetched{Token: []byte("v1")}, nil }
	store := newMemStore()
	if err := New(Options{Store: store}).Check(ctx, "u", "m", "", plainFetch, tokenVerify(&n, "v1", v), n.rechecks(nil)); err != nil {
		t.Fatal(err)
	}
	if store.len() != 0 {
		t.Errorf("a token without validators was kept")
	}

	s := &server{token: "v1"}
	store.records[recordName(key{"u", "m"})] = []byte(`{"uri":"other","media_type":"m","etag":"\"v1\"","token":"djE="}`)
	if err := New(Options{Store: store}).Check(ctx, "u", "m", "", s.fetch, tokenVerify(&n, "v1", v), n.rechecks(nil)); err != nil {
		t.Fatal(err)
	}
	if s.fetches[0] != (Validators{}) {
		t.Errorf("another key's record was revalidated: %v", s.fetches[0])
	}

	store.failing = true
	s.fetches = nil
	if err := New(Options{Store: store}).Check(ctx, "u", "m", "", s.fetch, tokenVerify(&n, "v1", v), n.rechecks(nil)); err != nil {
		t.Errorf("Check = %v over a failing store", err)
	}
}

// A 304 to an entry in memory that gives new validators updates the
// kept record's.
func TestStore_NewValidatorsKept(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	store := newMemStore()
	c := New(Options{MaxAge: time.Minute, Now: func() time.Time { return now }, Store: store})
	ctx := context.Background()
	var n counter
	v := Verified{Iat: now.Unix()}
	etag := `"a"`
	fetch := func(_ context.Context, held Validators) (Fetched, error) {
		if held.ETag != "" {
			etag = `"b"`
			return Fetched{NotModified: true, Validators: Validators{ETag: etag}}, nil
		}
		return Fetched{Token: []byte("v1"), Validators: Validators{ETag: etag}}, nil
	}
	if err := c.Check(ctx, "u", "m", "", fetch, tokenVerify(&n, "v1", v), n.rechecks(nil)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if err := c.Check(ctx, "u", "m", "", fetch, tokenVerify(&n, "v1", v), n.rechecks(nil)); err != nil {
		t.Fatal(err)
	}
	if r := c.load(key{"u", "m"}); r == nil || r.ETag != `"b"` || string(r.Token) != "v1" {
		t.Errorf("record %+v, want v1 under the 304's ETag", r)
	}
}
