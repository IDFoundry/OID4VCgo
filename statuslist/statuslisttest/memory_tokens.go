package statuslisttest

import (
	"context"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcgo/statuslist"
)

// MemoryTokenStore is a statuslist.TokenStore in one process's memory,
// for tests of replicas sharing tokens: its versions are raised only by
// Bump, and its every method fails while Fail has set an error.
type MemoryTokenStore struct {
	mu       sync.Mutex
	versions map[string]int64
	tokens   map[memoryTokenKey]*memoryToken
	err      error
}

type memoryTokenKey struct {
	uri  string
	form statuslist.Form
}

type memoryToken struct {
	token      *statuslist.StoredToken
	holder     string
	leaseUntil time.Time
}

// NewMemoryTokenStore returns an empty MemoryTokenStore.
func NewMemoryTokenStore() *MemoryTokenStore {
	return &MemoryTokenStore{versions: map[string]int64{}, tokens: map[memoryTokenKey]*memoryToken{}}
}

// Bump raises the version of the list at uri, as a status change on it
// would.
func (s *MemoryTokenStore) Bump(uri string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.versions[uri]++
}

// Fail makes every method return err until it's called with nil.
func (s *MemoryTokenStore) Fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

func (s *MemoryTokenStore) entry(uri string, form statuslist.Form) *memoryToken {
	k := memoryTokenKey{uri, form}
	if s.tokens[k] == nil {
		s.tokens[k] = &memoryToken{}
	}
	return s.tokens[k]
}

// Head implements statuslist.TokenStore.
func (s *MemoryTokenStore) Head(_ context.Context, uri string, form statuslist.Form) (statuslist.TokenHead, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return statuslist.TokenHead{}, s.err
	}
	head := statuslist.TokenHead{Version: s.versions[uri]}
	if t := s.entry(uri, form).token; t != nil {
		head.Stored, head.Token = true, *t
		head.Token.Bytes = nil
	}
	return head, nil
}

// Token implements statuslist.TokenStore.
func (s *MemoryTokenStore) Token(_ context.Context, uri string, form statuslist.Form) (statuslist.StoredToken, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return statuslist.StoredToken{}, false, s.err
	}
	if t := s.entry(uri, form).token; t != nil {
		return *t, true, nil
	}
	return statuslist.StoredToken{}, false, nil
}

// Claim implements statuslist.TokenStore.
func (s *MemoryTokenStore) Claim(_ context.Context, uri string, form statuslist.Form, holder string, now, until time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return false, s.err
	}
	e := s.entry(uri, form)
	if e.holder != "" && e.holder != holder && e.leaseUntil.After(now) {
		return false, nil
	}
	e.holder, e.leaseUntil = holder, until
	return true, nil
}

// Put implements statuslist.TokenStore.
func (s *MemoryTokenStore) Put(_ context.Context, uri string, form statuslist.Form, holder string, token statuslist.StoredToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	e := s.entry(uri, form)
	if t := e.token; t == nil || t.Version < token.Version || (t.Version == token.Version && t.SignedAt.Before(token.SignedAt)) {
		e.token = &token
	}
	if e.holder == holder {
		e.holder, e.leaseUntil = "", time.Time{}
	}
	return nil
}
