package main

import (
	"crypto/ecdsa"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcigo/dcql"
	"github.com/idfoundry/oid4vcigo/verifier"
)

// sessionTTL bounds how long a pending session (one BuildAuthorizationRequest
// call the suite hasn't yet responded to) is kept in memory — this is a
// conformance-only binary, not a production Verifier, so an unbounded
// map is a real risk across a long-running suite session; expired
// entries are swept lazily on each new session creation.
const sessionTTL = 10 * time.Minute

// session is one pending (or completed) Authorization Request this
// binary built, keyed by an opaque path segment used in both
// /request/{id} and /result/{id}.
type session struct {
	id            string
	requestObject string
	query         dcql.Query
	nonce         string
	decryptionKey *ecdsa.PrivateKey
	createdAt     time.Time

	mu      sync.Mutex
	done    bool
	result  []verifier.VerifiedCredential
	failErr error
}

// sessionStore holds every pending/completed session in memory,
// keyed by id. Response correlation (see handlers.go's
// handleResponse) has no explicit session id to key off — a
// direct_post.jwt response carries no such field — so it instead
// tries every still-pending session's own decryptionKey in turn until
// one successfully decrypts, relying on JWE's own authenticated
// encryption to reject every wrong key.
type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]*session
}

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: make(map[string]*session)}
}

func (s *sessionStore) put(sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, existing := range s.sessions {
		if time.Since(existing.createdAt) > sessionTTL {
			delete(s.sessions, id)
		}
	}
	s.sessions[sess.id] = sess
}

func (s *sessionStore) get(id string) (*session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	return sess, ok
}

// pendingDecryptionKeys returns every not-yet-completed session, in no
// particular order — handleResponse tries each one's decryptionKey in
// turn until JWE decryption (authenticated encryption, so a wrong key
// fails rather than silently producing garbage) succeeds against one
// of them. Correctness doesn't depend on the order; it only affects
// how many failed attempts happen first.
func (s *sessionStore) pendingDecryptionKeys() []*session {
	s.mu.Lock()
	defer s.mu.Unlock()
	pending := make([]*session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		if !sess.done {
			pending = append(pending, sess)
		}
	}
	return pending
}
