package main

import (
	"crypto/ecdsa"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/verifier"
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
	id        string
	query     dcql.Query
	createdAt time.Time

	mu sync.Mutex
	// built, requestObject, nonce, and decryptionKey are filled in by
	// ensureBuilt on the request_uri endpoint's first fetch (GET or
	// POST) — see its own doc comment for why signing is deferred this
	// long rather than happening eagerly in handleAuthorize.
	built         bool
	requestObject string
	nonce         string
	decryptionKey *ecdsa.PrivateKey
	done          bool
	result        []verifier.VerifiedCredential
	failErr       error
}

// ensureBuilt lazily builds and signs this session's own Authorization
// Request on the request_uri endpoint's first fetch, embedding
// walletNonce as the Request Object's own "wallet_nonce" claim when the
// Wallet's POST supplied one (OID4VP §5.10.1). Signing is deferred from
// handleAuthorize to here — not done eagerly — specifically so a POST's
// own wallet_nonce (unknowable until this fetch happens) can be baked
// into the signed object rather than requiring a second, inconsistent
// signature. Building happens exactly once per session: a repeat fetch
// (GET after POST, or vice versa) replays the same signed object
// regardless of a later wallet_nonce, since the nonce/response-
// encryption key embedded in it must stay stable for handleResponse's
// own later matching/decryption.
func (sess *session) ensureBuilt(v *verifier.Verifier, walletNonce string) (string, error) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.built {
		return sess.requestObject, nil
	}
	result, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{
		Query: sess.query, WalletNonce: walletNonce,
	})
	if err != nil {
		return "", err
	}
	sess.requestObject = result.RequestObject
	sess.nonce = result.Nonce
	sess.decryptionKey = result.ResponseDecryptionKey
	sess.built = true
	return sess.requestObject, nil
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

// pendingDecryptionKeys returns every not-yet-completed session whose
// own Authorization Request has actually been built (see ensureBuilt —
// a session the Wallet never fetched request_uri for has no
// decryptionKey yet and can't be a real match for any response), in no
// particular order — handleResponse tries each one's decryptionKey in
// turn until JWE decryption (authenticated encryption, so a wrong key
// fails rather than silently producing garbage) succeeds against one
// of them. Correctness doesn't depend on the order; it only affects
// how many failed attempts happen first.
//
// Checking sess.built under sess.mu here (rather than in handleResponse
// itself) is also what makes handleResponse's own later unguarded read
// of sess.decryptionKey race-free: decryptionKey is written exactly
// once, inside ensureBuilt's own locked section, before built is set —
// so observing built == true while holding sess.mu establishes a
// happens-before edge for every read after this function returns.
func (s *sessionStore) pendingDecryptionKeys() []*session {
	s.mu.Lock()
	defer s.mu.Unlock()
	pending := make([]*session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		sess.mu.Lock()
		stillPending := !sess.done && sess.built
		sess.mu.Unlock()
		if stillPending {
			pending = append(pending, sess)
		}
	}
	return pending
}
