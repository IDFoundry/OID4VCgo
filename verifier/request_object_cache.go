package verifier

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"sync"
	"time"
)

// maxCachedRequestObjects bounds requestObjectCache: past it, a
// request's Request Object is signed for each fetch, as without one.
const maxCachedRequestObjects = 1024

// requestObjectCache keeps, in process, the Request Object
// RequestObject signed for each request, so that an anonymous party
// fetching a request_uri over and over doesn't have each fetch signed.
// An entry is keyed by the request's ID and every bound field the
// object is signed from (its query, state, nonce and response
// encryption key's ID), as read from the store: it is served only for
// a record that would be signed into the same claims, so a store
// writer who changes a record gets it signed afresh, as before, never
// another request's object. Nothing in it comes from the store.
type requestObjectCache struct {
	mu      sync.Mutex
	entries map[[sha256.Size]byte]cachedRequestObject
}

type cachedRequestObject struct {
	object  string
	expires time.Time
}

// requestObjectKey identifies tx's Request Object: tx's ID and bound
// fields, each length-prefixed. ok is false when the query can't be
// encoded, and nothing is cached.
func requestObjectKey(tx Transaction) (key [sha256.Size]byte, ok bool) {
	query, err := json.Marshal(tx.Query)
	if err != nil {
		return key, false
	}
	h := sha256.New()
	var n [8]byte
	for _, field := range []string{tx.ID, tx.State, tx.Nonce, tx.KeyID, string(query)} {
		binary.BigEndian.PutUint64(n[:], uint64(len(field)))
		h.Write(n[:])
		h.Write([]byte(field))
	}
	h.Sum(key[:0])
	return key, true
}

// get is the object cached under key, if it hasn't expired at now.
func (c *requestObjectCache) get(key [sha256.Size]byte, now time.Time) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || !now.Before(e.expires) {
		return "", false
	}
	return e.object, true
}

// put caches object under key until expires, making room by dropping
// expired entries, then any one, when full.
func (c *requestObjectCache) put(key [sha256.Size]byte, object string, expires, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[[sha256.Size]byte]cachedRequestObject)
	}
	if len(c.entries) >= maxCachedRequestObjects {
		for k, e := range c.entries {
			if !now.Before(e.expires) {
				delete(c.entries, k)
			}
		}
	}
	if len(c.entries) >= maxCachedRequestObjects {
		for k := range c.entries {
			delete(c.entries, k)
			break
		}
	}
	c.entries[key] = cachedRequestObject{object: object, expires: expires}
}
