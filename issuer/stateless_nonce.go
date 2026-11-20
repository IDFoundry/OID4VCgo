package issuer

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/b64url"
)

// NonceSpender is a NonceStore that also records the c_nonces the
// Nonce Endpoint issues statelessly (Dependencies.NonceKeys) as spent,
// so each is still used once. The Nonce Endpoint then writes nothing:
// a record is written only when a Credential Request, already
// authorized by its access token, spends the nonce.
type NonceSpender interface {
	NonceStore

	// Spend records issuance.Nonce as used by issuance.Owner until
	// issuance.ExpiresAt. It returns an error wrapping ErrNonceUnknown
	// if the nonce is recorded already, under any Owner, and any other
	// error only when it couldn't answer. A store may forget the record
	// after ExpiresAt, by its own clock or the time a sweep is given:
	// ExpiresAt is 5 minutes past the nonce's own expiry, so the nonce
	// has expired by then on every replica whose clock is no more than
	// that behind (see Dependencies.NonceKeys). The Issuer spends
	// under an Owner its Consume never asks for, so Consume, which
	// returns only a nonce recorded under the Owner it's given, never
	// takes a spent nonce for an issued one.
	Spend(ctx context.Context, issuance NonceIssuance) error
}

// MinNonceKeyBytes and MaxNonceKeys bound Dependencies.NonceKeys.
//
// Each key is a secret of at least MinNonceKeyBytes bytes from a
// cryptographically secure random source, kept in a secret manager and
// the same on every replica: crypto/rand's Read into a
// MinNonceKeyBytes slice, or `openssl rand 32`. Hex or base64 text of
// MinNonceKeyBytes random bytes works too, its characters taken as the
// key's bytes (`openssl rand -hex 32` is 64 bytes, `openssl rand
// -base64 32` 44). Never a password or passphrase, nor anything derived
// from one: whoever learns or guesses a key can make c_nonces this
// issuer accepts, with any expiry within Limits.NonceLifetime, and so
// proofs ahead of time. Under AssuranceProduction, New refuses a key
// that plainly isn't random: one with fewer than four distinct byte
// values, or that repeats a pattern shorter than half its length, as an
// unset key, a repeated character or a word repeated to length does. A
// random key, in any of the three forms, is refused with a probability
// below 2^-67. Passing the check doesn't make a key random.
const (
	MinNonceKeyBytes = 32
	MaxNonceKeys     = 8
)

// statelessNoncePrefix starts every c_nonce issued with
// Dependencies.NonceKeys, telling it from one a NonceStore holds.
const statelessNoncePrefix = "s1."

// Sizes of a stateless c_nonce's parts: its expiry (Unix seconds,
// big-endian), its randomness and its HMAC-SHA256 tag.
const (
	statelessNonceExpBytes    = 8
	statelessNonceRandomBytes = 16
	statelessNonceTagBytes    = sha256.Size
	statelessNonceBytes       = statelessNonceExpBytes + statelessNonceRandomBytes + statelessNonceTagBytes
)

// statelessNonceDomain separates this tag from any other a key might
// be used for.
const statelessNonceDomain = "oid4vcgo issuer c_nonce s1\x00"

// validateNonceKeys checks Dependencies.NonceKeys: at most MaxNonceKeys
// keys of at least MinNonceKeyBytes, with a Nonces store that can
// spend.
func validateNonceKeys(deps Dependencies) error {
	if len(deps.NonceKeys) == 0 {
		return nil
	}
	if len(deps.NonceKeys) > MaxNonceKeys {
		return fmt.Errorf("issuer: dependencies: nonce_keys has %d keys, more than %d", len(deps.NonceKeys), MaxNonceKeys)
	}
	for i, key := range deps.NonceKeys {
		if len(key) < MinNonceKeyBytes {
			return fmt.Errorf("issuer: dependencies: nonce_keys[%d] is %d bytes, fewer than %d", i, len(key), MinNonceKeyBytes)
		}
	}
	if _, ok := deps.Nonces.(NonceSpender); !ok {
		return fmt.Errorf("issuer: dependencies: nonces must be an issuer.NonceSpender when nonce_keys is set")
	}
	return nil
}

// minNonceKeyDistinctBytes is the fewest distinct byte values
// checkProductionNonceKeys takes in a nonce key.
const minNonceKeyDistinctBytes = 4

// checkProductionNonceKeys refuses, under AssuranceProduction, a key in
// keys that plainly isn't random: one with fewer than
// minNonceKeyDistinctBytes distinct byte values, or one that repeats a
// pattern shorter than half its length (key[i] == key[i-p] for every
// i >= p, for some p with 2p < len(key)). An unset key (all zero bytes),
// a repeated character and a word repeated to length are refused.
//
// Neither test refuses a random key but with negligible probability,
// whether the key is raw random bytes, or hex or base64 text of random
// bytes taken as its bytes. In each form a byte is uniform over an
// alphabet of A values, independently of the others: 256 for raw
// bytes, 16 for hex, 64 for base64. For a key of n >= MinNonceKeyBytes
// bytes:
//   - Fewer than 4 distinct values: every byte falls within some 3
//     values, with a probability of at most C(A,3)·(3/A)^n. At n = 32
//     that is 2^-68.1 for hex, 2^-125.9 for base64 and 2^-183.9 for raw
//     bytes, and it falls as n grows.
//   - A period p: each of the n-p bytes after the first p must equal
//     the byte p before it, with a probability of A^-(n-p). With
//     2p < n, n-p >= 17 for every n >= 32, so the sum over p is below
//     A^-17·A/(A-1): 2^-67.9 for hex, 2^-102.0 for base64 and 2^-136.0
//     for raw bytes, at any n.
//
// So a random key is refused with a probability below 2^-67 in each
// form, whatever its length. Base64's last character can take fewer
// values when the random bytes aren't a multiple of three; counting it
// as matching anything leaves both base64 rates below 2^-95. Padding
// lowers them: "=" is outside the alphabet, so a padded key repeats no
// pattern, and it adds a distinct value. A tighter test refuses random
// hex keys first: requiring 5 distinct values would refuse a
// 32-character one with a probability of 2^-53.2 (8 values, 2^-24.7),
// and a period of half the key alone, 2^-64.
func checkProductionNonceKeys(keys [][]byte) error {
	const want = "under AssuranceProduction each key must be random bytes, as issuer.MinNonceKeyBytes says"
	for i, key := range keys {
		if distinctBytes(key) < minNonceKeyDistinctBytes {
			return fmt.Errorf("dependencies.nonce_keys[%d] isn't random: it has fewer than %d distinct byte values; %s", i, minNonceKeyDistinctBytes, want)
		}
		if p := repeatedPattern(key); p > 0 {
			return fmt.Errorf("dependencies.nonce_keys[%d] isn't random: it repeats a pattern of %d bytes; %s", i, p, want)
		}
	}
	return nil
}

// distinctBytes is the number of distinct byte values in key.
func distinctBytes(key []byte) int {
	var seen [256]bool
	n := 0
	for _, b := range key {
		if !seen[b] {
			seen[b] = true
			n++
		}
	}
	return n
}

// repeatedPattern is the length of the shortest pattern shorter than
// half of key that key repeats (key[i] == key[i-p] for every i >= p),
// or 0 when it repeats none.
func repeatedPattern(key []byte) int {
	for p := 1; 2*p < len(key); p++ {
		if bytes.Equal(key[p:], key[:len(key)-p]) {
			return p
		}
	}
	return 0
}

// statelessNonce is a c_nonce for owner expiring at exp, tagged with
// key: its expiry and randomness, and an HMAC binding both to owner.
func statelessNonce(random io.Reader, key []byte, owner string, exp time.Time) (string, error) {
	raw := make([]byte, statelessNonceBytes)
	binary.BigEndian.PutUint64(raw, uint64(exp.Unix())) // #nosec G115 -- a time after 1970, from Clock.Now plus NonceLifetime
	if _, err := io.ReadFull(random, raw[statelessNonceExpBytes:statelessNonceExpBytes+statelessNonceRandomBytes]); err != nil {
		return "", err
	}
	copy(raw[statelessNonceExpBytes+statelessNonceRandomBytes:], statelessNonceTag(key, owner, raw[:statelessNonceExpBytes+statelessNonceRandomBytes]))
	return statelessNoncePrefix + b64url.Encoding{}.EncodeToString(raw), nil
}

func statelessNonceTag(key []byte, owner string, body []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(statelessNonceDomain))
	mac.Write([]byte(owner))
	mac.Write([]byte{0})
	mac.Write(body)
	return mac.Sum(nil)
}

// errStatelessNonceForged is why a stateless c_nonce none of the keys
// tagged for this owner is refused.
var errStatelessNonceForged = errors.New("the c_nonce's tag doesn't verify under any nonce key")

// openStatelessNonce is the expiry of nonce, a stateless c_nonce, if
// one of keys tagged it for owner.
func openStatelessNonce(keys [][]byte, owner, nonce string) (time.Time, error) {
	// A nonce is spent by its string, so no other string may decode to
	// its bytes: b64url refuses one differing in the last character's
	// unused bits, and one with a '\r' or '\n' inserted, which
	// encoding/base64 skips even in Strict mode.
	raw, err := b64url.Encoding{}.DecodeString(strings.TrimPrefix(nonce, statelessNoncePrefix))
	if err != nil || len(raw) != statelessNonceBytes {
		return time.Time{}, errors.New("the c_nonce is malformed")
	}
	body, tag := raw[:statelessNonceExpBytes+statelessNonceRandomBytes], raw[statelessNonceExpBytes+statelessNonceRandomBytes:]
	for _, key := range keys {
		if hmac.Equal(tag, statelessNonceTag(key, owner, body)) {
			exp := binary.BigEndian.Uint64(body)
			if exp > uint64(maxUnixSeconds) {
				return time.Time{}, errors.New("the c_nonce's expiry is out of range")
			}
			return time.Unix(int64(exp), 0), nil // #nosec G115 -- bounded above
		}
	}
	return time.Time{}, errStatelessNonceForged
}

// maxUnixSeconds bounds a stateless c_nonce's expiry: year 9999.
const maxUnixSeconds = 253402300799

// spendStatelessNonce is consumeNonce for a c_nonce issued with
// Dependencies.NonceKeys: its tag is checked against every key, its
// expiry against the clock and NonceLifetime, and only then is it
// recorded as spent.
func (iss *Issuer) spendStatelessNonce(ctx context.Context, nonce string) error {
	exp, err := openStatelessNonce(iss.deps.NonceKeys, iss.storeOwner(), nonce)
	if err != nil {
		return newError(ErrorInvalidNonce, 400, unknownNonce, err)
	}
	now := iss.deps.Clock.Now()
	if now.After(exp) {
		return newError(ErrorInvalidNonce, 400, "nonce has expired", nil)
	}
	if exp.Sub(now) > iss.cfg.Limits.NonceLifetime {
		// Issued under a longer NonceLifetime than this issuer's now.
		return newError(ErrorInvalidNonce, 400, "nonce has expired", errors.New("the c_nonce outlives limits.nonce_lifetime"))
	}
	spender := iss.deps.Nonces.(NonceSpender) // validateNonceKeys
	err = spender.Spend(ctx, NonceIssuance{Nonce: nonce, Owner: spentNonceOwner(iss.storeOwner()), ExpiresAt: exp.Add(spentNonceMargin)})
	if errors.Is(err, ErrNonceUnknown) {
		return newError(ErrorInvalidNonce, 400, unknownNonce, err)
	}
	if err != nil {
		return fmt.Errorf("issuer: spend c_nonce: %w", err)
	}
	return nil
}

// spentNonceOwner is the Owner a stateless c_nonce is spent under: one
// no Credential Issuer's Consume asks for (a Config.Issuer is a URL,
// with no space), so a store's record of a spent nonce is never
// consumed as an issued one, by a replica without NonceKeys say.
// Spend refuses a nonce recorded under any Owner, so a nonce spent
// under the plain Owner, as v0.69.0 did, is still spent once.
func spentNonceOwner(owner string) string {
	return "c_nonce spent by " + owner
}

// spentNonceMargin keeps a spent c_nonce's record past the nonce's
// expiry, so that a store swept by a clock running ahead of this
// replica's doesn't forget a nonce this replica still accepts. It is
// the clock difference a deployment may have between the clock that
// expires records (a sweep's now, or a store's own) and any replica's:
// forgotten by a clock further ahead, the record no longer stops a
// replica accepting the nonce again. Dependencies.NonceKeys,
// NonceSpender and DEPLOYING.md state it; change them with it.
const spentNonceMargin = 5 * time.Minute

// isStatelessNonce reports whether nonce has a stateless c_nonce's
// form; a NonceStore's never does.
func isStatelessNonce(nonce string) bool {
	return strings.HasPrefix(nonce, statelessNoncePrefix)
}
