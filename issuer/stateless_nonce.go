package issuer

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
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
	// after ExpiresAt: the nonce has expired by then. The Issuer spends
	// under an Owner its Consume never asks for, so Consume, which
	// returns only a nonce recorded under the Owner it's given, never
	// takes a spent nonce for an issued one.
	Spend(ctx context.Context, issuance NonceIssuance) error
}

// MinNonceKeyBytes and MaxNonceKeys bound Dependencies.NonceKeys.
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

// statelessNonce is a c_nonce for owner expiring at exp, tagged with
// key: its expiry and randomness, and an HMAC binding both to owner.
func statelessNonce(random io.Reader, key []byte, owner string, exp time.Time) (string, error) {
	raw := make([]byte, statelessNonceBytes)
	binary.BigEndian.PutUint64(raw, uint64(exp.Unix())) // #nosec G115 -- a time after 1970, from Clock.Now plus NonceLifetime
	if _, err := io.ReadFull(random, raw[statelessNonceExpBytes:statelessNonceExpBytes+statelessNonceRandomBytes]); err != nil {
		return "", err
	}
	copy(raw[statelessNonceExpBytes+statelessNonceRandomBytes:], statelessNonceTag(key, owner, raw[:statelessNonceExpBytes+statelessNonceRandomBytes]))
	return statelessNoncePrefix + base64.RawURLEncoding.EncodeToString(raw), nil
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
	// Strict: a nonce is spent by its string, so no other string may
	// decode to its bytes, as one differing in the last character's
	// unused bits otherwise would.
	raw, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(nonce, statelessNoncePrefix))
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
// replica's doesn't forget a nonce this replica still accepts.
const spentNonceMargin = 5 * time.Minute

// isStatelessNonce reports whether nonce has a stateless c_nonce's
// form; a NonceStore's never does.
func isStatelessNonce(nonce string) bool {
	return strings.HasPrefix(nonce, statelessNoncePrefix)
}
