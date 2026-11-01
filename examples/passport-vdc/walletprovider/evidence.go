package walletprovider

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/androidattest"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/statefile"
)

const (
	// ChallengeBytes is the length of an attestation challenge.
	ChallengeBytes = 32
	// ChallengeLifetime is how long an attestation challenge can be
	// used.
	ChallengeLifetime = 5 * time.Minute
	// VerifiedKeyLifetime is how long the service recognises a key
	// whose attestation chain it verified: one re-attested later (the
	// instance key, for a refresh) brings the chain over the challenge
	// it was made with, already used.
	VerifiedKeyLifetime = 30 * 24 * time.Hour

	maxOutstandingChallenges = 10000
	maxVerifiedKeys          = 10000
	// maxUnanchoredKeys bounds the verified keys whose chains end at a
	// root that isn't trusted (an emulator's), kept so their
	// re-attestations work too; see record.
	maxUnanchoredKeys = 1000
	// verifiedKeysSaveInterval is the least time between writes of the
	// verified keys' file; a stop within it loses only the keys
	// recorded since the last write, which then need a new challenge.
	verifiedKeysSaveInterval = 10 * time.Second
)

// The key purposes a challenge is for, as the Kotlin library names
// them: the Wallet Attestation's instance key, or a holder key.
const (
	PurposeInstance = "instance"
	PurposeHolder   = "holder"
)

// ChallengeRequest asks the service for an attestation challenge for a
// key the wallet is about to make for Purpose.
type ChallengeRequest struct {
	Purpose string `json:"purpose"`
}

// ChallengeResponse is a fresh attestation challenge, base64url without
// padding, usable once within ExpiresIn seconds.
type ChallengeResponse struct {
	Challenge string `json:"challenge"`
	ExpiresIn int    `json:"expires_in"`
}

// KeyEvidenceOutcome is what the service made of a key's Android Key
// Attestation chain.
type KeyEvidenceOutcome struct {
	// Hardware: the chain is anchored at a Google hardware attestation
	// root, every certificate in it is valid, and the key and its
	// attestation are in the TEE or StrongBox.
	Hardware bool
	// AttestationSecurityLevel and KeyMintSecurityLevel are the levels
	// the chain claims.
	AttestationSecurityLevel, KeyMintSecurityLevel androidattest.SecurityLevel
	// Issues say why it isn't Hardware.
	Issues []string
	// Reattested: the key was verified before, over the challenge in
	// its chain.
	Reattested bool
}

func (o KeyEvidenceOutcome) String() string {
	s := fmt.Sprintf("Android Key Attestation, attestation %s, key %s", o.AttestationSecurityLevel, o.KeyMintSecurityLevel)
	if o.Hardware {
		s = "hardware: " + s + ", Google root"
	} else {
		s = "NOT hardware (" + strings.Join(o.Issues, "; ") + "): " + s
	}
	if o.Reattested {
		s += ", verified before"
	}
	return s
}

// evidence issues attestation challenges and checks key attestation
// chains against them: the chain's signatures, its leaf's key, and its
// challenge, which it consumes. It records each key it verified, by JWK
// thumbprint, so a later attestation of that key with the same chain is
// accepted; with a path, in a file, so a restart doesn't forget them.
type evidence struct {
	roots []*x509.Certificate
	now   func() time.Time
	path  string
	logf  func(format string, args ...any)

	mu          sync.Mutex
	outstanding map[string]challenge   // by the challenge's bytes
	verified    map[string]verifiedKey // by the key's JWK thumbprint
	lastSave    time.Time              // wall clock, of verified's last write to path
	saveTimer   *time.Timer            // a pending write of verified, if any
}

type challenge struct {
	purpose string
	expires time.Time
}

// verifiedKey is a key whose chain the service verified: its leaf
// certificate's SHA-256 and its purpose. Unanchored: the chain ends at
// a root that isn't a trusted one, such as an emulator's — or one its
// sender made.
type verifiedKey struct {
	Leaf       string    `json:"leaf_sha256"`
	Purpose    string    `json:"purpose"`
	VerifiedAt time.Time `json:"verified_at"`
	Unanchored bool      `json:"unanchored,omitempty"`
}

// newEvidence makes the checker, loading the keys verified before from
// path when it's set and exists.
func newEvidence(roots []*x509.Certificate, now func() time.Time, path string, logf func(string, ...any)) (*evidence, error) {
	e := &evidence{roots: roots, now: now, path: path, logf: logf, outstanding: map[string]challenge{}, verified: map[string]verifiedKey{}}
	if path == "" {
		return e, nil
	}
	data, err := os.ReadFile(path) // #nosec G304 -- operator-supplied path
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return e, nil
	case err != nil:
		return nil, fmt.Errorf("walletprovider: read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &e.verified); err != nil {
		return nil, fmt.Errorf("walletprovider: %s: %w", path, err)
	}
	return e, nil
}

// challenge issues a fresh challenge for purpose.
func (e *evidence) challenge(purpose string) ([]byte, error) {
	c := make([]byte, ChallengeBytes)
	if _, err := rand.Read(c); err != nil {
		return nil, err
	}
	now := e.now()
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.outstanding) >= maxOutstandingChallenges {
		for k, v := range e.outstanding {
			if !now.Before(v.expires) {
				delete(e.outstanding, k)
			}
		}
		if len(e.outstanding) >= maxOutstandingChallenges {
			return nil, errTooManyChallenges
		}
	}
	e.outstanding[string(c)] = challenge{purpose: purpose, expires: now.Add(ChallengeLifetime)}
	return c, nil
}

var errTooManyChallenges = errors.New("too many outstanding challenges")

// check verifies chain, base64 DER certificates, as key's (whose JWK
// thumbprint is thumbprint) Android Key Attestation for purpose. An
// error is a chain to refuse: malformed, its signatures don't hold, it
// isn't for key, or its challenge isn't one the service issued for
// purpose and hasn't used (unless for this key, with this chain).
// Whether the key is in hardware Google vouches for is in the outcome.
func (e *evidence) check(purpose string, key *ecdsa.PublicKey, thumbprint string, chain []string) (KeyEvidenceOutcome, error) {
	if len(chain) > androidattest.MaxChainLength {
		return KeyEvidenceOutcome{}, fmt.Errorf("a chain of %d certificates, want at most %d", len(chain), androidattest.MaxChainLength)
	}
	ders := make([][]byte, len(chain))
	for i, c := range chain {
		der, err := base64.StdEncoding.DecodeString(c)
		if err != nil {
			return KeyEvidenceOutcome{}, fmt.Errorf("certificate %d isn't base64", i)
		}
		ders[i] = der
	}
	now := e.now()
	a, err := androidattest.Verify(ders, e.roots, now)
	if err != nil {
		return KeyEvidenceOutcome{}, err
	}
	if !key.Equal(a.Leaf.PublicKey) {
		return KeyEvidenceOutcome{}, errors.New("the attestation chain certifies another key")
	}
	out := KeyEvidenceOutcome{
		Hardware:                 a.Hardware(),
		AttestationSecurityLevel: a.AttestationSecurityLevel, KeyMintSecurityLevel: a.KeyMintSecurityLevel,
	}
	if !a.Anchored {
		out.Issues = append(out.Issues, "not a Google hardware attestation root")
	}
	if !a.AttestationSecurityLevel.Hardware() || !a.KeyMintSecurityLevel.Hardware() {
		out.Issues = append(out.Issues, "software security level")
	}
	if len(a.OutOfValidity) > 0 {
		out.Issues = append(out.Issues, fmt.Sprintf("certificates %v outside their validity", a.OutOfValidity))
	}
	leaf := sha256.Sum256(a.Leaf.Raw)
	out.Reattested, err = e.consume(purpose, thumbprint, a.AttestationChallenge, hex.EncodeToString(leaf[:]), a.Anchored, now)
	return out, err
}

// consume uses chal for the key with thumbprint and leaf hash leaf:
// an outstanding challenge for purpose is used up and the key recorded
// (anchored: whether its chain ends at a trusted root); otherwise the
// key must be one recorded before with the same leaf (reattested).
// Anything else is refused.
func (e *evidence) consume(purpose, thumbprint string, chal []byte, leaf string, anchored bool, now time.Time) (reattested bool, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if c, ok := e.outstanding[string(chal)]; ok {
		delete(e.outstanding, string(chal))
		switch {
		case !now.Before(c.expires):
			return false, errors.New("the attestation challenge has expired")
		case c.purpose != purpose:
			return false, fmt.Errorf("the attestation challenge was for a %s key", c.purpose)
		}
		e.record(thumbprint, verifiedKey{Leaf: leaf, Purpose: purpose, VerifiedAt: now, Unanchored: !anchored})
		return false, nil
	}
	v, ok := e.verified[thumbprint]
	if ok && v.Purpose == purpose && now.Sub(v.VerifiedAt) < VerifiedKeyLifetime &&
		subtle.ConstantTimeCompare([]byte(v.Leaf), []byte(leaf)) == 1 {
		return true, nil
	}
	return false, errors.New("the attestation challenge is unknown, used or expired; request a new challenge")
}

// record remembers a verified key, forgetting expired ones, and saves
// them when there's a path. Anyone can make an unanchored chain — for
// any public key, under a root of their own — so those keys can't
// displace the others: an unanchored key never replaces an anchored
// one's record, unanchored keys are kept to maxUnanchoredKeys, and past
// maxVerifiedKeys the oldest unanchored key goes first, an anchored one
// only when none is left (which an unanchored record can't cause).
// Callers hold e.mu.
func (e *evidence) record(thumbprint string, v verifiedKey) {
	if old, ok := e.verified[thumbprint]; ok && v.Unanchored && !old.Unanchored {
		return
	}
	e.verified[thumbprint] = v
	var oldest, oldestUnanchored string
	unanchored := 0
	for k, old := range e.verified {
		switch {
		case v.VerifiedAt.Sub(old.VerifiedAt) >= VerifiedKeyLifetime:
			delete(e.verified, k)
		case old.Unanchored:
			unanchored++
			if oldestUnanchored == "" || old.VerifiedAt.Before(e.verified[oldestUnanchored].VerifiedAt) {
				oldestUnanchored = k
			}
		case oldest == "" || old.VerifiedAt.Before(e.verified[oldest].VerifiedAt):
			oldest = k
		}
	}
	switch {
	case oldestUnanchored != "" && (unanchored > maxUnanchoredKeys || len(e.verified) > maxVerifiedKeys):
		delete(e.verified, oldestUnanchored)
	case len(e.verified) > maxVerifiedKeys:
		delete(e.verified, oldest)
	}
	e.save()
}

// save writes the verified keys to the file at path, at most once per
// verifiedKeysSaveInterval: a record soon after a write is saved, with
// any that follow it, when the interval is up, so a burst of
// attestations doesn't rewrite the file for each. Callers hold e.mu.
func (e *evidence) save() {
	if e.path == "" || e.saveTimer != nil { // a scheduled save will write it
		return
	}
	if wait := verifiedKeysSaveInterval - time.Since(e.lastSave); wait > 0 {
		e.saveTimer = time.AfterFunc(wait, func() {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.saveTimer = nil
			e.write()
		})
		return
	}
	e.write()
}

// write saves the verified keys now; a failure is logged, costing only
// a restart's memory of them. Callers hold e.mu.
func (e *evidence) write() {
	e.lastSave = time.Now()
	data, err := json.Marshal(e.verified)
	if err == nil {
		err = statefile.WriteAtomic(e.path, data)
	}
	if err != nil {
		e.logf("wallet provider: keeping verified keys: %v", err)
	}
}
