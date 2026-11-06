package issuer_test

import (
	"bytes"
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/storage"
)

// countingSpender is a storage.NonceStore counting what's written to
// it.
type countingSpender struct {
	*storage.NonceStore
	issued, spent atomic.Int32
}

func (s *countingSpender) Issue(ctx context.Context, issuance issuer.NonceIssuance) error {
	s.issued.Add(1)
	return s.NonceStore.Issue(ctx, issuance)
}

func (s *countingSpender) Spend(ctx context.Context, issuance issuer.NonceIssuance) error {
	s.spent.Add(1)
	return s.NonceStore.Spend(ctx, issuance)
}

func nonceKey(b byte) []byte { return bytes.Repeat([]byte{b}, issuer.MinNonceKeyBytes) }

// statelessFixture is a credential endpoint fixture issuing stateless
// c_nonces under keys into store, on clock.
func statelessFixture(t *testing.T, store issuer.NonceStore, clock *mutableClock, keys ...[]byte) credentialEndpointFixture {
	t.Helper()
	return newCredentialEndpointFixture(t, func(_ *issuer.Config, deps *issuer.Dependencies) {
		deps.Nonces, deps.NonceKeys, deps.Clock = store, keys, clock
	})
}

func requestNonce(t *testing.T, iss *issuer.Issuer) string {
	t.Helper()
	result, err := iss.RequestNonce(context.Background())
	if err != nil {
		t.Fatalf("RequestNonce: %v", err)
	}
	return result.CNonce
}

// With NonceKeys, the Nonce Endpoint writes nothing; a Credential
// Request spends its nonce once, and a second one carrying it is
// refused.
func TestStatelessNonce_IssuedWithoutWritingAndSpentOnce(t *testing.T) {
	store := &countingSpender{NonceStore: storage.NewNonceStore()}
	f := statelessFixture(t, store, &mutableClock{now: time.Now()}, nonceKey(1))
	nonce := requestNonce(t, f.iss)
	if second := requestNonce(t, f.iss); second == nonce {
		t.Fatalf("two nonces were identical: %q", nonce)
	}
	if n := store.issued.Load(); n != 0 {
		t.Fatalf("the Nonce Endpoint wrote %d records, want none", n)
	}
	if _, err := requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, buildJWTProof(t, testP256Key(t), testIssuer, nonce)); err != nil {
		t.Fatalf("RequestCredential: %v", err)
	}
	_, err := requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, buildJWTProof(t, testP256Key(t), testIssuer, nonce))
	assertIssuerError(t, err, issuer.ErrorInvalidNonce)
	if n := store.spent.Load(); n != 2 {
		t.Errorf("Spend called %d times, want 2", n)
	}
}

// A nonce whose tag doesn't verify, that differs from one issued only
// in its last character's unused bits, or that another Credential
// Issuer sharing the keys issued, is refused without being recorded.
func TestStatelessNonce_RefusesForgedAndAnotherIssuers(t *testing.T) {
	store := &countingSpender{NonceStore: storage.NewNonceStore()}
	clock := &mutableClock{now: time.Now()}
	f := statelessFixture(t, store, clock, nonceKey(1))
	nonce := requestNonce(t, f.iss)
	// 56 bytes are 75 characters, the last with two unused bits: one
	// differing only there names the same bytes.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	unusedBits := nonce[:len(nonce)-1] + string(alphabet[strings.IndexByte(alphabet, nonce[len(nonce)-1])|1])
	mid := len(nonce) / 2
	tampered := nonce[:mid] + flipBase64(nonce[mid]) + nonce[mid+1:]
	for _, bad := range []string{unusedBits, tampered, "s1.", "s1.!!!", nonce + "A"} {
		_, err := requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, buildJWTProof(t, testP256Key(t), testIssuer, bad))
		assertIssuerError(t, err, issuer.ErrorInvalidNonce)
	}

	other := tenantIssuer(t, tenantB, func(deps *issuer.Dependencies) {
		deps.Nonces, deps.NonceKeys, deps.Clock = store, [][]byte{nonceKey(1)}, clock
	})
	otherNonce := requestNonce(t, other)
	_, err := requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, buildJWTProof(t, testP256Key(t), testIssuer, otherNonce))
	assertIssuerError(t, err, issuer.ErrorInvalidNonce)
	if n := store.spent.Load(); n != 0 {
		t.Errorf("Spend called %d times for nonces refused, want none", n)
	}
	if _, err := requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, buildJWTProof(t, testP256Key(t), testIssuer, nonce)); err != nil {
		t.Errorf("the issuer's own nonce after the refusals: %v", err)
	}
}

// A nonce past its expiry, or issued under a longer NonceLifetime than
// the issuer's now, is refused.
func TestStatelessNonce_RefusesExpired(t *testing.T) {
	store := storage.NewNonceStore()
	clock := &mutableClock{now: time.Now()}
	f := statelessFixture(t, store, clock, nonceKey(1))
	nonce := requestNonce(t, f.iss)
	clock.now = clock.now.Add(time.Minute + time.Second)
	_, err := requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, buildJWTProof(t, testP256Key(t), testIssuer, nonce))
	assertIssuerError(t, err, issuer.ErrorInvalidNonce)

	long := newCredentialEndpointFixture(t, func(cfg *issuer.Config, deps *issuer.Dependencies) {
		cfg.Limits.NonceLifetime = time.Hour
		deps.Nonces, deps.NonceKeys, deps.Clock = store, [][]byte{nonceKey(1)}, clock
	})
	longNonce := requestNonce(t, long.iss)
	_, err = requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, buildJWTProof(t, testP256Key(t), testIssuer, longNonce))
	assertIssuerError(t, err, issuer.ErrorInvalidNonce)
}

// Rotating: a nonce the old key tagged is accepted while that key is
// still listed after the new one, and refused once it's dropped.
func TestStatelessNonce_KeyRotation(t *testing.T) {
	store := storage.NewNonceStore()
	clock := &mutableClock{now: time.Now()}
	old := statelessFixture(t, store, clock, nonceKey(1))
	first, second := requestNonce(t, old.iss), requestNonce(t, old.iss)

	rotated := statelessFixture(t, store, clock, nonceKey(2), nonceKey(1))
	if n := requestNonce(t, rotated.iss); !strings.HasPrefix(n, "s1.") {
		t.Fatalf("rotated issuer's nonce %q isn't stateless", n)
	}
	if _, err := requestSDJWTWithProof(rotated, oid4vci.ProofTypeJWT, buildJWTProof(t, testP256Key(t), testIssuer, first)); err != nil {
		t.Errorf("the old key's nonce, the old key still listed: %v", err)
	}
	dropped := statelessFixture(t, store, clock, nonceKey(2))
	_, err := requestSDJWTWithProof(dropped, oid4vci.ProofTypeJWT, buildJWTProof(t, testP256Key(t), testIssuer, second))
	assertIssuerError(t, err, issuer.ErrorInvalidNonce)
}

// A nonce the store holds, issued before NonceKeys was set, is still
// consumed once.
func TestStatelessNonce_StoredNoncesStillConsumed(t *testing.T) {
	store := storage.NewNonceStore()
	clock := &mutableClock{now: time.Now()}
	f := statelessFixture(t, store, clock, nonceKey(1))
	if err := store.Issue(context.Background(), issuer.NonceIssuance{Owner: testIssuer, Nonce: "stored-nonce", ExpiresAt: clock.now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if _, err := requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, buildJWTProof(t, testP256Key(t), testIssuer, "stored-nonce")); err != nil {
		t.Fatalf("a stored nonce: %v", err)
	}
	_, err := requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, buildJWTProof(t, testP256Key(t), testIssuer, "stored-nonce"))
	assertIssuerError(t, err, issuer.ErrorInvalidNonce)
}

// A stateless c_nonce spent by a replica with NonceKeys is refused by
// a replica of the same Credential Issuer without them, sharing the
// store, and alternating between the two never accepts it again: the
// spent record isn't consumed as an issued nonce.
func TestStatelessNonce_SpentNotReplayedAcrossReplicas(t *testing.T) {
	store := storage.NewNonceStore()
	clock := &mutableClock{now: time.Now()}
	withKeys := statelessFixture(t, store, clock, nonceKey(1))
	withoutKeys := newCredentialEndpointFixture(t, func(_ *issuer.Config, deps *issuer.Dependencies) {
		deps.Nonces, deps.Clock = store, clock
	})
	proof := buildJWTProof(t, testP256Key(t), testIssuer, requestNonce(t, withKeys.iss))
	if _, err := requestSDJWTWithProof(withKeys, oid4vci.ProofTypeJWT, proof); err != nil {
		t.Fatalf("first: %v", err)
	}
	for i, f := range []credentialEndpointFixture{withoutKeys, withKeys, withoutKeys, withKeys} {
		_, err := requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, proof)
		if err == nil {
			t.Fatalf("replay %d accepted", i)
		}
		assertIssuerError(t, err, issuer.ErrorInvalidNonce)
	}
}

// A stateless c_nonce reaching a replica without NonceKeys is refused
// without touching the store, even unspent.
func TestStatelessNonce_RefusedWithoutKeys(t *testing.T) {
	store := &countingSpender{NonceStore: storage.NewNonceStore()}
	clock := &mutableClock{now: time.Now()}
	nonce := requestNonce(t, statelessFixture(t, store, clock, nonceKey(1)).iss)
	withoutKeys := newCredentialEndpointFixture(t, func(_ *issuer.Config, deps *issuer.Dependencies) {
		deps.Nonces, deps.Clock = store, clock
	})
	_, err := requestSDJWTWithProof(withoutKeys, oid4vci.ProofTypeJWT, buildJWTProof(t, testP256Key(t), testIssuer, nonce))
	assertIssuerError(t, err, issuer.ErrorInvalidNonce)
	if n := store.spent.Load() + store.issued.Load(); n != 0 {
		t.Errorf("the store was written %d times", n)
	}
}

// A nonce v0.69.0 spent, recorded under the plain Owner, is still
// spent: a replica with NonceKeys refuses it.
func TestStatelessNonce_LegacySpentRecordRefused(t *testing.T) {
	store := storage.NewNonceStore()
	clock := &mutableClock{now: time.Now()}
	f := statelessFixture(t, store, clock, nonceKey(1))
	nonce := requestNonce(t, f.iss)
	if err := store.Spend(context.Background(), issuer.NonceIssuance{Nonce: nonce, Owner: testIssuer, ExpiresAt: clock.now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	_, err := requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, buildJWTProof(t, testP256Key(t), testIssuer, nonce))
	assertIssuerError(t, err, issuer.ErrorInvalidNonce)
}

// A spent nonce is recorded past its expiry, by a margin for a store
// swept on a clock ahead of the issuer's, and under an Owner no
// Consume uses.
func TestStatelessNonce_SpentRecord(t *testing.T) {
	store := &recordingSpender{NonceStore: storage.NewNonceStore()}
	clock := &mutableClock{now: time.Now()}
	f := statelessFixture(t, store, clock, nonceKey(1))
	nonce := requestNonce(t, f.iss)
	if _, err := requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, buildJWTProof(t, testP256Key(t), testIssuer, nonce)); err != nil {
		t.Fatal(err)
	}
	got := store.spent
	if got.Nonce != nonce || got.Owner == testIssuer || !strings.HasSuffix(got.Owner, testIssuer) {
		t.Errorf("spent %+v, want the nonce under an Owner other than %q", got, testIssuer)
	}
	if limit := clock.now.Add(time.Minute); !got.ExpiresAt.After(limit) { // the fixture's NonceLifetime
		t.Errorf("spent until %v, want past the nonce's expiry (%v)", got.ExpiresAt, limit)
	}
}

// recordingSpender is a storage.NonceStore keeping the last Spend.
type recordingSpender struct {
	*storage.NonceStore
	spent issuer.NonceIssuance
}

func (s *recordingSpender) Spend(ctx context.Context, issuance issuer.NonceIssuance) error {
	s.spent = issuance
	return s.NonceStore.Spend(ctx, issuance)
}

// New refuses NonceKeys too short or too many, or with a Nonces store
// that can't spend.
func TestStatelessNonce_ValidatesKeys(t *testing.T) {
	tooMany := make([][]byte, issuer.MaxNonceKeys+1)
	for i := range tooMany {
		tooMany[i] = nonceKey(byte(i))
	}
	for name, mutate := range map[string]func(*issuer.Dependencies){
		"short key": func(deps *issuer.Dependencies) {
			deps.Nonces, deps.NonceKeys = storage.NewNonceStore(), [][]byte{make([]byte, issuer.MinNonceKeyBytes-1)}
		},
		"too many keys": func(deps *issuer.Dependencies) {
			deps.Nonces, deps.NonceKeys = storage.NewNonceStore(), tooMany
		},
		"store can't spend": func(deps *issuer.Dependencies) {
			deps.Nonces, deps.NonceKeys = newFakeNonceStore(), [][]byte{nonceKey(1)}
		},
	} {
		if _, err := tryCredentialEndpointFixture(t, func(_ *issuer.Config, deps *issuer.Dependencies) { mutate(deps) }); err == nil {
			t.Errorf("%s: New accepted it", name)
		}
	}
}

// flipBase64 is another base64url character than c.
func flipBase64(c byte) string {
	if c == 'A' {
		return "B"
	}
	return "A"
}
