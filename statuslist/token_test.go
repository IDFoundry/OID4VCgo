package statuslist

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/jose"
)

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func TestIssueVerifyToken(t *testing.T) {
	key := testKey(t)
	sl, err := New(Bits1, []uint8{0, 1, 0, 1}, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	exp := time.Now().Add(24 * time.Hour).Unix()
	claims := TokenClaims{
		Sub:        "https://example.com/statuslists/1",
		Iat:        time.Now().Add(-2 * time.Hour).Unix(),
		Exp:        &exp,
		StatusList: sl,
	}

	token, err := IssueToken(key, jose.ES256, claims, "12")
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	got, err := VerifyToken(token, &key.PublicKey, jose.ES256, VerifyOptions{UnboundSigner: AnyListSigner})
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if got.Sub != claims.Sub {
		t.Errorf("Sub = %q, want %q", got.Sub, claims.Sub)
	}
	if got.StatusList.Bits != Bits1 {
		t.Errorf("Bits = %d, want 1", got.StatusList.Bits)
	}
	status, err := got.StatusList.Status(1)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status != 1 {
		t.Errorf("status[1] = %d, want 1", status)
	}
}

// TestVerifyToken_AcceptsLargerThanJoseDefault proves VerifyToken
// actually passes its own maxTokenBytes through to jose.VerifyMax
// rather than falling back to jose.Verify's smaller
// jose.MaxCompactBytes default — a token whose Additional claims push
// it past that default (but still comfortably under maxTokenBytes)
// must still verify.
func TestVerifyToken_AcceptsLargerThanJoseDefault(t *testing.T) {
	key := testKey(t)
	sl, err := New(Bits1, []uint8{0}, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	claims := TokenClaims{
		Sub:        "https://example.com/statuslists/1",
		Iat:        time.Now().Unix(),
		StatusList: sl,
		Additional: map[string]any{"padding": string(make([]byte, jose.MaxCompactBytes))},
	}

	token, err := IssueToken(key, jose.ES256, claims, "")
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	if len(token) <= jose.MaxCompactBytes {
		t.Fatalf("token is %d bytes, want > jose.MaxCompactBytes (%d)", len(token), jose.MaxCompactBytes)
	}

	if _, err := VerifyToken(token, &key.PublicKey, jose.ES256, VerifyOptions{UnboundSigner: AnyListSigner}); err != nil {
		t.Errorf("VerifyToken: %v", err)
	}
}

func TestVerifyToken_RejectsExpired(t *testing.T) {
	key := testKey(t)
	sl, err := New(Bits1, []uint8{0}, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	exp := time.Now().Add(-time.Hour).Unix()
	token, err := IssueToken(key, jose.ES256, TokenClaims{
		Sub:        "https://example.com/statuslists/1",
		Iat:        time.Now().Add(-2 * time.Hour).Unix(),
		Exp:        &exp,
		StatusList: sl,
	}, "")
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	if _, err := VerifyToken(token, &key.PublicKey, jose.ES256, VerifyOptions{UnboundSigner: AnyListSigner}); err == nil {
		t.Errorf("VerifyToken accepted an expired token")
	}
}

func TestVerifyToken_RejectsWrongTyp(t *testing.T) {
	key := testKey(t)
	// Sign a JWT with the wrong typ directly via internal/jose, bypassing IssueToken.
	sl, err := New(Bits1, []uint8{0}, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	payload := map[string]any{
		"sub": "https://example.com/statuslists/1",
		"iat": time.Now().Unix(),
		"status_list": map[string]any{
			"bits": int(sl.Bits),
			"lst":  sl.Lst,
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// typ is a media type (RFC 7515 §4.1.9): case-insensitive, its
	// "application/" prefix optional.
	for typ, ok := range map[string]bool{"not-a-statuslist+jwt": false, "Application/StatusList+JWT": true} {
		compact, err := jose.Sign(jose.ES256, key, map[string]any{"typ": typ}, raw)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if _, err := VerifyToken(compact, &key.PublicKey, jose.ES256, VerifyOptions{UnboundSigner: AnyListSigner}); (err == nil) != ok {
			t.Errorf("typ %q: %v", typ, err)
		}
	}
}

func TestIssueToken_RequiresSub(t *testing.T) {
	key := testKey(t)
	sl, err := New(Bits1, []uint8{0}, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := IssueToken(key, jose.ES256, TokenClaims{Iat: 1, StatusList: sl}, ""); err == nil {
		t.Errorf("IssueToken accepted TokenClaims with no Sub")
	}
}

// IssueToken and IssueTokenCWT refuse claims a Relying Party would
// refuse (draft-14 §5.1): no iat, a ttl that isn't positive, an exp not
// after iat.
func TestIssueToken_RefusesInvalidClaims(t *testing.T) {
	key := testKey(t)
	sl, err := New(Bits1, []uint8{0}, "")
	if err != nil {
		t.Fatal(err)
	}
	now, zero := time.Now().Unix(), int64(0)
	before := now - 1
	for name, claims := range map[string]TokenClaims{
		"no iat":             {Sub: "https://example.com/statuslists/1", StatusList: sl},
		"a zero ttl":         {Sub: "https://example.com/statuslists/1", Iat: now, TTL: &zero, StatusList: sl},
		"exp before iat":     {Sub: "https://example.com/statuslists/1", Iat: now, Exp: &before, StatusList: sl},
		"no sub (as before)": {Iat: now, StatusList: sl},
	} {
		if _, err := IssueToken(key, jose.ES256, claims, ""); err == nil {
			t.Errorf("%s: JWT issued", name)
		}
		if _, err := IssueTokenCWT(key, cose.ES256, claims, nil); err == nil {
			t.Errorf("%s: CWT issued", name)
		}
	}
}
