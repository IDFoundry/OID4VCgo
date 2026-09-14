package statuslist

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcigo/internal/jose"
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
		Iat:        time.Now().Unix(),
		Exp:        &exp,
		StatusList: sl,
	}

	token, err := IssueToken(key, jose.ES256, claims, "12")
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	got, err := VerifyToken(token, &key.PublicKey, jose.ES256, VerifyOptions{})
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

func TestVerifyToken_RejectsExpired(t *testing.T) {
	key := testKey(t)
	sl, err := New(Bits1, []uint8{0}, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	exp := time.Now().Add(-time.Hour).Unix()
	token, err := IssueToken(key, jose.ES256, TokenClaims{
		Sub:        "https://example.com/statuslists/1",
		Iat:        time.Now().Unix(),
		Exp:        &exp,
		StatusList: sl,
	}, "")
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	if _, err := VerifyToken(token, &key.PublicKey, jose.ES256, VerifyOptions{}); err == nil {
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
	compact, err := jose.Sign(jose.ES256, key, map[string]any{"typ": "not-a-statuslist+jwt"}, raw)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := VerifyToken(compact, &key.PublicKey, jose.ES256, VerifyOptions{}); err == nil {
		t.Errorf("VerifyToken accepted the wrong typ header")
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
