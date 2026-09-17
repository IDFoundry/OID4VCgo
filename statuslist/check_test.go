package statuslist

import (
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

func TestCheck_FullFlow(t *testing.T) {
	key := testKey(t)
	sl, err := New(Bits2, []uint8{0, 1, 2, 0, 1}, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const uri = "https://example.com/statuslists/1"
	token, err := IssueToken(key, jose.ES256, TokenClaims{
		Sub:        uri,
		Iat:        time.Now().Unix(),
		StatusList: sl,
	}, "")
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	ref := StatusListRef{Idx: 2, URI: uri}
	status, claims, err := Check(token, &key.PublicKey, jose.ES256, ref, VerifyOptions{})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if status != StatusSuspended {
		t.Errorf("status = %v, want %v", status, StatusSuspended)
	}
	if claims.Sub != uri {
		t.Errorf("Sub = %q, want %q", claims.Sub, uri)
	}
}

func TestCheck_RejectsMismatchedURI(t *testing.T) {
	key := testKey(t)
	sl, err := New(Bits1, []uint8{0}, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	token, err := IssueToken(key, jose.ES256, TokenClaims{
		Sub:        "https://example.com/statuslists/1",
		Iat:        time.Now().Unix(),
		StatusList: sl,
	}, "")
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	ref := StatusListRef{Idx: 0, URI: "https://example.com/statuslists/OTHER"}
	if _, _, err := Check(token, &key.PublicKey, jose.ES256, ref, VerifyOptions{}); err == nil {
		t.Errorf("Check accepted a token whose sub doesn't match the Referenced Token's uri")
	}
}

func TestCheck_RejectsOutOfBoundsIndex(t *testing.T) {
	key := testKey(t)
	sl, err := New(Bits1, []uint8{0, 1}, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const uri = "https://example.com/statuslists/1"
	token, err := IssueToken(key, jose.ES256, TokenClaims{
		Sub:        uri,
		Iat:        time.Now().Unix(),
		StatusList: sl,
	}, "")
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	ref := StatusListRef{Idx: 1000, URI: uri}
	if _, _, err := Check(token, &key.PublicKey, jose.ES256, ref, VerifyOptions{}); err == nil {
		t.Errorf("Check accepted an out-of-bounds index")
	}
}

func TestStatusListRef_ClaimRoundTrip(t *testing.T) {
	ref := StatusListRef{Idx: 42, URI: "https://example.com/statuslists/1"}
	claim := ref.Claim()

	// Round trip through JSON the way a real Referenced Token would
	// carry it, so this exercises the same float64-decoded-idx path
	// ParseStatusClaim has to handle for real JSON input.
	raw, err := marshalUnmarshal(claim)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}

	got, err := ParseStatusClaim(raw)
	if err != nil {
		t.Fatalf("ParseStatusClaim: %v", err)
	}
	if got != ref {
		t.Errorf("ParseStatusClaim = %+v, want %+v", got, ref)
	}
}

func TestParseStatusClaim_RejectsMissingFields(t *testing.T) {
	if _, err := ParseStatusClaim(map[string]any{}); err == nil {
		t.Errorf("ParseStatusClaim accepted a claim with no status_list")
	}
	if _, err := ParseStatusClaim(map[string]any{
		"status_list": map[string]any{"uri": "https://example.com/x"},
	}); err == nil {
		t.Errorf("ParseStatusClaim accepted a status_list with no idx")
	}
	if _, err := ParseStatusClaim(map[string]any{
		"status_list": map[string]any{"idx": float64(0)},
	}); err == nil {
		t.Errorf("ParseStatusClaim accepted a status_list with no uri")
	}
}
