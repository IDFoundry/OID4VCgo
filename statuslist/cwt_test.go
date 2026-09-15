package statuslist

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcigo/internal/cose"
)

func TestIssueVerifyTokenCWT(t *testing.T) {
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

	token, err := IssueTokenCWT(key, cose.ES256, claims, []byte("12"))
	if err != nil {
		t.Fatalf("IssueTokenCWT: %v", err)
	}

	got, err := VerifyTokenCWT(token, &key.PublicKey, cose.ES256, VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyTokenCWT: %v", err)
	}
	if got.Sub != claims.Sub {
		t.Errorf("Sub = %q, want %q", got.Sub, claims.Sub)
	}
	if got.Iat != claims.Iat {
		t.Errorf("Iat = %d, want %d", got.Iat, claims.Iat)
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

func TestVerifyTokenCWTRejectsExpired(t *testing.T) {
	key := testKey(t)
	sl, err := New(Bits1, []uint8{0}, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	exp := time.Now().Add(-time.Hour).Unix()
	token, err := IssueTokenCWT(key, cose.ES256, TokenClaims{
		Sub:        "https://example.com/statuslists/1",
		Iat:        time.Now().Unix(),
		Exp:        &exp,
		StatusList: sl,
	}, nil)
	if err != nil {
		t.Fatalf("IssueTokenCWT: %v", err)
	}
	if _, err := VerifyTokenCWT(token, &key.PublicKey, cose.ES256, VerifyOptions{}); err == nil {
		t.Errorf("VerifyTokenCWT accepted an expired token")
	}
}

func TestVerifyTokenCWTRejectsWrongTyp(t *testing.T) {
	key := testKey(t)
	sl, err := New(Bits1, []uint8{0}, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	payload := map[int]interface{}{
		cwtClaimSub:        "https://example.com/statuslists/1",
		cwtClaimIat:        time.Now().Unix(),
		cwtClaimStatusList: cwtStatusList{Bits: sl.Bits, Lst: []byte{0}},
	}
	raw, err := cbor.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	sign1, err := cose.SignTagged(cose.ES256, key, cose.Headers{Typ: "not-a-statuslist+cwt"}, cose.Headers{}, raw, nil)
	if err != nil {
		t.Fatalf("SignTagged: %v", err)
	}
	if _, err := VerifyTokenCWT(sign1, &key.PublicKey, cose.ES256, VerifyOptions{}); err == nil {
		t.Errorf("VerifyTokenCWT accepted the wrong typ header")
	}
}

func TestIssueTokenCWTRequiresSub(t *testing.T) {
	key := testKey(t)
	sl, err := New(Bits1, []uint8{0}, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := IssueTokenCWT(key, cose.ES256, TokenClaims{Iat: 1, StatusList: sl}, nil); err == nil {
		t.Errorf("IssueTokenCWT accepted TokenClaims with no Sub")
	}
}

func TestVerifyTokenCWTRejectsMalformedInput(t *testing.T) {
	key := testKey(t)
	if _, err := VerifyTokenCWT([]byte("not cbor"), &key.PublicKey, cose.ES256, VerifyOptions{}); err == nil {
		t.Errorf("VerifyTokenCWT accepted malformed input")
	}
}

// TestVectorCWTStatusListToken decodes draft-ietf-oauth-status-list-12
// §5.2's own non-normative Status List Token example (a real,
// spec-published COSE_Sign1_Tagged CWT — not one this package
// produced) and checks every claim this package's parseCWTClaims
// extracts against the values the draft's own CBOR-annotated
// breakdown publishes. The draft gives no example signing key, so this
// checks decoding, not signature verification — the CWT counterpart to
// credential/mdoc's Annex D digest vectors.
func TestVectorCWTStatusListToken(t *testing.T) {
	token := mustHexCWT(t, "d2845820a2012610781a6170706c69636174696f6e2f7374617475736c6973742b637774"+
		"a1044231325850a502782168747470733a2f2f6578616d706c652e636f6d2f7374617475736c697374732f"+
		"31061a648c5bea041a8898dfea19fffe19a8c019fffda2646269747301636c73744a78dadbb918000217015d"+
		"584064b10e1ed8874064d944e483e53b97b0349a7897db9f875986c501d88203bb0a278de3410fff7a99387c"+
		"ceffbc84c4fb6a24bf82b61bc09815c76cb5f9e2d9be")

	protected, _, raw, err := cose.DecodeUnverifiedTagged(token)
	if err != nil {
		t.Fatalf("DecodeUnverifiedTagged: %v", err)
	}
	if protected.Typ != CWTTokenMediaType {
		t.Errorf("Typ = %q, want %q", protected.Typ, CWTTokenMediaType)
	}
	if protected.Alg != cose.ES256 {
		t.Errorf("Alg = %d, want ES256", protected.Alg)
	}

	var decoded map[int]interface{}
	if err := cbor.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	claims, err := parseCWTClaims(decoded)
	if err != nil {
		t.Fatalf("parseCWTClaims: %v", err)
	}

	if claims.Sub != "https://example.com/statuslists/1" {
		t.Errorf("Sub = %q", claims.Sub)
	}
	if claims.Iat != 1686920170 {
		t.Errorf("Iat = %d, want 1686920170", claims.Iat)
	}
	if claims.Exp == nil || *claims.Exp != 2291720170 {
		t.Errorf("Exp = %v, want 2291720170", claims.Exp)
	}
	if claims.TTL == nil || *claims.TTL != 43200 {
		t.Errorf("TTL = %v, want 43200", claims.TTL)
	}
	if claims.StatusList.Bits != Bits1 {
		t.Errorf("Bits = %d, want 1", claims.StatusList.Bits)
	}
	wantLst := base64.RawURLEncoding.EncodeToString(mustHexCWT(t, "78dadbb918000217015d"))
	if claims.StatusList.Lst != wantLst {
		t.Errorf("Lst = %q, want %q", claims.StatusList.Lst, wantLst)
	}
}

// TestVectorCWTReferencedTokenStatusClaim decodes draft-12 §6.3's own
// non-normative "Referenced Token in CWT format" example and checks
// ParseCWTStatusClaim against the exact idx/uri it publishes.
func TestVectorCWTReferencedTokenStatusClaim(t *testing.T) {
	token := mustHexCWT(t, "d28443a10126a1044231325866a502653132333435017368747470733a2f2f65786"+
		"16d706c652e636f6d061a648c5bea041a8898dfea19ffffa16b7374617475735f6c69"+
		"7374a2636964780063757269782168747470733a2f2f6578616d706c652e636f6d2f"+
		"7374617475736c697374732f3158400c5aeec0aa51ffe7c1bd50def316df26e0d424"+
		"94ba7d5e168bf4dddc0cac365793754eb8e6dd3452210614dcef25e9ccbc35f62689"+
		"9f1b23dddad6d8c514106c")

	_, _, raw, err := cose.DecodeUnverifiedTagged(token)
	if err != nil {
		t.Fatalf("DecodeUnverifiedTagged: %v", err)
	}
	var decoded map[int]interface{}
	if err := cbor.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	statusRaw, ok := decoded[CWTClaimStatus]
	if !ok {
		t.Fatalf("claims are missing key %d (status)", CWTClaimStatus)
	}
	var status map[string]interface{}
	if err := decodeCBORValue(statusRaw, &status); err != nil {
		t.Fatalf("decode status claim: %v", err)
	}

	ref, err := ParseCWTStatusClaim(status)
	if err != nil {
		t.Fatalf("ParseCWTStatusClaim: %v", err)
	}
	if ref.Idx != 0 {
		t.Errorf("Idx = %d, want 0", ref.Idx)
	}
	if ref.URI != "https://example.com/statuslists/1" {
		t.Errorf("URI = %q", ref.URI)
	}
}

func TestCheckCWT_FullFlow(t *testing.T) {
	key := testKey(t)
	sl, err := New(Bits2, []uint8{0, 1, 2, 0, 1}, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const uri = "https://example.com/statuslists/1"
	token, err := IssueTokenCWT(key, cose.ES256, TokenClaims{
		Sub:        uri,
		Iat:        time.Now().Unix(),
		StatusList: sl,
	}, nil)
	if err != nil {
		t.Fatalf("IssueTokenCWT: %v", err)
	}

	ref := StatusListRef{Idx: 2, URI: uri}
	status, claims, err := CheckCWT(token, &key.PublicKey, cose.ES256, ref, VerifyOptions{})
	if err != nil {
		t.Fatalf("CheckCWT: %v", err)
	}
	if status != StatusSuspended {
		t.Errorf("status = %v, want %v", status, StatusSuspended)
	}
	if claims.Sub != uri {
		t.Errorf("Sub = %q, want %q", claims.Sub, uri)
	}
}

func TestCheckCWT_RejectsMismatchedURI(t *testing.T) {
	key := testKey(t)
	sl, err := New(Bits1, []uint8{0}, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	token, err := IssueTokenCWT(key, cose.ES256, TokenClaims{
		Sub:        "https://example.com/statuslists/1",
		Iat:        time.Now().Unix(),
		StatusList: sl,
	}, nil)
	if err != nil {
		t.Fatalf("IssueTokenCWT: %v", err)
	}

	ref := StatusListRef{Idx: 0, URI: "https://example.com/statuslists/OTHER"}
	if _, _, err := CheckCWT(token, &key.PublicKey, cose.ES256, ref, VerifyOptions{}); err == nil {
		t.Errorf("CheckCWT accepted a token whose sub doesn't match the Referenced Token's uri")
	}
}

func TestCWTStatusClaimRoundTrip(t *testing.T) {
	ref := StatusListRef{Idx: 5, URI: "https://example.com/statuslists/1"}
	claim, err := ref.CWTStatusClaim()
	if err != nil {
		t.Fatalf("CWTStatusClaim: %v", err)
	}
	got, err := ParseCWTStatusClaim(claim)
	if err != nil {
		t.Fatalf("ParseCWTStatusClaim: %v", err)
	}
	if got != ref {
		t.Errorf("round-tripped = %+v, want %+v", got, ref)
	}
}

func TestCWTStatusClaimRejectsNegativeIdx(t *testing.T) {
	ref := StatusListRef{Idx: -1, URI: "https://example.com/statuslists/1"}
	if _, err := ref.CWTStatusClaim(); err == nil {
		t.Errorf("CWTStatusClaim accepted a negative Idx")
	}
}

func TestParseCWTStatusClaimRejectsMissingFields(t *testing.T) {
	if _, err := ParseCWTStatusClaim(map[string]interface{}{}); err == nil {
		t.Errorf("ParseCWTStatusClaim accepted a status claim with no status_list member")
	}
	if _, err := ParseCWTStatusClaim(map[string]interface{}{
		"status_list": map[string]interface{}{"uri": "https://example.com"},
	}); err == nil {
		t.Errorf("ParseCWTStatusClaim accepted a status_list missing idx")
	}
	if _, err := ParseCWTStatusClaim(map[string]interface{}{
		"status_list": map[string]interface{}{"idx": uint64(0)},
	}); err == nil {
		t.Errorf("ParseCWTStatusClaim accepted a status_list missing uri")
	}
}

func mustHexCWT(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return b
}
