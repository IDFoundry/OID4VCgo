package statuslist

import (
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/cose"
)

// A Status List Token MUST NOT be wrapped in the CWT tag (61, RFC 8392
// §6) under either draft: draft-21 §5.2 says so, and draft-14 §5.2's
// COSE_Sign1 is the CWT itself. VerifyTokenCWT refuses one, tagged
// COSE_Sign1 or not.
func TestVerifyTokenCWTRefusesCWTTag(t *testing.T) {
	key := testKey(t)
	sl, err := New(Bits1, []uint8{0, 1, 0}, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tagged, err := IssueTokenCWT(key, cose.ES256, TokenClaims{Sub: "https://example.com/statuslists/1", Iat: time.Now().Unix(), StatusList: sl}, nil)
	if err != nil {
		t.Fatalf("IssueTokenCWT: %v", err)
	}
	cwtTag := []byte{0xd8, 0x3d} // tag(61)
	for name, token := range map[string][]byte{
		"CWT tag around COSE_Sign1_Tagged": append(append([]byte{}, cwtTag...), tagged...),
		"CWT tag around COSE_Sign1":        append(append([]byte{}, cwtTag...), tagged[1:]...),
	} {
		if _, err := VerifyTokenCWT(token, &key.PublicKey, cose.ES256, VerifyOptions{UnboundSigner: AnyListSigner}); err == nil {
			t.Errorf("%s: VerifyTokenCWT accepted it", name)
		}
	}
}
