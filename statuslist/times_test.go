package statuslist

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// A Status List Token's NumericDates may be fractional (RFC 7519 §2,
// RFC 8392 §2), and one not yet valid by its nbf is refused (RFC 7519
// §4.1.5), in both forms.
func TestVerifyToken_NbfAndFractionalDates(t *testing.T) {
	key := testKey(t)
	sl, err := New(Bits1, []uint8{0}, "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	jwt := func(claims map[string]any) string {
		t.Helper()
		claims["sub"], claims["status_list"] = "https://example.com/statuslists/1", sl
		payload, err := json.Marshal(claims)
		if err != nil {
			t.Fatal(err)
		}
		token, err := jose.Sign(jose.ES256, key, map[string]any{"typ": TokenTyp}, payload)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	cwtSL, err := toCWTStatusList(sl)
	if err != nil {
		t.Fatal(err)
	}
	cwt := func(claims map[int]any) []byte {
		t.Helper()
		claims[cwtClaimSub], claims[cwtClaimStatusList] = "https://example.com/statuslists/1", cwtSL
		raw, err := cbor.Marshal(claims)
		if err != nil {
			t.Fatal(err)
		}
		token, err := cose.SignTagged(cose.ES256, key, cose.Headers{Typ: CWTTokenMediaType}, cose.Headers{}, raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	fractional := float64(now.UnixMilli()) / 1000
	later := now.Add(time.Hour).Unix()

	if _, err := VerifyToken(jwt(map[string]any{"iat": fractional, "exp": fractional + 3600}), &key.PublicKey, "ES256", VerifyOptions{UnboundSigner: AnyListSigner}); err != nil {
		t.Errorf("JWT with fractional dates: %v", err)
	}
	if _, err := VerifyToken(jwt(map[string]any{"iat": now.Unix(), "nbf": now.Add(-time.Minute).Unix()}), &key.PublicKey, "ES256", VerifyOptions{UnboundSigner: AnyListSigner}); err != nil {
		t.Errorf("JWT with a past nbf: %v", err)
	}
	if _, err := VerifyToken(jwt(map[string]any{"iat": now.Unix(), "nbf": later}), &key.PublicKey, "ES256", VerifyOptions{UnboundSigner: AnyListSigner}); err == nil {
		t.Error("JWT not valid for an hour was accepted")
	}
	if _, err := VerifyTokenCWT(cwt(map[int]any{cwtClaimIat: fractional}), &key.PublicKey, cose.ES256, VerifyOptions{UnboundSigner: AnyListSigner}); err != nil {
		t.Errorf("CWT with a fractional iat: %v", err)
	}
	if _, err := VerifyTokenCWT(cwt(map[int]any{cwtClaimIat: now.Unix(), cwtClaimNbf: later}), &key.PublicKey, cose.ES256, VerifyOptions{UnboundSigner: AnyListSigner}); err == nil {
		t.Error("CWT not valid for an hour was accepted")
	}
}
