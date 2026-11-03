package statuslist

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/internal/cose"
)

// VerifyTokenCWT refuses a CWT whose iss (claim 1) names another issuer
// than opts.Issuer, as VerifyToken does for a JWT's.
func TestVerifyTokenCWT_ComparesIss(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sl, err := New(Bits1, []uint8{0}, "")
	if err != nil {
		t.Fatal(err)
	}
	token, err := IssueTokenCWT(key, cose.ES256, TokenClaims{Sub: "https://issuer.example/statuslists/1", Iat: time.Now().Unix(), StatusList: sl}, nil)
	if err != nil {
		t.Fatal(err)
	}
	withIss := func(iss any) []byte {
		t.Helper()
		_, _, payload, err := cose.DecodeUnverifiedTagged(token)
		if err != nil {
			t.Fatal(err)
		}
		var claims map[int]cbor.RawMessage
		if err := cbor.Unmarshal(payload, &claims); err != nil {
			t.Fatal(err)
		}
		if claims[cwtClaimIss], err = cbor.Marshal(iss); err != nil {
			t.Fatal(err)
		}
		if payload, err = cbor.Marshal(claims); err != nil {
			t.Fatal(err)
		}
		signed, err := cose.SignTagged(cose.ES256, key, cose.Headers{Typ: CWTTokenMediaType}, cose.Headers{}, payload, nil)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	opts := VerifyOptions{Issuer: "https://issuer.example"}
	if _, err := VerifyTokenCWT(withIss("https://issuer.example"), &key.PublicKey, cose.ES256, opts); err != nil {
		t.Errorf("its own issuer: %v", err)
	}
	if _, err := VerifyTokenCWT(withIss("https://other.example"), &key.PublicKey, cose.ES256, opts); err == nil || !strings.Contains(err.Error(), "iss") {
		t.Errorf("another issuer: %v, want it refused", err)
	}
	if _, err := VerifyTokenCWT(withIss(7), &key.PublicKey, cose.ES256, opts); err == nil || !strings.Contains(err.Error(), "iss") {
		t.Errorf("a non-text iss: %v, want it refused", err)
	}
	if _, err := VerifyTokenCWT(withIss("https://other.example"), &key.PublicKey, cose.ES256, VerifyOptions{}); err != nil {
		t.Errorf("no Issuer to compare with: %v", err)
	}
}
