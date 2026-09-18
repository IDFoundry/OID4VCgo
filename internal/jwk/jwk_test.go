package jwk

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
)

func TestMarshalPublicKeyRoundTripEC2(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	k, err := Marshal(&key.PublicKey)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := k.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	pub, ok := got.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		t.Errorf("PublicKey = %v, want %v", got, &key.PublicKey)
	}
}

func TestMarshalPublicKeyRoundTripOKP(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	k, err := Marshal(pub)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := k.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	edPub, ok := got.(ed25519.PublicKey)
	if !ok || !edPub.Equal(pub) {
		t.Errorf("PublicKey = %v, want %v", got, pub)
	}
}

func TestParsePublicKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	k, err := Marshal(&key.PublicKey)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	raw, err := json.Marshal(k)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	got, err := ParsePublicKey(raw)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	pub, ok := got.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		t.Errorf("ParsePublicKey = %v, want %v", got, &key.PublicKey)
	}
}

func TestMatches(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	k, err := Marshal(&key.PublicKey)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	raw, err := json.Marshal(k)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	ok, err := Matches(raw, &key.PublicKey)
	if err != nil || !ok {
		t.Errorf("Matches(same key) = %v, %v, want true, nil", ok, err)
	}
	ok, err = Matches(raw, &other.PublicKey)
	if err != nil || ok {
		t.Errorf("Matches(different key) = %v, %v, want false, nil", ok, err)
	}
}

func TestMarshalRejectsUnsupportedKeyType(t *testing.T) {
	if _, err := Marshal("not-a-key"); err == nil {
		t.Errorf("Marshal accepted an unsupported key type")
	}
}

func TestMarshalRejectsUnsupportedCurve(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if _, err := Marshal(&key.PublicKey); err == nil {
		t.Errorf("Marshal accepted a non-P-256 curve")
	}
}

func TestPublicKeyRejectsUnsupportedKty(t *testing.T) {
	if _, err := (JWK{Kty: "RSA"}).PublicKey(); err == nil {
		t.Errorf("PublicKey accepted an unsupported kty")
	}
}

func TestPublicKeyRejectsUnsupportedCrv(t *testing.T) {
	if _, err := (JWK{Kty: "EC", Crv: "P-384"}).PublicKey(); err == nil {
		t.Errorf("PublicKey accepted an unsupported EC curve")
	}
	if _, err := (JWK{Kty: "OKP", Crv: "X25519"}).PublicKey(); err == nil {
		t.Errorf("PublicKey accepted an unsupported OKP curve")
	}
}

func TestPublicKeyRejectsMalformedCoordinates(t *testing.T) {
	if _, err := (JWK{Kty: "EC", Crv: "P-256", X: "not-base64!", Y: "AA"}).PublicKey(); err == nil {
		t.Errorf("PublicKey accepted malformed x")
	}
	if _, err := (JWK{Kty: "EC", Crv: "P-256", X: "AA", Y: "not-base64!"}).PublicKey(); err == nil {
		t.Errorf("PublicKey accepted malformed y")
	}
	if _, err := (JWK{Kty: "EC", Crv: "P-256", X: "AA", Y: "AA"}).PublicKey(); err == nil {
		t.Errorf("PublicKey accepted coordinates of the wrong length")
	}
	if _, err := (JWK{Kty: "OKP", Crv: "Ed25519", X: "not-base64!"}).PublicKey(); err == nil {
		t.Errorf("PublicKey accepted malformed OKP x")
	}
	if _, err := (JWK{Kty: "OKP", Crv: "Ed25519", X: "AA"}).PublicKey(); err == nil {
		t.Errorf("PublicKey accepted an OKP x of the wrong length")
	}
}

func TestParsePublicKeyRejectsMalformedJSON(t *testing.T) {
	if _, err := ParsePublicKey([]byte("not json")); err == nil {
		t.Errorf("ParsePublicKey accepted malformed JSON")
	}
}

func TestMatchesRejectsMalformedJSON(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if _, err := Matches([]byte("not json"), &key.PublicKey); err == nil {
		t.Errorf("Matches accepted malformed JSON")
	}
}

// TestThumbprintEC256KnownAnswer is a P-256 EC thumbprint independently
// cross-checked against Python's jwcrypto (JWK(**jwk).thumbprint()) —
// this package has no RFC 7638 Appendix A.1 worked example of its own
// to check against (that example is an RSA key; this package only
// supports EC/OKP), so an independent cross-language computation
// stands in, the same discipline internal/jwe's own ECDH-ES tests
// apply to a similarly precisely-specified-but-easy-to-get-wrong
// construction.
func TestThumbprintEC256KnownAnswer(t *testing.T) {
	k := JWK{
		Kty: "EC", Crv: "P-256",
		X: "2Tyl8GNWQ2AvlGyN1fuOAxJJgjPZoGUaPaWN3PDKT24",
		Y: "50Bc7ATi3wJAZHoLpYaiJADdjrZQ5vgbdUDRMciX3vQ",
	}
	got, err := k.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	want := "-_J6uf9LweGjx5PbUVEAKEwOqF5LBkEg1nOCOv2BNLg"
	if got != want {
		t.Errorf("Thumbprint = %q, want %q", got, want)
	}
}

func TestThumbprintOKP(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	k, err := Marshal(pub)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := k.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	if got == "" {
		t.Fatalf("Thumbprint is empty")
	}
	// Deterministic and stable across repeated calls.
	again, err := k.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	if got != again {
		t.Errorf("Thumbprint is not deterministic: %q != %q", got, again)
	}
}

func TestThumbprintDiffersByKey(t *testing.T) {
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwk1, err := Marshal(&key1.PublicKey)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	jwk2, err := Marshal(&key2.PublicKey)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	tp1, err := jwk1.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	tp2, err := jwk2.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	if tp1 == tp2 {
		t.Errorf("distinct keys produced the same thumbprint")
	}
}

func TestThumbprintRejectsUnsupportedKty(t *testing.T) {
	if _, err := (JWK{Kty: "RSA"}).Thumbprint(); err == nil {
		t.Errorf("Thumbprint accepted an unsupported kty")
	}
}

func TestThumbprintRejectsUnsupportedCurve(t *testing.T) {
	if _, err := (JWK{Kty: "EC", Crv: "P-384", X: "AA", Y: "AA"}).Thumbprint(); err == nil {
		t.Errorf("Thumbprint accepted an unsupported EC curve")
	}
	if _, err := (JWK{Kty: "OKP", Crv: "X25519", X: "AA"}).Thumbprint(); err == nil {
		t.Errorf("Thumbprint accepted an unsupported OKP curve")
	}
}

func TestMarshalPrivateEC(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	k, err := MarshalPrivate(key)
	if err != nil {
		t.Fatalf("MarshalPrivate: %v", err)
	}
	wantPub, err := Marshal(&key.PublicKey)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if k.Kty != wantPub.Kty || k.Crv != wantPub.Crv || k.X != wantPub.X || k.Y != wantPub.Y {
		t.Errorf("public half = %+v, want %+v", k, wantPub)
	}
	d, err := b64.DecodeString(k.D)
	if err != nil {
		t.Fatalf("decode d: %v", err)
	}
	if len(d) != 32 {
		t.Errorf("d is %d bytes, want 32", len(d))
	}
	wantD, err := key.Bytes()
	if err != nil {
		t.Fatalf("key.Bytes: %v", err)
	}
	if b64.EncodeToString(wantD) != k.D {
		t.Errorf("d = %q, want %q", k.D, b64.EncodeToString(wantD))
	}
}

func TestMarshalPrivateOKP(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	k, err := MarshalPrivate(priv)
	if err != nil {
		t.Fatalf("MarshalPrivate: %v", err)
	}
	wantPub, err := Marshal(pub)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if k.Kty != wantPub.Kty || k.Crv != wantPub.Crv || k.X != wantPub.X {
		t.Errorf("public half = %+v, want %+v", k, wantPub)
	}
	d, err := b64.DecodeString(k.D)
	if err != nil {
		t.Fatalf("decode d: %v", err)
	}
	if b64.EncodeToString(d) != b64.EncodeToString(priv.Seed()) {
		t.Errorf("d does not match priv.Seed()")
	}
}

func TestMarshalPrivateRejectsUnsupportedType(t *testing.T) {
	if _, err := MarshalPrivate("not a key"); err == nil {
		t.Error("MarshalPrivate accepted an unsupported private key type")
	}
}

func TestSetEntryRoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub, err := Marshal(&key.PublicKey)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	set := Set{Keys: []SetEntry{
		{JWK: pub, Kid: "k1", Use: "enc", Alg: "ECDH-ES", X5C: []string{"cert-bytes"}},
	}}
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got Set
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(got.Keys))
	}
	entry := got.Keys[0]
	if entry.Kid != "k1" || entry.Use != "enc" || entry.Alg != "ECDH-ES" || len(entry.X5C) != 1 || entry.X5C[0] != "cert-bytes" {
		t.Errorf("SetEntry metadata = %+v", entry)
	}
	if entry.Kty != pub.Kty || entry.Crv != pub.Crv || entry.X != pub.X || entry.Y != pub.Y {
		t.Errorf("SetEntry key material = %+v, want %+v", entry.JWK, pub)
	}

	roundTripped, err := entry.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	ecPub, ok := roundTripped.(*ecdsa.PublicKey)
	if !ok || !ecPub.Equal(&key.PublicKey) {
		t.Errorf("PublicKey() = %v, want %v", roundTripped, &key.PublicKey)
	}
}
