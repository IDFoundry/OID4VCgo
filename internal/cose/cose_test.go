package cose

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestSignVerifyES256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	payload := []byte(`{"hello":"world"}`)

	sign1, err := Sign(ES256, key, Headers{KID: []byte("k1")}, Headers{}, payload, nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	protected, unprotected, got, err := Verify(ES256, &key.PublicKey, sign1, nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("payload = %s, want %s", got, payload)
	}
	if protected.Alg != ES256 {
		t.Errorf("protected.Alg = %d, want %d", protected.Alg, ES256)
	}
	if string(protected.KID) != "k1" {
		t.Errorf("protected.KID = %q, want k1", protected.KID)
	}
	if unprotected.Alg != 0 {
		t.Errorf("unprotected.Alg = %d, want 0", unprotected.Alg)
	}
}

func TestSignVerifyEdDSA(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	payload := []byte(`{"hello":"world"}`)

	sign1, err := Sign(EdDSA, priv, Headers{}, Headers{}, payload, nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	_, _, got, err := Verify(EdDSA, pub, sign1, nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("payload = %s, want %s", got, payload)
	}
}

func TestSignVerifyWithTyp(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sign1, err := Sign(ES256, key, Headers{Typ: "application/statuslist+cwt"}, Headers{}, []byte(`{"a":1}`), nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	protected, _, _, err := Verify(ES256, &key.PublicKey, sign1, nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if protected.Typ != "application/statuslist+cwt" {
		t.Errorf("Typ = %q, want application/statuslist+cwt", protected.Typ)
	}
}

func TestHeadersFromMapRejectsNonStringTyp(t *testing.T) {
	if _, err := headersFromMap(map[int]interface{}{labelTyp: 123}); err == nil {
		t.Errorf("headersFromMap accepted a non-string typ header")
	}
}

func TestSignVerifyTaggedRoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	payload := []byte(`{"sub":"https://example.com/statuslists/1"}`)

	sign1, err := SignTagged(ES256, key, Headers{Typ: "application/statuslist+cwt"}, Headers{}, payload, nil)
	if err != nil {
		t.Fatalf("SignTagged: %v", err)
	}
	if sign1[0] != 0xD2 {
		t.Errorf("tagged COSE_Sign1 does not start with tag 18's byte (0xD2): got %#x", sign1[0])
	}

	protected, _, got, err := VerifyTagged(ES256, &key.PublicKey, sign1, nil)
	if err != nil {
		t.Fatalf("VerifyTagged: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("payload = %s, want %s", got, payload)
	}
	if protected.Typ != "application/statuslist+cwt" {
		t.Errorf("Typ = %q, want application/statuslist+cwt", protected.Typ)
	}

	decProtected, _, decPayload, err := DecodeUnverifiedTagged(sign1)
	if err != nil {
		t.Fatalf("DecodeUnverifiedTagged: %v", err)
	}
	if string(decPayload) != string(payload) {
		t.Errorf("DecodeUnverifiedTagged payload = %s, want %s", decPayload, payload)
	}
	if decProtected.Typ != "application/statuslist+cwt" {
		t.Errorf("DecodeUnverifiedTagged Typ = %q, want application/statuslist+cwt", decProtected.Typ)
	}
}

func TestVerifyTaggedRejectsUntaggedInput(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	untagged, err := Sign(ES256, key, Headers{}, Headers{}, []byte(`{"a":1}`), nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, _, _, err := VerifyTagged(ES256, &key.PublicKey, untagged, nil); err == nil {
		t.Errorf("VerifyTagged accepted untagged input")
	}
	if _, _, _, err := DecodeUnverifiedTagged(untagged); err == nil {
		t.Errorf("DecodeUnverifiedTagged accepted untagged input")
	}
}

func TestVerifyTaggedRejectsWrongTagNumber(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	untagged, err := Sign(ES256, key, Headers{}, Headers{}, []byte(`{"a":1}`), nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	wrongTag, err := cbor.Marshal(cbor.RawTag{Number: 24, Content: cbor.RawMessage(untagged)})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, _, _, err := VerifyTagged(ES256, &key.PublicKey, wrongTag, nil); err == nil {
		t.Errorf("VerifyTagged accepted the wrong tag number")
	}
}

func TestSignVerifyWithX5Chain(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	payload := []byte(`{"a":1}`)

	t.Run("single certificate", func(t *testing.T) {
		unprotected := Headers{X5Chain: [][]byte{[]byte("leaf-cert")}}
		sign1, err := Sign(ES256, key, Headers{}, unprotected, payload, nil)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		_, got, _, err := Verify(ES256, &key.PublicKey, sign1, nil)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if len(got.X5Chain) != 1 || string(got.X5Chain[0]) != "leaf-cert" {
			t.Errorf("X5Chain = %v, want [leaf-cert]", got.X5Chain)
		}
	})

	t.Run("chain", func(t *testing.T) {
		unprotected := Headers{X5Chain: [][]byte{[]byte("leaf-cert"), []byte("intermediate-cert")}}
		sign1, err := Sign(ES256, key, Headers{}, unprotected, payload, nil)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		_, got, _, err := Verify(ES256, &key.PublicKey, sign1, nil)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if len(got.X5Chain) != 2 || string(got.X5Chain[0]) != "leaf-cert" || string(got.X5Chain[1]) != "intermediate-cert" {
			t.Errorf("X5Chain = %v", got.X5Chain)
		}
	})
}

func TestSignVerifyWithExternalAAD(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	payload := []byte(`{"a":1}`)
	aad := []byte("external-aad")

	sign1, err := Sign(ES256, key, Headers{}, Headers{}, payload, aad)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, _, _, err := Verify(ES256, &key.PublicKey, sign1, aad); err != nil {
		t.Fatalf("Verify with matching external AAD: %v", err)
	}
	if _, _, _, err := Verify(ES256, &key.PublicKey, sign1, []byte("wrong-aad")); err == nil {
		t.Errorf("Verify accepted a signature under the wrong external AAD")
	}
	if _, _, _, err := Verify(ES256, &key.PublicKey, sign1, nil); err == nil {
		t.Errorf("Verify accepted a signature with external AAD omitted")
	}
}

func TestSignRejectsNilPayload(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if _, err := Sign(ES256, key, Headers{}, Headers{}, nil, nil); err == nil {
		t.Errorf("Sign accepted a nil payload")
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sign1, err := Sign(ES256, key, Headers{}, Headers{}, []byte(`{"a":1}`), nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	tampered := make([]byte, len(sign1))
	copy(tampered, sign1)
	tampered[len(tampered)-1] ^= 0xFF
	if _, _, _, err := Verify(ES256, &key.PublicKey, tampered, nil); err == nil {
		t.Errorf("Verify accepted a tampered COSE_Sign1")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sign1, err := Sign(ES256, key1, Headers{}, Headers{}, []byte(`{"a":1}`), nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, _, _, err := Verify(ES256, &key2.PublicKey, sign1, nil); err == nil {
		t.Errorf("Verify accepted a signature under the wrong key")
	}
}

func TestVerifyRejectsAlgMismatch(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sign1, err := Sign(ES256, key, Headers{}, Headers{}, []byte(`{"a":1}`), nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, _, _, err := Verify(EdDSA, &key.PublicKey, sign1, nil); err == nil {
		t.Errorf("Verify accepted a COSE_Sign1 whose protected alg does not match the requested alg")
	}
}

func TestVerifyRejectsWrongKeyType(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sign1, err := Sign(ES256, key, Headers{}, Headers{}, []byte(`{"a":1}`), nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if _, _, _, err := Verify(ES256, pub, sign1, nil); err == nil {
		t.Errorf("Verify accepted an Ed25519 key for ES256")
	}
}

func TestSignRejectsWrongSignerType(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if _, err := Sign(ES256, priv, Headers{}, Headers{}, []byte(`{"a":1}`), nil); err == nil {
		t.Errorf("Sign accepted an Ed25519 signer for ES256")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if _, err := Sign(EdDSA, key, Headers{}, Headers{}, []byte(`{"a":1}`), nil); err == nil {
		t.Errorf("Sign accepted an ECDSA signer for EdDSA")
	}
}

func TestSignVerifyRejectsUnsupportedAlg(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	const unsupported Alg = -99
	if _, err := Sign(unsupported, key, Headers{}, Headers{}, []byte(`{"a":1}`), nil); err == nil {
		t.Errorf("Sign accepted an unsupported algorithm")
	}

	sign1, err := Sign(ES256, key, Headers{}, Headers{}, []byte(`{"a":1}`), nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, _, _, err := Verify(unsupported, &key.PublicKey, sign1, nil); err == nil {
		t.Errorf("Verify accepted an unsupported algorithm")
	}
}

func TestDecodeUnverified(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sign1, err := Sign(ES256, key, Headers{KID: []byte("k1")}, Headers{}, []byte(`{"iss":"issuer"}`), nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	protected, _, payload, err := DecodeUnverified(sign1)
	if err != nil {
		t.Fatalf("DecodeUnverified: %v", err)
	}
	if string(protected.KID) != "k1" {
		t.Errorf("KID = %q, want k1", protected.KID)
	}
	if string(payload) != `{"iss":"issuer"}` {
		t.Errorf("payload = %s", payload)
	}
}

func TestDecodeUnverifiedRejectsMalformedInput(t *testing.T) {
	if _, _, _, err := DecodeUnverified([]byte("not cbor")); err == nil {
		t.Errorf("DecodeUnverified accepted malformed input")
	}
	if _, _, _, err := Verify(ES256, nil, []byte("not cbor"), nil); err == nil {
		t.Errorf("Verify accepted malformed input")
	}
}

func TestHeadersFromMapRejectsWrongTypes(t *testing.T) {
	cases := map[int]interface{}{
		labelKID: "not-bytes",
	}
	if _, err := headersFromMap(cases); err == nil {
		t.Errorf("headersFromMap accepted a non-byte-string kid")
	}

	if _, err := headersFromMap(map[int]interface{}{labelAlg: "not-an-int"}); err == nil {
		t.Errorf("headersFromMap accepted a non-integer alg")
	}

	// A positive alg value decodes off the wire as uint64, not int64
	// (CBOR major type 0 vs. 1) — toInt64 must accept both.
	got, err := headersFromMap(map[int]interface{}{labelAlg: uint64(4)})
	if err != nil {
		t.Fatalf("headersFromMap rejected a uint64-valued alg: %v", err)
	}
	if got.Alg != Alg(4) {
		t.Errorf("Alg = %d, want 4", got.Alg)
	}

	if _, err := headersFromMap(map[int]interface{}{labelX5Chain: "not-a-chain"}); err == nil {
		t.Errorf("headersFromMap accepted a malformed x5chain")
	}

	if _, err := headersFromMap(map[int]interface{}{labelX5Chain: []interface{}{"not-bytes"}}); err == nil {
		t.Errorf("headersFromMap accepted an x5chain entry that isn't a byte string")
	}
}

func TestVerifyRejectsMalformedProtectedHeaderBytes(t *testing.T) {
	raw, err := encMode.Marshal(rawSign1{
		Protected:   []byte("not a cbor map"),
		Unprotected: map[int]interface{}{},
		Payload:     []byte("x"),
		Signature:   []byte("y"),
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, _, _, err := DecodeUnverified(raw); err == nil {
		t.Errorf("DecodeUnverified accepted malformed protected header bytes")
	}
}

// x5ChainRoundTripsThroughCBOR confirms Headers.toMap/headersFromMap
// agree with how the cbor library actually encodes/decodes the wire
// types they build (map[int]interface{}, []byte, []interface{}), rather
// than only ever being exercised against Go values we constructed by
// hand.
func TestX5ChainRoundTripsThroughCBOR(t *testing.T) {
	h := Headers{Alg: ES256, KID: []byte("k1"), X5Chain: [][]byte{[]byte("a"), []byte("b")}}
	raw, err := cbor.Marshal(h.toMap())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded map[int]interface{}
	if err := cbor.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	got, err := headersFromMap(decoded)
	if err != nil {
		t.Fatalf("headersFromMap: %v", err)
	}
	if got.Alg != h.Alg || string(got.KID) != string(h.KID) || len(got.X5Chain) != 2 {
		t.Errorf("round-tripped Headers = %+v, want %+v", got, h)
	}
}
