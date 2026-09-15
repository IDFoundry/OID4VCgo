package cose

import (
	"testing"
)

func TestComputeVerifyMACRoundTrip(t *testing.T) {
	key := []byte("a shared 32-byte HMAC key!!!!!!")
	payload := []byte(`{"a":1}`)

	mac0, err := ComputeMAC(key, Headers{KID: []byte("k1")}, Headers{}, payload, nil)
	if err != nil {
		t.Fatalf("ComputeMAC: %v", err)
	}

	protected, _, err := VerifyMAC(key, mac0, payload, nil)
	if err != nil {
		t.Fatalf("VerifyMAC: %v", err)
	}
	if protected.Alg != HMAC256 {
		t.Errorf("protected.Alg = %d, want %d", protected.Alg, HMAC256)
	}
	if string(protected.KID) != "k1" {
		t.Errorf("protected.KID = %q, want k1", protected.KID)
	}
}

func TestVerifyMACRejectsWrongPayload(t *testing.T) {
	key := []byte("a shared 32-byte HMAC key!!!!!!")
	mac0, err := ComputeMAC(key, Headers{}, Headers{}, []byte(`{"a":1}`), nil)
	if err != nil {
		t.Fatalf("ComputeMAC: %v", err)
	}
	if _, _, err := VerifyMAC(key, mac0, []byte(`{"a":2}`), nil); err == nil {
		t.Errorf("VerifyMAC accepted the wrong payload")
	}
}

func TestVerifyMACRejectsWrongKey(t *testing.T) {
	key1 := []byte("a shared 32-byte HMAC key!!!!!!")
	key2 := []byte("a different 32-byte HMAC key!!!")
	mac0, err := ComputeMAC(key1, Headers{}, Headers{}, []byte(`{"a":1}`), nil)
	if err != nil {
		t.Fatalf("ComputeMAC: %v", err)
	}
	if _, _, err := VerifyMAC(key2, mac0, []byte(`{"a":1}`), nil); err == nil {
		t.Errorf("VerifyMAC accepted the wrong key")
	}
}

func TestVerifyMACRejectsTamperedTag(t *testing.T) {
	key := []byte("a shared 32-byte HMAC key!!!!!!")
	mac0, err := ComputeMAC(key, Headers{}, Headers{}, []byte(`{"a":1}`), nil)
	if err != nil {
		t.Fatalf("ComputeMAC: %v", err)
	}
	tampered := make([]byte, len(mac0))
	copy(tampered, mac0)
	tampered[len(tampered)-1] ^= 0xFF
	if _, _, err := VerifyMAC(key, tampered, []byte(`{"a":1}`), nil); err == nil {
		t.Errorf("VerifyMAC accepted a tampered tag")
	}
}

func TestComputeMACRejectsNilPayload(t *testing.T) {
	key := []byte("a shared 32-byte HMAC key!!!!!!")
	if _, err := ComputeMAC(key, Headers{}, Headers{}, nil, nil); err == nil {
		t.Errorf("ComputeMAC accepted a nil payload")
	}
}

func TestVerifyMACRejectsMalformedInput(t *testing.T) {
	key := []byte("a shared 32-byte HMAC key!!!!!!")
	if _, _, err := VerifyMAC(key, []byte("not cbor"), []byte("x"), nil); err == nil {
		t.Errorf("VerifyMAC accepted malformed input")
	}
}

func TestVerifyMACRejectsEmbeddedPayload(t *testing.T) {
	key := []byte("a shared 32-byte HMAC key!!!!!!")
	raw, err := encMode.Marshal(rawMac0{
		Protected:   mustProtectedHMAC(t),
		Unprotected: map[int]interface{}{},
		Payload:     []byte("embedded"),
		Tag:         []byte("x"),
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, _, err := VerifyMAC(key, raw, []byte("embedded"), nil); err == nil {
		t.Errorf("VerifyMAC accepted a COSE_Mac0 with an embedded payload")
	}
}

func TestVerifyMACRejectsWrongAlg(t *testing.T) {
	key := []byte("a shared 32-byte HMAC key!!!!!!")
	raw, err := encMode.Marshal(rawMac0{
		Protected:   mustProtectedAlg(t, ES256),
		Unprotected: map[int]interface{}{},
		Payload:     nil,
		Tag:         []byte("x"),
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, _, err := VerifyMAC(key, raw, []byte("x"), nil); err == nil {
		t.Errorf("VerifyMAC accepted the wrong protected alg")
	}
}

func mustProtectedHMAC(t *testing.T) []byte {
	t.Helper()
	return mustProtectedAlg(t, HMAC256)
}

func mustProtectedAlg(t *testing.T, alg Alg) []byte {
	t.Helper()
	b, err := encMode.Marshal(map[int]interface{}{labelAlg: int64(alg)})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return b
}
