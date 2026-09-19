package cose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestVerifyRejectsOversizedSign1(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sign1, err := Sign(ES256, key, Headers{}, Headers{}, make([]byte, MaxBytes), nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sign1) <= MaxBytes {
		t.Fatalf("sign1 is %d bytes, want > MaxBytes (%d)", len(sign1), MaxBytes)
	}

	if _, _, _, err := Verify(ES256, &key.PublicKey, sign1, nil); err == nil {
		t.Error("Verify = nil error, want error (oversized COSE_Sign1)")
	}
	if _, _, _, err := DecodeUnverified(sign1); err == nil {
		t.Error("DecodeUnverified = nil error, want error (oversized COSE_Sign1)")
	}

	// VerifyMax/DecodeUnverifiedMax with a raised ceiling accept the
	// same input Verify/DecodeUnverified reject.
	if _, _, _, err := VerifyMax(ES256, &key.PublicKey, sign1, nil, len(sign1)); err != nil {
		t.Errorf("VerifyMax with a raised ceiling: %v", err)
	}
	if _, _, _, err := DecodeUnverifiedMax(sign1, len(sign1)); err != nil {
		t.Errorf("DecodeUnverifiedMax with a raised ceiling: %v", err)
	}
}

func TestVerifyDetachedRejectsOversizedSign1(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	detachedPayload := []byte(`{"a":1}`)
	// SignDetached's own wire COSE_Sign1 never embeds detachedPayload
	// (that's the whole point of "detached") — an oversized protected
	// header (KID here) is what actually inflates the wire bytes
	// VerifyDetached/decodeRaw parses, not an oversized payload.
	sign1, err := SignDetached(ES256, key, Headers{KID: make([]byte, MaxBytes)}, Headers{}, detachedPayload, nil)
	if err != nil {
		t.Fatalf("SignDetached: %v", err)
	}
	if len(sign1) <= MaxBytes {
		t.Fatalf("sign1 is %d bytes, want > MaxBytes (%d)", len(sign1), MaxBytes)
	}

	if _, _, err := VerifyDetached(ES256, &key.PublicKey, sign1, detachedPayload, nil); err == nil {
		t.Error("VerifyDetached = nil error, want error (oversized COSE_Sign1)")
	}
	if _, _, err := VerifyDetachedMax(ES256, &key.PublicKey, sign1, detachedPayload, nil, len(sign1)); err != nil {
		t.Errorf("VerifyDetachedMax with a raised ceiling: %v", err)
	}
}

func TestVerifyTaggedRejectsOversizedSign1(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sign1, err := SignTagged(ES256, key, Headers{}, Headers{}, make([]byte, MaxBytes), nil)
	if err != nil {
		t.Fatalf("SignTagged: %v", err)
	}
	if len(sign1) <= MaxBytes {
		t.Fatalf("sign1 is %d bytes, want > MaxBytes (%d)", len(sign1), MaxBytes)
	}

	if _, _, _, err := VerifyTagged(ES256, &key.PublicKey, sign1, nil); err == nil {
		t.Error("VerifyTagged = nil error, want error (oversized COSE_Sign1_Tagged)")
	}
	if _, _, _, err := DecodeUnverifiedTagged(sign1); err == nil {
		t.Error("DecodeUnverifiedTagged = nil error, want error (oversized COSE_Sign1_Tagged)")
	}
	if _, _, _, err := VerifyTaggedMax(ES256, &key.PublicKey, sign1, nil, len(sign1)); err != nil {
		t.Errorf("VerifyTaggedMax with a raised ceiling: %v", err)
	}
	if _, _, _, err := DecodeUnverifiedTaggedMax(sign1, len(sign1)); err != nil {
		t.Errorf("DecodeUnverifiedTaggedMax with a raised ceiling: %v", err)
	}
}

func TestVerifyMACRejectsOversizedMac0(t *testing.T) {
	key := []byte("a shared 32-byte HMAC key!!!!!!")
	payload := []byte(`{"a":1}`)
	// ComputeMAC's own wire COSE_Mac0 never embeds payload (always
	// detached, per its own doc comment) — an oversized protected
	// header (KID here) is what actually inflates the wire bytes
	// VerifyMAC parses, not an oversized payload.
	mac0, err := ComputeMAC(key, Headers{KID: make([]byte, MaxBytes)}, Headers{}, payload, nil)
	if err != nil {
		t.Fatalf("ComputeMAC: %v", err)
	}
	if len(mac0) <= MaxBytes {
		t.Fatalf("mac0 is %d bytes, want > MaxBytes (%d)", len(mac0), MaxBytes)
	}

	if _, _, err := VerifyMAC(key, mac0, payload, nil); err == nil {
		t.Error("VerifyMAC = nil error, want error (oversized COSE_Mac0)")
	}
	if _, _, err := VerifyMACMax(key, mac0, payload, nil, len(mac0)); err != nil {
		t.Errorf("VerifyMACMax with a raised ceiling: %v", err)
	}
}
