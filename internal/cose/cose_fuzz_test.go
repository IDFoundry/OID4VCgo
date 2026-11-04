package cose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// FuzzDecodeUnverified exercises DecodeUnverified/Verify against
// arbitrary bytes — an mdoc's own IssuerAuth (COSE_Sign1) is untrusted
// CBOR presented by a Wallet before any signature is checked, and
// DecodeUnverified is the entry point a caller uses to read its own
// x5chain/kid to resolve a verification key in the first place. A
// value DecodeUnverified accepts must also survive a Verify call
// without panicking, whether or not the signature actually checks out.
func FuzzDecodeUnverified(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}
	valid, err := Sign(ES256, key, Headers{KID: []byte("fuzz-kid")}, Headers{}, []byte(`{"hello":"world"}`), nil)
	if err != nil {
		f.Fatalf("sign: %v", err)
	}
	withX5Chain, err := Sign(ES256, key, Headers{}, Headers{X5Chain: [][]byte{[]byte("fuzz-cert")}}, []byte("hi"), nil)
	if err != nil {
		f.Fatalf("sign with x5chain: %v", err)
	}

	f.Add(valid)
	f.Add(withX5Chain)
	f.Add([]byte{})
	f.Add([]byte{0x84})
	f.Add([]byte{0xa0})
	f.Add(append([]byte{0x00}, valid...))
	f.Add(valid[:len(valid)-1])
	// Tags in front of the array: its own (18), once and twice,
	// COSE_Mac0's (17) and the CWT tag (61).
	f.Add(append([]byte{0xd2}, valid...))
	f.Add(append([]byte{0xd2, 0xd2}, valid...))
	f.Add(append([]byte{0xd1}, valid...))
	f.Add(append([]byte{0xd8, 0x3d}, valid...))
	protectedX5Chain, err := Sign(ES256, key, Headers{X5Chain: [][]byte{[]byte("fuzz-cert")}}, Headers{}, []byte("hi"), nil)
	if err != nil {
		f.Fatalf("sign with a protected x5chain: %v", err)
	}
	f.Add(protectedX5Chain)

	f.Fuzz(func(t *testing.T, data []byte) {
		protected, unprotected, _, err := DecodeUnverified(data)
		if err != nil {
			return
		}
		// Only a COSE_Sign1 array, untagged or with its own tag 18, is
		// accepted: never one behind another tag.
		body := data
		if len(body) > 0 && body[0] == 0xd2 {
			body = body[1:]
		}
		if len(body) == 0 || body[0]>>5 != 4 {
			t.Fatalf("DecodeUnverified accepted %x, which isn't a COSE_Sign1 array, untagged or tagged 18", data[:min(len(data), 8)])
		}
		_ = X5ChainOf(protected, unprotected)
		_, _, _, _ = Verify(ES256, &key.PublicKey, data, nil)
	})
}

// FuzzVerifyDetached exercises VerifyDetached against arbitrary
// bytes — the COSE_Sign1 variant mdoc's own DeviceSigned uses for its
// device signature (the payload is carried separately, in
// SessionTranscript/DeviceAuthentication, not embedded in the
// COSE_Sign1 structure itself), a distinct wire-decoding path from
// FuzzDecodeUnverified's embedded-payload form.
func FuzzVerifyDetached(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}
	valid, err := SignDetached(ES256, key, Headers{}, Headers{}, []byte("detached-payload"), nil)
	if err != nil {
		f.Fatalf("sign detached: %v", err)
	}

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		f.Fatalf("generate P-384 key: %v", err)
	}
	valid384, err := SignDetached(ES384, p384, Headers{}, Headers{}, []byte("detached-payload"), nil)
	if err != nil {
		f.Fatalf("sign detached ES384: %v", err)
	}

	f.Add(valid)
	f.Add(valid384)
	f.Add([]byte{})
	f.Add([]byte{0x84})
	f.Add(valid[:len(valid)-1])
	f.Add(valid384[:len(valid384)-1])

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = VerifyDetached(ES256, &key.PublicKey, data, []byte("detached-payload"), nil)
		_, _, _ = VerifyDetached(ES384, &p384.PublicKey, data, []byte("detached-payload"), nil)
	})
}

// FuzzDecodeUnverifiedTagged exercises DecodeUnverifiedTagged/VerifyTagged
// against arbitrary bytes — same attacker model as
// FuzzDecodeUnverified, for the CBOR-tagged (18) COSE_Sign1 encoding
// mdoc's own DeviceSigned uses instead of the untagged form.
func FuzzDecodeUnverifiedTagged(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}
	tagged, err := SignTagged(ES256, key, Headers{}, Headers{}, []byte("hi"), nil)
	if err != nil {
		f.Fatalf("sign tagged: %v", err)
	}
	untagged, err := Sign(ES256, key, Headers{}, Headers{}, []byte("hi"), nil)
	if err != nil {
		f.Fatalf("sign untagged: %v", err)
	}

	f.Add(tagged)
	f.Add(untagged)
	f.Add([]byte{})
	f.Add([]byte{0xd2, 0x84})
	f.Add(tagged[:len(tagged)-1])

	f.Fuzz(func(t *testing.T, data []byte) {
		if _, _, _, err := DecodeUnverifiedTagged(data); err != nil {
			return
		}
		_, _, _, _ = VerifyTagged(ES256, &key.PublicKey, data, nil)
	})
}
