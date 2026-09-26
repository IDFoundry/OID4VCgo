package statuslist

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// FuzzCheckSigned exercises Check/CheckCWT's post-signature path —
// base64url/ZLIB decoding of "lst" (including maxDecompressedSize's
// decompression-bomb bound) and the bit-packed index lookup — which
// FuzzVerifyToken/FuzzVerifyTokenCWT can't reach: a mutated token
// there almost never carries a valid signature. Here the fuzzer
// controls the raw compressed "lst" bytes, bits and index, and the
// harness signs the result itself, modelling a malicious or
// compromised status list issuer whose key the caller trusts.
func FuzzCheckSigned(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}
	const sub = "https://example.com/statuslists/1"

	for _, bits := range []Bits{Bits1, Bits2, Bits8} {
		sl, err := New(bits, []uint8{0, 1, 1, 0, 1}, "")
		if err != nil {
			f.Fatalf("New(StatusList): %v", err)
		}
		lst, err := base64.RawURLEncoding.DecodeString(sl.Lst)
		if err != nil {
			f.Fatalf("decode lst: %v", err)
		}
		f.Add(uint8(bits), lst, 1, false)
		f.Add(uint8(bits), lst, 4, true)
	}
	f.Add(uint8(Bits1), []byte{}, 0, false)
	f.Add(uint8(3), []byte{0x78, 0x9c}, -1, true)

	f.Fuzz(func(t *testing.T, bits uint8, lst []byte, idx int, cwt bool) {
		claims := TokenClaims{
			Sub: sub, Iat: 1767225600,
			StatusList: StatusList{Bits: Bits(bits), Lst: base64.RawURLEncoding.EncodeToString(lst)},
		}
		ref := StatusListRef{Idx: idx, URI: sub}

		var status StatusType
		if cwt {
			token, err := IssueTokenCWT(key, cose.ES256, claims, nil)
			if err != nil {
				return
			}
			if status, _, err = CheckCWT(token, &key.PublicKey, cose.ES256, ref, VerifyOptions{}); err != nil {
				return
			}
		} else {
			token, err := IssueToken(key, jose.ES256, claims, "")
			if err != nil {
				return
			}
			if status, _, err = Check(token, &key.PublicKey, jose.ES256, ref, VerifyOptions{}); err != nil {
				return
			}
		}
		if uint(status) >= 1<<uint(bits) {
			t.Fatalf("status %d does not fit in %d bits", status, bits)
		}
	})
}
