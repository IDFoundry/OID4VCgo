package proximity

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// An EReaderKey that isn't on one of cipher suite 1's ECDH curves — an
// Ed25519 COSE_Key, which decodes to a valid public key — is refused
// (§9.1.5.2), not handed to ECDH.
func TestDecodeCoseKey_RefusesNonECDHKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := cbor.Marshal(map[int]any{1: 1, -1: 6, -2: []byte(pub)}) // kty OKP, crv Ed25519, x
	if err != nil {
		t.Fatal(err)
	}
	_, err = decodeCoseKey(b)
	if err == nil || !strings.Contains(err.Error(), "cipher suite 1") {
		t.Errorf("decodeCoseKey(Ed25519) = %v, want a cipher suite 1 refusal", err)
	}
}
