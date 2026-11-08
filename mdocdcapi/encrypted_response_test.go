package mdocdcapi

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// An EncryptedResponse holds exactly Annex C.3's members, untagged: a
// member it doesn't define, or a tag on the protocol, is refused
// before decryption, while the same response re-encoded verifies.
func TestVerifyResponseRefusesLooseEncryptedResponse(t *testing.T) {
	h := newHarness(t, bothNames())
	raw, err := base64.RawURLEncoding.DecodeString(respond(t, h.request.Data, testOrigin, h.f))
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		_        struct{} `cbor:",toarray"`
		Protocol string
		Data     map[string][]byte
	}
	if err := cbor.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	encode := func(protocol any, data map[any]any) string {
		return base64.RawURLEncoding.EncodeToString(mustCBOR(t, []any{protocol, data}))
	}
	members := func(extra ...any) map[any]any {
		m := map[any]any{"enc": wire.Data["enc"], "cipherText": wire.Data["cipherText"]}
		for i := 0; i < len(extra); i += 2 {
			m[extra[i]] = extra[i+1]
		}
		return m
	}

	if _, err := verify(t, h, encode("dcapi", members()), nil); err != nil {
		t.Fatalf("the response re-encoded: %v", err)
	}
	for name, response := range map[string]string{
		"an extra text member":    encode("dcapi", members("extra", 1)),
		"an extra integer member": encode("dcapi", members(1, []byte{0})),
		"a tagged protocol":       encode(cbor.Tag{Number: 100, Content: "dcapi"}, members()),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := verify(t, h, response, nil); err == nil || !strings.Contains(err.Error(), "decode EncryptedResponse") {
				t.Errorf("verify = %v, want the EncryptedResponse refused", err)
			}
		})
	}
}
