package sdjwtvc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// FuzzParse exercises Parse/Verify against arbitrary strings — an
// SD-JWT(+KB) presentation is Holder-supplied wire data, entirely
// attacker-controlled before its Issuer signature, digest matching, or
// any Key Binding JWT are checked. A value Parse accepts must also
// survive a Verify call without panicking, whether or not it actually
// verifies.
func FuzzParse(f *testing.F) {
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate issuer key: %v", err)
	}
	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate holder key: %v", err)
	}
	raw, err := holderKey.PublicKey.Bytes()
	if err != nil {
		f.Fatalf("encode holder public key: %v", err)
	}
	size := (len(raw) - 1) / 2
	holderJWK := map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": b64.EncodeToString(raw[1 : 1+size]),
		"y": b64.EncodeToString(raw[1+size:]),
	}

	sdjwt, _, err := Issue(issuerKey, jose.ES256, Claims{
		VCT: "https://credentials.example.com/identity_credential",
		Iss: "https://example.com/issuer",
		CNF: map[string]any{"jwk": holderJWK},
		Additional: map[string]any{
			"given_name":  "Alice",
			"family_name": SD("Doe"),
		},
	}, IssueOptions{})
	if err != nil {
		f.Fatalf("Issue: %v", err)
	}
	pres, err := Parse(sdjwt)
	if err != nil {
		f.Fatalf("Parse(sdjwt): %v", err)
	}
	bare, err := pres.Compact()
	if err != nil {
		f.Fatalf("Compact(bare): %v", err)
	}

	kbJWT, err := NewKeyBindingJWT(holderKey, jose.ES256, pres, SHA256, KeyBindingClaims{
		Audience: "https://example.com/verifier", Nonce: "fuzz-nonce",
	})
	if err != nil {
		f.Fatalf("NewKeyBindingJWT: %v", err)
	}
	pres.KeyBindingJWT = kbJWT
	withKB, err := pres.Compact()
	if err != nil {
		f.Fatalf("Compact(with kb): %v", err)
	}

	f.Add(bare)
	f.Add(withKB)
	f.Add("")
	f.Add("~")
	f.Add("a~b~")
	f.Add("a")
	f.Add(bare + "~extra")

	f.Fuzz(func(t *testing.T, s string) {
		if _, err := Parse(s); err != nil {
			return
		}
		_, _, _ = Verify(s, &issuerKey.PublicKey, jose.ES256, VerifyOptions{
			RequireKeyBinding: KeyBindingRequired, HolderPublicKey: &holderKey.PublicKey,
			KeyBindingAlg: jose.ES256, ExpectedAudience: "https://example.com/verifier",
			ExpectedNonce: "fuzz-nonce", MaxKeyBindingAge: time.Hour,
		})
	})
}

// FuzzParseDisclosure exercises ParseDisclosure against arbitrary
// strings — one Presentation-supplied "~"-separated segment,
// base64url-decoded and JSON-array-unmarshaled before its shape
// (object vs array-element, per RFC 9901 §4.2) is even determined.
func FuzzParseDisclosure(f *testing.F) {
	obj, err := NewObjectDisclosure("given_name", "Alice")
	if err != nil {
		f.Fatalf("NewObjectDisclosure: %v", err)
	}
	objEnc, err := obj.Encode()
	if err != nil {
		f.Fatalf("Encode(object): %v", err)
	}
	arr, err := NewArrayElementDisclosure("US")
	if err != nil {
		f.Fatalf("NewArrayElementDisclosure: %v", err)
	}
	arrEnc, err := arr.Encode()
	if err != nil {
		f.Fatalf("Encode(array): %v", err)
	}

	f.Add(objEnc)
	f.Add(arrEnc)
	f.Add("")
	f.Add("not-base64!!!")
	f.Add(b64.EncodeToString([]byte("null")))
	f.Add(b64.EncodeToString([]byte("[]")))
	f.Add(b64.EncodeToString([]byte(`["salt"]`)))
	f.Add(b64.EncodeToString([]byte(`["salt","name","value","extra"]`)))
	f.Add(b64.EncodeToString([]byte(`["salt","_sd","value"]`)))

	f.Fuzz(func(t *testing.T, s string) {
		_, _ = ParseDisclosure(s)
	})
}
