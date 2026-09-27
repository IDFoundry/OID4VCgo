package issuer_test

import (
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jwe"
)

// FuzzParseCredentialRequest exercises ParseCredentialRequest, which
// reads a Credential Endpoint's request body — anyone can send one. With
// encrypt set, the harness encrypts the fuzzed body to the issuer's own
// request key, so mutations reach the JSON parsing behind a successful
// decryption rather than stopping at the JWE layer (which
// internal/jwe's FuzzDecrypt covers).
func FuzzParseCredentialRequest(f *testing.F) {
	iss, key := newEncryptionIssuer(f, nil)

	f.Add([]byte(`{"credential_configuration_id":"pid","proofs":{"jwt":["a.b.c"]}}`), false)
	f.Add([]byte(`{"credential_identifier":"pid-1","credential_response_encryption":{"jwk":{},"enc":"A128GCM","zip":"DEF"}}`), true)
	f.Add([]byte(`[]`), false)
	f.Add([]byte(`a.b.c.d.e`), false)
	f.Add([]byte(``), true)

	f.Fuzz(func(t *testing.T, body []byte, encrypt bool) {
		contentType := "application/json"
		if encrypt {
			compact, err := jwe.Encrypt(&key.PrivateKey.PublicKey, jwe.A128GCM, body, jwe.EncryptOptions{KeyID: key.KeyID})
			if err != nil {
				return
			}
			body, contentType = []byte(compact), "application/jwt"
		}
		_, _ = iss.ParseCredentialRequest(body, contentType)
	})
}
