package issuer_test

import (
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/issuer"
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

// FuzzParseDeferredCredentialRequest is FuzzParseCredentialRequest's
// counterpart for the Deferred Credential Endpoint (§9.1), whose body
// anyone holding an access token can send. It also checks
// RequestWasEncrypted reports how the body actually arrived.
func FuzzParseDeferredCredentialRequest(f *testing.F) {
	iss, key := newEncryptionIssuer(f, nil)

	f.Add([]byte(`{"transaction_id":"txn-1"}`), false)
	f.Add([]byte(`{"transaction_id":"txn-1","credential_response_encryption":{"jwk":{},"enc":"A128GCM"}}`), true)
	f.Add([]byte(`{"transaction_id":7}`), false)
	f.Add([]byte(`null`), false)

	f.Fuzz(func(t *testing.T, body []byte, encrypt bool) {
		contentType := "application/json"
		if encrypt {
			compact, err := jwe.Encrypt(&key.PrivateKey.PublicKey, jwe.A128GCM, body, jwe.EncryptOptions{KeyID: key.KeyID})
			if err != nil {
				return
			}
			body, contentType = []byte(compact), "application/jwt"
		}
		req, err := iss.ParseDeferredCredentialRequest(body, contentType)
		if err == nil && req.RequestWasEncrypted != encrypt {
			t.Errorf("RequestWasEncrypted = %v for a request sent encrypted=%v", req.RequestWasEncrypted, encrypt)
		}
	})
}

// FuzzParseNotificationRequest exercises ParseNotificationRequest, which
// reads a Notification Endpoint's request body (§11.1).
func FuzzParseNotificationRequest(f *testing.F) {
	f.Add([]byte(`{"notification_id":"n-1","event":"credential_accepted","event_description":"stored"}`))
	f.Add([]byte(`{"notification_id":["n"],"event":1}`))
	f.Add([]byte(`"x"`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = issuer.ParseNotificationRequest(body)
	})
}
