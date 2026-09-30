package wallet_test

import (
	"encoding/json"
	"slices"
	"testing"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// FuzzDecodeMetadata exercises oid4vci.DecodeMetadata on Credential
// Issuer Metadata — which any server a Wallet is pointed at can serve —
// and EncryptionFromMetadata on the result, checking what it chooses
// is something the Issuer offered and the Wallet can use.
func FuzzDecodeMetadata(f *testing.F) {
	f.Add([]byte(`{"credential_issuer":"https://issuer.example","credential_endpoint":"https://issuer.example/credential",` +
		`"credential_configurations_supported":{"pid":{"format":"dc+sd-jwt","vct":"urn:pid"}},` +
		`"credential_request_encryption":{"jwks":{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","use":"enc"}]},"enc_values_supported":["A256GCM","A128GCM"]},` +
		`"credential_response_encryption":{"alg_values_supported":["ECDH-ES"],"enc_values_supported":["A128GCM"]}}`))
	f.Add([]byte(`{"credential_issuer":"https://issuer.example","credential_endpoint":"https://issuer.example/credential","credential_configurations_supported":{}}`))
	f.Add([]byte(`{"credential_response_encryption":{"alg_values_supported":[],"enc_values_supported":[]}}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		meta, err := oid4vci.DecodeMetadata(data)
		if err != nil {
			return
		}
		req, resp, err := wallet.EncryptionFromMetadata(meta)
		if err != nil || req == nil {
			if resp != nil {
				t.Errorf("response encryption chosen without request encryption")
			}
			return
		}
		if !slices.Contains(meta.CredentialRequestEncryption.EncValuesSupported, req.Enc) {
			t.Errorf("request enc %q wasn't offered", req.Enc)
		}
		var key jwk.JWK
		if err := json.Unmarshal(req.RecipientJWK, &key); err != nil {
			t.Fatalf("chosen key isn't a JWK: %v", err)
		}
		if _, err := key.PublicKey(); err != nil || key.Kty != "EC" || key.Crv != "P-256" {
			t.Errorf("chosen key %s isn't a usable P-256 key: %v", req.RecipientJWK, err)
		}
		if resp != nil && (meta.CredentialResponseEncryption == nil || !slices.Contains(meta.CredentialResponseEncryption.EncValuesSupported, resp.Enc) ||
			!slices.Contains(meta.CredentialResponseEncryption.AlgValuesSupported, jwe.ECDHES)) {
			t.Errorf("response encryption %+v wasn't offered", resp)
		}
	})
}
