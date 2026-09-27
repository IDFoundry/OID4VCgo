package issuer_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/issuer"
)

func TestParseCredentialRequest_Plain(t *testing.T) {
	iss, _ := newEncryptionIssuer(t, nil)
	walletJWK := testWalletJWK(t)
	body, err := json.Marshal(map[string]any{
		"credential_configuration_id": "pid",
		"proofs":                      map[string][]string{"jwt": {"a.b.c"}},
		"credential_response_encryption": map[string]any{
			"jwk": json.RawMessage(walletJWK), "enc": "A256GCM", "zip": "DEF",
		},
		"unrecognized": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := iss.ParseCredentialRequest(body, "application/json")
	if err != nil {
		t.Fatalf("ParseCredentialRequest: %v", err)
	}
	want := issuer.CredentialRequest{
		CredentialConfigurationID: "pid",
		Proofs:                    map[string][]string{"jwt": {"a.b.c"}},
		ResponseEncryption:        &issuer.ResponseEncryptionRequest{JWK: walletJWK, Enc: jwe.A256GCM, Zip: jwe.DEF},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseCredentialRequest = %+v, want %+v", got, want)
	}
}

// TestParseCredentialRequest_Encrypted checks a JWE request is decrypted
// and marked RequestWasEncrypted — what RequestCredential needs to
// allow credential_response_encryption (§8.2).
func TestParseCredentialRequest_Encrypted(t *testing.T) {
	iss, key := newEncryptionIssuer(t, nil)
	compact, err := jwe.Encrypt(&key.PrivateKey.PublicKey, jwe.A128GCM, []byte(`{"credential_identifier":"pid-1"}`), jwe.EncryptOptions{KeyID: key.KeyID})
	if err != nil {
		t.Fatalf("jwe.Encrypt: %v", err)
	}
	got, err := iss.ParseCredentialRequest([]byte(compact), "application/jwt")
	if err != nil {
		t.Fatalf("ParseCredentialRequest: %v", err)
	}
	if got.CredentialIdentifier != "pid-1" || !got.RequestWasEncrypted {
		t.Errorf("ParseCredentialRequest = %+v, want pid-1 and RequestWasEncrypted", got)
	}
}

func TestParseCredentialRequest_Rejects(t *testing.T) {
	iss, _ := newEncryptionIssuer(t, nil)
	for name, tc := range map[string]struct {
		body        string
		contentType string
	}{
		"not JSON":          {`nope`, "application/json"},
		"a JSON array":      {`[]`, "application/json"},
		"a JSON string":     {`"x"`, "application/json"},
		"oversized":         {`{"x":"` + strings.Repeat("a", issuer.MaxCredentialRequestBytes) + `"}`, "application/json"},
		"undecryptable JWE": {`a.b.c.d.e`, "application/jwt"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := iss.ParseCredentialRequest([]byte(tc.body), tc.contentType)
			var ierr *issuer.Error
			if !errors.As(err, &ierr) {
				t.Fatalf("error = %v, want an *issuer.Error", err)
			}
		})
	}
}
