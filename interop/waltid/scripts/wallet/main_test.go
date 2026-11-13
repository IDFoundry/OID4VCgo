package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

func TestRecorderRefusesAnOversizedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, maxRecordedBody+1))
	}))
	defer srv.Close()
	client := &http.Client{Transport: recorder{next: http.DefaultTransport, seen: &observed{}}}
	res, err := client.Get(srv.URL)
	if err == nil {
		_ = res.Body.Close()
		t.Fatal("a body past maxRecordedBody was handed on, cut short")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("err = %v", err)
	}
}

// presentation is an SD-JWT VC with one disclosure and a Key Binding
// JWT by a key of keys.
func presentation(t *testing.T, keys *keyring) string {
	t.Helper()
	ctx := context.Background()
	holder, err := keys.NewKey(ctx, walletflow.KeyPurposeHolder)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cnf, err := jwk.Marshal(holder.Public())
	if err != nil {
		t.Fatal(err)
	}
	disclosure := base64.RawURLEncoding.EncodeToString([]byte(`["salt","birthdate","1990-01-01"]`))
	digest := sha256.Sum256([]byte(disclosure))
	claims, _ := json.Marshal(map[string]any{"_sd": []string{base64.RawURLEncoding.EncodeToString(digest[:])}, "cnf": map[string]any{"jwk": cnf}})
	issued, err := jose.Sign(jose.ES256, issuer, map[string]any{"typ": "dc+sd-jwt"}, claims)
	if err != nil {
		t.Fatal(err)
	}
	sdJWT := issued + "~" + disclosure + "~"
	sum := sha256.Sum256([]byte(sdJWT))
	kb, _ := json.Marshal(map[string]any{"nonce": "n", "aud": "x509_hash:abc", "iat": 1, "sd_hash": base64.RawURLEncoding.EncodeToString(sum[:])})
	signed, err := jose.Sign(jose.ES256, holder, map[string]any{"typ": "kb+jwt"}, kb)
	if err != nil {
		t.Fatal(err)
	}
	return sdJWT + signed
}

func TestTamperChange(t *testing.T) {
	for _, mode := range tamperModes {
		t.Run(mode, func(t *testing.T) {
			keys := &keyring{KeyStore: walletflow.NewMemoryKeyStore()}
			original := presentation(t, keys)
			tr := &tamperer{mode: mode, keys: keys}
			changed, what, err := tr.change(original)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "relay" {
				if changed != original || what != "nothing" {
					t.Errorf("relay changed it: %q", what)
				}
				return
			}
			parts := strings.Split(changed, "~")
			holder, err := keys.holderOf(parts[0])
			if err != nil {
				t.Fatal(err)
			}
			// The Key Binding JWT verifies under the holder's key, and
			// its sd_hash is over the presentation as changed.
			_, payload, err := jose.Verify(jose.ES256, holder.Public(), parts[len(parts)-1])
			if err != nil {
				t.Fatalf("the KB-JWT doesn't verify: %v", err)
			}
			var kb map[string]any
			if err := json.Unmarshal(payload, &kb); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256([]byte(strings.TrimSuffix(changed, parts[len(parts)-1])))
			if kb["sd_hash"] != base64.RawURLEncoding.EncodeToString(sum[:]) {
				t.Error("sd_hash isn't over the changed presentation")
			}
			changedOnly := map[string]bool{
				"nonce":      kb["nonce"] != "n",
				"aud":        kb["aud"] != "x509_hash:abc",
				"disclosure": parts[1] != strings.Split(original, "~")[1],
				"issuer":     parts[0] != strings.Split(original, "~")[0],
			}
			for m, differs := range changedOnly {
				if differs != (m == mode) {
					t.Errorf("%s: %s differs = %v (%s)", mode, m, differs, what)
				}
			}
		})
	}
}
