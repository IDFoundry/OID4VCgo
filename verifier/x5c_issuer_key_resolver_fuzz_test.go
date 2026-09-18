package verifier_test

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/idfoundry/oid4vcgo/verifier"
)

// FuzzResolveIssuerKey exercises X5CIssuerKeyResolver.ResolveIssuerKey
// against arbitrary JSON — the "x5c" header member it reads is
// attacker-controlled (any part of a presented SD-JWT VC's own JOSE
// header), and x5cCertificates' own base64/DER parsing runs on it
// before any chain validation. Only checks for panics/hangs — the
// resolver almost never has a trusted root to validate against for
// fuzzer-generated certificates, so there's no useful oracle beyond
// "never crashes, never loops".
func FuzzResolveIssuerKey(f *testing.F) {
	resolver := verifier.X5CIssuerKeyResolver{Roots: x509.NewCertPool()}

	validX5C, err := json.Marshal(map[string]any{
		"x5c": []string{base64.StdEncoding.EncodeToString([]byte("not-a-real-certificate"))},
	})
	if err != nil {
		f.Fatalf("marshal valid-shaped header: %v", err)
	}

	f.Add(validX5C)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"x5c":[]}`))
	f.Add([]byte(`{"x5c":"not-an-array"}`))
	f.Add([]byte(`{"x5c":[1,2,3]}`))
	f.Add([]byte(`{"x5c":["not base64!!!"]}`))
	f.Add([]byte(`not json`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var header map[string]any
		if err := json.Unmarshal(data, &header); err != nil {
			return
		}
		_, _, _ = resolver.ResolveIssuerKey(context.Background(), header, nil)
	})
}
