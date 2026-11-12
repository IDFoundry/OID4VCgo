package verifier_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/internal/testjose"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// An SD-JWT VC presentation verifies with its Issuer-signed JWT signed
// ES384 or ES512 by an x5c certificate on P-384 or P-521, and its Key
// Binding JWT signed ES384 or ES512 by a cnf key on those curves
// (HAIP 1.0 §7 makes ES256 a minimum); an alg its key doesn't take
// fails it, whichever of the two JWTs carries it.
func TestVerifyResponse_SDJWTVCES384ES512(t *testing.T) {
	ca, caKey := testcert.CA(t, "sd-jwt vc alg test CA")
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	gen := func(c elliptic.Curve) *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	p256, p384, p521 := gen(elliptic.P256()), gen(elliptic.P384()), gen(elliptic.P521())

	for name, tc := range map[string]struct {
		issuerAlg string
		issuer    *ecdsa.PrivateKey
		kbAlg     string
		holder    *ecdsa.PrivateKey
		want      string // empty: verifies
	}{
		"ES384 issuer, ES384 holder":        {"ES384", p384, "ES384", p384, ""},
		"ES512 issuer, ES512 holder":        {"ES512", p521, "ES512", p521, ""},
		"ES256 issuer, ES512 holder":        {"ES256", p256, "ES512", p521, ""},
		"ES512 issuer, ES256 holder":        {"ES512", p521, "ES256", p256, ""},
		"ES512 issuer header, P-384 cert":   {"ES512", p384, "ES256", p256, `verify issuer JWT: jose: header alg "ES512" does not match expected "ES384"`},
		"ES256 issuer header, P-521 cert":   {"ES256", p521, "ES256", p256, `verify issuer JWT: jose: header alg "ES256" does not match expected "ES512"`},
		"ES512 KB-JWT, P-384 cnf key":       {"ES384", p384, "ES512", p384, `key binding JWT signature: jose: header alg "ES512" does not match expected "ES384"`},
		"ES384 KB-JWT, P-256 cnf key":       {"ES384", p384, "ES384", p256, `key binding JWT signature: jose: header alg "ES384" does not match expected "ES256"`},
		"ES256 KB-JWT, P-521 cnf key":       {"ES384", p384, "ES256", p521, `key binding JWT signature: jose: header alg "ES256" does not match expected "ES512"`},
		"ES384 KB-JWT by another P-384 key": {"ES384", p384, "ES384", nil, "key binding JWT signature: jose: ES384 signature verification failed"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, v := newTestVerifierWithConfig(t)
			holder, kbSigner := tc.holder, tc.holder
			if holder == nil {
				holder, kbSigner = p384, gen(elliptic.P384())
			}
			holderJWK, err := jwk.Marshal(&holder.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			// Issued under a throwaway ES256 key, then signed again as the
			// issuer under test.
			cred, _, err := sdjwtvc.Issue(testP256Key(t), jose.ES256, sdjwtvc.Claims{
				VCT: testVCT, CNF: map[string]any{"jwk": holderJWK},
				Additional: map[string]any{"given_name": sdjwtvc.SD("Jean")},
			}, sdjwtvc.IssueOptions{})
			if err != nil {
				t.Fatal(err)
			}
			issuerJWT, rest, _ := strings.Cut(cred, "~")
			header, payload, err := jose.DecodeUnverified(issuerJWT)
			if err != nil {
				t.Fatal(err)
			}
			leaf := testcert.LeafFor(t, "issuer "+name, &tc.issuer.PublicKey, ca, caKey)
			header["x5c"] = []string{base64.StdEncoding.EncodeToString(leaf.Raw)}
			sdjwt := testjose.Sign(t, tc.issuerAlg, tc.issuer, header, payload) + "~" + rest

			nonce := "nonce-" + tc.kbAlg
			sdHash := sha256.Sum256([]byte(sdjwt))
			kbClaims, err := json.Marshal(map[string]any{
				"aud": v.ClientID(), "nonce": nonce, "iat": time.Now().Unix(),
				"sd_hash": base64.RawURLEncoding.EncodeToString(sdHash[:]),
			})
			if err != nil {
				t.Fatal(err)
			}
			presented := sdjwt + testjose.Sign(t, tc.kbAlg, kbSigner, map[string]any{"typ": sdjwtvc.KeyBindingTyp}, kbClaims)

			result, err := v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
				Query:         testIdentityQuery(t),
				Response:      verifier.ParsedResponse{VPToken: map[string][]string{"identity_credential": {presented}}},
				ExpectedNonce: nonce, MaxKeyBindingAge: time.Hour, AllowUnrequestedClaims: true,
				IssuerKeys: verifier.X5CIssuerKeyResolver{Roots: roots, Revocation: certrevocation.NoCheck{}},
			})
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("VerifyResponse = %v, want an error containing %q", err, tc.want)
				}
				return
			}
			if err != nil {
				t.Fatalf("VerifyResponse: %v", err)
			}
			if len(result.Credentials) != 1 || result.Credentials[0].Claims["given_name"] != "Jean" {
				t.Fatalf("Credentials = %+v", result.Credentials)
			}
		})
	}
}
