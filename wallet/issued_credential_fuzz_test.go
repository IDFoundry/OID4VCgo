package wallet_test

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// FuzzVerifyIssuedCredential exercises VerifyIssuedCredential against
// arbitrary credentials of either format — what a Credential Issuer
// returns, before the Wallet has established anything about it. Seeded
// with genuine credentials of each format.
func FuzzVerifyIssuedCredential(f *testing.F) {
	fx := caIssuedFixture(f)
	f.Add(fx.sdjwt, false)
	f.Add(fx.mdocB, true)
	f.Add("", false)
	f.Add("a.b.c~", false)
	f.Add("oA", true)

	f.Fuzz(func(t *testing.T, credential string, mdocFormat bool) {
		conf := fx.sdjwtConf
		if mdocFormat {
			conf = fx.mdocConf
		}
		_, _ = wallet.VerifyIssuedCredential(context.Background(), wallet.VerifyIssuedCredentialParams{
			Configuration: conf, Credential: credential, HolderKey: &fx.holder.PublicKey,
			IssuerRoots: fx.roots, Now: fx.now,
		})
	})
}

// FuzzVerifyIssuedCredentialSigned reaches VerifyIssuedCredential's
// checks past the issuer signature — the vct and cnf.jwk holder binding
// — which a mutated credential almost never passes: the harness signs
// the fuzzed Issuer-signed JWT payload with a certificate the roots
// trust, as a (compromised or careless) trusted issuer could.
func FuzzVerifyIssuedCredentialSigned(f *testing.F) {
	ca, caKey := testcert.CA(f, "issued credential fuzz CA")
	leaf, leafKey := testcert.Leaf(f, "issued credential fuzz issuer", ca, caKey)
	fx := caIssuedFixture(f)
	fx.roots.AddCert(ca)
	header := map[string]any{"typ": sdjwtvc.TypHeader, "x5c": []string{base64.StdEncoding.EncodeToString(leaf.Raw)}}

	f.Add([]byte(`{"vct":"https://credentials.example.com/identity_credential","cnf":{"jwk":{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}}}`))
	f.Add([]byte(`{"vct":"https://credentials.example.com/identity_credential","cnf":{}}`))
	f.Add([]byte(`{"vct":1,"cnf":"x","exp":"soon"}`))
	f.Add([]byte(`{"_sd":["x"],"_sd_alg":"sha-256"}`))

	f.Fuzz(func(t *testing.T, payload []byte) {
		signed, err := jose.Sign(jose.ES256, leafKey, header, payload)
		if err != nil {
			return
		}
		_, _ = wallet.VerifyIssuedCredential(context.Background(), wallet.VerifyIssuedCredentialParams{
			Configuration: fx.sdjwtConf, Credential: signed + "~", HolderKey: &fx.holder.PublicKey,
			IssuerRoots: fx.roots, Now: fx.now,
		})
	})
}

// FuzzParseAuthorizationRequestLink exercises ParseAuthorizationRequestLink
// against arbitrary links — a QR code or deep link anyone can produce.
func FuzzParseAuthorizationRequestLink(f *testing.F) {
	f.Add("openid4vp://?client_id=x509_hash%3Aabc&request_uri=https%3A%2F%2Fverifier.example%2Fro%2F1")
	f.Add("https://wallet.example/present?client_id=c&request_uri=https%3A%2F%2Fv.example%2Fr&request_uri_method=post")
	f.Add("openid4vp://?client_id=c&request=eyJ.eyJ.sig")
	f.Add("%")
	f.Add("")

	f.Fuzz(func(t *testing.T, link string) {
		parsed, err := wallet.ParseAuthorizationRequestLink(link)
		if err != nil {
			return
		}
		if parsed.ClientID == "" || parsed.RequestURI == "" {
			t.Fatalf("accepted %q with an empty client_id or request_uri: %+v", link, parsed)
		}
		if parsed.RequestURIMethod != wallet.RequestURIMethodGet && parsed.RequestURIMethod != wallet.RequestURIMethodPost {
			t.Fatalf("accepted %q with request_uri_method %q", link, parsed.RequestURIMethod)
		}
	})
}

// fuzzReplyClient answers every request with one fixed reply.
type fuzzReplyClient struct {
	status      int
	contentType string
	body        []byte
}

func (c fuzzReplyClient) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: c.status, Request: req,
		Header: http.Header{"Content-Type": {c.contentType}},
		Body:   io.NopCloser(strings.NewReader(string(c.body))),
	}, nil
}

// FuzzSubmitDirectPostResponse exercises SubmitDirectPostResponse's
// handling of the Verifier's reply — status, Content-Type and body are
// all Verifier-controlled — and checks any redirect_uri it returns is
// an absolute https URL, and any rejection's text is sanitized.
func FuzzSubmitDirectPostResponse(f *testing.F) {
	f.Add(200, "application/json", []byte(`{"redirect_uri":"https://verifier.example/cb"}`))
	f.Add(200, "application/json", []byte(`{"redirect_uri":"http://verifier.example/cb"}`))
	f.Add(400, "application/json", []byte(`{"error":"invalid_request","error_description":"x\ny"}`))
	f.Add(302, "text/html", []byte(``))
	f.Add(200, "application/json; charset=utf-8", []byte(`{`))

	f.Fuzz(func(t *testing.T, status int, contentType string, body []byte) {
		if status < 100 || status > 999 {
			return
		}
		result, err := wallet.SubmitDirectPostResponse(context.Background(), fuzzReplyClient{status, contentType, body}, "https://verifier.example/response", "the-jwe")
		if err == nil && result.RedirectURI != "" && !strings.HasPrefix(result.RedirectURI, "https://") {
			t.Fatalf("returned non-https redirect_uri %q", result.RedirectURI)
		}
		if rejected, ok := err.(*wallet.DirectPostRejectedError); ok {
			for _, r := range rejected.Code + rejected.Description {
				if r < 0x20 || r == 0x7f {
					t.Fatalf("rejection text carries control character %U", r)
				}
			}
		}
	})
}
