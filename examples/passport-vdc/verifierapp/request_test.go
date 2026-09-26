package verifierapp_test

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demotest"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/verifierapp"
)

// fetchRequestObject GETs the Request Object a request link points at.
func fetchRequestObject(t *testing.T, env *demotest.Env, link string) (requestURI, requestObject string) {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatalf("parse link: %v", err)
	}
	requestURI = u.Query().Get("request_uri")
	resp, err := env.HTTP.Get(requestURI)
	if err != nil {
		t.Fatalf("GET request_uri: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET request_uri: status %d, %v", resp.StatusCode, err)
	}
	return requestURI, string(body)
}

func decodeSegment(t *testing.T, compact string, i int, v any) {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(compact, ".")[i])
	if err != nil {
		t.Fatalf("decode segment %d: %v", i, err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("unmarshal segment %d: %v", i, err)
	}
}

// TestRequest_ResultIsNotReachableFromTheLink checks what a wallet (or
// anyone who sees the link) learns — the request_uri and the Request
// Object's state — doesn't open the result page (OpenID4VP §14.3.3).
func TestRequest_ResultIsNotReachableFromTheLink(t *testing.T) {
	env := demotest.New(t, nil)
	env.StartVerifier(t, nil)
	id, link, err := env.Verifier.CreateRequest(verifierapp.ModeIssuer)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	requestURI, requestObject := fetchRequestObject(t, env, link)
	var claims struct {
		State string `json:"state"`
	}
	decodeSegment(t, requestObject, 1, &claims)

	if strings.Contains(link, id) || claims.State == id {
		t.Fatal("the request link or state carries the result ID")
	}
	for _, guess := range []string{claims.State, requestURI[strings.LastIndex(requestURI, "/")+1:]} {
		resp, err := env.HTTP.Get(env.VerifierURL + "/requests/" + guess)
		if err != nil {
			t.Fatalf("GET result page: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("result page for %q: status %d, want 404", guess, resp.StatusCode)
		}
	}
	resp, err := env.HTTP.Get(env.VerifierURL + "/requests/" + id)
	if err != nil {
		t.Fatalf("GET result page: %v", err)
	}
	page, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("own result page: status %d, Cache-Control %q, %v", resp.StatusCode, resp.Header.Get("Cache-Control"), err)
	}
	if !strings.Contains(string(page), `src="data:image/png;base64,`) {
		t.Error("the waiting page has no QR code of the request")
	}
}

// TestRequest_SignedWithCAIssuedCertificate checks the Request Object's
// x5c leaf isn't self-signed (HAIP 1.0 §5).
func TestRequest_SignedWithCAIssuedCertificate(t *testing.T) {
	env := demotest.New(t, nil)
	env.StartVerifier(t, nil)
	_, link, err := env.Verifier.CreateRequest(verifierapp.ModeIssuer)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	_, requestObject := fetchRequestObject(t, env, link)
	var header struct {
		X5C []string `json:"x5c"`
	}
	decodeSegment(t, requestObject, 0, &header)
	if len(header.X5C) != 1 {
		t.Fatalf("x5c has %d certificates, want the leaf only", len(header.X5C))
	}
	der, err := base64.StdEncoding.DecodeString(header.X5C[0])
	if err != nil {
		t.Fatalf("decode x5c: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse x5c: %v", err)
	}
	if cert.CheckSignatureFrom(cert) == nil {
		t.Error("the request-signing certificate is self-signed")
	}
}

// TestResponse_ForgedResponseDoesNotCloseTheRequest posts a response
// that doesn't verify, routed by the Request Object's own (public) key
// ID: it's rejected without closing the request, and the real wallet's
// answer is still accepted afterwards.
func TestResponse_ForgedResponseDoesNotCloseTheRequest(t *testing.T) {
	env := demotest.New(t, nil)
	env.StartVerifier(t, nil)
	store := receiveInto(t, env, demotest.SyntheticEvidence())
	id, link, err := env.Verifier.CreateRequest(verifierapp.ModeIssuer)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	_, requestObject := fetchRequestObject(t, env, link)
	var claims struct {
		ClientMetadata struct {
			JWKS struct {
				Keys []struct {
					Kid string `json:"kid"`
				} `json:"keys"`
			} `json:"jwks"`
		} `json:"client_metadata"`
	}
	decodeSegment(t, requestObject, 1, &claims)
	header, err := json.Marshal(map[string]string{"alg": "ECDH-ES", "enc": "A128GCM", "kid": claims.ClientMetadata.JWKS.Keys[0].Kid})
	if err != nil {
		t.Fatal(err)
	}
	forged := base64.RawURLEncoding.EncodeToString(header) + ".AAAA.AAAA.AAAA.AAAA"
	resp, err := env.HTTP.PostForm(env.VerifierURL+"/response", url.Values{"response": {forged}})
	if err != nil {
		t.Fatalf("POST forged response: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("forged response: status %d, want 400", resp.StatusCode)
	}
	if _, answered := env.Verifier.Outcome(id); answered || env.Verifier.LastError(id) == "" {
		t.Fatal("a forged response was recorded as the outcome, or its rejection wasn't noted")
	}

	presentTo(t, env, store, link, "dc+sd-jwt")
	if _, answered := env.Verifier.Outcome(id); !answered {
		t.Fatalf("the real presentation wasn't accepted after a forged one (last rejection: %q)", env.Verifier.LastError(id))
	}
}
