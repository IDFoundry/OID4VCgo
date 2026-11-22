package wallet_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// requestFixture is a valid signed Request Object, its parts, and what
// signed it, for the vectors below to change one thing in.
type requestFixture struct {
	key      *ecdsa.PrivateKey
	cert     *x509.Certificate
	caKey    *ecdsa.PrivateKey
	caCert   *x509.Certificate
	trust    wallet.VerifierTrust
	clientID string
	header   map[string]any
	payload  map[string]any
	object   string
}

func newRequestFixture(t *testing.T) requestFixture {
	t.Helper()
	caKey, caCert := testCA(t, "request vectors CA")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := leafUnder(t, caCert, caKey, &key.PublicKey, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	v := newTestVerifierWith(t, key, cert)
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: testQuery(t)})
	if err != nil {
		t.Fatal(err)
	}
	header, raw, err := jose.DecodeUnverified(built.RequestObject)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	return requestFixture{key: key, cert: cert, caKey: caKey, caCert: caCert, trust: wallet.X5CVerifierRoots{Roots: roots},
		clientID: v.ClientID(), header: header, payload: payload, object: built.RequestObject}
}

func leafUnder(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, pub *ecdsa.PublicKey, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "request vectors verifier"},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
	}, ca, pub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// sign is the fixture's Request Object with header and payload changed
// by the given functions, signed by key.
func (f requestFixture) sign(t *testing.T, key *ecdsa.PrivateKey, header, payload func(map[string]any)) string {
	t.Helper()
	h, p := map[string]any{}, map[string]any{}
	for k, v := range f.header {
		h[k] = v
	}
	for k, v := range f.payload {
		p[k] = v
	}
	if header != nil {
		header(h)
	}
	if payload != nil {
		payload(p)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	object, err := jose.Sign(jose.ES256, key, h, raw)
	if err != nil {
		t.Fatal(err)
	}
	return object
}

func x5cOfCerts(certs ...*x509.Certificate) []any {
	out := make([]any, len(certs))
	for i, c := range certs {
		out[i] = base64.StdEncoding.EncodeToString(c.Raw)
	}
	return out
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// requestVector is a Request Object with one thing wrong, which the
// Wallet must refuse: with code, the RequestRejectedError it answers
// the Verifier with; with untrusted, ErrUntrustedVerifier; otherwise
// any error.
type requestVector struct {
	id, clause string
	code       string
	untrusted  bool
	object     func(t *testing.T, f requestFixture) string
	clientID   func(f requestFixture) string
}

var requestObjectVectors = []requestVector{
	{id: "typ-not-oauth-authz-req-jwt", clause: "OpenID4VP 1.0 §5.1, RFC 9101 §10.8 (typ)",
		object: func(t *testing.T, f requestFixture) string {
			return f.sign(t, f.key, func(h map[string]any) { h["typ"] = "JWT" }, nil)
		}},
	{id: "typ-missing", clause: "RFC 9101 §10.8 (typ)",
		object: func(t *testing.T, f requestFixture) string {
			return f.sign(t, f.key, func(h map[string]any) { delete(h, "typ") }, nil)
		}},
	{id: "alg-none", clause: "RFC 9101 §6.1 (signed), HAIP 1.0 §5",
		object: func(t *testing.T, f requestFixture) string {
			parts := strings.Split(f.object, ".")
			h, _ := json.Marshal(map[string]any{"alg": "none", "typ": f.header["typ"], "x5c": f.header["x5c"]})
			return b64(string(h)) + "." + parts[1] + "."
		}},
	{id: "alg-hs256-with-the-public-key", clause: "RFC 8725 §2.1 (algorithm confusion)",
		object: func(t *testing.T, f requestFixture) string {
			parts := strings.Split(f.object, ".")
			h, _ := json.Marshal(map[string]any{"alg": "HS256", "typ": f.header["typ"], "x5c": f.header["x5c"]})
			return b64(string(h)) + "." + parts[1] + "." + parts[2]
		}},
	{id: "signed-by-another-key", clause: "OpenID4VP 1.0 §5.9.3 (signed by the x5c leaf)",
		object: func(t *testing.T, f requestFixture) string {
			other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			return f.sign(t, other, nil, nil)
		}},
	{id: "payload-tampered", clause: "RFC 7515 §5.2 (signature)",
		object: func(t *testing.T, f requestFixture) string {
			parts := strings.Split(f.object, ".")
			var p map[string]any
			raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
			_ = json.Unmarshal(raw, &p)
			p["nonce"] = "another-nonce"
			changed, _ := json.Marshal(p)
			return parts[0] + "." + base64.RawURLEncoding.EncodeToString(changed) + "." + parts[2]
		}},
	{id: "x5c-missing", clause: "OpenID4VP 1.0 §5.9.3 (x5c)",
		object: func(t *testing.T, f requestFixture) string {
			return f.sign(t, f.key, func(h map[string]any) { delete(h, "x5c") }, nil)
		}},
	{id: "x5c-under-an-untrusted-ca", clause: "HAIP 1.0 §5 (trusted Verifier)", untrusted: true,
		object: func(t *testing.T, f requestFixture) string {
			otherKey, otherCA := testCA(t, "untrusted CA")
			leaf := leafUnder(t, otherCA, otherKey, &f.key.PublicKey, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
			return f.sign(t, f.key, func(h map[string]any) { h["x5c"] = x5cOfCerts(leaf) }, nil)
		}},
	{id: "x5c-includes-anchor", clause: "HAIP 1.0 §5 (the trust anchor MUST NOT be included)",
		object: func(t *testing.T, f requestFixture) string {
			return f.sign(t, f.key, func(h map[string]any) { h["x5c"] = x5cOfCerts(f.cert, f.caCert) }, nil)
		}},
	{id: "x5c-leaf-self-signed", clause: "HAIP 1.0 §5 (no self-signed leaf)",
		object: func(t *testing.T, f requestFixture) string {
			return f.sign(t, f.caKey, func(h map[string]any) { h["x5c"] = x5cOfCerts(f.caCert) }, nil)
		},
		clientID: func(f requestFixture) string { return x509HashOf(f.caCert) }},
	{id: "x5c-leaf-expired", clause: "RFC 5280 §6.1.3 (validity)",
		object: func(t *testing.T, f requestFixture) string {
			expired := leafUnder(t, f.caCert, f.caKey, &f.key.PublicKey, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
			return f.sign(t, f.key, func(h map[string]any) { h["x5c"] = x5cOfCerts(expired) }, nil)
		}},
	{id: "client-id-another-prefix", clause: "OpenID4VP 1.0 §5.9.3 (x509_hash)",
		clientID: func(f requestFixture) string { return "x509_san_dns:verifier.example.com" }},
	{id: "client-id-not-the-leafs-hash", clause: "OpenID4VP 1.0 §5.9.3 (x509_hash of the leaf)",
		clientID: func(f requestFixture) string { return x509HashOf(f.caCert) }},
	{id: "payload-client-id-differs", clause: "OpenID4VP 1.0 §5.10 (client_id in the Request Object)",
		object: func(t *testing.T, f requestFixture) string {
			return f.sign(t, f.key, nil, func(p map[string]any) { p["client_id"] = "x509_hash:another" })
		}},
	{id: "response-uri-not-https", clause: "OpenID4VP 1.0 §8.2 (response_uri)",
		object: func(t *testing.T, f requestFixture) string {
			return f.sign(t, f.key, nil, func(p map[string]any) { p["response_uri"] = "http://verifier.example.com/response" })
		}},
	{id: "redirect-uri-with-direct-post", clause: "OpenID4VP 1.0 §8.2 (redirect_uri MUST NOT be present)", code: "invalid_request",
		object: func(t *testing.T, f requestFixture) string {
			return f.sign(t, f.key, nil, func(p map[string]any) { p["redirect_uri"] = "https://verifier.example.com/cb" })
		}},
	{id: "response-type-not-vp-token", clause: "OpenID4VP 1.0 §5.1 (response_type)", code: "unsupported_response_type",
		object: func(t *testing.T, f requestFixture) string {
			return f.sign(t, f.key, nil, func(p map[string]any) { p["response_type"] = "code" })
		}},
	{id: "response-mode-not-direct-post-jwt", clause: "HAIP 1.0 §5 (direct_post.jwt)", code: "invalid_request",
		object: func(t *testing.T, f requestFixture) string {
			return f.sign(t, f.key, nil, func(p map[string]any) { p["response_mode"] = "direct_post" })
		}},
	{id: "client-metadata-no-encryption-key", clause: "OpenID4VP 1.0 §8.3 (jwks)",
		object: func(t *testing.T, f requestFixture) string {
			return f.sign(t, f.key, nil, func(p map[string]any) { p["client_metadata"] = map[string]any{"jwks": map[string]any{"keys": []any{}}} })
		}},
	{id: "transaction-data-unknown-type", clause: "OpenID4VP 1.0 §8.5 (invalid_transaction_data)", code: "invalid_transaction_data",
		object: func(t *testing.T, f requestFixture) string {
			return f.sign(t, f.key, nil, func(p map[string]any) {
				p["transaction_data"] = []any{b64(`{"type":"unknown","credential_ids":["cred1"]}`)}
			})
		}},
	{id: "nonce-missing", clause: "OpenID4VP 1.0 §5.2 (nonce REQUIRED)", code: "invalid_request",
		object: func(t *testing.T, f requestFixture) string {
			return f.sign(t, f.key, nil, func(p map[string]any) { delete(p, "nonce") })
		}},
	{id: "dcql-query-missing", clause: "OpenID4VP 1.0 §5.1 (dcql_query or scope REQUIRED)", code: "invalid_request",
		object: func(t *testing.T, f requestFixture) string {
			return f.sign(t, f.key, nil, func(p map[string]any) { delete(p, "dcql_query") })
		}},
}

func x509HashOf(cert *x509.Certificate) string {
	return "x509_hash:" + base64.RawURLEncoding.EncodeToString(sha256Sum(cert.Raw))
}

// Every request-object negative vector is refused, for its reason; the
// unchanged, re-signed Request Object, the control, is accepted.
func TestRequestObjectNegativeVectors(t *testing.T) {
	control := newRequestFixture(t)
	if _, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
		RequestObject: control.sign(t, control.key, nil, nil), ClientID: control.clientID, VerifierTrust: control.trust,
	}); err != nil {
		t.Fatalf("the control is refused, so no refusal below means anything: %v", err)
	}
	for _, vec := range requestObjectVectors {
		t.Run(vec.id, func(t *testing.T) {
			f := newRequestFixture(t)
			object, clientID := f.object, f.clientID
			if vec.object != nil {
				object = vec.object(t, f)
			}
			if vec.clientID != nil {
				clientID = vec.clientID(f)
			}
			_, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{RequestObject: object, ClientID: clientID, VerifierTrust: f.trust})
			var rejected *wallet.RequestRejectedError
			switch {
			case err == nil:
				t.Fatalf("accepted (%s)", vec.clause)
			case vec.untrusted && !errors.Is(err, wallet.ErrUntrustedVerifier):
				t.Errorf("refused for another reason: %v, want ErrUntrustedVerifier (%s)", err, vec.clause)
			case vec.code != "" && (!errors.As(err, &rejected) || rejected.Code != vec.code):
				t.Errorf("refused for another reason: %v, want a %q answer (%s)", err, vec.code, vec.clause)
			}
		})
	}
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// A Request Object addressed to another audience, expired, or not yet
// valid is refused (RFC 7519 §4.1.3–§4.1.5, OpenID4VP 1.0 §5.8); the
// self-issued audience, as a string or in an array, and a fractional
// NumericDate in the future are accepted.
func TestRequestObjectAudienceAndTimes(t *testing.T) {
	now := time.Now()
	for name, tc := range map[string]struct {
		set func(map[string]any)
		ok  bool
	}{
		"another audience":          {func(p map[string]any) { p["aud"] = "https://another-wallet.example" }, false},
		"expired":                   {func(p map[string]any) { p["exp"] = now.Add(-time.Hour).Unix() }, false},
		"not valid yet":             {func(p map[string]any) { p["nbf"] = now.Add(time.Hour).Unix() }, false},
		"aud not a string":          {func(p map[string]any) { p["aud"] = 7 }, false},
		"self-issued in an array":   {func(p map[string]any) { p["aud"] = []any{"https://self-issued.me/v2", "x"} }, true},
		"no aud at all":             {func(p map[string]any) { delete(p, "aud") }, true},
		"fractional exp in a while": {func(p map[string]any) { p["exp"] = float64(now.Add(time.Hour).Unix()) + 0.5 }, true},
	} {
		t.Run(name, func(t *testing.T) {
			f := newRequestFixture(t)
			_, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
				RequestObject: f.sign(t, f.key, nil, tc.set), ClientID: f.clientID, VerifierTrust: f.trust,
			})
			if (err == nil) != tc.ok {
				t.Errorf("err = %v, want accepted %v", err, tc.ok)
			}
		})
	}
}

// A request's DCQL query is checked when it's parsed: an exact
// duplicate claims query is ignored (OpenID4VP 1.0 §6.1: "Wallets
// SHOULD ignore such duplicate claim queries"), and a query beyond the
// size bounds, or otherwise invalid, is answered invalid_request.
func TestRequestObjectDCQLCheckedAtParse(t *testing.T) {
	query := func(n int, claims ...map[string]any) map[string]any {
		var creds []any
		for i := range n {
			creds = append(creds, map[string]any{"id": fmt.Sprintf("q%d", i), "format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []any{"urn:x"}}, "claims": claims})
		}
		return map[string]any{"credentials": creds}
	}
	given := map[string]any{"path": []any{"given_name"}}
	f := newRequestFixture(t)
	req, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
		RequestObject: f.sign(t, f.key, nil, func(p map[string]any) { p["dcql_query"] = query(1, given, given) }),
		ClientID:      f.clientID, VerifierTrust: f.trust,
	})
	if err != nil || len(req.Query.Credentials[0].Claims) != 1 {
		t.Fatalf("a duplicate claims query: %v, %v; want it ignored", req.Query, err)
	}
	for name, q := range map[string]map[string]any{
		"too many credential queries":  query(65, given),
		"the same path, different ids": query(1, map[string]any{"id": "a", "path": []any{"given_name"}}, map[string]any{"id": "b", "path": []any{"given_name"}}),
	} {
		_, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
			RequestObject: f.sign(t, f.key, nil, func(p map[string]any) { p["dcql_query"] = q }),
			ClientID:      f.clientID, VerifierTrust: f.trust,
		})
		var rejected *wallet.RequestRejectedError
		if !errors.As(err, &rejected) || rejected.Code != "invalid_request" {
			t.Errorf("%s: %v, want answered invalid_request", name, err)
		}
	}
}
