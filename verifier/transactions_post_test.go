package verifier_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// postFixture is a txFixture with RequestURIMethodPost, its
// RequestObjectHandler served at srv.
type postFixture struct {
	*txFixture
	srv *httptest.Server
}

func newPostFixture(t *testing.T, post bool) *postFixture {
	t.Helper()
	f := newTxFixture(t, func(c *verifier.TransactionsConfig) { c.RequestURIMethodPost = post })
	mux := http.NewServeMux()
	mux.Handle("/request-objects/{id}", f.txs.RequestObjectHandler())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &postFixture{txFixture: f, srv: srv}
}

// fetch sends method to begun's request_uri with body (form-encoded
// when contentType is ""), and returns the status, Content-Type and
// body of the reply.
func (f *postFixture) fetch(method, id, contentType, body string) (int, http.Header, string) {
	f.t.Helper()
	if contentType == "" {
		contentType = "application/x-www-form-urlencoded"
	}
	req, err := http.NewRequest(method, f.srv.URL+"/request-objects/"+id, strings.NewReader(body))
	if err != nil {
		f.t.Fatal(err)
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("Accept", "application/oauth-authz-req+jwt")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		f.t.Fatal(err)
	}
	return resp.StatusCode, resp.Header, string(b)
}

// claims are the Request Object's payload, unverified.
func requestObjectClaims(t *testing.T, object string) map[string]any {
	t.Helper()
	_, payload, err := jose.DecodeUnverified(object)
	if err != nil {
		t.Fatalf("DecodeUnverified: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

// parse verifies object as the wallet does, with walletNonce.
func (f *postFixture) parse(begun verifier.Begun, object, walletNonce string) wallet.AuthorizationRequest {
	f.t.Helper()
	link, err := url.Parse(begun.Link)
	if err != nil {
		f.t.Fatal(err)
	}
	req, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
		RequestObject: object, ClientID: link.Query().Get("client_id"), VerifierTrust: wallet.NoVerifierTrust{}, WalletNonce: walletNonce,
	})
	if err != nil {
		f.t.Fatalf("ParseAuthorizationRequest: %v", err)
	}
	return req
}

func TestTransactions_RequestURIMethodPostLink(t *testing.T) {
	for _, post := range []bool{false, true} {
		f := newPostFixture(t, post)
		link, err := url.Parse(f.begin("browser-binding-A", false).Link)
		if err != nil {
			t.Fatal(err)
		}
		got, want := link.Query()["request_uri_method"], []string(nil)
		if post {
			want = []string{"post"}
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("RequestURIMethodPost %v: request_uri_method = %v, want %v", post, got, want)
		}
	}
}

// TestTransactions_RequestURIPost: a POST fetch (OpenID4VP 1.0 §5.10)
// is answered with a Request Object carrying the wallet_nonce, with
// the request's own nonce, state and response key, so the answer to it
// completes the request; GET is still served (§5.1), and each fetch is
// served, as today.
func TestTransactions_RequestURIPost(t *testing.T) {
	f := newPostFixture(t, true)
	begun := f.begin("browser-binding-A", false)
	getObject, err := f.txs.RequestObject(context.Background(), begun.ID)
	if err != nil {
		t.Fatal(err)
	}
	get := requestObjectClaims(t, getObject)
	if _, ok := get["wallet_nonce"]; ok {
		t.Error("the GET Request Object carries a wallet_nonce")
	}

	var answered string
	for i, nonce := range []string{"wallet-nonce-1", "wallet-nonce-2"} {
		status, header, body := f.fetch(http.MethodPost, begun.ID, "", url.Values{"wallet_nonce": {nonce}}.Encode())
		if status != http.StatusOK || header.Get("Content-Type") != "application/oauth-authz-req+jwt" || header.Get("Cache-Control") != "no-store" {
			t.Fatalf("POST %d: %d %v %q", i+1, status, header, body)
		}
		claims := requestObjectClaims(t, body)
		if claims["wallet_nonce"] != nonce {
			t.Errorf("POST %d: wallet_nonce = %v, want %q", i+1, claims["wallet_nonce"], nonce)
		}
		for _, name := range []string{"nonce", "state", "client_id", "response_uri", "dcql_query", "client_metadata"} {
			if !reflect.DeepEqual(claims[name], get[name]) {
				t.Errorf("POST %d: %s = %v, want the GET object's %v", i+1, name, claims[name], get[name])
			}
		}
		f.parse(begun, body, nonce) // the wallet's §5.10.1 check
		answered = body
	}
	if status, _, body := f.fetch(http.MethodGet, begun.ID, "", ""); status != http.StatusOK || body != getObject {
		t.Errorf("GET of a POST-enabled request: %d, the GET object %v", status, body == getObject)
	}
	if status, _, body := f.fetch(http.MethodPost, begun.ID, "", ""); status != http.StatusOK || requestObjectClaims(t, body)["wallet_nonce"] != nil {
		t.Errorf("POST without wallet_nonce: %d, wallet_nonce %v", status, requestObjectClaims(t, body)["wallet_nonce"])
	}

	// The answer to the POSTed object completes the request.
	req := f.parse(begun, answered, "wallet-nonce-2")
	vpToken, err := wallet.PresentCredentials(context.Background(), wallet.PresentationRequest{
		Query: req.Query, Credentials: []wallet.HeldCredential{f.held}, Audience: req.ClientID, Nonce: req.Nonce,
	})
	if err != nil {
		t.Fatal(err)
	}
	response, err := wallet.BuildDirectPostResponse(wallet.BuildDirectPostResponseParams{
		VPToken: vpToken, State: req.State, EncryptionKey: req.ResponseEncryptionKey,
		EncryptionKeyID: req.ResponseEncryptionKeyID, EncryptionEnc: req.ResponseEncryptionEnc,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.txs.HandleResponse(context.Background(), response); err != nil {
		t.Fatalf("HandleResponse of the answer to the POSTed object: %v", err)
	}
	// Still served once answered, as a GET is (RequestObject).
	if status, _, _ := f.fetch(http.MethodPost, begun.ID, "", ""); status != http.StatusOK {
		t.Errorf("POST of an answered request: %d, want 200", status)
	}
}

// TestTransactions_RequestURIPostWalletMetadata: wallet_metadata
// narrows the client_metadata to what both support; jwks, a key to
// encrypt the Request Object to, is ignored (§5.10.1: "a signed,
// optionally encrypted, request object").
func TestTransactions_RequestURIPostWalletMetadata(t *testing.T) {
	f := newPostFixture(t, true)
	begun := f.begin("browser-binding-A", false)
	metadata := `{"vp_formats_supported":{"dc+sd-jwt":{"sd-jwt_alg_values":["ES384","ES256"],"kb-jwt_alg_values":["ES256"]},"jwt_vc_json":{}},` +
		`"client_id_prefixes_supported":["x509_hash","x509_san_dns"],"request_object_signing_alg_values_supported":["ES256"],` +
		`"authorization_encryption_alg_values_supported":["ECDH-ES"],"authorization_encryption_enc_values_supported":["A256GCM","A192GCM"],` +
		`"jwks":{"keys":[]},"response_types_supported":["vp_token"],"unknown":1}`
	status, _, body := f.fetch(http.MethodPost, begun.ID, "", url.Values{"wallet_nonce": {"n"}, "wallet_metadata": {metadata}}.Encode())
	if status != http.StatusOK {
		t.Fatalf("POST: %d %q", status, body)
	}
	if parts := strings.Split(body, "."); len(parts) != 3 {
		t.Fatalf("the Request Object isn't a compact JWS: %d parts", len(parts))
	}
	cm, _ := requestObjectClaims(t, body)["client_metadata"].(map[string]any)
	wantFormats := map[string]any{"dc+sd-jwt": map[string]any{"sd-jwt_alg_values": []any{"ES256"}}}
	if !reflect.DeepEqual(cm["vp_formats_supported"], wantFormats) {
		t.Errorf("vp_formats_supported = %v, want %v", cm["vp_formats_supported"], wantFormats)
	}
	if want := []any{"A256GCM"}; !reflect.DeepEqual(cm["encrypted_response_enc_values_supported"], want) {
		t.Errorf("encrypted_response_enc_values_supported = %v, want %v", cm["encrypted_response_enc_values_supported"], want)
	}
	if req := f.parse(begun, body, "n"); req.ResponseEncryptionEnc != "A256GCM" {
		t.Errorf("the wallet picks enc %q, want A256GCM", req.ResponseEncryptionEnc)
	}

	// Metadata naming none of the members that narrow leaves the
	// client_metadata as the GET object's.
	getObject, err := f.txs.RequestObject(context.Background(), begun.ID)
	if err != nil {
		t.Fatal(err)
	}
	status, _, body = f.fetch(http.MethodPost, begun.ID, "", url.Values{"wallet_metadata": {`{"issuer":"https://self-issued.me/v2"}`}}.Encode())
	if got, want := requestObjectClaims(t, body)["client_metadata"], requestObjectClaims(t, getObject)["client_metadata"]; status != http.StatusOK || !reflect.DeepEqual(got, want) {
		t.Errorf("wallet_metadata narrowing nothing: %d, client_metadata %v, want %v", status, got, want)
	}

	// The wallet package's own metadata (walletflow's) fits too.
	walletflowMetadata := `{"vp_formats_supported":{"dc+sd-jwt":{"sd-jwt_alg_values":["ES256","ES384","ES512","EdDSA"],"kb-jwt_alg_values":["ES256"]},` +
		`"mso_mdoc":{"issuerauth_alg_values":[-7,-35,-36,-8],"deviceauth_alg_values":[-7]}},"client_id_prefixes_supported":["x509_hash"],` +
		`"response_types_supported":["vp_token"],"response_modes_supported":["direct_post.jwt"],"issuer":"https://self-issued.me/v2"}`
	if status, _, body := f.fetch(http.MethodPost, begun.ID, "", url.Values{"wallet_metadata": {walletflowMetadata}}.Encode()); status != http.StatusOK {
		t.Errorf("walletflow's wallet_metadata: %d %q", status, body)
	}
}

// TestTransactions_RequestURIPostRefusals: each refusal's exact status
// and error.
func TestTransactions_RequestURIPostRefusals(t *testing.T) {
	f := newPostFixture(t, true)
	begun := f.begin("browser-binding-A", false)
	form := func(metadata string) string { return url.Values{"wallet_metadata": {metadata}}.Encode() }
	cases := []struct {
		name, contentType, body string
		status                  int
		description             string
	}{
		{"another media type", "application/json", `{}`, http.StatusUnsupportedMediaType, "a request_uri POST must be application/x-www-form-urlencoded"},
		{"no media type", "-", "", http.StatusUnsupportedMediaType, "a request_uri POST must be application/x-www-form-urlencoded"},
		{"malformed form", "", "%zz", http.StatusBadRequest, "the request_uri POST's form is malformed"},
		{"too large", "", "wallet_metadata=" + strings.Repeat("a", 33<<10), http.StatusRequestEntityTooLarge, "the request_uri POST is too large"},
		{"two wallet_nonces", "", "wallet_nonce=a&wallet_nonce=b", http.StatusBadRequest, "the request_uri POST repeats wallet_nonce or wallet_metadata"},
		{"two wallet_metadata", "", "wallet_metadata=%7B%7D&wallet_metadata=%7B%7D", http.StatusBadRequest, "the request_uri POST repeats wallet_nonce or wallet_metadata"},
		{"wallet_metadata not JSON", "", form("{"), http.StatusBadRequest, "wallet_metadata isn't a JSON object of the members OpenID4VP 1.0 §10 defines"},
		{"wallet_metadata an array", "", form("[]"), http.StatusBadRequest, "wallet_metadata isn't a JSON object of the members OpenID4VP 1.0 §10 defines"},
		{"wallet_metadata null", "", form("null"), http.StatusBadRequest, "wallet_metadata isn't a JSON object of the members OpenID4VP 1.0 §10 defines"},
		{"wallet_metadata empty", "", form(""), http.StatusBadRequest, "wallet_metadata isn't a JSON object of the members OpenID4VP 1.0 §10 defines"},
		{"a member of the wrong type", "", form(`{"vp_formats_supported":["dc+sd-jwt"]}`), http.StatusBadRequest, "wallet_metadata isn't a JSON object of the members OpenID4VP 1.0 §10 defines"},
		{"a duplicate member", "", form(`{"client_id_prefixes_supported":["x509_hash"],"client_id_prefixes_supported":["x509_hash"]}`), http.StatusBadRequest, "wallet_metadata isn't a JSON object of the members OpenID4VP 1.0 §10 defines"},
		{"no format in common", "", form(`{"vp_formats_supported":{"jwt_vc_json":{}}}`), http.StatusBadRequest, "vp_formats_supported leaves the request's credential queries no way to be answered"},
		{"no algorithm in common", "", form(`{"vp_formats_supported":{"dc+sd-jwt":{"sd-jwt_alg_values":["EdDSA"]}}}`), http.StatusBadRequest, "vp_formats_supported leaves the request's credential queries no way to be answered"},
		{"an algorithm list that isn't one", "", form(`{"vp_formats_supported":{"dc+sd-jwt":{"sd-jwt_alg_values":"ES256"}}}`), http.StatusBadRequest, "vp_formats_supported has a format parameter that isn't an array where this Verifier's is"},
		{"another client_id prefix", "", form(`{"client_id_prefixes_supported":["x509_san_dns"]}`), http.StatusBadRequest, "client_id_prefixes_supported doesn't include x509_hash, this Verifier's Client Identifier Prefix"},
		{"another signing alg", "", form(`{"request_object_signing_alg_values_supported":["EdDSA"]}`), http.StatusBadRequest, "request_object_signing_alg_values_supported doesn't include the algorithm this Verifier signs with"},
		{"another encryption alg", "", form(`{"authorization_encryption_alg_values_supported":["RSA-OAEP-256"]}`), http.StatusBadRequest, "authorization_encryption_alg_values_supported doesn't include ECDH-ES"},
		{"another enc", "", form(`{"authorization_encryption_enc_values_supported":["A192GCM"]}`), http.StatusBadRequest, "authorization_encryption_enc_values_supported has none of the content encryption algorithms this Verifier decrypts"},
	}
	for _, c := range cases {
		contentType := c.contentType
		if contentType == "-" {
			contentType = " "
		}
		status, header, body := f.fetch(http.MethodPost, begun.ID, contentType, c.body)
		var got map[string]string
		_ = json.Unmarshal([]byte(body), &got)
		if status != c.status || header.Get("Content-Type") != "application/json" || got["error"] != "invalid_request" || got["error_description"] != c.description {
			t.Errorf("%s: %d %q, want %d invalid_request %q", c.name, status, body, c.status, c.description)
		}
	}

	if status, _, _ := f.fetch(http.MethodPost, "unknown", "", ""); status != http.StatusNotFound {
		t.Errorf("POST of an unknown request: %d, want 404", status)
	}
	status, header, _ := f.fetch(http.MethodPut, begun.ID, "", "")
	if status != http.StatusMethodNotAllowed || header.Get("Allow") != "GET, POST" {
		t.Errorf("PUT: %d Allow %q, want 405 Allow \"GET, POST\"", status, header.Get("Allow"))
	}

	// The request's own key no longer the one its KeyID names: the
	// Verifier's fault, a 500.
	if err := f.store.Update(context.Background(), begun.ID, func(tx *verifier.Transaction) error { tx.KeyID = "another"; return nil }); err != nil {
		t.Fatal(err)
	}
	if status, _, body := f.fetch(http.MethodPost, begun.ID, "", ""); status != http.StatusInternalServerError || !strings.Contains(body, "server_error") {
		t.Errorf("POST of a request whose key changed: %d %q, want 500 server_error", status, body)
	}
	if err := f.store.Update(context.Background(), begun.ID, func(tx *verifier.Transaction) error { tx.ResponseDecryptionKey = nil; return nil }); err != nil {
		t.Fatal(err)
	}
	if status, _, _ := f.fetch(http.MethodPost, begun.ID, "", ""); status != http.StatusInternalServerError {
		t.Errorf("POST of a request without its key: %d, want 500", status)
	}

	var metadataErr *verifier.WalletMetadataError
	_, err := f.txs.RequestObjectPost(context.Background(), f.begin("browser-binding-C", false).ID, verifier.RequestURIPost{WalletMetadata: []byte(`{"client_id_prefixes_supported":["pre-registered"]}`)})
	if !errors.As(err, &metadataErr) || err.Error() != "verifier: wallet_metadata refused: "+metadataErr.Reason {
		t.Errorf("RequestObjectPost: %v, want a *WalletMetadataError", err)
	}

	expiring := f.begin("browser-binding-B", false)
	f.now = f.now.Add(time.Hour)
	if status, _, _ := f.fetch(http.MethodPost, expiring.ID, "", ""); status != http.StatusNotFound {
		t.Errorf("POST of an expired request: %d, want 404", status)
	}
}

// TestTransactions_RequestURIPostDisabled: without RequestURIMethodPost,
// a POST is refused as before.
func TestTransactions_RequestURIPostDisabled(t *testing.T) {
	f := newPostFixture(t, false)
	begun := f.begin("browser-binding-A", false)
	status, header, _ := f.fetch(http.MethodPost, begun.ID, "", "wallet_nonce=n")
	if status != http.StatusMethodNotAllowed || header.Get("Allow") != "GET" {
		t.Errorf("POST: %d Allow %q, want 405 Allow GET", status, header.Get("Allow"))
	}
	if _, err := f.txs.RequestObjectPost(context.Background(), begun.ID, verifier.RequestURIPost{WalletNonce: "n"}); !errors.Is(err, verifier.ErrRequestURIMethodPostDisabled) {
		t.Errorf("RequestObjectPost: %v, want ErrRequestURIMethodPostDisabled", err)
	}
	if status, _, _ := f.fetch(http.MethodGet, begun.ID, "", ""); status != http.StatusOK {
		t.Errorf("GET: %d, want 200", status)
	}
}
