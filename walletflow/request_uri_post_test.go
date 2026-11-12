package walletflow_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// requestURIServer is a Verifier's request_uri endpoint answering GET
// and, for request_uri_method=post, POST (OpenID4VP 1.0 §5.10.1) with
// a Request Object carrying echo as its wallet_nonce, or the posted one
// when echo is empty. It records the last request's method and form.
type requestURIServer struct {
	v    *verifier.Verifier
	echo string

	mu     sync.Mutex
	method string
	form   url.Values
}

func (s *requestURIServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	form, _ := url.ParseQuery(string(body))
	s.mu.Lock()
	s.method, s.form = r.Method, form
	s.mu.Unlock()
	nonce := s.echo
	if nonce == "" {
		nonce = form.Get("wallet_nonce")
	}
	built, err := s.v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{
		Query: dcql.Query{Credentials: []dcql.CredentialQuery{dcql.SDJWTVCQuery("pid", "urn:example:pid")}}, WalletNonce: nonce,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
	_, _ = io.WriteString(w, built.RequestObject)
}

// last is the last request's method and form.
func (s *requestURIServer) last() (string, url.Values) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.method, s.form
}

// newRequestURIServer starts a requestURIServer and a wallet trusting
// its Verifier, and returns the link for request_uri_method method
// ("" for none).
func newRequestURIServer(t *testing.T, echo string) (*requestURIServer, *walletflow.Wallet, func(method string) string) {
	t.Helper()
	ca, caKey := testcert.CA(t, "request_uri test verifier CA")
	cert, key := testcert.Leaf(t, "request_uri test verifier", ca, caKey)
	responseURI, err := fapi.ParseEndpointURL("https://verifier.example/response")
	if err != nil {
		t.Fatal(err)
	}
	v, err := verifier.New(verifier.Config{
		Assurance: verifier.AssuranceDevelopment, ClientCertificate: cert, ResponseURI: responseURI,
		SigningAlg: jose.ES256, EncValuesSupported: []jwe.Enc{jwe.A128GCM},
		VPFormatsSupported: verifier.SDJWTVCFormatSupport([]string{"ES256"}, []string{"ES256"}),
	}, verifier.Dependencies{Signer: key, Random: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	s := &requestURIServer{v: v, echo: echo}
	ts := httptest.NewTLSServer(s)
	t.Cleanup(ts.Close)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	w, err := walletflow.New(walletflow.Config{VerifierTrust: wallet.X5CVerifierRoots{Roots: roots}, Development: true},
		walletflow.Dependencies{Keys: walletflow.NewMemoryKeyStore(), Credentials: walletflow.NewMemoryCredentialStore(), HTTP: ts.Client()})
	if err != nil {
		t.Fatal(err)
	}
	link := func(method string) string {
		q := url.Values{"client_id": {v.ClientID()}, "request_uri": {ts.URL + "/request/1"}}
		if method != "" {
			q.Set("request_uri_method", method)
		}
		return "openid4vp://?" + q.Encode()
	}
	return s, w, link
}

// A link saying request_uri_method=post has its request_uri POSTed a
// fresh wallet_nonce and the wallet's metadata, and the Request Object
// must carry that wallet_nonce back; any other link is fetched by GET.
func TestStartPresentation_RequestURIMethod(t *testing.T) {
	s, w, link := newRequestURIServer(t, "")
	ctx := context.Background()
	for _, method := range []string{"", "get"} {
		if _, err := w.StartPresentation(ctx, link(method)); err != nil {
			t.Fatalf("request_uri_method %q: %v", method, err)
		}
		if got, _ := s.last(); got != http.MethodGet {
			t.Errorf("request_uri_method %q: fetched by %s, want GET", method, got)
		}
	}

	var nonces []string
	for range 2 {
		if _, err := w.StartPresentation(ctx, link("post")); err != nil {
			t.Fatalf("request_uri_method post: %v", err)
		}
		got, form := s.last()
		if got != http.MethodPost {
			t.Fatalf("request_uri_method post: fetched by %s", got)
		}
		nonce := form.Get("wallet_nonce")
		if raw, err := base64.RawURLEncoding.DecodeString(nonce); err != nil || len(raw) < 16 {
			t.Errorf("wallet_nonce %q isn't 128 bits or more, base64url-encoded", nonce)
		}
		nonces = append(nonces, nonce)
		var metadata struct {
			VPFormats        wallet.VPFormats `json:"vp_formats_supported"`
			ClientIDPrefixes []string         `json:"client_id_prefixes_supported"`
			ResponseTypes    []string         `json:"response_types_supported"`
			ResponseModes    []string         `json:"response_modes_supported"`
			Issuer           string           `json:"issuer"`
		}
		if err := json.Unmarshal([]byte(form.Get("wallet_metadata")), &metadata); err != nil {
			t.Fatalf("wallet_metadata: %v", err)
		}
		if _, ok := metadata.VPFormats["dc+sd-jwt"]; !ok {
			t.Errorf("wallet_metadata = %s, want dc+sd-jwt among its formats", form.Get("wallet_metadata"))
		}
		if f, ok := metadata.VPFormats["mso_mdoc"]; !ok {
			t.Errorf("wallet_metadata = %s, want mso_mdoc among its formats", form.Get("wallet_metadata"))
		} else if !slices.Equal(f.IssuerAuthAlgValues, []int64{-7, -35, -36, -8}) {
			// The IssuerAuth algorithms VerifyIssuedCredential accepts:
			// ES256, ES384, ES512 and EdDSA.
			t.Errorf("mso_mdoc issuerauth_alg_values = %v, want [-7 -35 -36 -8]", f.IssuerAuthAlgValues)
		}
		// RFC 8414 §2's required response_types_supported and issuer,
		// and the one response mode the wallet answers a fetched request
		// in. The issuer is the one aud the wallet accepts, which the
		// Request Object then carries (OpenID4VP 1.0 §5.8).
		if !slices.Equal(metadata.ResponseTypes, []string{"vp_token"}) ||
			!slices.Equal(metadata.ResponseModes, []string{"direct_post.jwt"}) || metadata.Issuer != "https://self-issued.me/v2" {
			t.Errorf("wallet_metadata = %s, want response_types_supported [vp_token], response_modes_supported [direct_post.jwt] and issuer https://self-issued.me/v2",
				form.Get("wallet_metadata"))
		}
	}
	if nonces[0] == nonces[1] {
		t.Error("the same wallet_nonce was sent twice")
	}
}

// A Request Object carrying another wallet_nonce than the one posted,
// one fetched for another request, is refused.
func TestStartPresentation_RequestURIPostRefusesOtherWalletNonce(t *testing.T) {
	_, w, link := newRequestURIServer(t, "another fetch's nonce")
	if _, err := w.StartPresentation(context.Background(), link("post")); err == nil || !strings.Contains(err.Error(), "wallet_nonce") {
		t.Fatalf("StartPresentation = %v, want the wallet_nonce mismatch refused", err)
	}
}
