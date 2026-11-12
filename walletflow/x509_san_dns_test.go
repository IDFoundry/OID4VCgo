package walletflow_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
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

// sanDNSClientID names the Verifier of these tests by the host of its
// response_uri, https://verifier.example/response.
const sanDNSClientID = "x509_san_dns:verifier.example"

// sanDNSServer is a Verifier's request_uri endpoint. Its Request
// Objects, built by v, are re-signed by key, whose certificate cert has
// the dNSName verifier.example, under the client_id sanDNSClientID. It
// records the last request's form.
type sanDNSServer struct {
	v    *verifier.Verifier
	cert *x509.Certificate
	key  *ecdsa.PrivateKey

	mu   sync.Mutex
	form url.Values
}

func (s *sanDNSServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	form, _ := url.ParseQuery(string(body))
	s.mu.Lock()
	s.form = form
	s.mu.Unlock()
	object, err := s.requestObject(form.Get("wallet_nonce"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
	_, _ = io.WriteString(w, object)
}

func (s *sanDNSServer) requestObject(walletNonce string) (string, error) {
	built, err := s.v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{
		Query: dcql.Query{Credentials: []dcql.CredentialQuery{dcql.SDJWTVCQuery("pid", "urn:example:pid")}}, WalletNonce: walletNonce,
	})
	if err != nil {
		return "", err
	}
	header, raw, err := jose.DecodeUnverified(built.RequestObject)
	if err != nil {
		return "", err
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", err
	}
	payload["client_id"] = sanDNSClientID
	header["x5c"] = []string{base64.StdEncoding.EncodeToString(s.cert.Raw)}
	if raw, err = json.Marshal(payload); err != nil {
		return "", err
	}
	return jose.Sign(jose.ES256, s.key, header, raw)
}

// walletMetadataPrefixes is the client_id_prefixes_supported of the
// wallet_metadata last posted.
func (s *sanDNSServer) walletMetadataPrefixes(t *testing.T) []string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var metadata struct {
		ClientIDPrefixes []string `json:"client_id_prefixes_supported"`
	}
	if err := json.Unmarshal([]byte(s.form.Get("wallet_metadata")), &metadata); err != nil {
		t.Fatalf("wallet_metadata %q: %v", s.form.Get("wallet_metadata"), err)
	}
	return metadata.ClientIDPrefixes
}

// newSANDNSFlow starts a sanDNSServer and a development wallet trusting
// its Verifier's CA, with Config.AcceptX509SANDNS accept, and returns
// the link for request_uri_method method.
func newSANDNSFlow(t *testing.T, accept bool) (*sanDNSServer, *walletflow.Wallet, func(method string) string) {
	t.Helper()
	ca, caKey := testcert.CA(t, "x509_san_dns test verifier CA")
	cert, key := testcert.Issue(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "x509_san_dns test verifier"}, DNSNames: []string{"verifier.example"},
		KeyUsage: x509.KeyUsageDigitalSignature,
	}, ca, caKey)
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
	s := &sanDNSServer{v: v, cert: cert, key: key}
	ts := httptest.NewTLSServer(s)
	t.Cleanup(ts.Close)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	w, err := walletflow.New(walletflow.Config{VerifierTrust: wallet.X5CVerifierRoots{Roots: roots}, AcceptX509SANDNS: accept, Development: true},
		walletflow.Dependencies{Keys: walletflow.NewMemoryKeyStore(), Credentials: walletflow.NewMemoryCredentialStore(), HTTP: ts.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return s, w, func(method string) string {
		return "openid4vp://?" + url.Values{
			"client_id": {sanDNSClientID}, "request_uri": {ts.URL + "/request/1"}, "request_uri_method": {method},
		}.Encode()
	}
}

// With Config.AcceptX509SANDNS, a Verifier identified by x509_san_dns is
// answered, and the wallet_metadata posted lists the prefix alongside
// x509_hash (OpenID4VP 1.0 §10.1); without it, the Verifier is refused
// and the metadata lists x509_hash alone, as before.
func TestStartPresentation_X509SANDNS(t *testing.T) {
	ctx := context.Background()

	s, w, link := newSANDNSFlow(t, true)
	for _, method := range []string{"get", "post"} {
		p, err := w.StartPresentation(ctx, link(method))
		if err != nil {
			t.Fatalf("request_uri_method %s: %v", method, err)
		}
		if got := p.Verifier(); got.ClientID != sanDNSClientID || got.ResponseURI != "https://verifier.example/response" {
			t.Errorf("request_uri_method %s: Verifier = %+v, want client_id %s", method, got, sanDNSClientID)
		}
	}
	if got, want := s.walletMetadataPrefixes(t), []string{"x509_hash", "x509_san_dns"}; !slices.Equal(got, want) {
		t.Errorf("opted in: client_id_prefixes_supported = %q, want %q", got, want)
	}

	s, w, link = newSANDNSFlow(t, false)
	_, err := w.StartPresentation(ctx, link("post"))
	if err == nil || !strings.Contains(err.Error(), `client_id "x509_san_dns:verifier.example" does not match x5c leaf's own x509_hash`) {
		t.Errorf("not opted in: StartPresentation = %v, want x509_san_dns refused", err)
	}
	if got, want := s.walletMetadataPrefixes(t), []string{"x509_hash"}; !slices.Equal(got, want) {
		t.Errorf("not opted in: client_id_prefixes_supported = %q, want %q", got, want)
	}
}

// New refuses AcceptX509SANDNS without a VerifierTrust that verifies
// chains: none, or the NoVerifierTrust that Development permits.
func TestNew_X509SANDNSNeedsTrustAnchors(t *testing.T) {
	const want = "walletflow: wallet: config: accept_x509_san_dns needs a VerifierTrust that verifies the x5c chain to trust anchors: X5CVerifierRoots with Roots, or another VerifierTrust, never NoVerifierTrust or none"
	for name, trust := range map[string]wallet.VerifierTrust{"none": nil, "NoVerifierTrust": wallet.NoVerifierTrust{}} {
		_, err := walletflow.New(walletflow.Config{VerifierTrust: trust, AcceptX509SANDNS: true, Development: true},
			walletflow.Dependencies{Keys: walletflow.NewMemoryKeyStore(), Credentials: walletflow.NewMemoryCredentialStore()})
		if err == nil || err.Error() != want {
			t.Errorf("%s: New = %v, want %s", name, err, want)
		}
	}
}
