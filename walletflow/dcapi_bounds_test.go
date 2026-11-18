package walletflow_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/wallet"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

const boundsVCT = "urn:walletflowtest:bounds:pid"

// boundsWallet is a development Wallet holding n SD-JWT VCs of
// boundsVCT, each bound to a holder key.
func boundsWallet(t *testing.T, n int) *walletflow.Wallet {
	t.Helper()
	ca, caKey := testcert.CA(t, "bounds issuer CA")
	leaf, leafKey := testcert.Leaf(t, "bounds issuer", ca, caKey)
	store := walletflow.NewMemoryCredentialStore()
	exp := time.Now().Add(24 * time.Hour).Unix()
	for i := range n {
		holder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cnf := map[string]any{"jwk": map[string]any{
			"kty": "EC", "crv": "P-256",
			"x": base64.RawURLEncoding.EncodeToString(holder.X.FillBytes(make([]byte, 32))),
			"y": base64.RawURLEncoding.EncodeToString(holder.Y.FillBytes(make([]byte, 32))),
		}}
		compact, _, err := sdjwtvc.Issue(leafKey, jose.ES256, sdjwtvc.Claims{
			VCT: boundsVCT, Exp: &exp, CNF: cnf,
			Additional: map[string]any{
				"given_name": sdjwtvc.SD("Erika"), "family_name": sdjwtvc.SD("Mustermann"),
				"address":         sdjwtvc.SD(map[string]any{"locality": sdjwtvc.SD("Koeln"), "country": sdjwtvc.SD("DE")}),
				"document_number": sdjwtvc.SD(fmt.Sprintf("T2200%04d", i)),
			},
		}, sdjwtvc.IssueOptions{IssuerCertificate: leaf})
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Put(context.Background(), walletflow.StoredCredential{
			ID: fmt.Sprintf("cred%d", i), Format: sdjwtvc.CredentialFormat, VCT: boundsVCT, Credential: compact,
			HolderKeyID: "k", ReceivedAt: time.Now().Add(-time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatal(err)
		}
	}
	w, err := walletflow.New(walletflow.Config{Development: true}, walletflow.Dependencies{Keys: walletflow.NewMemoryKeyStore(), Credentials: store})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// boundsRequest is an unsigned DC API request of dcql.MaxCredentialQueries
// credential queries for boundsVCT, each with a few claims and a meta of
// about metaBytes, its vct_values followed by a member a Wallet ignores,
// padded at its top level to just under wallet.MaxDCAPIRequestBytes.
func boundsRequest(t *testing.T, metaBytes int) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x := base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32)))
	y := base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32)))
	metaHead := fmt.Sprintf(`{"vct_values":[%q],"x":[`, boundsVCT)
	// JSON's costliest shape to decode for its size: an array of zeros.
	zeros := func(n int) string { return strings.TrimSuffix(strings.Repeat("0,", max(n, 1)), ",") }
	meta := metaHead + zeros((metaBytes-len(metaHead)-2)/2) + "]}"
	cqs := make([]string, dcql.MaxCredentialQueries)
	for i := range cqs {
		cqs[i] = fmt.Sprintf(`{"id":"q%d","format":"dc+sd-jwt","meta":%s,"claims":[{"path":["given_name"]},{"path":["family_name"]},{"path":["address","locality"]}]}`, i, meta)
	}
	head := fmt.Sprintf(`{"response_type":"vp_token","response_mode":"dc_api.jwt","nonce":"bounds-nonce","client_metadata":{"jwks":{"keys":[{"kty":"EC","crv":"P-256","x":%q,"y":%q,"use":"enc","alg":"ECDH-ES","kid":"k"}]}},"dcql_query":{"credentials":[%s]},"padding":[`,
		x, y, strings.Join(cqs, ","))
	req := head + zeros((wallet.MaxDCAPIRequestBytes-len(head)-64)/2) + "]}"
	if len(req) > wallet.MaxDCAPIRequestBytes {
		t.Fatalf("request is %d bytes, over the %d bound", len(req), wallet.MaxDCAPIRequestBytes)
	}
	return []byte(req)
}

// An unsigned DC API request is anyone's to send, so opening one costs
// the wallet about its size, however many credentials it holds: the
// largest request, every credential query at its meta's bound, is
// opened, previewed and answered, each query listing every held
// credential (matched together, each credential decoded once, and each
// query's meta read in full once, wallet.MatchEachCredentialQuery). A
// meta past the bound (dcql.MaxMetaBytes), which the wallet would read
// for every credential it holds, is refused to the page.
func TestDCAPIPresentation_UnsignedRequestAtTheBounds(t *testing.T) {
	ctx := context.Background()
	const held = 8
	w := boundsWallet(t, held)
	const origin = "https://anyone.walletflowtest.example"

	data := boundsRequest(t, dcql.MaxMetaBytes)
	p, err := w.StartDCAPIPresentation(ctx, wallet.DCAPIProtocolUnsigned, data, origin)
	if err != nil {
		t.Fatalf("a %d-byte request at the bounds: %v", len(data), err)
	}
	if got := len(p.Queries()); got != dcql.MaxCredentialQueries {
		t.Fatalf("%d queries, want %d", got, dcql.MaxCredentialQueries)
	}
	for _, q := range p.Queries() {
		if len(q.Credentials) != held {
			t.Errorf("query %s lists %d credentials, want all %d", q.ID, len(q.Credentials), held)
		}
	}
	sel, err := p.DefaultSelection(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Preview(ctx, sel); err != nil {
		t.Errorf("Preview: %v", err)
	}

	_, err = w.StartDCAPIPresentation(ctx, wallet.DCAPIProtocolUnsigned, boundsRequest(t, dcql.MaxMetaBytes+16), origin)
	var refused *walletflow.RequestRefusedError
	if !errors.As(err, &refused) || refused.Code != "invalid_request" || !strings.Contains(err.Error(), fmt.Sprintf("more than %d", dcql.MaxMetaBytes)) {
		t.Errorf("a meta past the bound: err = %v, want the request refused for its size", err)
	}
	if refused != nil && len(refused.DCAPIResponse) == 0 {
		t.Error("the refusal has no response for the page")
	}
}
