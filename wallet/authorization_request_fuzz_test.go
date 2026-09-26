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
	"math/big"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testverifier"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// FuzzParseAuthorizationRequest exercises ParseAuthorizationRequest
// against arbitrary strings — a Request Object is Verifier-supplied
// (or, in the request_uri flow, fetched from wherever the Verifier
// named), attacker-controlled wire data a Wallet must parse before it
// discloses anything. Notable: PR #110 found a real bug here
// (selectResponseEncryptionKey blindly trusting keys[0] instead of
// skipping unparseable decoy JWKs) — the exact class of defect fuzzing
// exists to catch, in this exact function. Builds one genuine,
// verifier.BuildAuthorizationRequest-produced Request Object as seed
// material so the fuzzer starts from something that actually parses.
func FuzzParseAuthorizationRequest(f *testing.F) {
	requestObject, clientID := seedRequestObject(f)

	f.Add(requestObject)
	f.Add("")
	f.Add(".")
	f.Add("a.b.c")

	f.Fuzz(func(t *testing.T, requestObject string) {
		_, _ = wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
			RequestObject: requestObject, ClientID: clientID,
		})
	})
}

// FuzzParseAuthorizationRequestSigned exercises ParseAuthorizationRequest's
// post-signature path — the payload and client_metadata parsing,
// selectResponseEncryptionKey and the redirect_uri/transaction_data
// rejections — which FuzzParseAuthorizationRequest can't reach: a
// mutated Request Object there almost never carries a valid signature.
// No trust anchor is involved in reaching that path: the verification
// key is the x5c leaf's own, and an x509_hash client_id is just that
// leaf's hash, so any attacker can produce a validly signed Request
// Object. The harness does exactly that with its own self-signed
// certificate, signing the fuzzed payload.
func FuzzParseAuthorizationRequestSigned(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fuzz-verifier"},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		f.Fatalf("CreateCertificate: %v", err)
	}
	hash := sha256.Sum256(der)
	clientID := "x509_hash:" + base64.RawURLEncoding.EncodeToString(hash[:])
	header := map[string]any{"typ": "oauth-authz-req+jwt", "x5c": []string{base64.StdEncoding.EncodeToString(der)}}

	requestObject, _ := seedRequestObject(f)
	_, rawPayload, err := jose.DecodeUnverified(requestObject)
	if err != nil {
		f.Fatalf("DecodeUnverified: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(rawPayload, &claims); err != nil {
		f.Fatalf("unmarshal payload: %v", err)
	}
	claims["client_id"] = clientID
	seed, err := json.Marshal(claims)
	if err != nil {
		f.Fatalf("marshal payload: %v", err)
	}

	f.Add(seed)
	claims["transaction_data"] = []string{"e30"}
	withTxData, err := json.Marshal(claims)
	if err != nil {
		f.Fatalf("marshal payload: %v", err)
	}
	f.Add(withTxData)
	f.Add([]byte(`{}`))

	f.Fuzz(func(t *testing.T, payload []byte) {
		requestObject, err := jose.Sign(jose.ES256, key, header, payload)
		if err != nil {
			t.Fatalf("sign request object: %v", err)
		}
		req, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
			RequestObject: requestObject, ClientID: clientID,
		})
		if err != nil {
			return
		}
		if req.ResponseEncryptionKey == nil {
			t.Fatal("ParseAuthorizationRequest succeeded without a response encryption key")
		}
	})
}

// seedRequestObject builds one genuine, verifier.BuildAuthorizationRequest-
// produced Request Object and returns it with the Verifier's client_id.
func seedRequestObject(f *testing.F) (requestObject, clientID string) {
	v := testverifier.New(f)
	meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{"urn:eudi:pid:1"}})
	if err != nil {
		f.Fatalf("NewSDJWTVCMeta: %v", err)
	}
	query := dcql.Query{Credentials: []dcql.CredentialQuery{{ID: "cred1", Format: "dc+sd-jwt", Meta: meta}}}
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query, State: "fuzz-state"})
	if err != nil {
		f.Fatalf("BuildAuthorizationRequest: %v", err)
	}
	return built.RequestObject, v.ClientID()
}
