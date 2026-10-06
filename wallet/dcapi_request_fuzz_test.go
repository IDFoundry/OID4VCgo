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
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testverifier"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// FuzzParseDCAPIRequest exercises ParseDCAPIRequest past the signature
// check, as FuzzParseAuthorizationRequestSigned does for the redirect
// flow: the harness signs each fuzzed payload with its own self-signed
// certificate, whose x509_hash it sets as client_id in the seeds, and
// fuzzes the platform's origin alongside. A request it accepts must
// expect exactly the origin it was given, ask for vp_token in dc_api.jwt,
// and carry a nonce.
func FuzzParseDCAPIRequest(f *testing.F) {
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
	const seedOrigin = "https://verifier.example.com"

	meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{"urn:eudi:pid:1"}})
	if err != nil {
		f.Fatalf("NewSDJWTVCMeta: %v", err)
	}
	built, err := testverifier.New(f).BuildDCAPIAuthorizationRequest(verifier.BuildDCAPIAuthorizationRequestRequest{
		Query:           dcql.Query{Credentials: []dcql.CredentialQuery{{ID: "cred1", Format: "dc+sd-jwt", Meta: meta}}},
		ExpectedOrigins: []string{seedOrigin},
	})
	if err != nil {
		f.Fatalf("BuildDCAPIAuthorizationRequest: %v", err)
	}
	_, rawPayload, err := jose.DecodeUnverified(built.RequestObject)
	if err != nil {
		f.Fatalf("DecodeUnverified: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(rawPayload, &claims); err != nil {
		f.Fatalf("unmarshal payload: %v", err)
	}
	claims["client_id"] = clientID
	for _, mutate := range []func(){
		func() {},
		func() { claims["transaction_data"] = []string{"e30"} },
		func() { claims["expected_origins"] = []string{"https://other.example.com"} },
	} {
		mutate()
		seed, err := json.Marshal(claims)
		if err != nil {
			f.Fatalf("marshal payload: %v", err)
		}
		f.Add(seed, seedOrigin)
		f.Add(seed, seedOrigin+"/")
	}
	f.Add([]byte(`{}`), seedOrigin)
	f.Add([]byte(`{"expected_origins":["null"]}`), "null")

	f.Fuzz(func(t *testing.T, payload []byte, origin string) {
		requestObject, err := jose.Sign(jose.ES256, key, header, payload)
		if err != nil {
			t.Fatalf("sign request object: %v", err)
		}
		req, err := wallet.ParseDCAPIRequest(wallet.ParseDCAPIRequestParams{
			Request: requestObject, Origin: origin, VerifierTrust: wallet.NoVerifierTrust{},
		})
		if err != nil {
			return
		}
		var got struct {
			ExpectedOrigins []string `json:"expected_origins"`
			ResponseType    string   `json:"response_type"`
			ResponseMode    string   `json:"response_mode"`
			Nonce           string   `json:"nonce"`
		}
		if err := json.Unmarshal(payload, &got); err != nil || !slices.Contains(got.ExpectedOrigins, origin) {
			t.Fatalf("accepted origin %q for a request whose expected_origins are %v", origin, got.ExpectedOrigins)
		}
		if got.ResponseType != "vp_token" || got.ResponseMode != "dc_api.jwt" || got.Nonce == "" {
			t.Fatalf("accepted response_type %q, response_mode %q, nonce %q", got.ResponseType, got.ResponseMode, got.Nonce)
		}
		if req.Origin != origin || req.Nonce != got.Nonce || req.ResponseEncryptionKey == nil {
			t.Fatalf("accepted request = %+v", req)
		}
	})
}

// FuzzParseDCAPIRequestData feeds ParseDCAPIRequestData arbitrary data
// under each protocol, seeded with a valid request of each form signed
// by the harness's own self-signed certificate. Whatever a page sends,
// an accepted request is bound to the platform's origin, asks for
// dc_api.jwt with a nonce and an encryption key, and names no Verifier
// when unsigned.
func FuzzParseDCAPIRequestData(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fuzz-verifier"},
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		f.Fatalf("CreateCertificate: %v", err)
	}
	hash := sha256.Sum256(der)
	clientID := "x509_hash:" + base64.RawURLEncoding.EncodeToString(hash[:])
	const seedOrigin = "https://verifier.example.com"
	meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{"urn:eudi:pid:1"}})
	if err != nil {
		f.Fatalf("NewSDJWTVCMeta: %v", err)
	}
	built, err := testverifier.New(f).BuildDCAPIAuthorizationRequest(verifier.BuildDCAPIAuthorizationRequestRequest{
		Query:           dcql.Query{Credentials: []dcql.CredentialQuery{{ID: "cred1", Format: "dc+sd-jwt", Meta: meta}}},
		ExpectedOrigins: []string{seedOrigin},
	})
	if err != nil {
		f.Fatalf("BuildDCAPIAuthorizationRequest: %v", err)
	}
	_, rawPayload, err := jose.DecodeUnverified(built.RequestObject)
	if err != nil {
		f.Fatalf("DecodeUnverified: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(rawPayload, &claims); err != nil {
		f.Fatalf("unmarshal payload: %v", err)
	}
	f.Add(uint8(0), rawPayload, seedOrigin)

	claims["client_id"] = clientID
	signedPayload, _ := json.Marshal(claims)
	signed, err := jose.Sign(jose.ES256, key, map[string]any{"typ": "oauth-authz-req+jwt", "x5c": []string{base64.StdEncoding.EncodeToString(der)}}, signedPayload)
	if err != nil {
		f.Fatalf("sign: %v", err)
	}
	signedData, _ := json.Marshal(map[string]string{"request": signed})
	f.Add(uint8(1), signedData, seedOrigin)

	delete(claims, "client_id")
	multiPayload, _ := json.Marshal(claims)
	multi, err := jose.Sign(jose.ES256, key, map[string]any{"typ": "oauth-authz-req+jwt", "client_id": clientID, "x5c": []string{base64.StdEncoding.EncodeToString(der)}}, multiPayload)
	if err != nil {
		f.Fatalf("sign: %v", err)
	}
	parts := strings.Split(multi, ".")
	multiData, _ := json.Marshal(map[string]any{"request": map[string]any{"payload": parts[1], "signatures": []map[string]string{
		{"protected": parts[0], "signature": strings.Repeat("A", len(parts[2]))}, {"protected": parts[0], "signature": parts[2]},
	}}})
	f.Add(uint8(2), multiData, seedOrigin)
	f.Add(uint8(2), []byte(`{"request":{"payload":"e30","signatures":[{"protected":"e30","signature":""}]}}`), seedOrigin)

	protocols := []string{wallet.DCAPIProtocolUnsigned, wallet.DCAPIProtocolSigned, wallet.DCAPIProtocolMultiSigned}
	f.Fuzz(func(t *testing.T, which uint8, data []byte, origin string) {
		protocol := protocols[int(which)%len(protocols)]
		req, err := wallet.ParseDCAPIRequestData(wallet.ParseDCAPIRequestDataParams{
			Protocol: protocol, Data: data, Origin: origin, VerifierTrust: wallet.NoVerifierTrust{},
		})
		if err != nil {
			return
		}
		if req.Origin != origin || origin == "" || req.Nonce == "" || req.ResponseEncryptionKey == nil {
			t.Fatalf("%s: accepted request = %+v", protocol, req)
		}
		if protocol == wallet.DCAPIProtocolUnsigned && (req.ClientID != "" || req.VerifierCertificate != nil) {
			t.Fatalf("unsigned request names a Verifier: %+v", req)
		}
		if protocol != wallet.DCAPIProtocolUnsigned && (req.ClientID == "" || req.VerifierCertificate == nil) {
			t.Fatalf("%s request names no Verifier: %+v", protocol, req)
		}
	})
}
