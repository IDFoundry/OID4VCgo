package wallet_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testverify"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// dcapiForms is a Verifier's DC API request, and the material to
// re-express it as an unsigned or multi-signed request.
type dcapiForms struct {
	v      *verifier.Verifier
	built  verifier.BuildDCAPIAuthorizationRequestResult
	key    *ecdsa.PrivateKey
	cert   *x509.Certificate
	trust  wallet.VerifierTrust
	claims map[string]any
}

func newDCAPIForms(t *testing.T) dcapiForms {
	t.Helper()
	key, cert, trust := testVerifierSignerAndCert(t)
	v := newTestVerifierWith(t, key, cert)
	built, err := v.BuildDCAPIAuthorizationRequest(verifier.BuildDCAPIAuthorizationRequestRequest{
		Query: testPresentationQuery(t), ExpectedOrigins: []string{testDCAPIOrigin},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, payload, err := jose.DecodeUnverified(built.RequestObject)
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	return dcapiForms{v: v, built: built, key: key, cert: cert, trust: trust, claims: claims}
}

// unsigned is the request's parameters as an unsigned request's data,
// changed by mutate.
func (f dcapiForms) unsigned(t *testing.T, mutate func(map[string]any)) json.RawMessage {
	t.Helper()
	claims := map[string]any{}
	for k, v := range f.claims {
		claims[k] = v
	}
	if mutate != nil {
		mutate(claims)
	}
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// signer is one signature of a multi-signed request.
type signer struct {
	key      crypto.Signer
	cert     *x509.Certificate
	clientID string // "" for the certificate's own x509_hash
	corrupt  bool
}

func x509Hash(cert *x509.Certificate) string {
	h := sha256.Sum256(cert.Raw)
	return "x509_hash:" + base64.RawURLEncoding.EncodeToString(h[:])
}

// multiSigned is the request as a multi-signed request's data: its
// payload without client_id, signed by each of signers.
func (f dcapiForms) multiSigned(t *testing.T, mutate func(map[string]any), signers ...signer) json.RawMessage {
	t.Helper()
	claims := map[string]any{}
	for k, v := range f.claims {
		claims[k] = v
	}
	delete(claims, "client_id")
	if mutate != nil {
		mutate(claims)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	type signature struct {
		Protected string `json:"protected"`
		Signature string `json:"signature"`
	}
	var sigs []signature
	var encodedPayload string
	for _, s := range signers {
		clientID := s.clientID
		if clientID == "" {
			clientID = x509Hash(s.cert)
		}
		compact, err := jose.Sign(jose.ES256, s.key, map[string]any{
			"typ": "oauth-authz-req+jwt", "client_id": clientID,
			"x5c": []string{base64.StdEncoding.EncodeToString(s.cert.Raw)},
		}, payload)
		if err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(compact, ".")
		encodedPayload = parts[1]
		if s.corrupt {
			parts[2] = strings.Repeat("A", len(parts[2]))
		}
		sigs = append(sigs, signature{Protected: parts[0], Signature: parts[2]})
	}
	raw, err := json.Marshal(map[string]any{"request": map[string]any{"payload": encodedPayload, "signatures": sigs}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// answer presents the held SD-JWT VC for req and verifies the answer at
// f's Verifier.
func (f dcapiForms) answer(t *testing.T, req wallet.AuthorizationRequest) {
	t.Helper()
	fixture := newHeldSDJWTVC(t)
	vpToken, err := wallet.PresentCredentials(context.Background(), wallet.PresentationRequest{
		Query: req.Query, Credentials: []wallet.HeldCredential{fixture.held}, Origin: req.Origin, Nonce: req.Nonce,
		ResponseEncryptionKey: req.ResponseEncryptionKey,
	})
	if err != nil {
		t.Fatalf("PresentCredentials: %v", err)
	}
	response, err := wallet.BuildDirectPostResponse(wallet.BuildDirectPostResponseParams{
		VPToken: vpToken, EncryptionKey: req.ResponseEncryptionKey,
		EncryptionKeyID: req.ResponseEncryptionKeyID, EncryptionEnc: req.ResponseEncryptionEnc,
	})
	if err != nil {
		t.Fatalf("BuildDirectPostResponse: %v", err)
	}
	parsed, err := f.v.ParseDirectPostJWTResponse(response, f.built.ResponseDecryptionKey)
	if err != nil {
		t.Fatalf("ParseDirectPostJWTResponse: %v", err)
	}
	result, err := f.v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query: testPresentationQuery(t), Response: parsed, ExpectedNonce: f.built.Nonce, Origin: testDCAPIOrigin, ExpectedOrigins: []string{testDCAPIOrigin}, MaxKeyBindingAge: time.Hour,
		IssuerKeys: issuerKeyResolverFunc(func(context.Context, map[string]any, map[string]any) (crypto.PublicKey, jose.Alg, error) {
			return &fixture.issuerKey.PublicKey, jose.ES256, nil
		}),
	})
	testverify.RequireOneCredential(t, result, err, "identity_credential")
}

// An unsigned request is identified by its origin alone: its client_id
// and expected_origins are ignored (OID4VP Appendix A.2), and the answer
// is bound to the origin.
func TestParseDCAPIRequestData_Unsigned(t *testing.T) {
	f := newDCAPIForms(t)
	data := f.unsigned(t, func(c map[string]any) { c["expected_origins"] = []string{"https://elsewhere.example"} })
	req, err := wallet.ParseDCAPIRequestData(wallet.ParseDCAPIRequestDataParams{
		Protocol: wallet.DCAPIProtocolUnsigned, Data: data, Origin: testDCAPIOrigin,
	})
	if err != nil {
		t.Fatal(err)
	}
	if req.ClientID != "" || req.VerifierCertificate != nil || req.Origin != testDCAPIOrigin || req.Nonce != f.built.Nonce {
		t.Fatalf("request = %+v", req)
	}
	f.answer(t, req)
}

// A multi-signed request is authenticated by the first signature the
// Wallet trusts that verifies: others — another trust framework's, or
// an invalid one — are skipped.
func TestParseDCAPIRequestData_MultiSigned(t *testing.T) {
	f := newDCAPIForms(t)
	otherKey, otherCert, _ := testVerifierSignerAndCert(t)
	for name, signers := range map[string][]signer{
		"untrusted first": {{key: otherKey, cert: otherCert}, {key: f.key, cert: f.cert}},
		"invalid first":   {{key: f.key, cert: f.cert, corrupt: true}, {key: f.key, cert: f.cert}},
		"trusted only":    {{key: f.key, cert: f.cert}},
	} {
		t.Run(name, func(t *testing.T) {
			req, err := wallet.ParseDCAPIRequestData(wallet.ParseDCAPIRequestDataParams{
				Protocol: wallet.DCAPIProtocolMultiSigned, Data: f.multiSigned(t, nil, signers...), Origin: testDCAPIOrigin, VerifierTrust: f.trust,
			})
			if err != nil {
				t.Fatal(err)
			}
			if req.ClientID != f.built.ClientID || !req.VerifierCertificate.Equal(f.cert) {
				t.Fatalf("ClientID %q, want %q", req.ClientID, f.built.ClientID)
			}
			f.answer(t, req)
		})
	}
}

func TestParseDCAPIRequestData_Signed(t *testing.T) {
	f := newDCAPIForms(t)
	data, _ := json.Marshal(map[string]string{"request": f.built.RequestObject})
	req, err := wallet.ParseDCAPIRequestData(wallet.ParseDCAPIRequestDataParams{
		Protocol: wallet.DCAPIProtocolSigned, Data: data, Origin: testDCAPIOrigin, VerifierTrust: f.trust,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.answer(t, req)
}

func TestParseDCAPIRequestData_Refusals(t *testing.T) {
	f := newDCAPIForms(t)
	otherKey, otherCert, _ := testVerifierSignerAndCert(t)
	me := signer{key: f.key, cert: f.cert}
	for name, tc := range map[string]struct {
		params wallet.ParseDCAPIRequestDataParams
		want   string
	}{
		"unsigned without a nonce": {wallet.ParseDCAPIRequestDataParams{Protocol: wallet.DCAPIProtocolUnsigned, Origin: testDCAPIOrigin,
			Data: f.unsigned(t, func(c map[string]any) { delete(c, "nonce") })}, "nonce"},
		"unsigned dc_api": {wallet.ParseDCAPIRequestDataParams{Protocol: wallet.DCAPIProtocolUnsigned, Origin: testDCAPIOrigin,
			Data: f.unsigned(t, func(c map[string]any) { c["response_mode"] = "dc_api" })}, "response_mode"},
		"unsigned without client_metadata": {wallet.ParseDCAPIRequestDataParams{Protocol: wallet.DCAPIProtocolUnsigned, Origin: testDCAPIOrigin,
			Data: f.unsigned(t, func(c map[string]any) { delete(c, "client_metadata") })}, "client_metadata"},
		"no origin":        {wallet.ParseDCAPIRequestDataParams{Protocol: wallet.DCAPIProtocolUnsigned, Data: f.unsigned(t, nil)}, "Origin is required"},
		"unknown protocol": {wallet.ParseDCAPIRequestDataParams{Protocol: "openid4vp-v2", Origin: testDCAPIOrigin, Data: f.unsigned(t, nil)}, "unsupported protocol"},
		"signed without request": {wallet.ParseDCAPIRequestDataParams{Protocol: wallet.DCAPIProtocolSigned, Origin: testDCAPIOrigin, VerifierTrust: f.trust,
			Data: json.RawMessage(`{}`)}, "data.request"},
		"multi-signed, none trusted": {wallet.ParseDCAPIRequestDataParams{Protocol: wallet.DCAPIProtocolMultiSigned, Origin: testDCAPIOrigin, VerifierTrust: f.trust,
			Data: f.multiSigned(t, nil, signer{key: otherKey, cert: otherCert})}, "no signature verifies"},
		"multi-signed, all invalid": {wallet.ParseDCAPIRequestDataParams{Protocol: wallet.DCAPIProtocolMultiSigned, Origin: testDCAPIOrigin, VerifierTrust: f.trust,
			Data: f.multiSigned(t, nil, signer{key: f.key, cert: f.cert, corrupt: true})}, "no signature verifies"},
		"multi-signed, wrong client_id": {wallet.ParseDCAPIRequestDataParams{Protocol: wallet.DCAPIProtocolMultiSigned, Origin: testDCAPIOrigin, VerifierTrust: f.trust,
			Data: f.multiSigned(t, nil, signer{key: f.key, cert: f.cert, clientID: "x509_hash:other"})}, "no signature verifies"},
		"multi-signed, client_id in payload": {wallet.ParseDCAPIRequestDataParams{Protocol: wallet.DCAPIProtocolMultiSigned, Origin: testDCAPIOrigin, VerifierTrust: f.trust,
			Data: f.multiSigned(t, func(c map[string]any) { c["client_id"] = f.built.ClientID }, me)}, "protected headers"},
		"multi-signed, another origin": {wallet.ParseDCAPIRequestDataParams{Protocol: wallet.DCAPIProtocolMultiSigned, Origin: "https://attacker.example", VerifierTrust: f.trust,
			Data: f.multiSigned(t, nil, me)}, "expected_origins"},
		"multi-signed, not JWS JSON": {wallet.ParseDCAPIRequestDataParams{Protocol: wallet.DCAPIProtocolMultiSigned, Origin: testDCAPIOrigin, VerifierTrust: f.trust,
			Data: json.RawMessage(`{"request":"eyJ"}`)}, "JWS JSON"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := wallet.ParseDCAPIRequestData(tc.params)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want one mentioning %q", err, tc.want)
			}
		})
	}
}

// The Wallet method needs VerifierTrust only for signed forms.
func TestWallet_ParseDCAPIRequestData(t *testing.T) {
	f := newDCAPIForms(t)
	w := newTestWalletTrusting(t, nil, nil)
	if _, err := w.ParseDCAPIRequestData(wallet.DCAPIProtocolUnsigned, f.unsigned(t, nil), testDCAPIOrigin); err != nil {
		t.Errorf("unsigned without VerifierTrust: %v", err)
	}
	if _, err := w.ParseDCAPIRequestData(wallet.DCAPIProtocolMultiSigned, f.multiSigned(t, nil, signer{key: f.key, cert: f.cert}), testDCAPIOrigin); err == nil ||
		!strings.Contains(err.Error(), "VerifierTrust is required") {
		t.Errorf("multi-signed without VerifierTrust: %v", err)
	}
	if _, err := newTestWalletTrusting(t, f.trust, nil).ParseDCAPIRequestData(wallet.DCAPIProtocolMultiSigned,
		f.multiSigned(t, nil, signer{key: f.key, cert: f.cert}), testDCAPIOrigin); err != nil {
		t.Errorf("multi-signed with VerifierTrust: %v", err)
	}
}

// A request without a nonce is answered with invalid_request, in every
// form, as the redirect flow answers it.
func TestParseDCAPIRequestData_MissingNonceIsAnErrorResponse(t *testing.T) {
	f := newDCAPIForms(t)
	noNonce := func(c map[string]any) { delete(c, "nonce") }
	signed := resign(t, f.key, f.built.RequestObject, noNonce)
	signedData, _ := json.Marshal(map[string]string{"request": signed})
	for protocol, data := range map[string]json.RawMessage{
		wallet.DCAPIProtocolUnsigned:    f.unsigned(t, noNonce),
		wallet.DCAPIProtocolSigned:      signedData,
		wallet.DCAPIProtocolMultiSigned: f.multiSigned(t, noNonce, signer{key: f.key, cert: f.cert}),
	} {
		_, err := wallet.ParseDCAPIRequestData(wallet.ParseDCAPIRequestDataParams{
			Protocol: protocol, Data: data, Origin: testDCAPIOrigin, VerifierTrust: f.trust,
		})
		var rejected *wallet.RequestRejectedError
		if !errors.As(err, &rejected) || rejected.Code != "invalid_request" || rejected.ResponseEncryptionKey == nil {
			t.Errorf("%s: err = %v, want an invalid_request error response", protocol, err)
		}
	}
}

// RequireSignedDCAPIRequests refuses an unsigned request as from an
// untrusted Verifier; signed ones are unaffected.
func TestWallet_RequireSignedDCAPIRequests(t *testing.T) {
	f := newDCAPIForms(t)
	cfg := validConfig()
	cfg.VerifierTrust, cfg.RequireSignedDCAPIRequests = f.trust, true
	w, err := wallet.New(cfg, wallet.Dependencies{HTTP: fakeHTTPClient{}, Clock: wallet.ClockFunc(time.Now)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.ParseDCAPIRequestData(wallet.DCAPIProtocolUnsigned, f.unsigned(t, nil), testDCAPIOrigin); !errors.Is(err, wallet.ErrUntrustedVerifier) {
		t.Errorf("unsigned: %v, want ErrUntrustedVerifier", err)
	}
	if _, err := w.ParseDCAPIRequestData(wallet.DCAPIProtocolMultiSigned, f.multiSigned(t, nil, signer{key: f.key, cert: f.cert}), testDCAPIOrigin); err != nil {
		t.Errorf("multi-signed: %v", err)
	}
}

func TestParseDCAPIRequestData_Limits(t *testing.T) {
	f := newDCAPIForms(t)
	me := signer{key: f.key, cert: f.cert}
	signers := make([]signer, wallet.MaxDCAPISignatures+1)
	for i := range signers {
		signers[i] = me
	}
	if _, err := wallet.ParseDCAPIRequestData(wallet.ParseDCAPIRequestDataParams{
		Protocol: wallet.DCAPIProtocolMultiSigned, Data: f.multiSigned(t, nil, signers...), Origin: testDCAPIOrigin, VerifierTrust: f.trust,
	}); err == nil || !strings.Contains(err.Error(), "signatures, more than") {
		t.Errorf("too many signatures: %v", err)
	}
	big := json.RawMessage(`{"padding":"` + strings.Repeat("a", wallet.MaxDCAPIRequestBytes) + `"}`)
	if _, err := wallet.ParseDCAPIRequestData(wallet.ParseDCAPIRequestDataParams{
		Protocol: wallet.DCAPIProtocolUnsigned, Data: big, Origin: testDCAPIOrigin,
	}); err == nil || !strings.Contains(err.Error(), "bytes, more than") {
		t.Errorf("too large: %v", err)
	}
}
