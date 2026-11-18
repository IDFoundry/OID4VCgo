package wallet_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// A signed or multi-signed DC API request from a page it doesn't name in
// expected_origins is refused before its signature or chain is checked,
// with one plain error whatever else is wrong with it (OpenID4VP 1.0
// Appendix A.2): never a *RequestRejectedError, which the page is
// answered with, and the same whether or not the Wallet trusts the
// Verifier. Otherwise any page could replay a Verifier's request, its
// redirect-flow Request Object say, and learn from the answer which
// Verifiers the Wallet trusts (audit 2026-11-18, WVP-1).
func TestParseDCAPIRequestData_AnotherOriginLearnsNothing(t *testing.T) {
	const page = "https://attacker.example"
	f := newDCAPIForms(t)
	otherKey, otherCert, otherTrust := testVerifierSignerAndCert(t)
	other := newTestVerifierWith(t, otherKey, otherCert)
	me := signer{key: f.key, cert: f.cert}
	stranger := signer{key: otherKey, cert: otherCert}

	signed := func(requestObject string) json.RawMessage {
		return mustJSON(t, map[string]string{"request": requestObject})
	}
	redirectObject := func(v *verifier.Verifier) string {
		t.Helper()
		built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: testPresentationQuery(t)})
		if err != nil {
			t.Fatal(err)
		}
		return built.RequestObject
	}
	otherDCAPI, err := other.BuildDCAPIAuthorizationRequest(verifier.BuildDCAPIAuthorizationRequestRequest{
		Query: testPresentationQuery(t), ExpectedOrigins: []string{testDCAPIOrigin},
	})
	if err != nil {
		t.Fatal(err)
	}
	redirectMode := func(c map[string]any) { c["response_mode"] = "direct_post.jwt" }

	// Each is refused from the origins it names with a
	// *RequestRejectedError, or is a request the trusting Wallet answers.
	type request struct {
		protocol string
		data     json.RawMessage
	}
	requests := map[string]request{
		"signed, DC API":                    {wallet.DCAPIProtocolSigned, signed(f.built.RequestObject)},
		"signed, untrusted DC API":          {wallet.DCAPIProtocolSigned, signed(otherDCAPI.RequestObject)},
		"signed, redirect flow":             {wallet.DCAPIProtocolSigned, signed(redirectObject(f.v))},
		"signed, untrusted redirect flow":   {wallet.DCAPIProtocolSigned, signed(redirectObject(other))},
		"signed, redirect mode":             {wallet.DCAPIProtocolSigned, signed(resign(t, f.key, f.built.RequestObject, redirectMode))},
		"signed, response_type code":        {wallet.DCAPIProtocolSigned, signed(resign(t, f.key, f.built.RequestObject, func(c map[string]any) { c["response_type"] = "code" }))},
		"signed, no nonce":                  {wallet.DCAPIProtocolSigned, signed(resign(t, f.key, f.built.RequestObject, func(c map[string]any) { delete(c, "nonce") }))},
		"signed, transaction_data":          {wallet.DCAPIProtocolSigned, signed(resign(t, f.key, f.built.RequestObject, func(c map[string]any) { c["transaction_data"] = []string{"e30"} }))},
		"multi-signed":                      {wallet.DCAPIProtocolMultiSigned, f.multiSigned(t, nil, me)},
		"multi-signed, untrusted first":     {wallet.DCAPIProtocolMultiSigned, f.multiSigned(t, nil, stranger, me)},
		"multi-signed, untrusted only":      {wallet.DCAPIProtocolMultiSigned, f.multiSigned(t, nil, stranger)},
		"multi-signed, redirect mode":       {wallet.DCAPIProtocolMultiSigned, f.multiSigned(t, redirectMode, stranger, me)},
		"multi-signed, no expected_origins": {wallet.DCAPIProtocolMultiSigned, f.multiSigned(t, func(c map[string]any) { redirectMode(c); delete(c, "expected_origins") }, me)},
		"multi-signed, no nonce":            {wallet.DCAPIProtocolMultiSigned, f.multiSigned(t, func(c map[string]any) { delete(c, "nonce") }, me)},
	}
	for name, r := range requests {
		t.Run(name, func(t *testing.T) {
			var errs []error
			for _, trust := range []wallet.VerifierTrust{f.trust, otherTrust} {
				for _, sanDNS := range []bool{false, true} {
					var calls int
					_, err := wallet.ParseDCAPIRequestData(wallet.ParseDCAPIRequestDataParams{
						Protocol: r.protocol, Data: r.data, Origin: page,
						VerifierTrust: countingTrust{trust, &calls}, AcceptX509SANDNS: sanDNS,
					})
					switch {
					case err == nil:
						t.Fatal("accepted from a page it doesn't name")
					case errors.As(err, new(*wallet.RequestRejectedError)):
						t.Fatalf("refused with an answer for the page: %v", err)
					case errors.Is(err, wallet.ErrUntrustedVerifier):
						t.Fatalf("refused as untrusted, which a page it names alone may learn: %v", err)
					case !strings.Contains(err.Error(), "expected_origins"):
						t.Fatalf("err = %v, want the origin refused", err)
					case calls != 0:
						t.Fatalf("VerifierTrust asked about %d chains before the origin was checked", calls)
					}
					errs = append(errs, err)
				}
			}
			for _, err := range errs[1:] {
				if err.Error() != errs[0].Error() {
					t.Errorf("refused as %q and as %q, depending on the Wallet's trust", errs[0], err)
				}
			}
		})
	}

	// From the origin it names, a trusted request in another mode is
	// still answered with invalid_request for the page (Appendix A.4).
	for _, name := range []string{"signed, redirect mode", "multi-signed, redirect mode"} {
		r := requests[name]
		_, err := wallet.ParseDCAPIRequestData(wallet.ParseDCAPIRequestDataParams{
			Protocol: r.protocol, Data: r.data, Origin: testDCAPIOrigin, VerifierTrust: f.trust,
		})
		var rejected *wallet.RequestRejectedError
		if !errors.As(err, &rejected) || rejected.Code != "invalid_request" {
			t.Errorf("%s, from the origin it names: err = %v, want invalid_request for the page", name, err)
		}
	}
}

// expected_origins is read before the signature is checked only to pick
// the error: a payload altered to name the calling page fails its
// signature, and is neither accepted nor answered.
func TestParseDCAPIRequestData_OriginReadBeforeSignatureDecidesNothing(t *testing.T) {
	const page = "https://attacker.example"
	f := newDCAPIForms(t)
	forge := func(payloadSegment string) string {
		t.Helper()
		raw, err := base64.RawURLEncoding.DecodeString(payloadSegment)
		if err != nil {
			t.Fatal(err)
		}
		var claims map[string]any
		if err := json.Unmarshal(raw, &claims); err != nil {
			t.Fatal(err)
		}
		claims["expected_origins"] = []string{page}
		return base64.RawURLEncoding.EncodeToString(mustJSON(t, claims))
	}

	parts := strings.Split(f.built.RequestObject, ".")
	parts[1] = forge(parts[1])
	signedData := mustJSON(t, map[string]string{"request": strings.Join(parts, ".")})

	var multi struct {
		Request struct {
			Payload    string            `json:"payload"`
			Signatures []json.RawMessage `json:"signatures"`
		} `json:"request"`
	}
	if err := json.Unmarshal(f.multiSigned(t, nil, signer{key: f.key, cert: f.cert}), &multi); err != nil {
		t.Fatal(err)
	}
	multi.Request.Payload = forge(multi.Request.Payload)

	for protocol, data := range map[string]json.RawMessage{
		wallet.DCAPIProtocolSigned:      signedData,
		wallet.DCAPIProtocolMultiSigned: mustJSON(t, multi),
	} {
		_, err := wallet.ParseDCAPIRequestData(wallet.ParseDCAPIRequestDataParams{
			Protocol: protocol, Data: data, Origin: page, VerifierTrust: f.trust,
		})
		if err == nil || errors.As(err, new(*wallet.RequestRejectedError)) || !strings.Contains(err.Error(), "signature") {
			t.Errorf("%s naming the page in a forged payload: err = %v, want its signature refused", protocol, err)
		}
	}
}
