package main

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"

	"github.com/idfoundry/oid4vcgo/wallet"
)

// dcapiRequest is what handleDCAPI takes: one of the DC API request's
// requests ({"protocol", "data"}), and the origin the browser would
// report for the page that made it.
type dcapiRequest struct {
	Protocol string          `json:"protocol"`
	Data     json.RawMessage `json:"data"`
	Origin   string          `json:"origin"`
}

// dcapiResult is exactly what the suite's
// log-detail page POSTs to its submit URL after navigator.credentials.get
// — the DigitalCredential's {"data", "protocol"}, or {"exception"} when
// the call's promise rejects.
type dcapiResult struct {
	Protocol  string          `json:"protocol,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
	Exception *dcapiException `json:"exception,omitempty"`
}

// dcapiAnswer is handleDCAPI's response: Result, for the driver to
// submit to the suite, and the error code when Result is an error
// response, for the driver to grade negative tests by (it can't read
// the encrypted response).
type dcapiAnswer struct {
	Result    dcapiResult `json:"result"`
	SentError string      `json:"sent_error,omitempty"`
}

type dcapiException struct {
	Name    string `json:"name"`
	Message string `json:"message"`
}

// maxDCAPIRequestBytes bounds handleDCAPI's request body.
const maxDCAPIRequestBytes = 1 << 20

// handleDCAPI answers an OpenID4VP request delivered over the Digital
// Credentials API (OID4VP Appendix A) as a platform wallet would, for
// the dc_api.jwt module lists of the HAIP wallet plan: the driver
// (conformance/wallet-vp/scripts/run-modules -response-mode dc_api.jwt)
// stands in for the browser, passing the request and origin here and
// the result on to the suite. It parses the request in whichever form
// it arrives (wallet.ParseDCAPIRequestData), presents the fixture
// credential bound to the origin, and returns its encrypted response.
// A request the wallet rejects with a protocol error is answered with
// that error, encrypted the same way; one it can't trust at all (a bad
// signature, an untrusted or mismatched client) is answered with no
// response — the browser's promise rejects — as a wallet would only
// show the holder an error.
func (s *server) handleDCAPI(w http.ResponseWriter, r *http.Request) {
	var req dcapiRequest
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxDCAPIRequestBytes))
	if err != nil || json.Unmarshal(body, &req) != nil {
		http.Error(w, "body must be {\"protocol\", \"data\", \"origin\"}", http.StatusBadRequest)
		return
	}
	writeJSON(w, s.answerDCAPI(r, req))
}

func (s *server) answerDCAPI(r *http.Request, req dcapiRequest) dcapiAnswer {
	authReq, err := wallet.ParseDCAPIRequestData(wallet.ParseDCAPIRequestDataParams{
		Protocol: req.Protocol, Data: req.Data, Origin: req.Origin, VerifierTrust: s.trust,
	})
	if err != nil {
		log.Printf("parse dc api request: %v", err)
		var rejected *wallet.RequestRejectedError
		if errors.As(err, &rejected) {
			return s.dcapiError(req.Protocol, errorResponseParams{
				encryptionKey: rejected.ResponseEncryptionKey, encryptionKeyID: rejected.ResponseEncryptionKeyID,
				encryptionEnc: rejected.ResponseEncryptionEnc, code: rejected.Code, description: rejected.Description,
			})
		}
		return dcapiAnswer{Result: dcapiResult{Exception: &dcapiException{Name: "NotAllowedError", Message: err.Error()}}}
	}
	vpToken, err := wallet.PresentCredentials(r.Context(), wallet.PresentationRequest{
		Query: authReq.Query, Credentials: []wallet.HeldCredential{s.cred},
		Origin: authReq.Origin, Nonce: authReq.Nonce, ResponseEncryptionKey: authReq.ResponseEncryptionKey,
	})
	if err != nil {
		log.Printf("present credentials: %v", err)
		code := "invalid_request"
		if errors.Is(err, wallet.ErrNoMatchingCredential) {
			code = "access_denied"
		}
		return s.dcapiError(req.Protocol, errorResponseParams{
			encryptionKey: authReq.ResponseEncryptionKey, encryptionKeyID: authReq.ResponseEncryptionKeyID,
			encryptionEnc: authReq.ResponseEncryptionEnc, code: code, description: err.Error(),
		})
	}
	responseJWE, err := wallet.BuildDirectPostResponse(wallet.BuildDirectPostResponseParams{
		VPToken: vpToken, EncryptionKey: authReq.ResponseEncryptionKey,
		EncryptionKeyID: authReq.ResponseEncryptionKeyID, EncryptionEnc: authReq.ResponseEncryptionEnc,
	})
	if err != nil {
		log.Printf("build dc_api.jwt response: %v", err)
		return dcapiAnswer{Result: dcapiResult{Exception: &dcapiException{Name: "UnknownError", Message: err.Error()}}}
	}
	return dcapiAnswer{Result: dcapiResponse(req.Protocol, responseJWE)}
}

// dcapiError is an error response for the DC API: the Authorization
// Error Response, encrypted as dc_api.jwt encrypts every response
// (OID4VP §8.3), in data's "response".
func (s *server) dcapiError(protocol string, p errorResponseParams) dcapiAnswer {
	responseJWE, err := wallet.BuildDirectPostErrorResponse(wallet.BuildDirectPostErrorResponseParams{
		Error: p.code, ErrorDescription: p.description,
		EncryptionKey: p.encryptionKey, EncryptionKeyID: p.encryptionKeyID, EncryptionEnc: p.encryptionEnc,
	})
	if err != nil {
		log.Printf("build dc_api.jwt error response: %v", err)
		return dcapiAnswer{Result: dcapiResult{Exception: &dcapiException{Name: "UnknownError", Message: err.Error()}}}
	}
	log.Printf("sent dc api error response: %s: %s", p.code, p.description)
	return dcapiAnswer{Result: dcapiResponse(protocol, responseJWE), SentError: p.code}
}

func dcapiResponse(protocol, responseJWE string) dcapiResult {
	data, _ := json.Marshal(map[string]string{"response": responseJWE})
	return dcapiResult{Protocol: protocol, Data: data}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set(contentTypeHeader, "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
