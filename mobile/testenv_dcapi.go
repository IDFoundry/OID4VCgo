//go:build mobiletest

package mobile

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// DCAPIRequest has the Verifier, from a page at origin, ask over the
// Digital Credentials API for family_name from an SD-JWT VC
// ("dc+sd-jwt") or an mdoc ("mso_mdoc"), signed (signedRequest) or
// not, and returns
// {"id", "protocol", "data", "origin"}: data is the request's, a JSON
// object as text, as the platform hands it over.
func (e *TestEnv) DCAPIRequest(format, origin string, signedRequest bool) (string, error) {
	var q dcql.CredentialQuery
	var err error
	if format == "mso_mdoc" {
		q, err = walletflowtest.MdocQuery("mdl", "family_name")
	} else {
		q, err = e.env.SDJWTQuery("pid", "family_name")
	}
	if err != nil {
		return "", wrapTest(err)
	}
	r, err := e.v.BeginDCAPI(dcql.Query{Credentials: []dcql.CredentialQuery{q}}, origin)
	if err != nil {
		return "", wrapTest(err)
	}
	protocol, data := r.Protocol, r.Data
	if !signedRequest {
		if protocol, data, err = unsigned(data); err != nil {
			return "", wrapTest(err)
		}
	}
	e.mu.Lock()
	id := "dcapi-" + strconv.Itoa(len(e.dcapi)+1)
	e.dcapi[id] = r
	e.mu.Unlock()
	return marshal(map[string]string{"id": id, "protocol": protocol, "data": string(data), "origin": origin})
}

// DCAPIResult is what the page makes of the wallet's answer to request
// id, responseData being the dcapi_response the wallet returned:
// {"status": "done", "claims": {…}}, or {"status": "error", "error":
// the OAuth error code, or the reason it was refused}.
func (e *TestEnv) DCAPIResult(id, responseData string) (string, error) {
	e.mu.Lock()
	r := e.dcapi[id]
	e.mu.Unlock()
	if r == nil {
		return "", newError(CodeNotFound, errors.New("no such DC API request"))
	}
	result, err := e.v.VerifyDCAPIResponse(context.Background(), r, []byte(responseData))
	var refusal *verifier.ResponseError
	switch {
	case errors.As(err, &refusal):
		return marshal(map[string]any{"status": "error", "error": refusal.Code})
	case err != nil:
		return marshal(map[string]any{"status": "error", "error": err.Error()})
	case len(result.Credentials) == 0:
		return marshal(map[string]any{"status": "error", "error": "no credentials"})
	}
	return marshal(map[string]any{"status": "done", "claims": result.Credentials[0].Claims})
}

// unsigned is a signed DC API request's data as an unsigned request's:
// its Request Object's claims, without client_id or expected_origins.
func unsigned(signed []byte) (string, []byte, error) {
	var data struct {
		Request string `json:"request"`
	}
	if err := json.Unmarshal(signed, &data); err != nil {
		return "", nil, err
	}
	parts := strings.Split(data.Request, ".")
	if len(parts) != 3 {
		return "", nil, errors.New("not a JWS")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", nil, err
	}
	delete(claims, "client_id")
	delete(claims, "expected_origins")
	out, err := json.Marshal(claims)
	return wallet.DCAPIProtocolUnsigned, out, err
}
