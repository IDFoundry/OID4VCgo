package walletflowtest

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// DCAPIRequest is a signed OpenID4VP request for the Digital
// Credentials API (OpenID4VP 1.0 Appendix A), as a page at Origin hands
// it to the platform: Protocol and Data are what the platform gives the
// wallet.
type DCAPIRequest struct {
	Protocol string
	Data     []byte
	Origin   string

	query dcql.Query
	nonce string
	key   *ecdsa.PrivateKey
}

// BeginDCAPI builds a signed DC API request for query, from a page at
// origin (expected_origins).
func (v *Verifier) BeginDCAPI(query dcql.Query, origin string) (*DCAPIRequest, error) {
	built, err := v.v.BuildDCAPIAuthorizationRequest(verifier.BuildDCAPIAuthorizationRequestRequest{Query: query, ExpectedOrigins: []string{origin}})
	if err != nil {
		return nil, fmt.Errorf("walletflowtest: %w", err)
	}
	data, err := json.Marshal(map[string]string{"request": built.RequestObject})
	if err != nil {
		return nil, fmt.Errorf("walletflowtest: %w", err)
	}
	return &DCAPIRequest{
		Protocol: wallet.DCAPIProtocolSigned, Data: data, Origin: origin,
		query: query, nonce: built.Nonce, key: built.ResponseDecryptionKey,
	}, nil
}

// VerifyDCAPIResponse decrypts and verifies the wallet's answer to r,
// the data it handed back to the platform ({"response": JWE}), as the
// page would. An error response is a *verifier.ResponseError.
func (v *Verifier) VerifyDCAPIResponse(ctx context.Context, r *DCAPIRequest, data []byte) (verifier.VerifyResponseResult, error) {
	var answer struct {
		Response string `json:"response"`
	}
	if err := json.Unmarshal(data, &answer); err != nil || answer.Response == "" {
		return verifier.VerifyResponseResult{}, errors.New("walletflowtest: the DC API response's data isn't {\"response\": JWE}")
	}
	parsed, err := v.v.ParseDirectPostJWTResponse(answer.Response, r.key)
	if err != nil {
		return verifier.VerifyResponseResult{}, fmt.Errorf("walletflowtest: %w", err)
	}
	req := v.verify
	req.Query, req.Response, req.ExpectedNonce = r.query, parsed, r.nonce
	req.Origin, req.ExpectedOrigins, req.ResponseEncryptionKey = r.Origin, []string{r.Origin}, r.key
	result, err := v.v.VerifyResponse(ctx, req)
	if err != nil {
		return verifier.VerifyResponseResult{}, fmt.Errorf("walletflowtest: %w", err)
	}
	return result, nil
}
