package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/idfoundry/oid4vcgo/mdocdcapi"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// mdocProtocol is the Digital Credentials API protocol of ISO/IEC TS
// 18013-7 Annex C.
const mdocProtocol = "org-iso-mdoc"

// dcapiRequest is what a browser's navigator.credentials.get() hands
// the platform, as -dcapi's file holds it: the request's protocol and
// data, and the page's origin.
type dcapiRequest struct {
	Protocol string          `json:"protocol"`
	Data     json.RawMessage `json:"data"`
	Origin   string          `json:"origin"`
}

// dcapiAnswer is what the wallet hands back to the page: the
// response's data, which the page posts to the Verifier, and, for an
// org-iso-mdoc request, the reader it recognized ("" for none).
type dcapiAnswer struct {
	Data   json.RawMessage `json:"data"`
	Reader string          `json:"reader,omitempty"`
}

// presentDCAPI answers the Digital Credentials API request in file as
// the platform hands it to the wallet: an OpenID4VP one
// (openid4vp-v1-*) through StartDCAPIPresentation, an org-iso-mdoc one
// through StartMdocPresentation, each with the held credentials it
// asks for, all it asks of them disclosed. No request is fetched and
// nothing is sent: the page posts res.DCAPI.Data on.
func presentDCAPI(ctx context.Context, w *walletflow.Wallet, file string, res *result) error {
	res.Stage = "request"
	raw, err := os.ReadFile(file) // #nosec G304 -- the operator's own file
	if err != nil {
		return err
	}
	var req dcapiRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("-dcapi %s: %w", file, err)
	}
	if req.Protocol == mdocProtocol {
		return presentMdocDCAPI(ctx, w, req, res)
	}
	p, err := w.StartDCAPIPresentation(ctx, req.Protocol, req.Data, req.Origin)
	if err != nil {
		return err
	}
	res.Stage = "selection"
	sel, err := p.DefaultSelection(ctx)
	if err != nil {
		return err
	}
	res.Stage = "response"
	presented, err := p.Respond(ctx, sel)
	if err != nil {
		return err
	}
	res.QueryIDs = presented.QueryIDs
	res.DCAPI = &dcapiAnswer{Data: presented.DCAPIResponse}
	return nil
}

// presentMdocDCAPI answers an org-iso-mdoc request with the first held
// mdoc of each requested document, disclosing every element asked for.
func presentMdocDCAPI(ctx context.Context, w *walletflow.Wallet, req dcapiRequest, res *result) error {
	p, err := w.StartMdocPresentation(ctx, req.Data, req.Origin)
	if err != nil {
		return err
	}
	answer := &dcapiAnswer{}
	if c := p.Reader(); c != nil {
		answer.Reader = c.Subject.CommonName
	}
	res.Stage = "selection"
	var answers []walletflow.MdocAnswer
	for i, r := range p.Requests() {
		if len(r.Credentials) == 0 {
			continue
		}
		elements := make([][2]string, 0, len(r.Elements))
		for _, e := range r.Elements {
			elements = append(elements, [2]string{e.Namespace, e.Identifier})
		}
		answers = append(answers, walletflow.MdocAnswer{Request: i, CredentialID: r.Credentials[0].ID, Elements: elements})
		res.QueryIDs = append(res.QueryIDs, r.DocType)
	}
	if len(answers) == 0 {
		return fmt.Errorf("no held mdoc answers the org-iso-mdoc request")
	}
	res.Stage = "response"
	presented, err := p.RespondDocuments(ctx, answers)
	if err != nil {
		return err
	}
	answer.Data = mdocdcapi.ResponseData(presented.EncryptedResponse)
	res.DCAPI = answer
	return nil
}
