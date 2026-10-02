package mobile

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// Presentation answers one OpenID4VP Authorization Request
// (walletflow.Presentation): show Verifier and Candidates, Preview the
// holder's choice, then Respond or Decline.
type Presentation struct {
	p *walletflow.Presentation
}

// StartPresentation fetches and verifies the request requestLink (an
// openid4vp:// link) from a Verifier the configuration's verifier_roots
// trust, and finds the credentials that can answer it.
func (w *Wallet) StartPresentation(op *Operation, requestLink string) (*Presentation, error) {
	p, err := w.w.StartPresentation(op.context(), requestLink)
	if err != nil {
		return nil, classify(err)
	}
	return &Presentation{p: p}, nil
}

// Verifier returns who's asking: {"abi", "client_id", "name",
// "response_uri"}.
func (p *Presentation) Verifier() string {
	v := p.p.Verifier()
	text, _ := marshal(struct {
		result
		ClientID    string `json:"client_id"`
		Name        string `json:"name"`
		ResponseURI string `json:"response_uri"`
	}{result{ABIVersion}, v.ClientID, v.Name, v.ResponseURI})
	return text
}

type candidatesJSON struct {
	QueryID     string              `json:"query_id"`
	Credentials []credentialSummary `json:"credentials"`
}

// Candidates returns {"abi", "queries": [{"query_id", "credentials":
// [summary]}]}: for each of the request's credential queries the
// wallet can answer, the credentials that can answer it. None means
// Decline.
func (p *Presentation) Candidates() string {
	out := struct {
		result
		Queries []candidatesJSON `json:"queries"`
	}{result: result{ABIVersion}, Queries: []candidatesJSON{}}
	for _, c := range p.p.Candidates() {
		out.Queries = append(out.Queries, candidatesJSON{QueryID: c.QueryID, Credentials: summariesOf(c.Credentials)})
	}
	text, _ := marshal(out)
	return text
}

// credentialIDs parses a JSON array of credential IDs; "" or "null"
// means nil: every candidate.
func credentialIDs(idsJSON string) ([]string, error) {
	if idsJSON == "" || idsJSON == "null" {
		return nil, nil
	}
	var ids []string
	if err := json.Unmarshal([]byte(idsJSON), &ids); err != nil {
		return nil, newError(CodeInvalidInput, fmt.Errorf("credential IDs: %w", err))
	}
	return ids, nil
}

// Preview returns what responding with credentialIDsJSON (a JSON array
// of IDs from Candidates; "" for the request's own choice) would
// disclose: {"abi", "disclosures": [{"query_id", "credential_id",
// "claims": [claim path]}]}, a claim path being a JSON array of keys
// (and indexes, or null for every element).
func (p *Presentation) Preview(credentialIDsJSON string) (string, error) {
	ids, err := credentialIDs(credentialIDsJSON)
	if err != nil {
		return "", err
	}
	disclosed, err := p.p.Preview(context.Background(), ids)
	if err != nil {
		return "", classify(err)
	}
	type disclosure struct {
		QueryID      string      `json:"query_id"`
		CredentialID string      `json:"credential_id"`
		Claims       []dcql.Path `json:"claims"`
	}
	out := struct {
		result
		Disclosures []disclosure `json:"disclosures"`
	}{result: result{ABIVersion}, Disclosures: []disclosure{}}
	for _, d := range disclosed {
		out.Disclosures = append(out.Disclosures, disclosure{d.QueryID, d.CredentialID, d.Claims})
	}
	return marshal(out)
}

// Respond presents credentialIDsJSON (as for Preview) — holder keys sign
// here, so a KeyStore requiring user presence prompts now — and returns
// {"abi", "query_ids", "redirect_uri"}: when redirect_uri is set, open
// it in the browser.
func (p *Presentation) Respond(op *Operation, credentialIDsJSON string) (string, error) {
	ids, err := credentialIDs(credentialIDsJSON)
	if err != nil {
		return "", err
	}
	presented, err := p.p.Respond(op.context(), ids)
	if err != nil {
		return "", classify(err)
	}
	return presentedJSON(presented)
}

// Decline tells the Verifier the holder declined, and returns {"abi",
// "query_ids": [], "redirect_uri"}.
func (p *Presentation) Decline(op *Operation) (string, error) {
	presented, err := p.p.Decline(op.context())
	if err != nil {
		return "", classify(err)
	}
	return presentedJSON(presented)
}

func presentedJSON(p walletflow.Presented) (string, error) {
	queryIDs := p.QueryIDs
	if queryIDs == nil {
		queryIDs = []string{}
	}
	return marshal(struct {
		result
		QueryIDs    []string `json:"query_ids"`
		RedirectURI string   `json:"redirect_uri,omitempty"`
	}{result{ABIVersion}, queryIDs, p.RedirectURI})
}
