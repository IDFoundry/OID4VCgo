package mobile

import (
	"time"

	"context"
	"encoding/json"
	"fmt"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// Presentation answers one OpenID4VP Authorization Request
// (walletflow.Presentation): show Verifier and Queries, choose a
// selection (or start from DefaultSelection), Preview it, then Respond
// or Decline.
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
// "response_uri", "registration": {"status", "name", "purpose",
// "privacy_policy", "registrar", "claims", "expires"}}. The registration
// is the Verifier's, from its request's verifier_info, checked against
// registrar_roots: status "verified" (with the rest), "invalid" (it
// didn't verify, so isn't relied on), or "none".
func (p *Presentation) Verifier() string {
	v := p.p.Verifier()
	reg := p.p.Registration()
	r := registrationJSON{Status: string(reg.Status)}
	if reg.Status == walletflow.RegistrationVerified {
		r.Name, r.Purpose, r.PrivacyPolicy, r.Registrar = reg.Name, reg.Purpose, reg.PrivacyPolicy, reg.Registrar
		r.Claims, r.Expires = reg.Claims, reg.Expires.UTC().Format(time.RFC3339)
		if r.Claims == nil {
			r.Claims = []dcql.Path{}
		}
	}
	text, _ := marshal(struct {
		result
		ClientID     string           `json:"client_id"`
		Name         string           `json:"name"`
		ResponseURI  string           `json:"response_uri"`
		Registration registrationJSON `json:"registration"`
	}{result{ABIVersion}, v.ClientID, v.Name, v.ResponseURI, r})
	return text
}

type registrationJSON struct {
	Status        string      `json:"status"`
	Name          string      `json:"name,omitempty"`
	Purpose       string      `json:"purpose,omitempty"`
	PrivacyPolicy string      `json:"privacy_policy,omitempty"`
	Registrar     string      `json:"registrar,omitempty"`
	Claims        []dcql.Path `json:"claims,omitempty"`
	Expires       string      `json:"expires,omitempty"`
}

type queryJSON struct {
	QueryID     string              `json:"query_id"`
	Multiple    bool                `json:"multiple"`
	Credentials []credentialSummary `json:"credentials"`
	// Unregistered are the claims it asks for beyond the Verifier's
	// registration, and UnregisteredAll whether it asks for every claim.
	Unregistered    []dcql.Path `json:"unregistered"`
	UnregisteredAll bool        `json:"unregistered_all"`
}

type credentialSetJSON struct {
	Options  [][]string `json:"options"`
	Required bool       `json:"required"`
}

// Queries returns the request, for the app to choose what to present:
// {"abi", "queries": [{"query_id", "multiple", "credentials":
// [summary], "unregistered": [path], "unregistered_all"}],
// "credential_sets": [{"options": [[query ID]], "required"}]}. Each
// query is the request's, in its order, with the credentials that can
// answer it (none when nothing can); multiple says whether it takes more
// than one. For a Verifier with a verified registration, unregistered
// are the claims paths the query asks for beyond it, and
// unregistered_all whether it asks for every claim, which no
// registration covers; nothing is refused for them. credential_sets are its sets of
// alternatives, each option the query IDs that together answer it, most
// preferred first; none means every query must be answered.
func (p *Presentation) Queries() string {
	out := struct {
		result
		Queries        []queryJSON         `json:"queries"`
		CredentialSets []credentialSetJSON `json:"credential_sets"`
	}{result: result{ABIVersion}, Queries: []queryJSON{}, CredentialSets: []credentialSetJSON{}}
	clientID := p.p.Verifier().ClientID
	for _, q := range p.p.Queries() {
		candidates := make([]credentialSummary, 0, len(q.Credentials))
		for _, c := range q.Credentials {
			s := summaryOf(c)
			shown, linkable := c.ShownTo(clientID), p.p.Linkable(c.ID)
			s.ShownToVerifier, s.LinkableHere = &shown, &linkable
			candidates = append(candidates, s)
		}
		qj := queryJSON{QueryID: q.ID, Multiple: q.Multiple, Credentials: candidates, Unregistered: []dcql.Path{}}
		for _, path := range p.p.Registration().Unregistered[q.ID] {
			if path == nil {
				qj.UnregisteredAll = true
				continue
			}
			qj.Unregistered = append(qj.Unregistered, path)
		}
		out.Queries = append(out.Queries, qj)
	}
	for _, cs := range p.p.CredentialSets() {
		out.CredentialSets = append(out.CredentialSets, credentialSetJSON{Options: cs.Options, Required: cs.Required})
	}
	text, _ := marshal(out)
	return text
}

// DefaultSelection returns the selection the wallet would make itself,
// for an app with no policy of its own, or to start from: {"abi",
// "selection": {query ID: [credential ID]}}. A request the wallet can't
// answer is no_matching_credential.
func (p *Presentation) DefaultSelection() (string, error) {
	sel, err := p.p.DefaultSelection(context.Background())
	if err != nil {
		return "", classify(err)
	}
	return marshal(struct {
		result
		Selection walletflow.Selection `json:"selection"`
	}{result{ABIVersion}, sel})
}

// selection parses a selection: a JSON object of query ID → array of
// credential IDs.
func selection(selectionJSON string) (walletflow.Selection, error) {
	var sel walletflow.Selection
	if err := json.Unmarshal([]byte(selectionJSON), &sel); err != nil {
		return nil, newError(CodeInvalidInput, fmt.Errorf("selection: %w", err))
	}
	return sel, nil
}

// Preview returns what responding with selectionJSON — {query ID:
// [credential ID]}, the app's choice from Queries — would disclose:
// {"abi", "disclosures": [{"query_id", "credential_id", "claims":
// [claim path]}]}, a claim path being a JSON array of keys (and
// indexes, or null for every element). A selection that doesn't answer
// the request as it asks is invalid_selection.
func (p *Presentation) Preview(selectionJSON string) (string, error) {
	sel, err := selection(selectionJSON)
	if err != nil {
		return "", err
	}
	disclosed, err := p.p.Preview(context.Background(), sel)
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

// Respond presents exactly selectionJSON (as for Preview) — holder keys
// sign here, so a KeyStore requiring user presence prompts now — and
// returns {"abi", "query_ids", "redirect_uri"}: when redirect_uri is
// set, open it in the browser.
func (p *Presentation) Respond(op *Operation, selectionJSON string) (string, error) {
	sel, err := selection(selectionJSON)
	if err != nil {
		return "", err
	}
	presented, err := p.p.Respond(op.context(), sel)
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
