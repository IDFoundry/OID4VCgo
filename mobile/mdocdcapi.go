package mobile

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// MdocPresentation answers one org-iso-mdoc request: an mdoc asked for
// over the Digital Credentials API (ISO/IEC TS 18013-7 Annex C), as iOS
// hands one to a document provider extension
// (walletflow.MdocPresentation). Show Request, then Respond; to
// decline, cancel the platform's request.
type MdocPresentation struct {
	p *walletflow.MdocPresentation
}

// StartMdocPresentation parses requestData — the request's data, as the
// platform hands it over (on iOS, IdentityDocumentWebPresentmentRawRequest's
// requestData) — from the page at origin, the origin the platform
// reports, serialized as scheme://host[:port] with no trailing slash.
// It finds the held mdocs that can answer it, without answering.
func (w *Wallet) StartMdocPresentation(op *Operation, requestData []byte, origin string) (*MdocPresentation, error) {
	p, err := w.w.StartMdocPresentation(op.context(), requestData, origin)
	if err != nil {
		return nil, classify(err)
	}
	return &MdocPresentation{p: p}, nil
}

type mdocElementJSON struct {
	Namespace  string `json:"namespace"`
	Identifier string `json:"identifier"`
	Retain     bool   `json:"retain"`
}

type mdocDocumentJSON struct {
	DocType     string              `json:"doctype"`
	Elements    []mdocElementJSON   `json:"elements"`
	Credentials []credentialSummary `json:"credentials"`
}

// Request returns the request, for the holder's consent: {"abi",
// "origin", "reader", "documents": [{"doctype", "elements":
// [{"namespace", "identifier", "retain"}], "credentials": [summary]}]}.
// reader is the subject common name of the reader that signed the
// request, when its certificate chains to mdoc_reader_roots; "" when
// the holder can only be shown origin. Each document is the request's,
// in its order, with the held mdocs of its doctype (none when nothing
// can answer it); retain is whether the reader says it will keep the
// value. Each summary says whether this origin has been shown it
// (shown_to_verifier) and whether presenting it now would be linkable
// (linkable_here).
func (p *MdocPresentation) Request() string {
	out := struct {
		result
		Origin            string             `json:"origin"`
		Reader            string             `json:"reader"`
		ReaderCertificate []byte             `json:"reader_certificate,omitempty"`
		Documents         []mdocDocumentJSON `json:"documents"`
	}{result: result{ABIVersion}, Origin: p.p.Origin(), Documents: []mdocDocumentJSON{}}
	if r := p.p.Reader(); r != nil {
		out.Reader = displayName(r.Subject.CommonName)
		out.ReaderCertificate = r.Raw
	}
	for _, r := range p.p.Requests() {
		d := mdocDocumentJSON{DocType: r.DocType, Elements: []mdocElementJSON{}, Credentials: []credentialSummary{}}
		for _, e := range r.Elements {
			d.Elements = append(d.Elements, mdocElementJSON{e.Namespace, e.Identifier, e.Retain})
		}
		for _, c := range r.Credentials {
			s := summaryOf(c)
			shown, linkable := c.ShownTo("origin:"+p.p.Origin()), p.p.Linkable(c.ID)
			s.ShownToVerifier, s.LinkableHere = &shown, &linkable
			d.Credentials = append(d.Credentials, s)
		}
		out.Documents = append(out.Documents, d)
	}
	text, _ := marshal(out)
	return text
}

// MdocCandidates returns the held mdocs, each with whether the page at
// origin has been shown it (shown_to_verifier) and whether presenting
// it there now would be linkable (linkable_here): {"abi",
// "credentials": [summary]}. It's for a consent screen shown before the
// request itself is available — iOS releases an org-iso-mdoc request
// to a document provider only once the holder agrees — so the holder
// can be told before agreeing; Request says the same once it is. Every
// held mdoc is listed, an expired, revoked or suspended one too, with
// presentable false: the screen offers only the presentable ones.
func (w *Wallet) MdocCandidates(origin string) (string, error) {
	creds, err := w.w.Credentials(context.Background())
	if err != nil {
		return "", classify(err)
	}
	out := make([]credentialSummary, 0, len(creds))
	for _, c := range creds {
		if c.Format != mdoc.CredentialFormat {
			continue
		}
		s, err := w.summary(c)
		if err != nil {
			return "", err
		}
		shown, linkable := c.ShownTo("origin:"+origin), w.w.MdocLinkable(c, origin)
		s.ShownToVerifier, s.LinkableHere = &shown, &linkable
		out = append(out, s)
	}
	return marshal(struct {
		result
		Credentials []credentialSummary `json:"credentials"`
	}{result{ABIVersion}, out})
}

// Respond presents the held mdoc credentialID for document number
// document, disclosing exactly elementsJSON — a JSON array of
// [namespace, identifier] pairs, each one the document requested
// (invalid_selection otherwise) — and returns {"abi", "response",
// "linkable"}: response is the base64-encoded EncryptedResponse to hand
// back to the platform (on iOS, ISO18013MobileDocumentResponse's
// responseData), linkable whether the copy presented had been seen by
// another Verifier. The holder key signs here, so a KeyStore requiring
// user presence prompts now. Answered once.
func (p *MdocPresentation) Respond(op *Operation, document int, credentialID, elementsJSON string) (string, error) {
	elements, err := mdocElementsJSON(elementsJSON)
	if err != nil {
		return "", err
	}
	presented, err := p.p.Respond(op.context(), document, credentialID, elements)
	if err != nil {
		return "", classify(err)
	}
	return mdocPresentedJSON(presented)
}

// RespondDocuments presents several of the request's documents in one
// EncryptedResponse (walletflow.MdocPresentation.RespondDocuments):
// answersJSON is a JSON array of {"document", "credential_id",
// "elements"}, each as Respond's arguments, at least one, no document
// twice and no credential twice (invalid_selection otherwise). It
// returns Respond's {"abi", "response", "linkable",
// "linkable_credentials"}: linkable whether any copy presented had been
// seen by another Verifier, linkable_credentials which, by credential
// ID. Each holder key signs here, in the request's order, so each
// KeyStore requiring user presence prompts in turn; if one fails or the
// holder cancels, nothing is returned and the request can be answered
// again. Answered once.
func (p *MdocPresentation) RespondDocuments(op *Operation, answersJSON string) (string, error) {
	answers, err := mdocAnswers(answersJSON)
	if err != nil {
		return "", err
	}
	presented, err := p.p.RespondDocuments(op.context(), answers)
	if err != nil {
		return "", classify(err)
	}
	return mdocPresentedJSON(presented)
}

func mdocPresentedJSON(presented walletflow.MdocPresented) (string, error) {
	return marshal(struct {
		result
		Response            string   `json:"response"`
		Linkable            bool     `json:"linkable"`
		LinkableCredentials []string `json:"linkable_credentials"`
	}{result{ABIVersion}, base64.StdEncoding.EncodeToString(presented.EncryptedResponse), presented.Linkable, nonNil(presented.LinkableCredentials)})
}

// mdocAnswer is one of RespondDocuments' answers, as JSON.
type mdocAnswer struct {
	Document     *int       `json:"document"`
	CredentialID string     `json:"credential_id"`
	Elements     [][]string `json:"elements"`
}

// mdocAnswers parses answersJSON, refusing unknown members, an answer
// without a document number, an element that isn't a pair, and
// anything after the array.
func mdocAnswers(answersJSON string) ([]walletflow.MdocAnswer, error) {
	var in []mdocAnswer
	if err := decodeStrict(answersJSON, &in); err != nil {
		return nil, newError(CodeInvalidInput, fmt.Errorf("answers: %w", err))
	}
	out := make([]walletflow.MdocAnswer, 0, len(in))
	for i, a := range in {
		if a.Document == nil {
			return nil, newError(CodeInvalidInput, fmt.Errorf("answers[%d]: no document", i))
		}
		elements, err := mdocElementPairs(a.Elements)
		if err != nil {
			return nil, newError(CodeInvalidInput, fmt.Errorf("answers[%d]: %w", i, err))
		}
		out = append(out, walletflow.MdocAnswer{Request: *a.Document, CredentialID: a.CredentialID, Elements: elements})
	}
	return out, nil
}

// mdocElementsJSON parses Respond's elementsJSON, a JSON array of
// [namespace, identifier] pairs, refusing an element that isn't a
// pair and anything after the array.
func mdocElementsJSON(elementsJSON string) ([][2]string, error) {
	var in [][]string
	if err := decodeStrict(elementsJSON, &in); err != nil {
		return nil, newError(CodeInvalidInput, fmt.Errorf("elements: %w", err))
	}
	elements, err := mdocElementPairs(in)
	if err != nil {
		return nil, newError(CodeInvalidInput, err)
	}
	return elements, nil
}

// mdocElementPairs is in as [namespace, identifier] pairs, refusing an
// element of another length rather than dropping or zero-filling it.
func mdocElementPairs(in [][]string) ([][2]string, error) {
	if in == nil {
		return nil, nil
	}
	out := make([][2]string, len(in))
	for i, e := range in {
		if len(e) != 2 {
			return nil, fmt.Errorf("elements[%d]: %d items, want [namespace, identifier]", i, len(e))
		}
		out[i] = [2]string{e[0], e[1]}
	}
	return out, nil
}

// nonNil is s, or an empty slice for nil: a JSON array either way.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
