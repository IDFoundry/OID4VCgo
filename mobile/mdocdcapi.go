package mobile

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
		Origin    string             `json:"origin"`
		Reader    string             `json:"reader"`
		Documents []mdocDocumentJSON `json:"documents"`
	}{result: result{ABIVersion}, Origin: p.p.Origin(), Documents: []mdocDocumentJSON{}}
	if r := p.p.Reader(); r != nil {
		out.Reader = r.Subject.CommonName
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
// can be told before agreeing; Request says the same once it is.
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
	var elements [][2]string
	if err := json.Unmarshal([]byte(elementsJSON), &elements); err != nil {
		return "", newError(CodeInvalidInput, fmt.Errorf("elements: %w", err))
	}
	presented, err := p.p.Respond(op.context(), document, credentialID, elements)
	if err != nil {
		return "", classify(err)
	}
	return marshal(struct {
		result
		Response string `json:"response"`
		Linkable bool   `json:"linkable"`
	}{result{ABIVersion}, base64.StdEncoding.EncodeToString(presented.EncryptedResponse), presented.Linkable})
}
