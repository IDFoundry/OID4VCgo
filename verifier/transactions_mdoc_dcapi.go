package verifier

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/strictjson"
	"github.com/idfoundry/oid4vcgo/internal/weborigin"
	"github.com/idfoundry/oid4vcgo/oid4vpmdoc"
)

// DCAPIProtocolMdoc is the Digital Credentials API protocol of an ISO/IEC
// TS 18013-7 Annex C request (mdocdcapi.Protocol): the one Safari
// offers, and Chrome too.
const DCAPIProtocolMdoc = "org-iso-mdoc"

// MaxMdocDCAPIResponseBytes bounds the data HandleMdocDCAPIResponse
// takes: room for mdocdcapi.MaxResponseBytes of response in its JSON
// object. Bound the request that carries it to the page's endpoint by
// this much too.
const MaxMdocDCAPIResponseBytes = 2*oid4vpmdoc.MaxBytes + 4096

// MdocDCAPICredentialQueryID is the CredentialQueryID the verified
// document of an org-iso-mdoc request carries when its
// MdocDCAPIRequest names none.
const MdocDCAPICredentialQueryID = "mdoc"

// MdocDCAPIRequest is what an org-iso-mdoc request (BeginMdocDCAPI)
// asks for: one document, and data elements of it. It is what an Annex
// C DeviceRequest carries, and no more: DCQL's values, claim sets and
// credential sets have no counterpart there, so a dcql.Query isn't
// taken, to leave nothing asked for that a wallet wouldn't be told.
type MdocDCAPIRequest struct {
	// DocType is the requested document type, for example
	// "org.iso.18013.5.1.mDL". REQUIRED.
	DocType string

	// Elements are the requested data elements, by namespace, each with
	// whether the Verifier intends to retain it (ISO/IEC 18013-5
	// IntentToRetain). At least one. REQUIRED.
	Elements map[string]map[string]bool

	// CredentialQueryID is the CredentialQueryID the verified document
	// carries in the request's result — what TransactionsConfig.Accept
	// and Status see — so an Accept shared with OpenID4VP requests can
	// read it as its own query's mdoc. A DCQL Credential Query ID:
	// [A-Za-z0-9_-]. "" means MdocDCAPICredentialQueryID.
	CredentialQueryID string
}

// MdocDCAPIRequestData is an org-iso-mdoc request's data (Annex C.2):
// the page passes it to navigator.credentials.get as is.
type MdocDCAPIRequestData struct {
	// DeviceRequest is the CBOR DeviceRequest, base64url-encoded.
	DeviceRequest string `json:"deviceRequest"`
	// EncryptionInfo is the CBOR EncryptionInfo — the nonce and the key
	// the response is sealed to — base64url-encoded.
	EncryptionInfo string `json:"encryptionInfo"`
}

// MdocDCAPIDigitalRequest is one entry of navigator.credentials.get's
// digital.requests for an org-iso-mdoc request: encode it as JSON for
// the page.
type MdocDCAPIDigitalRequest struct {
	Protocol string               `json:"protocol"`
	Data     MdocDCAPIRequestData `json:"data"`
}

// BegunMdocDCAPI is a newly created org-iso-mdoc request.
type BegunMdocDCAPI struct {
	// ID identifies the request: the handle HandleMdocDCAPIResponse,
	// Lookup, Close and Forget take. Treat it as public, as BegunDCAPI's:
	// the browser binding is what protects the request.
	ID string

	// Request is what the page passes to navigator.credentials.get.
	Request MdocDCAPIDigitalRequest
}

// MdocDCAPIProtocol carries out ISO/IEC TS 18013-7 Annex C for
// Transactions (TransactionsConfig.MdocDCAPI): it builds each request
// and decrypts and verifies its response, while Transactions keeps the
// request's state — sealed, bound to its browser and origin, answered
// at most once. mdocdcapi.ForTransactions is the implementation: it
// signs each request with the Verifier's reader keys. Implementing it
// otherwise isn't supported: what it verifies is what the request's
// result vouches for.
type MdocDCAPIProtocol interface {
	// BuildMdocDCAPIRequest builds a request for p, with a fresh nonce
	// and response encryption key.
	BuildMdocDCAPIRequest(p MdocDCAPIBuild) (MdocDCAPIBuilt, error)

	// VerifyMdocDCAPIResponse decrypts and verifies the response to the
	// request p describes, checking no revocation status: Transactions
	// does (TransactionsConfig.Status). Its CredentialQueryID is left
	// for Transactions to set. An error is the response's refusal:
	// Transactions has checked the configuration it's given, at
	// NewTransactions and BeginMdocDCAPI.
	VerifyMdocDCAPIResponse(ctx context.Context, p MdocDCAPIVerify) (VerifiedCredential, error)
}

// MdocDCAPIBuild is the input to MdocDCAPIProtocol.BuildMdocDCAPIRequest.
type MdocDCAPIBuild struct {
	// Origin is the page's origin, normalized and checked against
	// TransactionsConfig.Origins.
	Origin   string
	DocType  string
	Elements map[string]map[string]bool
	// Random supplies the nonce and the response encryption key: the
	// Verifier's Dependencies.Random.
	Random io.Reader
	// Now is the time the request is built at.
	Now func() time.Time
}

// MdocDCAPIBuilt is MdocDCAPIProtocol.BuildMdocDCAPIRequest's result.
type MdocDCAPIBuilt struct {
	// Data goes to the page.
	Data MdocDCAPIRequestData
	// RecipientKey is the P-256 key the response is sealed to:
	// Transactions keeps it as the transaction's ResponseDecryptionKey,
	// sealed where the store seals.
	RecipientKey *ecdh.PrivateKey
}

// MdocDCAPIVerify is the input to
// MdocDCAPIProtocol.VerifyMdocDCAPIResponse: the request as it was
// built, the response, and the Verifier's verification settings.
type MdocDCAPIVerify struct {
	Origin         string
	DocType        string
	Elements       map[string]map[string]bool
	EncryptionInfo string
	RecipientKey   *ecdh.PrivateKey
	ExpiresAt      time.Time

	// Response is the credential's data.response: the base64url
	// EncryptedResponse (Annex C.3).
	Response string

	// IssuerKeys, Now, MaxClockSkew, IssuerAuthorized and
	// AnyIssuerForAnyType are TransactionsConfig.Verify's MdocIssuerKeys,
	// Now, MaxClockSkew, IssuerAuthorized and AnyIssuerForAnyType.
	IssuerKeys          MdocIssuerKeyResolver
	Now                 func() time.Time
	MaxClockSkew        time.Duration
	IssuerAuthorized    func(ctx context.Context, a IssuerAuthorization) error
	AnyIssuerForAnyType bool

	// Assurance is the Verifier's Config.Assurance, and Origins
	// TransactionsConfig.Origins, normalized.
	Assurance AssuranceLevel
	Origins   []string
}

// BeginMdocDCAPI creates an org-iso-mdoc presentation request (ISO/IEC
// TS 18013-7 Annex C) for request, over the Digital Credentials API,
// from the page at origin: TransactionsConfig.MdocDCAPI builds it,
// signed by its reader keys, with a fresh nonce and response encryption
// key, bound to origin. The page's answer comes back through
// HandleMdocDCAPIResponse; Lookup, Close and Forget work as for
// BeginDCAPI's requests.
//
// origin and browserBinding are as for BeginDCAPI: origin must be one of
// TransactionsConfig.Origins, which AssuranceProduction requires, and
// the page's answer must arrive with browserBinding. The response
// decryption key is kept in the transaction, sealed as an OpenID4VP
// request's is (TransactionCodec), and the request asked for is the
// transaction's Query: a single mso_mdoc Credential Query, with
// request.CredentialQueryID as its ID and a claim for each element.
func (t *Transactions) BeginMdocDCAPI(ctx context.Context, request MdocDCAPIRequest, browserBinding, origin string) (BegunMdocDCAPI, error) {
	if len(browserBinding) < MinBrowserBindingLength {
		return BegunMdocDCAPI{}, fmt.Errorf("verifier: transactions: a browser binding of at least %d bytes is required: an unguessable random token", MinBrowserBindingLength)
	}
	if t.cfg.MdocDCAPI == nil {
		return BegunMdocDCAPI{}, errors.New("verifier: transactions: BeginMdocDCAPI needs TransactionsConfig.MdocDCAPI (mdocdcapi.ForTransactions)")
	}
	origin = weborigin.Normalize(origin)
	if err := t.checkDCAPIOrigin(origin); err != nil {
		return BegunMdocDCAPI{}, fmt.Errorf("verifier: transactions: %w", err)
	}
	query, err := mdocDCAPIQuery(request)
	if err != nil {
		return BegunMdocDCAPI{}, fmt.Errorf("verifier: transactions: %w", err)
	}
	if err := t.checkVerifies(query); err != nil {
		return BegunMdocDCAPI{}, err
	}
	id, err := t.randomToken()
	if err != nil {
		return BegunMdocDCAPI{}, err
	}
	built, err := t.cfg.MdocDCAPI.BuildMdocDCAPIRequest(MdocDCAPIBuild{
		Origin: origin, DocType: request.DocType, Elements: request.Elements, Random: t.v.deps.Random, Now: t.now,
	})
	if err != nil {
		return BegunMdocDCAPI{}, fmt.Errorf("verifier: transactions: %w", err)
	}
	key, err := recipientKeyAsECDSA(built.RecipientKey)
	if err != nil {
		return BegunMdocDCAPI{}, fmt.Errorf("verifier: transactions: %w", err)
	}
	if built.Data.EncryptionInfo == "" || built.Data.DeviceRequest == "" {
		return BegunMdocDCAPI{}, errors.New("verifier: transactions: the org-iso-mdoc request was built without its DeviceRequest or EncryptionInfo")
	}
	tx := Transaction{
		ID: id, Query: query, ResponseDecryptionKey: key, MdocEncryptionInfo: built.Data.EncryptionInfo,
		Origin: origin, Status: TransactionPending, Owner: t.owner,
	}
	tx.ExpiresAt, tx.RetainUntil = t.expiry()
	sum := sha256.Sum256([]byte(browserBinding))
	tx.BrowserBindingHash = sum[:]
	if err := t.create(ctx, tx); err != nil {
		return BegunMdocDCAPI{}, err
	}
	return BegunMdocDCAPI{ID: id, Request: MdocDCAPIDigitalRequest{Protocol: DCAPIProtocolMdoc, Data: built.Data}}, nil
}

// HandleMdocDCAPIResponse processes the answer to the org-iso-mdoc
// request id, which the page posts back with the browser binding the
// request began with: data is the DigitalCredential's data as the
// browser returned it, {"response": EncryptedResponse}
// (mdocdcapi.ResponseData's form). It checks the binding and that the
// request is still pending, decrypts and verifies the response with
// TransactionsConfig.MdocDCAPI — bound to the request's own origin,
// never one the page reports, and to its encryption key, disclosing
// only what was asked — checks its revocation status
// (TransactionsConfig.Status), runs TransactionsConfig.Accept, and
// completes the request at most once, returning its result.
//
// As for HandleDCAPIResponse, a refused answer is recorded as the
// request's LastError and returned, and the request stays open within
// its lifetime: a response that verified completes it, after which
// another — the same one replayed among them — gets
// ErrTransactionAnswered. A refusal of the response itself is an
// *Error, whose Reason is ReasonMdocDCAPIResponse unless the cause has
// one of its own. An answer arriving with another browser binding is
// refused with ErrWrongBrowser and leaves the request as it was.
// Another kind of request's ID — BeginDCAPI's, Begin's — is
// ErrTransactionUnknown here, as this request's is to
// HandleDCAPIResponse.
func (t *Transactions) HandleMdocDCAPIResponse(ctx context.Context, id, browserBinding string, data []byte) (TransactionView, error) {
	return t.handlePageAnswer(ctx, id, browserBinding, true, func(tx Transaction) (VerifyResponseResult, error) {
		return t.verifyMdocDCAPI(ctx, tx, data)
	})
}

// handlePageAnswer is HandleDCAPIResponse and HandleMdocDCAPIResponse:
// the answer to the Digital Credentials API request id — an org-iso-mdoc
// one when mdocRequest, an OpenID4VP one otherwise — that verify
// verifies, completing the request at most once.
func (t *Transactions) handlePageAnswer(ctx context.Context, id, browserBinding string, mdocRequest bool, verify func(Transaction) (VerifyResponseResult, error)) (TransactionView, error) {
	tx, err := t.get(ctx, id)
	if err != nil {
		return TransactionView{}, storeFault(err)
	}
	if tx.Origin == "" || (tx.MdocEncryptionInfo != "") != mdocRequest {
		return TransactionView{}, ErrTransactionUnknown
	}
	if !bindingMatches(tx.BrowserBindingHash, browserBinding) {
		return TransactionView{}, ErrWrongBrowser
	}
	if err := t.checkPending(tx); err != nil {
		return TransactionView{}, err
	}
	result, err := verify(tx)
	if err != nil {
		t.recordFailure(ctx, id, err)
		return TransactionView{}, err
	}
	var view TransactionView
	err = t.update(ctx, id, func(cur *Transaction) error {
		if err := t.checkPending(*cur); err != nil {
			return err
		}
		cur.Result, cur.LastError, cur.Status = &result, "", TransactionDone
		view = t.release(cur)
		return nil
	})
	if err != nil {
		return TransactionView{}, storeFault(err)
	}
	return view, nil
}

// verifyMdocDCAPI decrypts, verifies and accepts one org-iso-mdoc
// answer to tx.
func (t *Transactions) verifyMdocDCAPI(ctx context.Context, tx Transaction, data []byte) (VerifyResponseResult, error) {
	if len(data) > MaxMdocDCAPIResponseBytes {
		return VerifyResponseResult{}, newError(ReasonMalformed, fmt.Sprintf("the org-iso-mdoc response is over %d bytes", MaxMdocDCAPIResponseBytes), nil)
	}
	var answer struct {
		Response string `json:"response"`
	}
	if err := strictjson.Unmarshal(data, &answer); err != nil {
		return VerifyResponseResult{}, newError(ReasonMalformed, "the org-iso-mdoc response isn't a JSON object", err)
	}
	if answer.Response == "" {
		return VerifyResponseResult{}, newError(ReasonMalformed, `the org-iso-mdoc response has no "response"`, nil)
	}
	cq, docType, elements, err := mdocDCAPIRequestOf(tx.Query)
	if err != nil {
		// Begin wrote the query: a store that changed it.
		return VerifyResponseResult{}, &serverFault{fmt.Errorf("verifier: transactions: %w", err)}
	}
	recipient, err := tx.ResponseDecryptionKey.ECDH()
	if err != nil {
		return VerifyResponseResult{}, &serverFault{fmt.Errorf("verifier: transactions: the response decryption key: %w", err)}
	}
	verify := t.cfg.Verify
	vc, err := t.cfg.MdocDCAPI.VerifyMdocDCAPIResponse(ctx, MdocDCAPIVerify{
		Origin: tx.Origin, DocType: docType, Elements: elements, EncryptionInfo: tx.MdocEncryptionInfo,
		RecipientKey: recipient, ExpiresAt: tx.ExpiresAt, Response: answer.Response,
		IssuerKeys: verify.MdocIssuerKeys, Now: t.now, MaxClockSkew: verify.MaxClockSkew,
		IssuerAuthorized: verify.IssuerAuthorized, AnyIssuerForAnyType: verify.AnyIssuerForAnyType,
		Assurance: t.v.cfg.Assurance, Origins: t.cfg.Origins,
	})
	if err != nil {
		var verr *Error
		if errors.As(err, &verr) {
			return VerifyResponseResult{}, err
		}
		return VerifyResponseResult{}, newError(ReasonMdocDCAPIResponse, "the org-iso-mdoc response was refused", err)
	}
	vc.CredentialQueryID = cq
	return t.acceptVerified(ctx, tx, VerifyResponseResult{Credentials: []VerifiedCredential{vc}})
}

// mdocDCAPIQuery is request as the Query of its transaction: one
// mso_mdoc Credential Query, its claims sorted by namespace and element,
// so a request always has one Query, and one seal binding.
func mdocDCAPIQuery(request MdocDCAPIRequest) (dcql.Query, error) {
	if request.DocType == "" {
		return dcql.Query{}, errors.New("an org-iso-mdoc request needs a DocType")
	}
	if len(request.Elements) == 0 {
		return dcql.Query{}, errors.New("an org-iso-mdoc request needs at least one data element")
	}
	id := request.CredentialQueryID
	if id == "" {
		id = MdocDCAPICredentialQueryID
	}
	meta, err := dcql.NewMdocMeta(dcql.MdocMeta{DoctypeValue: request.DocType})
	if err != nil {
		return dcql.Query{}, err
	}
	namespaces := make([]string, 0, len(request.Elements))
	for ns := range request.Elements {
		namespaces = append(namespaces, ns)
	}
	slices.Sort(namespaces)
	var claims []dcql.ClaimsQuery
	for _, ns := range namespaces {
		if ns == "" || len(request.Elements[ns]) == 0 {
			return dcql.Query{}, fmt.Errorf("an org-iso-mdoc request's namespace %q must be named and request at least one element", ns)
		}
		elements := make([]string, 0, len(request.Elements[ns]))
		for el := range request.Elements[ns] {
			if el == "" {
				return dcql.Query{}, fmt.Errorf("an org-iso-mdoc request's namespace %q requests an unnamed element", ns)
			}
			elements = append(elements, el)
		}
		slices.Sort(elements)
		for _, el := range elements {
			retain := request.Elements[ns][el]
			claims = append(claims, dcql.ClaimsQuery{Path: dcql.Path{dcql.PathKey(ns), dcql.PathKey(el)}, IntentToRetain: &retain})
		}
	}
	query := dcql.Query{Credentials: []dcql.CredentialQuery{{ID: id, Format: mdoc.CredentialFormat, Meta: meta, Claims: claims}}}
	if err := query.Validate(); err != nil {
		return dcql.Query{}, fmt.Errorf("an org-iso-mdoc request: %w", err)
	}
	return query, nil
}

// mdocDCAPIRequestOf is the request mdocDCAPIQuery made query of: its
// credential query ID, doctype and elements.
func mdocDCAPIRequestOf(query dcql.Query) (id, docType string, elements map[string]map[string]bool, err error) {
	if len(query.Credentials) != 1 || query.Credentials[0].Format != mdoc.CredentialFormat {
		return "", "", nil, errors.New("an org-iso-mdoc request's query isn't one mso_mdoc Credential Query")
	}
	cq := query.Credentials[0]
	meta, err := cq.MdocMeta()
	if err != nil {
		return "", "", nil, fmt.Errorf("an org-iso-mdoc request's query: %w", err)
	}
	elements = map[string]map[string]bool{}
	for _, cl := range cq.Claims {
		ns, el, ok := cl.Path.MdocNamespaceAndElement()
		if !ok {
			return "", "", nil, errors.New("an org-iso-mdoc request's query has a claim that isn't a namespace and an element")
		}
		if elements[ns] == nil {
			elements[ns] = map[string]bool{}
		}
		elements[ns][el] = cl.IntentToRetain != nil && *cl.IntentToRetain
	}
	if len(elements) == 0 {
		return "", "", nil, errors.New("an org-iso-mdoc request's query asks for no element")
	}
	return cq.ID, meta.DoctypeValue, elements, nil
}

// recipientKeyAsECDSA is key, a P-256 ECDH key, as the ECDSA key a
// Transaction's ResponseDecryptionKey holds.
func recipientKeyAsECDSA(key *ecdh.PrivateKey) (*ecdsa.PrivateKey, error) {
	if key == nil || key.Curve() != ecdh.P256() {
		return nil, errors.New("the org-iso-mdoc request's response encryption key isn't a P-256 key")
	}
	return ecdsa.ParseRawPrivateKey(elliptic.P256(), key.Bytes())
}
