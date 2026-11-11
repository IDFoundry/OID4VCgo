package mdocdcapi

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hpke"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/idfoundry/oid4vcgo/internal/identifier"
	"github.com/idfoundry/oid4vcgo/internal/mdocresponse"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/readerauth"
	"github.com/idfoundry/oid4vcgo/internal/strictjson"
	"github.com/idfoundry/oid4vcgo/oid4vpmdoc"
)

// The wallet side: an mdoc answering an org-iso-mdoc request, as an iOS
// document provider or an Android credential provider does. The
// platform hands it the request's data and the origin of the page that
// made it; the wallet parses it, checks who signed it, asks the holder,
// and returns Respond's EncryptedResponse.

// MaxRequestBytes bounds the request data ParseRequest decodes.
const MaxRequestBytes = 1 << 20

// Limits on what ParseRequest accepts, beyond its size: each reader
// signature costs a certificate chain verification, and each requested
// element a line on the holder's consent screen.
const (
	// MaxDocRequests is the most documents one request may ask for.
	MaxDocRequests = 8
	// MaxReaderSignatures is the most ReaderAuthAll signatures one
	// request may carry.
	MaxReaderSignatures = 8
	// MaxRequestedElements is the most data elements one request may
	// ask for, across its documents.
	MaxRequestedElements = 256
)

// ErrUntrustedReader is VerifyReader's and VerifyReaderTrust's error
// when no reader signature on the request verifies under a trusted root
// (and, for VerifyReaderTrust, passes its LeafPolicy).
var ErrUntrustedReader = errors.New("mdocdcapi: the request isn't signed by a trusted reader")

// Incoming is an org-iso-mdoc request, as a wallet receives it.
type Incoming struct {
	// Origin is the requesting page's origin, as the platform reported
	// it: the session transcript is bound to it.
	Origin string
	// Documents are the requested documents, in the request's order.
	Documents []RequestedDocument

	encryptionInfo    string
	recipient         *ecdh.PublicKey
	transcript        []byte
	readerAuthAll     [][]byte
	deviceRequestInfo []byte
}

// RequestedDocument is one DocRequest.
type RequestedDocument struct {
	DocType string
	// Elements are the requested data elements by namespace, each with
	// whether the reader intends to retain it.
	Elements map[string]map[string]bool

	itemsRequestBytes []byte
	readerAuth        []byte
}

// Requested reports whether el, in ns, is one of d's elements.
func (d RequestedDocument) Requested(ns, el string) bool {
	_, ok := d.Elements[ns][el]
	return ok
}

// ParseRequest decodes data — the request's data member, the JSON
// {"deviceRequest", "encryptionInfo"} of Annex C.2 — for origin, the
// requesting page's serialized origin (no trailing slash), which the
// platform reports. It checks the structure only: VerifyReader checks
// who signed it.
func ParseRequest(data []byte, origin string) (Incoming, error) {
	if len(data) > MaxRequestBytes {
		return Incoming{}, fmt.Errorf("mdocdcapi: request is %d bytes, more than %d", len(data), MaxRequestBytes)
	}
	if err := checkOrigin(origin); err != nil {
		return Incoming{}, err
	}
	var wire RequestData
	if err := strictjson.Unmarshal(data, &wire); err != nil {
		return Incoming{}, fmt.Errorf("mdocdcapi: request data must be {\"deviceRequest\", \"encryptionInfo\"}: %w", err)
	}
	if wire.DeviceRequest == "" || wire.EncryptionInfo == "" {
		return Incoming{}, errors.New("mdocdcapi: request data must be {\"deviceRequest\", \"encryptionInfo\"}")
	}
	recipient, err := parseEncryptionInfo(wire.EncryptionInfo)
	if err != nil {
		return Incoming{}, err
	}
	transcript, err := sessionTranscript(wire.EncryptionInfo, origin)
	if err != nil {
		return Incoming{}, err
	}
	in := Incoming{Origin: origin, encryptionInfo: wire.EncryptionInfo, recipient: recipient, transcript: transcript}
	if err := in.parseDeviceRequest(wire.DeviceRequest); err != nil {
		return Incoming{}, err
	}
	return in, nil
}

// parseEncryptionInfo decodes Base64EncryptionInfo, returning the
// response's recipient key.
func parseEncryptionInfo(encryptionInfo string) (*ecdh.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encryptionInfo)
	if err != nil {
		return nil, fmt.Errorf("mdocdcapi: encryptionInfo isn't base64url: %w", err)
	}
	var info struct {
		_        struct{} `cbor:",toarray"`
		Protocol string
		Params   encryptionParameters
	}
	if err := decMode.Unmarshal(raw, &info); err != nil {
		return nil, fmt.Errorf("mdocdcapi: decode EncryptionInfo: %w", err)
	}
	if info.Protocol != "dcapi" {
		return nil, fmt.Errorf("mdocdcapi: EncryptionInfo protocol %q, want \"dcapi\"", info.Protocol)
	}
	if len(info.Params.Nonce) < 16 {
		return nil, errors.New("mdocdcapi: EncryptionInfo nonce must be at least 16 bytes")
	}
	pub, err := info.Params.RecipientPublicKey.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("mdocdcapi: recipientPublicKey: %w", err)
	}
	// Annex C's HPKE suite is DHKEM(P-256): a key on another curve would
	// make NewDHKEMPublicKey seal with another KEM.
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("mdocdcapi: recipientPublicKey must be P-256, not %T", pub)
	}
	if ec.Curve != elliptic.P256() {
		return nil, fmt.Errorf("mdocdcapi: recipientPublicKey must be P-256, not %s", ec.Curve.Params().Name)
	}
	recipient, err := ec.ECDH()
	if err != nil {
		return nil, fmt.Errorf("mdocdcapi: recipientPublicKey: %w", err)
	}
	return recipient, nil
}

// parseDeviceRequest decodes Base64DeviceRequest into in.
func (in *Incoming) parseDeviceRequest(deviceRequest string) error {
	raw, err := base64.RawURLEncoding.DecodeString(deviceRequest)
	if err != nil {
		return fmt.Errorf("mdocdcapi: deviceRequest isn't base64url: %w", err)
	}
	var wire struct {
		Version     string `cbor:"version"`
		DocRequests []struct {
			ItemsRequest cbor.RawMessage `cbor:"itemsRequest"`
			ReaderAuth   cbor.RawMessage `cbor:"readerAuth"`
		} `cbor:"docRequests"`
		DeviceRequestInfo cbor.RawMessage   `cbor:"deviceRequestInfo"`
		ReaderAuthAll     []cbor.RawMessage `cbor:"readerAuthAll"`
	}
	if err := decMode.Unmarshal(raw, &wire); err != nil {
		return fmt.Errorf("mdocdcapi: decode DeviceRequest: %w", err)
	}
	if !strings.HasPrefix(wire.Version, "1.") {
		return fmt.Errorf("mdocdcapi: DeviceRequest version %q, want 1.x", wire.Version)
	}
	switch {
	case len(wire.DocRequests) == 0:
		return errors.New("mdocdcapi: DeviceRequest requests no document")
	case len(wire.DocRequests) > MaxDocRequests:
		return fmt.Errorf("mdocdcapi: DeviceRequest requests %d documents, more than %d", len(wire.DocRequests), MaxDocRequests)
	case len(wire.ReaderAuthAll) > MaxReaderSignatures:
		return fmt.Errorf("mdocdcapi: DeviceRequest carries %d reader signatures, more than %d", len(wire.ReaderAuthAll), MaxReaderSignatures)
	}
	elements := 0
	for i, dr := range wire.DocRequests {
		doc, err := parseItemsRequest(dr.ItemsRequest)
		if err != nil {
			return fmt.Errorf("mdocdcapi: docRequests[%d]: %w", i, err)
		}
		// A DeviceResponse carries one document of each type, so a
		// reader asks for each type once.
		if slices.ContainsFunc(in.Documents, func(d RequestedDocument) bool { return d.DocType == doc.DocType }) {
			return fmt.Errorf("mdocdcapi: DeviceRequest asks for %q twice", doc.DocType)
		}
		for _, els := range doc.Elements {
			elements += len(els)
		}
		if elements > MaxRequestedElements {
			return fmt.Errorf("mdocdcapi: DeviceRequest asks for more than %d data elements", MaxRequestedElements)
		}
		doc.readerAuth = dr.ReaderAuth
		in.Documents = append(in.Documents, doc)
	}
	for _, sig := range wire.ReaderAuthAll {
		in.readerAuthAll = append(in.readerAuthAll, sig)
	}
	in.deviceRequestInfo = wire.DeviceRequestInfo
	return nil
}

// parseItemsRequest decodes ItemsRequestBytes.
func parseItemsRequest(itemsRequestBytes cbor.RawMessage) (RequestedDocument, error) {
	var tag cbor.Tag
	if err := decMode.Unmarshal(itemsRequestBytes, &tag); err != nil || tag.Number != tag24 {
		return RequestedDocument{}, errors.New("itemsRequest must be #6.24(bstr .cbor ItemsRequest)")
	}
	inner, ok := tag.Content.([]byte)
	if !ok {
		return RequestedDocument{}, errors.New("itemsRequest must be #6.24(bstr .cbor ItemsRequest)")
	}
	var items itemsRequest
	if err := decMode.Unmarshal(inner, &items); err != nil {
		return RequestedDocument{}, fmt.Errorf("decode ItemsRequest: %w", err)
	}
	if items.DocType == "" || len(items.NameSpaces) == 0 {
		return RequestedDocument{}, errors.New("ItemsRequest needs a docType and at least one namespace")
	}
	if err := identifier.Check(items.DocType); err != nil {
		return RequestedDocument{}, fmt.Errorf("docType: %w", err)
	}
	for ns, elements := range items.NameSpaces {
		if len(elements) == 0 {
			return RequestedDocument{}, fmt.Errorf("namespace %q requests no element", ns)
		}
		if err := identifier.Check(ns); err != nil {
			return RequestedDocument{}, fmt.Errorf("namespace: %w", err)
		}
		for el := range elements {
			if err := identifier.Check(el); err != nil {
				return RequestedDocument{}, fmt.Errorf("data element: %w", err)
			}
		}
	}
	return RequestedDocument{DocType: items.DocType, Elements: items.NameSpaces, itemsRequestBytes: itemsRequestBytes}, nil
}

// ReaderTrust is which mdoc readers a wallet recognizes.
type ReaderTrust struct {
	// Roots are the trust anchors a reader's certificate must chain to.
	// REQUIRED: a nil pool recognizes no reader (never the system's
	// roots).
	Roots *x509.CertPool
	// LeafPolicy, if set, is run on the chain-verified reader
	// certificate and its verified paths, and can refuse it. Chain
	// validation accepts a leaf with any key usage, so a certificate
	// issued for another role under the same Roots would otherwise be
	// recognized as a reader: RequireReaderAuthenticationEKU requires
	// what ISO/IEC 18013-5 Annex B profiles a reader authentication
	// certificate with.
	LeafPolicy func(leaf *x509.Certificate, chains [][]*x509.Certificate) error
	// Revocation, if set, checks the reader's certificate chain for
	// revocation: only a verified path LeafPolicy approves and
	// Revocation passes recognizes the reader, and a revoked
	// certificate leaves it unrecognized, with an error wrapping
	// certrevocation.ErrRevoked. Its context is context.Background():
	// a certrevocation.CRLs's Lists should keep its lists in memory.
	// nil checks no revocation; see certrevocation.
	Revocation certrevocation.Checker
	// Now is when the certificates must be valid; zero: the current
	// time.
	Now time.Time
}

// ReaderAuthenticationEKU is the extended key usage of an mdoc reader
// authentication certificate (ISO/IEC 18013-5 Annex B.1.7:
// 1.0.18013.5.1.6).
var ReaderAuthenticationEKU = readerauth.EKU

// RequireReaderAuthenticationEKU is a ReaderTrust.LeafPolicy refusing a
// reader certificate without ReaderAuthenticationEKU.
func RequireReaderAuthenticationEKU(leaf *x509.Certificate, chains [][]*x509.Certificate) error {
	return readerauth.RequireEKU(leaf, chains)
}

// VerifyReader is VerifyReaderTrust with Roots roots and Now now, and
// no LeafPolicy.
func (in Incoming) VerifyReader(roots *x509.CertPool, now time.Time) (*x509.Certificate, error) {
	return in.VerifyReaderTrust(ReaderTrust{Roots: roots, Now: now})
}

// VerifyReaderTrust checks who signed the request: a ReaderAuthAll over
// the whole request, or else a ReaderAuth on every DocRequest, whose
// certificate chains to t.Roots at t.Now and passes t.LeafPolicy. It
// returns the reader's certificate, or an error wrapping
// ErrUntrustedReader for an unsigned request or one no reader t
// recognizes signed.
func (in Incoming) VerifyReaderTrust(t ReaderTrust) (*x509.Certificate, error) {
	items := make([][]byte, len(in.Documents))
	for i, d := range in.Documents {
		items[i] = d.itemsRequestBytes
	}
	var allErr error
	if len(in.readerAuthAll) > 0 {
		// Every ReaderAuthAll signs the same structure: encode it once.
		detached, err := wrapTag24(readerAuthenticationAll(in.transcript, items, in.deviceRequestInfo))
		if err != nil {
			return nil, fmt.Errorf("mdocdcapi: encode ReaderAuthenticationAll: %w", err)
		}
		for _, sig := range in.readerAuthAll {
			leaf, err := verifyReaderAuth(sig, detached, t)
			if err == nil {
				return leaf, nil
			}
			allErr = err
		}
	}
	// An mdoc reader of the first edition signs each DocRequest instead.
	reader, signed, docErr := in.verifyDocumentReaderAuth(t)
	if docErr == nil {
		return reader, nil
	}
	switch {
	case allErr != nil && !signed:
		// A request signed only as a whole: its reason is the one.
		docErr = allErr
	case allErr != nil:
		docErr = fmt.Errorf("%w; signed per document: %w", allErr, docErr)
	case !signed:
		docErr = errors.New("the request carries no reader signature")
	}
	return nil, fmt.Errorf("%w: %w", ErrUntrustedReader, docErr)
}

// verifyDocumentReaderAuth verifies the ReaderAuth on every DocRequest,
// returning their one reader. signed reports whether any DocRequest
// carries a ReaderAuth at all.
func (in Incoming) verifyDocumentReaderAuth(t ReaderTrust) (reader *x509.Certificate, signed bool, err error) {
	for _, d := range in.Documents {
		if d.readerAuth != nil {
			signed = true
		}
	}
	for _, d := range in.Documents {
		if d.readerAuth == nil {
			return nil, signed, errors.New("a document request isn't signed")
		}
		detached, err := wrapTag24(readerAuthentication(in.transcript, d.itemsRequestBytes))
		if err != nil {
			return nil, signed, fmt.Errorf("mdocdcapi: encode ReaderAuthentication: %w", err)
		}
		leaf, err := verifyReaderAuth(d.readerAuth, detached, t)
		if err == nil && reader != nil && !reader.Equal(leaf) {
			err = errors.New("the documents are signed by different readers")
		}
		if err != nil {
			return nil, signed, err
		}
		reader = leaf
	}
	if reader == nil {
		return nil, signed, errors.New("the request carries no reader signature")
	}
	return reader, signed, nil
}

// verifyReaderAuth verifies one ReaderAuth or ReaderAuthAll over
// detached, the encoded ReaderAuthentication(All), by the certificate in
// its x5chain, which must chain to t's roots and pass its LeafPolicy.
func verifyReaderAuth(sig, detached []byte, t ReaderTrust) (*x509.Certificate, error) {
	return readerauth.Verify(sig, detached, readerauth.Trust{Roots: t.Roots, LeafPolicy: t.LeafPolicy, Revocation: t.Revocation, Now: t.Now})
}

// Respond answers document doc of the request with issuerSigned — the
// held mdoc — disclosing elements, which the holder consented to and
// which must each be requested, and signed by holder, the mdoc's device
// key, over the session transcript. It returns the CBOR EncryptedResponse
// (Annex C.3) — what an iOS document provider returns, the platform
// encoding it into the response's "response" member; ResponseData is the
// whole {"response"} object. It is RespondDocuments with one answer.
func (in Incoming) Respond(doc int, issuerSigned mdoc.IssuerSigned, holder crypto.Signer, elements [][2]string) ([]byte, error) {
	return in.RespondDocuments(context.Background(), []Answer{{Document: doc, IssuerSigned: issuerSigned, Holder: holder, Elements: elements}})
}

// Answer is one document request the holder answers: Document, the
// request's index in Incoming.Documents, with IssuerSigned — the held
// mdoc — disclosing Elements, and signed by Holder, its device key.
type Answer struct {
	Document     int
	IssuerSigned mdoc.IssuerSigned
	Holder       crypto.Signer
	Elements     [][2]string
}

// RespondDocuments answers several of the request's documents in one
// EncryptedResponse, as Respond answers one: a Document for each
// answer, in order, each signed by its own holder key. A document
// request the holder doesn't answer is left out of the response, which
// ISO/IEC 18013-5 allows; none is answered twice. Everything is checked
// before any key signs, including that each credential is of its
// request's document type (its MSO's docType, read unverified) and
// holds an element to disclose, and an error leaves nothing to send. Once ctx ends, no
// further key signs: a holder key that asks the holder isn't asked again
// for a response that will fail.
func (in Incoming) RespondDocuments(ctx context.Context, answers []Answer) ([]byte, error) {
	if in.recipient == nil {
		return nil, errors.New("mdocdcapi: Incoming isn't a parsed request")
	}
	if len(answers) == 0 {
		return nil, errors.New("mdocdcapi: no document to answer")
	}
	selected := make([]mdoc.IssuerSigned, len(answers))
	for i, a := range answers {
		if a.Document < 0 || a.Document >= len(in.Documents) {
			return nil, fmt.Errorf("mdocdcapi: no document request %d", a.Document)
		}
		for _, prev := range answers[:i] {
			if prev.Document == a.Document {
				return nil, fmt.Errorf("mdocdcapi: document request %d answered twice", a.Document)
			}
		}
		if err := checkConsented(in.Documents[a.Document], a.Elements); err != nil {
			return nil, err
		}
		if held, err := mdocresponse.UnverifiedDocType(a.IssuerSigned, MaxResponseBytes); err != nil {
			return nil, fmt.Errorf("mdocdcapi: document request %d: %w", a.Document, err)
		} else if held != in.Documents[a.Document].DocType {
			return nil, fmt.Errorf("mdocdcapi: document request %d is for %q, the mdoc is a %q", a.Document, in.Documents[a.Document].DocType, held)
		}
		if a.Holder == nil {
			return nil, fmt.Errorf("mdocdcapi: document request %d has no device key", a.Document)
		}
		if _, err := deviceAlgFor(a.Holder.Public()); err != nil {
			return nil, err
		}
		selected[i] = a.IssuerSigned.SelectNameSpaces(a.Elements)
		if len(selected[i].NameSpaces) == 0 {
			return nil, fmt.Errorf("mdocdcapi: document request %d: the credential holds none of the elements to disclose", a.Document)
		}
	}
	stBytes, err := sessionTranscriptBytes(in.transcript)
	if err != nil {
		return nil, fmt.Errorf("mdocdcapi: encode SessionTranscriptBytes: %w", err)
	}
	docs := make([]oid4vpmdoc.Document, 0, len(answers))
	for i, a := range answers {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("mdocdcapi: %w", err)
		}
		requested := in.Documents[a.Document]
		alg, err := deviceAlgFor(a.Holder.Public())
		if err != nil {
			return nil, err
		}
		deviceSigned, err := mdoc.SignDeviceSignature(a.Holder, alg, stBytes, requested.DocType, map[string]map[string]interface{}{})
		if err != nil {
			return nil, fmt.Errorf("mdocdcapi: device signature: %w", err)
		}
		docs = append(docs, oid4vpmdoc.Document{DocType: requested.DocType, IssuerSigned: selected[i], DeviceSigned: deviceSigned})
	}
	deviceResponse, err := mdocresponse.Marshal(docs...)
	if err != nil {
		return nil, fmt.Errorf("mdocdcapi: %w", err)
	}
	return in.seal(deviceResponse)
}

// checkConsented refuses an empty disclosure, and any element doc
// didn't request.
func checkConsented(doc RequestedDocument, elements [][2]string) error {
	if len(elements) == 0 {
		return errors.New("mdocdcapi: no element to disclose")
	}
	var extra []string
	for _, e := range elements {
		if !doc.Requested(e[0], e[1]) {
			extra = append(extra, e[0]+"/"+e[1])
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return fmt.Errorf("mdocdcapi: %s weren't requested", strings.Join(slices.Compact(extra), ", "))
	}
	return nil
}

// seal HPKE-encrypts deviceResponse to the request's recipient key with
// the session transcript as info (Annex C.4), as an EncryptedResponse.
func (in Incoming) seal(deviceResponse []byte) ([]byte, error) {
	pkR, err := hpke.NewDHKEMPublicKey(in.recipient)
	if err != nil {
		return nil, fmt.Errorf("mdocdcapi: recipient key: %w", err)
	}
	enc, sender, err := hpke.NewSender(pkR, hpke.HKDFSHA256(), hpke.AES128GCM(), in.transcript)
	if err != nil {
		return nil, fmt.Errorf("mdocdcapi: HPKE: %w", err)
	}
	ct, err := sender.Seal(nil, deviceResponse)
	if err != nil {
		return nil, fmt.Errorf("mdocdcapi: encrypt the response: %w", err)
	}
	out, err := encMode.Marshal([]any{"dcapi", encryptedResponseData{Enc: enc, CipherText: ct}})
	if err != nil {
		return nil, fmt.Errorf("mdocdcapi: encode EncryptedResponse: %w", err)
	}
	return out, nil
}

// ResponseData is the response's data member for a platform that takes
// the whole object (Annex C.3): {"response": base64url EncryptedResponse}.
func ResponseData(encryptedResponse []byte) []byte {
	out, _ := json.Marshal(map[string]string{"response": base64.RawURLEncoding.EncodeToString(encryptedResponse)})
	return out
}
