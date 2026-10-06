package mdocdcapi

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hpke"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/oid4vpmdoc"
)

// The wallet side: an mdoc answering an org-iso-mdoc request, as an iOS
// document provider or an Android credential provider does. The
// platform hands it the request's data and the origin of the page that
// made it; the wallet parses it, checks who signed it, asks the holder,
// and returns Respond's EncryptedResponse.

// MaxRequestBytes bounds the request data ParseRequest decodes.
const MaxRequestBytes = 1 << 20

// ErrUntrustedReader is VerifyReader's error when no reader signature on
// the request verifies under a trusted root.
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
	if err := json.Unmarshal(data, &wire); err != nil || wire.DeviceRequest == "" || wire.EncryptionInfo == "" {
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
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("mdocdcapi: recipientPublicKey must be P-256, not %T", pub)
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
	if len(wire.DocRequests) == 0 {
		return errors.New("mdocdcapi: DeviceRequest requests no document")
	}
	for i, dr := range wire.DocRequests {
		doc, err := parseItemsRequest(dr.ItemsRequest)
		if err != nil {
			return fmt.Errorf("mdocdcapi: docRequests[%d]: %w", i, err)
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
	for ns, elements := range items.NameSpaces {
		if len(elements) == 0 {
			return RequestedDocument{}, fmt.Errorf("namespace %q requests no element", ns)
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
	// Now is when the certificates must be valid; zero: the current
	// time.
	Now time.Time
}

// ReaderAuthenticationEKU is the extended key usage of an mdoc reader
// authentication certificate (ISO/IEC 18013-5 Annex B.1.7:
// 1.0.18013.5.1.6).
var ReaderAuthenticationEKU = asn1.ObjectIdentifier{1, 0, 18013, 5, 1, 6}

// RequireReaderAuthenticationEKU is a ReaderTrust.LeafPolicy refusing a
// reader certificate without ReaderAuthenticationEKU.
func RequireReaderAuthenticationEKU(leaf *x509.Certificate, _ [][]*x509.Certificate) error {
	for _, eku := range leaf.UnknownExtKeyUsage {
		if eku.Equal(ReaderAuthenticationEKU) {
			return nil
		}
	}
	return errors.New("the reader certificate lacks the mdoc reader authentication extended key usage (1.0.18013.5.1.6)")
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
	var lastErr error
	for _, sig := range in.readerAuthAll {
		leaf, err := verifyReaderAuth(sig, readerAuthenticationAll(in.transcript, items, in.deviceRequestInfo), t)
		if err == nil {
			return leaf, nil
		}
		lastErr = err
	}
	// An mdoc reader of the first edition signs each DocRequest instead.
	var reader *x509.Certificate
	for _, d := range in.Documents {
		if d.readerAuth == nil {
			reader, lastErr = nil, errors.New("a document request isn't signed")
			break
		}
		leaf, err := verifyReaderAuth(d.readerAuth, readerAuthentication(in.transcript, d.itemsRequestBytes), t)
		if err == nil && reader != nil && !reader.Equal(leaf) {
			err = errors.New("the documents are signed by different readers")
		}
		if err != nil {
			reader, lastErr = nil, err
			break
		}
		reader = leaf
	}
	if reader != nil {
		return reader, nil
	}
	if lastErr == nil {
		lastErr = errors.New("the request carries no reader signature")
	}
	return nil, fmt.Errorf("%w: %w", ErrUntrustedReader, lastErr)
}

// verifyReaderAuth verifies one ReaderAuth or ReaderAuthAll over
// authentication, by the certificate in its x5chain, which must chain to
// roots. The algorithm is the certificate key's, not the signature's own
// header's.
func verifyReaderAuth(sig []byte, authentication []any, t ReaderTrust) (*x509.Certificate, error) {
	_, unprotected, _, err := cose.DecodeUnverified(sig)
	if err != nil {
		return nil, fmt.Errorf("decode reader signature: %w", err)
	}
	leaf, chains, err := certchain.VerifyChainsAt(unprotected.X5Chain, t.Roots, t.Now)
	if err != nil {
		return nil, err
	}
	if t.LeafPolicy != nil {
		if err := t.LeafPolicy(leaf, chains); err != nil {
			return nil, err
		}
	}
	alg, err := readerKeyAlg(leaf.PublicKey)
	if err != nil {
		return nil, err
	}
	detached, err := wrapTag24(authentication)
	if err != nil {
		return nil, fmt.Errorf("encode %v: %w", authentication[0], err)
	}
	if _, _, err := cose.VerifyDetached(alg, leaf.PublicKey, sig, detached, nil); err != nil {
		return nil, fmt.Errorf("reader signature: %w", err)
	}
	return leaf, nil
}

// Respond answers document doc of the request with issuerSigned — the
// held mdoc — disclosing elements, which the holder consented to and
// which must each be requested, and signed by holder, the mdoc's device
// key, over the session transcript. It returns the CBOR EncryptedResponse
// (Annex C.3) — what an iOS document provider returns, the platform
// encoding it into the response's "response" member; ResponseData is the
// whole {"response"} object.
func (in Incoming) Respond(doc int, issuerSigned mdoc.IssuerSigned, holder crypto.Signer, elements [][2]string) ([]byte, error) {
	if doc < 0 || doc >= len(in.Documents) {
		return nil, fmt.Errorf("mdocdcapi: no document request %d", doc)
	}
	if in.recipient == nil {
		return nil, errors.New("mdocdcapi: Incoming isn't a parsed request")
	}
	requested := in.Documents[doc]
	if err := checkConsented(requested, elements); err != nil {
		return nil, err
	}
	selected := issuerSigned.SelectNameSpaces(elements)
	if len(selected.NameSpaces) == 0 {
		return nil, errors.New("mdocdcapi: the credential holds none of the elements to disclose")
	}
	alg, err := deviceAlgFor(holder.Public())
	if err != nil {
		return nil, err
	}
	stBytes, err := sessionTranscriptBytes(in.transcript)
	if err != nil {
		return nil, fmt.Errorf("mdocdcapi: encode SessionTranscriptBytes: %w", err)
	}
	deviceSigned, err := mdoc.SignDeviceSignature(holder, alg, stBytes, requested.DocType, map[string]map[string]interface{}{})
	if err != nil {
		return nil, fmt.Errorf("mdocdcapi: device signature: %w", err)
	}
	deviceResponse, err := oid4vpmdoc.MarshalDeviceResponse(oid4vpmdoc.Document{
		DocType: requested.DocType, IssuerSigned: selected, DeviceSigned: deviceSigned,
	})
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
