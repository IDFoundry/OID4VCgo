package mdocdcapi

import (
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/readerauth"
)

// Protocol is the Digital Credentials API protocol identifier for this
// mechanism (Annex C.1).
const Protocol = "org-iso-mdoc"

// nonceBytes is the EncryptionInfo nonce's length: Annex C.2 requires
// at least 16 bytes of entropy.
const nonceBytes = 32

// ReaderKey signs a request as one mdoc reader: a document provider
// shows, and decides whether to answer, by the certificate.
type ReaderKey struct {
	// Signer is the reader's private key: P-256 ECDSA or Ed25519.
	Signer crypto.Signer
	// Chain is its certificate chain, leaf first, carried in each
	// signature's x5chain header (ISO/IEC 18013-5 §12.5). The leaf
	// certifies Signer's public key.
	Chain []*x509.Certificate
}

// RequestParams is the input to BuildRequest.
type RequestParams struct {
	// Origin is the serialized origin of the page that calls the
	// Digital Credentials API, from the Verifier's configuration — for
	// example "https://verifier.example". REQUIRED.
	Origin string
	// DocType is the requested document type, for example
	// "org.iso.18013.5.1.mDL". REQUIRED.
	DocType string
	// Elements are the requested data elements, by namespace, each
	// with whether the Verifier intends to retain it (IntentToRetain).
	// At least one. REQUIRED.
	Elements map[string]map[string]bool
	// Readers sign the request, each with a ReaderAuthAll; the first
	// also signs the DocRequest's ReaderAuth, for an mdoc that only
	// checks that. A document provider app may refuse, or not even be
	// offered for, an unsigned request.
	Readers []ReaderKey
	// Random supplies the nonce and the response encryption key. nil
	// means crypto/rand.
	Random io.Reader
}

// RequestData is the request's "data" member for
// navigator.credentials.get (Annex C.2), as JSON.
type RequestData struct {
	DeviceRequest  string `json:"deviceRequest"`
	EncryptionInfo string `json:"encryptionInfo"`
}

// Pending is what VerifyResponse needs from BuildRequest, kept by the
// Verifier — never sent to the page. RecipientKey decrypts the
// response: keep it as secret as any private key, and only as long as
// the request.
type Pending struct {
	Origin         string
	DocType        string
	Elements       map[string]map[string]bool
	EncryptionInfo string
	RecipientKey   *ecdh.PrivateKey
}

// Request is BuildRequest's result.
type Request struct {
	// Data goes to the page, for navigator.credentials.get.
	Data RequestData
	// Pending stays with the Verifier, for VerifyResponse.
	Pending Pending
}

// itemsRequest is ISO/IEC 18013-5 §10.2.3's ItemsRequest.
type itemsRequest struct {
	DocType    string                     `cbor:"docType"`
	NameSpaces map[string]map[string]bool `cbor:"nameSpaces"`
}

// encryptionInfo is Annex C.2's EncryptionInfo: ["dcapi",
// EncryptionParameters].
type encryptionParameters struct {
	Nonce              []byte       `cbor:"nonce"`
	RecipientPublicKey mdoc.CoseKey `cbor:"recipientPublicKey"`
}

// BuildRequest builds an org-iso-mdoc request for one document, with a
// fresh nonce and response encryption key.
func BuildRequest(p RequestParams) (Request, error) {
	if err := checkRequestParams(p); err != nil {
		return Request{}, err
	}
	random := p.Random
	if random == nil {
		random = rand.Reader
	}

	recipient, err := ecdh.P256().GenerateKey(random)
	if err != nil {
		return Request{}, fmt.Errorf("mdocdcapi: generate response encryption key: %w", err)
	}
	encryptionInfo, err := buildEncryptionInfo(random, recipient.PublicKey())
	if err != nil {
		return Request{}, err
	}
	transcript, err := sessionTranscript(encryptionInfo, p.Origin)
	if err != nil {
		return Request{}, err
	}
	deviceRequest, err := buildDeviceRequest(p, transcript)
	if err != nil {
		return Request{}, err
	}
	return Request{
		Data: RequestData{DeviceRequest: deviceRequest, EncryptionInfo: encryptionInfo},
		Pending: Pending{
			Origin: p.Origin, DocType: p.DocType, Elements: cloneElements(p.Elements),
			EncryptionInfo: encryptionInfo, RecipientKey: recipient,
		},
	}, nil
}

func checkRequestParams(p RequestParams) error {
	if err := checkOrigin(p.Origin); err != nil {
		return err
	}
	if p.DocType == "" {
		return errors.New("mdocdcapi: DocType is required")
	}
	if len(p.Elements) == 0 {
		return errors.New("mdocdcapi: at least one data element must be requested")
	}
	for ns, elements := range p.Elements {
		if ns == "" || len(elements) == 0 {
			return fmt.Errorf("mdocdcapi: namespace %q must be named and request at least one element", ns)
		}
		for el := range elements {
			if el == "" {
				return fmt.Errorf("mdocdcapi: namespace %q requests an unnamed element", ns)
			}
		}
	}
	for i, r := range p.Readers {
		if _, err := readerauth.CheckKey(r.Signer, r.Chain); err != nil {
			return fmt.Errorf("mdocdcapi: reader %d: %w", i, err)
		}
	}
	return nil
}

// buildEncryptionInfo is Base64EncryptionInfo for recipient.
func buildEncryptionInfo(random io.Reader, recipient *ecdh.PublicKey) (string, error) {
	nonce := make([]byte, nonceBytes)
	if _, err := io.ReadFull(random, nonce); err != nil {
		return "", fmt.Errorf("mdocdcapi: nonce: %w", err)
	}
	point := recipient.Bytes() // 0x04 || X || Y
	key := mdoc.CoseKey{Kty: 2, Crv: 1, X: point[1:33], Y: point[33:]}
	raw, err := encMode.Marshal([]any{"dcapi", encryptionParameters{Nonce: nonce, RecipientPublicKey: key}})
	if err != nil {
		return "", fmt.Errorf("mdocdcapi: encode EncryptionInfo: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// buildDeviceRequest is Base64DeviceRequest: one DocRequest, signed by
// each reader.
func buildDeviceRequest(p RequestParams, transcript []byte) (string, error) {
	itemsRequestBytes, err := wrapTag24(itemsRequest{DocType: p.DocType, NameSpaces: p.Elements})
	if err != nil {
		return "", fmt.Errorf("mdocdcapi: encode ItemsRequest: %w", err)
	}
	docRequest := map[string]any{"itemsRequest": cbor.RawMessage(itemsRequestBytes)}
	deviceRequest := map[string]any{"version": "1.0", "docRequests": []any{docRequest}}
	if len(p.Readers) > 0 {
		readerAuth, err := signReaderAuth(p.Readers[0], readerAuthentication(transcript, itemsRequestBytes))
		if err != nil {
			return "", err
		}
		docRequest["readerAuth"] = cbor.RawMessage(readerAuth)
		all := make([]any, 0, len(p.Readers))
		for _, r := range p.Readers {
			sig, err := signReaderAuth(r, readerAuthenticationAll(transcript, [][]byte{itemsRequestBytes}, nil))
			if err != nil {
				return "", err
			}
			all = append(all, cbor.RawMessage(sig))
		}
		// "1.1" when readerAuthAll is present (ISO/IEC 18013-5 §10.2.2).
		deviceRequest["version"], deviceRequest["readerAuthAll"] = "1.1", all
	}
	raw, err := encMode.Marshal(deviceRequest)
	if err != nil {
		return "", fmt.Errorf("mdocdcapi: encode DeviceRequest: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// readerAuthentication is ISO/IEC 18013-5 §12.5's ReaderAuthentication,
// which a DocRequest's ReaderAuth signs.
func readerAuthentication(transcript, itemsRequestBytes []byte) []any {
	return []any{"ReaderAuthentication", cbor.RawMessage(transcript), cbor.RawMessage(itemsRequestBytes)}
}

// readerAuthenticationAll is the second edition's ReaderAuthenticationAll,
// which a ReaderAuthAll signs: every DocRequest's ItemsRequestBytes, in
// order, and the DeviceRequestInfoBytes or null.
func readerAuthenticationAll(transcript []byte, itemsRequestBytes [][]byte, deviceRequestInfo []byte) []any {
	items := make([]any, len(itemsRequestBytes))
	for i, b := range itemsRequestBytes {
		items[i] = cbor.RawMessage(b)
	}
	var info any
	if deviceRequestInfo != nil {
		info = cbor.RawMessage(deviceRequestInfo)
	}
	return []any{"ReaderAuthenticationAll", cbor.RawMessage(transcript), items, info}
}

// signReaderAuth is a ReaderAuth or ReaderAuthAll: a COSE_Sign1 with a
// null payload over the detached #6.24(bstr .cbor authentication), the
// reader's chain in the unprotected x5chain header.
func signReaderAuth(r ReaderKey, authentication []any) ([]byte, error) {
	detached, err := wrapTag24(authentication)
	if err != nil {
		return nil, fmt.Errorf("mdocdcapi: encode %v: %w", authentication[0], err)
	}
	sig, err := readerauth.Sign(r.Signer, r.Chain, detached)
	if err != nil {
		return nil, fmt.Errorf("mdocdcapi: sign %v: %w", authentication[0], err)
	}
	return sig, nil
}

func cloneElements(elements map[string]map[string]bool) map[string]map[string]bool {
	out := make(map[string]map[string]bool, len(elements))
	for ns, els := range elements {
		out[ns] = make(map[string]bool, len(els))
		for el, retain := range els {
			out[ns][el] = retain
		}
	}
	return out
}
