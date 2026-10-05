package mdocdcapi

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hpke"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/oid4vpmdoc"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// MaxResponseBytes bounds the base64url response VerifyResponse
// decodes: room for a document with a sizeable portrait, base64url
// encoded.
const MaxResponseBytes = 2 * oid4vpmdoc.MaxBytes

// VerifyParams is the input to VerifyResponse.
type VerifyParams struct {
	// Pending is the request's, from BuildRequest. REQUIRED.
	Pending Pending
	// Response is the credential's data.response: the base64url
	// EncryptedResponse (Annex C.3). REQUIRED.
	Response string
	// IssuerKeys resolves the document's issuer key from its
	// IssuerAuth x5chain — verifier.X5ChainIssuerKeyResolver against
	// the trusted issuers' roots. REQUIRED.
	IssuerKeys verifier.MdocIssuerKeyResolver
	// Now is compared against the MSO's validity. nil means time.Now.
	Now func() time.Time
	// MaxClockSkew is how far Now may be from the issuer's clock (see
	// mdoc.VerifyOptions.MaxClockSkew).
	MaxClockSkew time.Duration
}

// Verified is a verified document.
type Verified struct {
	DocType string
	// NameSpaces are the disclosed data elements, by namespace — each
	// one requested, issuer signed and bound to this request.
	NameSpaces   map[string]map[string]any
	ValidityInfo mdoc.ValidityInfo
	// IssuerChain is the IssuerAuth x5chain IssuerKeys resolved.
	IssuerChain [][]byte
	// Status is the MSO's revocation reference, nil if it has none;
	// checking it is the caller's (package statuslist).
	Status *mdoc.Status
}

// encryptedResponseData is Annex C.3's EncryptedResponseData.
type encryptedResponseData struct {
	Enc        []byte `cbor:"enc"`
	CipherText []byte `cbor:"cipherText"`
}

// VerifyResponse decrypts and verifies the response to the request
// Pending describes: one document of the requested type, issued by a
// trusted issuer, presented by the device it was issued to for this
// origin and encryption key, disclosing only requested elements.
func VerifyResponse(ctx context.Context, p VerifyParams) (Verified, error) {
	if p.IssuerKeys == nil {
		return Verified{}, errors.New("mdocdcapi: IssuerKeys is required")
	}
	if p.Pending.RecipientKey == nil || p.Pending.EncryptionInfo == "" {
		return Verified{}, errors.New("mdocdcapi: Pending is incomplete")
	}
	transcript, err := sessionTranscript(p.Pending.EncryptionInfo, p.Pending.Origin)
	if err != nil {
		return Verified{}, err
	}
	deviceResponse, err := decrypt(p.Response, p.Pending.RecipientKey, transcript)
	if err != nil {
		return Verified{}, err
	}
	doc, err := oid4vpmdoc.UnmarshalDeviceResponse(deviceResponse)
	if err != nil {
		return Verified{}, fmt.Errorf("mdocdcapi: %w", err)
	}
	if doc.DocType != p.Pending.DocType {
		return Verified{}, fmt.Errorf("mdocdcapi: the document is a %q, not the requested %q", doc.DocType, p.Pending.DocType)
	}
	return verifyDocument(ctx, p, doc, transcript)
}

// decrypt opens response's EncryptedResponse (Annex C.4) with key,
// returning the CBOR DeviceResponse.
func decrypt(response string, key *ecdh.PrivateKey, transcript []byte) ([]byte, error) {
	if len(response) > MaxResponseBytes {
		return nil, fmt.Errorf("mdocdcapi: response is %d bytes, more than %d", len(response), MaxResponseBytes)
	}
	raw, err := base64.RawURLEncoding.DecodeString(response)
	if err != nil {
		return nil, fmt.Errorf("mdocdcapi: response isn't base64url: %w", err)
	}
	var wire struct {
		_        struct{} `cbor:",toarray"`
		Protocol string
		Data     encryptedResponseData
	}
	if err := cbor.Unmarshal(raw, &wire); err != nil {
		return nil, fmt.Errorf("mdocdcapi: decode EncryptedResponse: %w", err)
	}
	if wire.Protocol != "dcapi" {
		return nil, fmt.Errorf("mdocdcapi: EncryptedResponse protocol %q, want \"dcapi\"", wire.Protocol)
	}
	recipientKey, err := hpke.NewDHKEMPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("mdocdcapi: response encryption key: %w", err)
	}
	recipient, err := hpke.NewRecipient(wire.Data.Enc, recipientKey, hpke.HKDFSHA256(), hpke.AES128GCM(), transcript)
	if err != nil {
		return nil, fmt.Errorf("mdocdcapi: HPKE: %w", err)
	}
	plaintext, err := recipient.Open(nil, wire.Data.CipherText)
	if err != nil {
		return nil, fmt.Errorf("mdocdcapi: decrypt the response: %w", err)
	}
	return plaintext, nil
}

// verifyDocument checks doc's issuer signature and digests, its device
// signature over transcript, and that it disclosed only requested
// elements.
func verifyDocument(ctx context.Context, p VerifyParams, doc oid4vpmdoc.Document, transcript []byte) (Verified, error) {
	_, unprotected, _, err := cose.DecodeUnverified(doc.IssuerSigned.IssuerAuth)
	if err != nil {
		return Verified{}, fmt.Errorf("mdocdcapi: decode IssuerAuth: %w", err)
	}
	issuerPub, issuerAlg, err := p.IssuerKeys.ResolveMdocIssuerKey(ctx, unprotected.X5Chain, doc.DocType)
	if err != nil {
		return Verified{}, fmt.Errorf("mdocdcapi: resolve the issuer key: %w", err)
	}
	mso, err := mdoc.Verify(doc.IssuerSigned, doc.DocType, issuerPub, issuerAlg, mdoc.VerifyOptions{Now: p.Now, MaxClockSkew: p.MaxClockSkew})
	if err != nil {
		return Verified{}, fmt.Errorf("mdocdcapi: %w", err)
	}

	// No reader key was exchanged, so only a device signature can bind
	// the document to this request.
	if doc.DeviceSigned.AuthType != mdoc.DeviceAuthSignature {
		return Verified{}, errors.New("mdocdcapi: the document must be authenticated by a device signature")
	}
	deviceAlg, err := deviceAlgFor(mso.DeviceKey)
	if err != nil {
		return Verified{}, err
	}
	stBytes, err := sessionTranscriptBytes(transcript)
	if err != nil {
		return Verified{}, fmt.Errorf("mdocdcapi: encode SessionTranscriptBytes: %w", err)
	}
	if err := mdoc.VerifyDeviceSignature(doc.DeviceSigned, mso.DeviceKey, deviceAlg, stBytes, doc.DocType); err != nil {
		return Verified{}, fmt.Errorf("mdocdcapi: %w", err)
	}
	if err := mdoc.CheckKeyAuthorizations(doc.DeviceSigned.NameSpaces, mso.KeyAuthorizations); err != nil {
		return Verified{}, fmt.Errorf("mdocdcapi: %w", err)
	}
	if err := checkRequested(mso.NameSpaces, p.Pending.Elements); err != nil {
		return Verified{}, err
	}
	return Verified{
		DocType: mso.DocType, NameSpaces: mso.NameSpaces, ValidityInfo: mso.ValidityInfo,
		IssuerChain: unprotected.X5Chain, Status: mso.Status,
	}, nil
}

// checkRequested refuses a disclosed element that wasn't requested: a
// document provider must disclose no more than was asked.
func checkRequested(disclosed map[string]map[string]any, requested map[string]map[string]bool) error {
	for ns, elements := range disclosed {
		for el := range elements {
			if _, ok := requested[ns][el]; !ok {
				return fmt.Errorf("mdocdcapi: the document disclosed %s/%s, which wasn't requested", ns, el)
			}
		}
	}
	return nil
}

func deviceAlgFor(pub crypto.PublicKey) (cose.Alg, error) {
	switch pub.(type) {
	case *ecdsa.PublicKey:
		return cose.ES256, nil
	case ed25519.PublicKey:
		return cose.EdDSA, nil
	default:
		return 0, fmt.Errorf("mdocdcapi: unsupported device key type %T", pub)
	}
}
