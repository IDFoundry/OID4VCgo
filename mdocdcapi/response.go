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
	"slices"
	"time"

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
	// Assurance is as verifier.Config.Assurance. REQUIRED. Under
	// verifier.AssuranceProduction, VerifyResponse requires the
	// decisions verifier.VerifyResponse does: IssuerKeys must declare
	// verifier.KeySourceAssurance with LiveFetchHardened and verify
	// issuer chains (a verifier.MdocIssuerChainResolver, as
	// verifier.X5ChainIssuerKeyResolver is); IssuerAuthorized or
	// AnyIssuerForAnyType must decide which issuers may issue the
	// doctype; and Accept or NoStatusCheck must decide revocation.
	Assurance verifier.AssuranceLevel
	// IssuerAuthorized, if set, decides whether the verified document's
	// issuer may issue its doctype, as
	// verifier.VerifyResponseRequest.IssuerAuthorized does; an error
	// refuses the response.
	IssuerAuthorized func(ctx context.Context, a verifier.IssuerAuthorization) error
	// AnyIssuerForAnyType declares that every issuer IssuerKeys trusts
	// may issue the requested doctype, so IssuerAuthorized is
	// deliberately unset (verifier.VerifyResponseRequest.AnyIssuerForAnyType).
	AnyIssuerForAnyType bool
	// Accept, if set, runs on the verified document before
	// VerifyResponse returns it, as verifier.VerifyResponseRequest.Accept
	// does, and its error refuses the response: result holds the one
	// credential, Verified.Credential, and id is "".
	// verifier.RequireValidStatus checks revocation, with the Status
	// List Token's signer bound to the document's issuer through
	// Verified.IssuerChain. Nothing else checks revocation.
	Accept func(ctx context.Context, id string, result verifier.VerifyResponseResult) error
	// NoStatusCheck declares that this Verifier deliberately checks no
	// revocation status, so Accept is unset.
	NoStatusCheck bool
}

// Verified is a verified document.
type Verified struct {
	// DocType is the document's type, the one requested.
	DocType string
	// NameSpaces are the disclosed data elements, by namespace — each
	// one requested, issuer signed and bound to this request.
	NameSpaces map[string]map[string]any
	// Missing are the requested data elements the document didn't
	// disclose, by namespace, sorted: a holder can withhold any of them,
	// so a caller relying on one checks it's there, not just that its
	// value isn't a refusal.
	Missing map[string][]string
	// ValidityInfo is the MSO's: when it was signed, and its validity.
	ValidityInfo mdoc.ValidityInfo
	// IssuerChain is the issuer certificate path IssuerKeys (an
	// verifier.MdocIssuerChainResolver) verified, document signer first,
	// without the trust anchor; nil when IssuerKeys verifies no chain.
	// Never the IssuerAuth x5chain itself, which is unprotected
	// (verifier.CheckMdocIssuer).
	IssuerChain [][]byte
	// Status is the MSO's revocation reference, nil if it has none;
	// VerifyParams.Accept checks it (verifier.RequireValidStatus).
	Status *mdoc.Status
}

// Credential is v as a verifier.VerifiedCredential — its NameSpaces as
// Claims, its Status and IssuerChain — for what takes one, such as
// verifier.RequireValidStatus. Its CredentialQueryID is "": an Annex C
// request has no DCQL query.
func (v Verified) Credential() verifier.VerifiedCredential {
	claims := make(map[string]any, len(v.NameSpaces))
	for ns, elements := range v.NameSpaces {
		claims[ns] = elements
	}
	return verifier.VerifiedCredential{Claims: claims, MdocStatus: v.Status, IssuerChain: v.IssuerChain}
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
//
// It keeps no state, so it can't tell a response it has verified
// before: a response verifies as often as it's presented with the same
// Pending. Remove the Pending atomically before calling it, so each
// request is answered at most once (see Pending).
func VerifyResponse(ctx context.Context, p VerifyParams) (Verified, error) {
	if p.IssuerKeys == nil {
		return Verified{}, errors.New("mdocdcapi: IssuerKeys is required")
	}
	if err := validIssuerKeys(p.IssuerKeys); err != nil {
		return Verified{}, fmt.Errorf("mdocdcapi: IssuerKeys: %w", err)
	}
	if err := checkAssurance(p); err != nil {
		return Verified{}, err
	}
	if p.MaxClockSkew < 0 || p.MaxClockSkew > verifier.MaxAllowedClockSkew {
		return Verified{}, fmt.Errorf("mdocdcapi: MaxClockSkew %s is outside 0..%s", p.MaxClockSkew, verifier.MaxAllowedClockSkew)
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
	doc, err := oid4vpmdoc.UnmarshalDeviceResponseMax(deviceResponse, MaxResponseBytes)
	if err != nil {
		return Verified{}, fmt.Errorf("mdocdcapi: %w", err)
	}
	if doc.DocType != p.Pending.DocType {
		return Verified{}, fmt.Errorf("mdocdcapi: the document is a %q, not the requested %q", doc.DocType, p.Pending.DocType)
	}
	verified, err := verifyDocument(ctx, p, doc, transcript)
	if err != nil {
		return Verified{}, err
	}
	if p.Accept != nil {
		if err := p.Accept(ctx, "", verifier.VerifyResponseResult{Credentials: []verifier.VerifiedCredential{verified.Credential()}}); err != nil {
			return Verified{}, err
		}
	}
	return verified, nil
}

// checkAssurance refuses an Assurance that isn't a level, and under
// verifier.AssuranceProduction, the undecided configurations
// verifier.VerifyResponse refuses there: left undecided, each silently
// accepts what it shouldn't.
func checkAssurance(p VerifyParams) error {
	switch p.Assurance {
	case verifier.AssuranceDevelopment:
		return nil
	case verifier.AssuranceProduction:
	default:
		return errors.New("mdocdcapi: Assurance is required: verifier.AssuranceDevelopment or verifier.AssuranceProduction")
	}
	if asserter, ok := p.IssuerKeys.(verifier.KeySourceAssurance); !ok || !asserter.Capabilities().LiveFetchHardened {
		return errors.New("mdocdcapi: under AssuranceProduction, IssuerKeys must implement verifier.KeySourceAssurance and declare LiveFetchHardened")
	}
	if !verifiesChains(p.IssuerKeys) {
		// Without the chain, ISO/IEC 18013-5's document signer checks
		// don't run, and status can't be bound to the document's issuer.
		return errors.New("mdocdcapi: under AssuranceProduction, IssuerKeys must verify issuer chains (verifier.MdocIssuerChainResolver, or Unwrap to one)")
	}
	if p.IssuerAuthorized == nil && !p.AnyIssuerForAnyType {
		return errors.New("mdocdcapi: under AssuranceProduction, set IssuerAuthorized (which issuers may issue which doctypes) or AnyIssuerForAnyType: without either, any trusted issuer is accepted for any doctype")
	}
	if p.Accept == nil && !p.NoStatusCheck {
		return errors.New("mdocdcapi: under AssuranceProduction, set Accept (verifier.RequireValidStatus checks revocation) or NoStatusCheck: without either, a revoked document is accepted")
	}
	return nil
}

// verifiesChains reports whether resolver is a
// verifier.MdocIssuerChainResolver, or wraps one.
func verifiesChains(resolver verifier.MdocIssuerKeyResolver) bool {
	for range 16 {
		if _, ok := resolver.(verifier.MdocIssuerChainResolver); ok {
			return true
		}
		wrapper, ok := resolver.(verifier.MdocIssuerKeyResolverWrapper)
		if !ok {
			return false
		}
		resolver = wrapper.Unwrap()
	}
	return false
}

// validIssuerKeys runs Validate on resolver, and on each resolver it
// wraps, that has one (verifier.X5ChainIssuerKeyResolver's refuses a
// missing Revocation), as verifier.VerifyResponse does.
func validIssuerKeys(resolver verifier.MdocIssuerKeyResolver) error {
	for range 16 {
		if v, ok := resolver.(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return err
			}
		}
		wrapper, ok := resolver.(verifier.MdocIssuerKeyResolverWrapper)
		if !ok {
			return nil
		}
		resolver = wrapper.Unwrap()
	}
	return nil
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
	if err := decMode.Unmarshal(raw, &wire); err != nil {
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
	protected, unprotected, _, err := cose.DecodeUnverified(doc.IssuerSigned.IssuerAuth)
	if err != nil {
		return Verified{}, fmt.Errorf("mdocdcapi: decode IssuerAuth: %w", err)
	}
	if p.Now != nil {
		// Certificates are valid, or not, at the verification's instant.
		ctx = verifier.WithVerificationTime(ctx, p.Now())
	}
	issuerPub, issuerAlg, err := p.IssuerKeys.ResolveMdocIssuerKey(ctx, cose.X5ChainOf(protected, unprotected), doc.DocType)
	if err != nil {
		return Verified{}, fmt.Errorf("mdocdcapi: resolve the issuer key: %w", err)
	}
	mso, err := mdoc.Verify(doc.IssuerSigned, doc.DocType, issuerPub, issuerAlg, mdoc.VerifyOptions{Now: p.Now, MaxClockSkew: p.MaxClockSkew})
	if err != nil {
		return Verified{}, fmt.Errorf("mdocdcapi: %w", err)
	}
	issuerChain, err := verifier.CheckMdocIssuer(ctx, p.IssuerKeys, cose.X5ChainOf(protected, unprotected), doc.DocType, issuerPub, mso)
	if err != nil {
		return Verified{}, fmt.Errorf("mdocdcapi: document signer: %w", err)
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
	if p.IssuerAuthorized != nil {
		if err := p.IssuerAuthorized(ctx, verifier.IssuerAuthorization{
			Format: mdoc.CredentialFormat, Type: mso.DocType, RequestedTypes: []string{p.Pending.DocType}, MatchedTypes: []string{mso.DocType},
			IssuerChain: issuerChain,
		}); err != nil {
			return Verified{}, fmt.Errorf("mdocdcapi: issuer authorization: %w", err)
		}
	}
	return Verified{
		DocType: mso.DocType, NameSpaces: mso.NameSpaces, Missing: missing(mso.NameSpaces, p.Pending.Elements), ValidityInfo: mso.ValidityInfo,
		IssuerChain: issuerChain, Status: mso.Status,
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

// missing are the requested elements not disclosed, by namespace,
// sorted; nil when every one was.
func missing(disclosed map[string]map[string]any, requested map[string]map[string]bool) map[string][]string {
	var out map[string][]string
	for ns, elements := range requested {
		for el := range elements {
			if _, ok := disclosed[ns][el]; ok {
				continue
			}
			if out == nil {
				out = map[string][]string{}
			}
			out[ns] = append(out[ns], el)
		}
	}
	for ns := range out {
		slices.Sort(out[ns])
	}
	return out
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
