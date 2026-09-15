package verifier

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/idfoundry/oid4vcigo/credential/mdoc"
	"github.com/idfoundry/oid4vcigo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcigo/dcql"
	"github.com/idfoundry/oid4vcigo/internal/cose"
	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/internal/jwk"
	"github.com/idfoundry/oid4vcigo/oid4vpmdoc"
)

// SDJWTVCIssuerKeyResolver resolves which public key/algorithm
// verifies a presented "dc+sd-jwt" Presentation's own Issuer-signed
// JWT — determining trust (validating the credential's own x5c chain,
// HAIP §5.3's own MUST, against a trust anchor; DID resolution; VCT
// metadata lookup) is a deployment/Ecosystem policy decision, not this
// package's — the same split credential/sdjwtvc's own doc comment
// draws for Verify's own issuerPub parameter, and
// issuer.AttestationVerifier/ProofBindingKeyResolver already draw on
// the issuance side.
type SDJWTVCIssuerKeyResolver interface {
	// ResolveIssuerKey inspects header/payload — the Issuer-signed
	// JWT's own JOSE header and (not yet cryptographically verified)
	// claims, e.g. its "x5c"/"vct" — and returns the key/algorithm to
	// verify its signature with.
	ResolveIssuerKey(ctx context.Context, header, payload map[string]any) (crypto.PublicKey, jose.Alg, error)
}

// MdocIssuerKeyResolver resolves which public key/algorithm verifies a
// presented "mso_mdoc" Presentation's own IssuerAuth (COSE_Sign1) —
// the same trust-resolution split SDJWTVCIssuerKeyResolver draws for
// "dc+sd-jwt", applied to the x5chain COSE header parameter (RFC 9360
// §2) instead of a JOSE x5c.
type MdocIssuerKeyResolver interface {
	// ResolveMdocIssuerKey inspects x5chain — the credential's own
	// (not yet cryptographically verified) IssuerAuth x5chain header
	// — and docType, returning the key/algorithm to verify IssuerAuth
	// with.
	ResolveMdocIssuerKey(ctx context.Context, x5chain [][]byte, docType string) (crypto.PublicKey, cose.Alg, error)
}

// VerifyResponseRequest is the input to VerifyResponse.
type VerifyResponseRequest struct {
	// Query is REQUIRED: the same dcql.Query BuildAuthorizationRequest
	// was called with — VerifyResponse checks the response actually
	// satisfies it (§8.6 point 3).
	Query dcql.Query

	// Response is REQUIRED: a parsed direct_post.jwt response, e.g.
	// from ParseDirectPostJWTResponse.
	Response ParsedResponse

	// ExpectedNonce is REQUIRED: the Nonce a prior
	// BuildAuthorizationRequest call returned — checked against every
	// Presentation's own Holder Binding proof (§14.1.2).
	ExpectedNonce string

	// IssuerKeys resolves the Issuer key for each "dc+sd-jwt"
	// Presentation. REQUIRED if Query requests any "dc+sd-jwt"
	// Credential.
	IssuerKeys SDJWTVCIssuerKeyResolver

	// Now, if set, is used instead of time.Now for Key Binding JWT
	// freshness checks. Defaults to time.Now.
	Now func() time.Time

	// MaxKeyBindingAge, if non-zero, bounds how old a Key Binding
	// JWT's own "iat" may be. Zero means no bound.
	MaxKeyBindingAge time.Duration

	// MdocIssuerKeys resolves the Issuer key for each "mso_mdoc"
	// Presentation. REQUIRED if Query requests any "mso_mdoc"
	// Credential.
	MdocIssuerKeys MdocIssuerKeyResolver

	// ResponseEncryptionKey is the same ephemeral private key a prior
	// BuildAuthorizationRequest call returned as
	// BuildAuthorizationRequestResult.ResponseDecryptionKey. REQUIRED
	// if Query requests any "mso_mdoc" Credential: rebuilding
	// SessionTranscriptBytes (oid4vpmdoc.BuildSessionTranscriptBytes)
	// needs its own public key's RFC 7638 thumbprint, per Appendix
	// B.2.6.1's own "jwkThumbprint" — the same value this Verifier
	// already advertised in the Authorization Request's own
	// client_metadata.jwks.
	ResponseEncryptionKey *ecdsa.PrivateKey
}

// VerifiedCredential is one successfully verified Presentation.
type VerifiedCredential struct {
	// CredentialQueryID is the dcql.CredentialQuery.ID this
	// Presentation was matched against.
	CredentialQueryID string

	// Claims is the Presentation's own disclosed claims — for
	// "dc+sd-jwt", credential/sdjwtvc.Verify's own resolved payload
	// (RFC 9901 §7.1's "Processed SD-JWT Payload").
	Claims map[string]any
}

// VerifyResponseResult is returned by a successful VerifyResponse.
type VerifyResponseResult struct {
	Credentials []VerifiedCredential
}

// VerifyResponse implements §8.6's own VP Token Validation for both
// the "dc+sd-jwt" and "mso_mdoc" formats: for each of req.Query's own
// Credential Queries, it locates the matching Presentation in
// req.Response.VPToken by id and dispatches by format.
//
// For "dc+sd-jwt", it resolves the Issuer key via req.IssuerKeys,
// derives the Holder Binding key from the credential's own
// (cryptographically verified) "cnf" claim — never from an
// externally-supplied value, since accepting one without deriving it
// from the credential itself would make the binding check meaningless
// — verifies the Presentation via credential/sdjwtvc.Verify (checking
// the Key Binding JWT's own "aud"/"nonce" against this Verifier's own
// ClientID/req.ExpectedNonce per §14.1.2, requiring it exactly when
// the Credential Query's own RequiresCryptographicHolderBinding is
// true), and checks the result via
// dcql.CredentialQuery.SatisfiedBySDJWTVCClaims (§8.6 point 3).
//
// For "mso_mdoc", it base64url-decodes the Presentation into an
// oid4vpmdoc.Document, resolves the Issuer key via req.MdocIssuerKeys
// (from the credential's own unverified IssuerAuth x5chain),
// cryptographically verifies IssuerSigned (credential/mdoc.Verify),
// rebuilds SessionTranscriptBytes exactly as the Wallet did
// (oid4vpmdoc.BuildSessionTranscriptBytes, using req.ResponseEncryptionKey's
// own public key thumbprint per Appendix B.2.6.1), verifies
// DeviceSigned against the now-trusted DeviceKeyInfo.DeviceKey
// (credential/mdoc.VerifyDeviceSignature — DeviceAuthMAC isn't
// supported, see verifyMdocPresentation's own doc comment),
// checks §12.8.2's own key-authorization rule
// (credential/mdoc.CheckKeyAuthorizations), and checks the result via
// dcql.CredentialQuery.SatisfiedByMdocClaims.
//
// Phase scope, explicitly: exactly one Presentation per Credential
// Query ("multiple: true" isn't supported yet), "claim_sets" isn't
// supported (every entry in a Credential Query's own Claims is treated
// as required), and every Credential Query in req.Query.Credentials is
// treated as required (no CredentialSets/§6.4.2 Credential-selection
// orchestration).
func (v *Verifier) VerifyResponse(ctx context.Context, req VerifyResponseRequest) (VerifyResponseResult, error) {
	if err := req.Query.Validate(); err != nil {
		return VerifyResponseResult{}, fmt.Errorf("verifier: verify response: query: %w", err)
	}
	if req.ExpectedNonce == "" {
		return VerifyResponseResult{}, fmt.Errorf("verifier: verify response: expected_nonce is required")
	}

	result := VerifyResponseResult{}
	for _, cq := range req.Query.Credentials {
		presentations := req.Response.VPToken[cq.ID]
		if len(presentations) == 0 {
			return VerifyResponseResult{}, fmt.Errorf("verifier: verify response: credential query %q: no presentation returned", cq.ID)
		}
		if len(presentations) > 1 || cq.Multiple {
			return VerifyResponseResult{}, fmt.Errorf("verifier: verify response: credential query %q: multiple presentations are not yet supported", cq.ID)
		}
		if len(cq.ClaimSets) > 0 {
			return VerifyResponseResult{}, fmt.Errorf("verifier: verify response: credential query %q: claim_sets is not yet supported", cq.ID)
		}

		switch cq.Format {
		case sdjwtvc.CredentialFormat:
			claims, err := v.verifySDJWTVCPresentation(ctx, cq, presentations[0], req)
			if err != nil {
				return VerifyResponseResult{}, fmt.Errorf("verifier: verify response: credential query %q: %w", cq.ID, err)
			}
			result.Credentials = append(result.Credentials, VerifiedCredential{CredentialQueryID: cq.ID, Claims: claims})
		case mdoc.CredentialFormat:
			claims, err := v.verifyMdocPresentation(ctx, cq, presentations[0], req)
			if err != nil {
				return VerifyResponseResult{}, fmt.Errorf("verifier: verify response: credential query %q: %w", cq.ID, err)
			}
			result.Credentials = append(result.Credentials, VerifiedCredential{CredentialQueryID: cq.ID, Claims: claims})
		default:
			return VerifyResponseResult{}, fmt.Errorf("verifier: verify response: credential query %q: format %q is not yet supported", cq.ID, cq.Format)
		}
	}
	return result, nil
}

func (v *Verifier) verifySDJWTVCPresentation(ctx context.Context, cq dcql.CredentialQuery, compact string, req VerifyResponseRequest) (map[string]any, error) {
	if req.IssuerKeys == nil {
		return nil, fmt.Errorf("dependencies.issuer_keys is required for a %q credential query", sdjwtvc.CredentialFormat)
	}
	pres, err := sdjwtvc.Parse(compact)
	if err != nil {
		return nil, fmt.Errorf("parse presentation: %w", err)
	}
	header, rawPayload, err := jose.DecodeUnverified(pres.IssuerJWT)
	if err != nil {
		return nil, fmt.Errorf("decode issuer jwt: %w", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return nil, fmt.Errorf("unmarshal issuer jwt payload: %w", err)
	}

	issuerPub, issuerAlg, err := req.IssuerKeys.ResolveIssuerKey(ctx, header, payload)
	if err != nil {
		return nil, fmt.Errorf("resolve issuer key: %w", err)
	}

	requireHolderBinding := cq.RequiresCryptographicHolderBinding()
	var holderPub crypto.PublicKey
	var holderAlg jose.Alg
	if requireHolderBinding {
		holderPub, holderAlg, err = holderPublicKeyFromCNF(payload["cnf"])
		if err != nil {
			return nil, fmt.Errorf("resolve holder binding key: %w", err)
		}
	}

	claims, _, err := sdjwtvc.Verify(compact, issuerPub, issuerAlg, sdjwtvc.VerifyOptions{
		RequireKeyBinding: requireHolderBinding,
		HolderPublicKey:   holderPub,
		KeyBindingAlg:     holderAlg,
		ExpectedAudience:  v.clientID,
		ExpectedNonce:     req.ExpectedNonce,
		MaxKeyBindingAge:  req.MaxKeyBindingAge,
		Now:               req.Now,
	})
	if err != nil {
		return nil, fmt.Errorf("verify: %w", err)
	}

	if err := cq.SatisfiedBySDJWTVCClaims(claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// verifyMdocPresentation verifies one "mso_mdoc" Presentation —
// base64url-decoded into an oid4vpmdoc.Document — and returns its own
// disclosed IssuerSigned namespaces as
// map[string]any{namespace: map[string]any{element: value}}.
//
// DeviceAuthMAC (§12.4.5) isn't supported: it needs an EReaderKey for
// ECDH agreement, but OID4VP's own redirect-flow SessionTranscript
// (Appendix B.2.6.1) always sets EReaderKeyBytes to null — there is no
// in-band reader ephemeral key to agree a MAC key from, so only
// DeviceAuthSignature (§12.4.6, ECDSA/EdDSA) is meaningful here.
func (v *Verifier) verifyMdocPresentation(ctx context.Context, cq dcql.CredentialQuery, presented string, req VerifyResponseRequest) (map[string]any, error) {
	if req.MdocIssuerKeys == nil {
		return nil, fmt.Errorf("dependencies.mdoc_issuer_keys is required for a %q credential query", mdoc.CredentialFormat)
	}
	if req.ResponseEncryptionKey == nil {
		return nil, fmt.Errorf("response_encryption_key is required for a %q credential query", mdoc.CredentialFormat)
	}

	raw, err := base64.RawURLEncoding.DecodeString(presented)
	if err != nil {
		return nil, fmt.Errorf("decode device response: %w", err)
	}
	doc, err := oid4vpmdoc.UnmarshalDeviceResponse(raw)
	if err != nil {
		return nil, fmt.Errorf("unmarshal device response: %w", err)
	}

	_, unprotected, _, err := cose.DecodeUnverified(doc.IssuerSigned.IssuerAuth)
	if err != nil {
		return nil, fmt.Errorf("decode issuer auth: %w", err)
	}
	issuerPub, issuerAlg, err := req.MdocIssuerKeys.ResolveMdocIssuerKey(ctx, unprotected.X5Chain, doc.DocType)
	if err != nil {
		return nil, fmt.Errorf("resolve issuer key: %w", err)
	}

	verified, err := mdoc.Verify(doc.IssuerSigned, issuerPub, issuerAlg, mdoc.VerifyOptions{})
	if err != nil {
		return nil, fmt.Errorf("verify issuer signed: %w", err)
	}
	if verified.DocType != doc.DocType {
		return nil, fmt.Errorf("document docType %q does not match issuer-signed docType %q", doc.DocType, verified.DocType)
	}

	thumbprintJWK, err := jwk.Marshal(&req.ResponseEncryptionKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal response encryption key: %w", err)
	}
	thumbprint, err := thumbprintJWK.Thumbprint()
	if err != nil {
		return nil, fmt.Errorf("thumbprint response encryption key: %w", err)
	}
	thumbprintBytes, err := base64.RawURLEncoding.DecodeString(thumbprint)
	if err != nil {
		return nil, fmt.Errorf("decode response encryption key thumbprint: %w", err)
	}
	sessionTranscriptBytes, err := oid4vpmdoc.BuildSessionTranscriptBytes(oid4vpmdoc.HandoverParams{
		ClientID: v.clientID, Nonce: req.ExpectedNonce, ResponseURI: v.cfg.ResponseURI.String(),
		ResponseEncryptionJWKThumbprint: thumbprintBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("build session transcript: %w", err)
	}

	if doc.DeviceSigned.AuthType != mdoc.DeviceAuthSignature {
		return nil, fmt.Errorf("device authentication type %d is not supported (see verifyMdocPresentation's own doc comment)", doc.DeviceSigned.AuthType)
	}
	deviceAlg, err := mdocDeviceAlgForKey(verified.DeviceKey)
	if err != nil {
		return nil, fmt.Errorf("device key: %w", err)
	}
	if err := mdoc.VerifyDeviceSignature(doc.DeviceSigned, verified.DeviceKey, deviceAlg, sessionTranscriptBytes, doc.DocType); err != nil {
		return nil, fmt.Errorf("verify device signature: %w", err)
	}

	if err := mdoc.CheckKeyAuthorizations(doc.DeviceSigned.NameSpaces, verified.KeyAuthorizations); err != nil {
		return nil, fmt.Errorf("check key authorizations: %w", err)
	}

	if err := cq.SatisfiedByMdocClaims(verified.DocType, verified.NameSpaces); err != nil {
		return nil, err
	}

	claims := make(map[string]any, len(verified.NameSpaces))
	for namespace, elements := range verified.NameSpaces {
		claims[namespace] = elements
	}
	return claims, nil
}

// mdocDeviceAlgForKey derives the mdoc authentication COSE algorithm
// from deviceKey's own Go type — the same "derive alg from the
// already-trusted key, never from an unverified wire claim" discipline
// holderPublicKeyFromCNF applies for "dc+sd-jwt".
func mdocDeviceAlgForKey(deviceKey crypto.PublicKey) (cose.Alg, error) {
	switch deviceKey.(type) {
	case *ecdsa.PublicKey:
		return cose.ES256, nil
	case ed25519.PublicKey:
		return cose.EdDSA, nil
	default:
		return 0, fmt.Errorf("unsupported device key type %T", deviceKey)
	}
}

// holderPublicKeyFromCNF derives the Holder Binding key from an
// already-cryptographically-verified Issuer JWT payload's own "cnf"
// claim (RFC 7800). This is the only source of that key VerifyResponse
// ever uses — see verifySDJWTVCPresentation's own doc comment for why
// accepting it from anywhere else would make the binding check
// meaningless.
func holderPublicKeyFromCNF(cnf any) (crypto.PublicKey, jose.Alg, error) {
	cnfObj, ok := cnf.(map[string]any)
	if !ok {
		return nil, "", fmt.Errorf("credential carries no cnf claim")
	}
	rawJWK, ok := cnfObj["jwk"]
	if !ok {
		return nil, "", fmt.Errorf("cnf claim carries no jwk member")
	}
	jwkJSON, err := json.Marshal(rawJWK)
	if err != nil {
		return nil, "", fmt.Errorf("marshal cnf.jwk: %w", err)
	}
	pub, err := jwk.ParsePublicKey(jwkJSON)
	if err != nil {
		return nil, "", fmt.Errorf("parse cnf.jwk: %w", err)
	}
	switch pub.(type) {
	case *ecdsa.PublicKey:
		return pub, jose.ES256, nil
	case ed25519.PublicKey:
		return pub, jose.EdDSA, nil
	default:
		return nil, "", fmt.Errorf("unsupported cnf.jwk key type %T", pub)
	}
}
