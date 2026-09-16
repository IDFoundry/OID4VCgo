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
// the issuance side. X5CIssuerKeyResolver implements the x5c-chain
// half of that policy for a deployment that just needs a trust anchor
// set, rather than DID resolution or VCT metadata lookup.
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
// §2) instead of a JOSE x5c. X5ChainIssuerKeyResolver implements the
// x5chain-validating half of that policy, mirroring X5CIssuerKeyResolver.
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
	// BuildAuthorizationRequest/BuildDCAPIAuthorizationRequest call
	// returned as ResponseDecryptionKey. REQUIRED if Query requests
	// any "mso_mdoc" Credential: rebuilding SessionTranscriptBytes
	// needs its own public key's RFC 7638 thumbprint, per Appendix
	// B.2.6.1/B.2.6.2's own "jwkThumbprint" — the same value this
	// Verifier already advertised in the Authorization Request's own
	// client_metadata.jwks.
	ResponseEncryptionKey *ecdsa.PrivateKey

	// Origin, if set, verifies a DC API response instead of a
	// redirect-flow one (Appendix A): the expected audience for a
	// "dc+sd-jwt" Presentation's own Key Binding JWT becomes
	// "origin:"+Origin (Appendix A.4's own "the audience for the
	// response ... MUST be the Origin, prefixed with origin:") instead
	// of this Verifier's own Client Identifier, and a "mso_mdoc"
	// Presentation's own SessionTranscript is rebuilt via
	// oid4vpmdoc.BuildDCAPISessionTranscriptBytes (Appendix B.2.6.2)
	// instead of oid4vpmdoc.BuildSessionTranscriptBytes (Appendix
	// B.2.6.1). Leave zero to verify a redirect-flow response, the
	// same as before this field existed.
	Origin string
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
// the "dc+sd-jwt" and "mso_mdoc" formats, and for both the redirect
// and DC API flows (req.Origin selects which — see its own doc
// comment): for each of req.Query's own Credential Queries, it locates
// the matching Presentation in req.Response.VPToken by id and
// dispatches by format.
//
// For "dc+sd-jwt", it resolves the Issuer key via req.IssuerKeys,
// derives the Holder Binding key from the credential's own
// (cryptographically verified) "cnf" claim — never from an
// externally-supplied value, since accepting one without deriving it
// from the credential itself would make the binding check meaningless
// — verifies the Presentation via credential/sdjwtvc.Verify (checking
// the Key Binding JWT's own "aud"/"nonce" against expectedAudience(req.Origin)/
// req.ExpectedNonce per §14.1.2/Appendix A.4, requiring it exactly when
// the Credential Query's own RequiresCryptographicHolderBinding is
// true), and checks the result via
// dcql.CredentialQuery.SatisfiedBySDJWTVCClaims (§8.6 point 3).
//
// For "mso_mdoc", it base64url-decodes the Presentation into an
// oid4vpmdoc.Document, resolves the Issuer key via req.MdocIssuerKeys
// (from the credential's own unverified IssuerAuth x5chain),
// cryptographically verifies IssuerSigned (credential/mdoc.Verify),
// rebuilds SessionTranscriptBytes exactly as the Wallet did
// (buildMdocSessionTranscriptBytes, using req.ResponseEncryptionKey's
// own public key thumbprint per Appendix B.2.6.1/B.2.6.2), verifies
// DeviceSigned against the now-trusted DeviceKeyInfo.DeviceKey
// (credential/mdoc.VerifyDeviceSignature — DeviceAuthMAC isn't
// supported, see verifyMdocPresentation's own doc comment),
// checks §12.8.2's own key-authorization rule
// (credential/mdoc.CheckKeyAuthorizations), and checks the result via
// dcql.CredentialQuery.SatisfiedByMdocClaims.
//
// req.Query.CredentialSets implements §6.4.2's own "Selecting
// Credentials" rule: when absent, every Credential Query in
// req.Query.Credentials is required (one with no verifying
// Presentation is a hard error). When present, only the Credential
// Queries referenced by req.Query.CredentialSets are checked at all —
// for each dcql.CredentialSetQuery, the first Options entry
// (most-preferred first) whose every referenced Credential Query id
// actually verifies wins; a required
// (dcql.CredentialSetQuery.IsRequired) Credential Set with no
// satisfiable option fails VerifyResponse entirely (per §6.4.2's own
// "MUST NOT return any Credential(s)"), while an optional one is
// silently omitted from VerifyResponseResult. A Credential Query not
// referenced by any Credential Set Query is never checked.
//
// Phase scope, explicitly: "claim_sets" (§6.4.1) is supported:
// dcql.CredentialQuery.SatisfiedBySDJWTVCClaims/SatisfiedByMdocClaims
// already try each option in order and report the Presentation as
// satisfying the query as soon as one option is fully present. A
// Credential Query's own Multiple (§6.1) is honored: when true,
// req.Response.VPToken may carry more than one Presentation for that
// id, and every one of them is verified and returned; when false (the
// default), more than one is a hard error.
func (v *Verifier) VerifyResponse(ctx context.Context, req VerifyResponseRequest) (VerifyResponseResult, error) {
	if err := req.Query.Validate(); err != nil {
		return VerifyResponseResult{}, fmt.Errorf("verifier: verify response: query: %w", err)
	}
	if req.ExpectedNonce == "" {
		return VerifyResponseResult{}, fmt.Errorf("verifier: verify response: expected_nonce is required")
	}

	if len(req.Query.CredentialSets) == 0 {
		result := VerifyResponseResult{}
		for _, cq := range req.Query.Credentials {
			vcs, err := v.verifyCredentialQuery(ctx, cq, req)
			if err != nil {
				return VerifyResponseResult{}, fmt.Errorf("verifier: verify response: credential query %q: %w", cq.ID, err)
			}
			result.Credentials = append(result.Credentials, vcs...)
		}
		return result, nil
	}

	byID := make(map[string]dcql.CredentialQuery, len(req.Query.Credentials))
	for _, cq := range req.Query.Credentials {
		byID[cq.ID] = cq
	}
	verified := make(map[string][]VerifiedCredential, len(req.Query.Credentials))
	for _, cs := range req.Query.CredentialSets {
		option, err := v.satisfiableCredentialSetOption(ctx, cs, byID, req)
		if err != nil {
			if cs.IsRequired() {
				return VerifyResponseResult{}, fmt.Errorf("verifier: verify response: credential set: %w", err)
			}
			continue
		}
		for id, vcs := range option {
			verified[id] = vcs
		}
	}
	result := VerifyResponseResult{}
	for _, cq := range req.Query.Credentials {
		if vcs, ok := verified[cq.ID]; ok {
			result.Credentials = append(result.Credentials, vcs...)
		}
	}
	return result, nil
}

// satisfiableCredentialSetOption returns the VerifiedCredentials for
// the first entry in cs.Options (most-preferred first, §6.4.2) whose
// every referenced Credential Query id actually verifies, or an error
// naming the last option's own failure if none does.
func (v *Verifier) satisfiableCredentialSetOption(ctx context.Context, cs dcql.CredentialSetQuery, byID map[string]dcql.CredentialQuery, req VerifyResponseRequest) (map[string][]VerifiedCredential, error) {
	var lastErr error
	for _, option := range cs.Options {
		verified := make(map[string][]VerifiedCredential, len(option))
		satisfied := true
		for _, id := range option {
			vcs, err := v.verifyCredentialQuery(ctx, byID[id], req)
			if err != nil {
				satisfied = false
				lastErr = fmt.Errorf("credential query %q: %w", id, err)
				break
			}
			verified[id] = vcs
		}
		if satisfied {
			return verified, nil
		}
	}
	return nil, fmt.Errorf("no option is satisfied: %w", lastErr)
}

// verifyCredentialQuery locates cq's own Presentation(s) in
// req.Response.VPToken, checks their count against cq.Multiple (§6.1
// and §8.1's own "when multiple is omitted, or set to false, the
// array MUST contain only one Presentation"), and verifies every one
// of them, dispatching to the format-specific verification
// VerifyResponse's own doc comment describes.
func (v *Verifier) verifyCredentialQuery(ctx context.Context, cq dcql.CredentialQuery, req VerifyResponseRequest) ([]VerifiedCredential, error) {
	presentations := req.Response.VPToken[cq.ID]
	if len(presentations) == 0 {
		return nil, fmt.Errorf("no presentation returned")
	}
	if len(presentations) > 1 && !cq.Multiple {
		return nil, fmt.Errorf("multiple presentations were returned but multiple is not requested")
	}

	vcs := make([]VerifiedCredential, 0, len(presentations))
	for _, presented := range presentations {
		var claims map[string]any
		var err error
		switch cq.Format {
		case sdjwtvc.CredentialFormat:
			claims, err = v.verifySDJWTVCPresentation(ctx, cq, presented, req)
		case mdoc.CredentialFormat:
			claims, err = v.verifyMdocPresentation(ctx, cq, presented, req)
		default:
			return nil, fmt.Errorf("format %q is not yet supported", cq.Format)
		}
		if err != nil {
			return nil, err
		}
		vcs = append(vcs, VerifiedCredential{CredentialQueryID: cq.ID, Claims: claims})
	}
	return vcs, nil
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
		ExpectedAudience:  v.expectedAudience(req.Origin),
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

// expectedAudience returns the audience a Presentation's own Holder
// Binding proof must be signed for: this Verifier's own Client
// Identifier for a redirect-flow response, or origin (Appendix A.4's
// own "origin:"-prefixed value) for a DC API one.
func (v *Verifier) expectedAudience(origin string) string {
	if origin != "" {
		return "origin:" + origin
	}
	return v.clientID
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
	sessionTranscriptBytes, err := v.buildMdocSessionTranscriptBytes(req, thumbprintBytes)
	if err != nil {
		return nil, fmt.Errorf("build session transcript: %w", err)
	}

	if doc.DeviceSigned.AuthType != mdoc.DeviceAuthSignature {
		return nil, fmt.Errorf("device authentication type %d is not supported (see verifyMdocPresentation's own doc comment)", doc.DeviceSigned.AuthType)
	}
	deviceAlg, err := mdocAlgForKey(verified.DeviceKey)
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

// buildMdocSessionTranscriptBytes rebuilds SessionTranscriptBytes
// exactly as the Wallet did: the redirect flow's own Handover
// (Appendix B.2.6.1) when req.Origin is empty, the DC API flow's own
// Handover (Appendix B.2.6.2) otherwise.
func (v *Verifier) buildMdocSessionTranscriptBytes(req VerifyResponseRequest, thumbprintBytes []byte) ([]byte, error) {
	if req.Origin != "" {
		return oid4vpmdoc.BuildDCAPISessionTranscriptBytes(oid4vpmdoc.DCAPIHandoverParams{
			Origin: req.Origin, Nonce: req.ExpectedNonce, ResponseEncryptionJWKThumbprint: thumbprintBytes,
		})
	}
	return oid4vpmdoc.BuildSessionTranscriptBytes(oid4vpmdoc.HandoverParams{
		ClientID: v.clientID, Nonce: req.ExpectedNonce, ResponseURI: v.cfg.ResponseURI.String(),
		ResponseEncryptionJWKThumbprint: thumbprintBytes,
	})
}

// mdocAlgForKey derives the mdoc COSE algorithm from a public key's
// own Go type — the same "derive alg from the already-trusted key,
// never from an unverified wire claim" discipline holderPublicKeyFromCNF
// applies for "dc+sd-jwt", used both for the mdoc authentication
// (device) key and X5ChainIssuerKeyResolver's own resolved issuer key.
func mdocAlgForKey(pub crypto.PublicKey) (cose.Alg, error) {
	switch pub.(type) {
	case *ecdsa.PublicKey:
		return cose.ES256, nil
	case ed25519.PublicKey:
		return cose.EdDSA, nil
	default:
		return 0, fmt.Errorf("unsupported public key type %T", pub)
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
	alg, err := sdjwtvcAlgForKey(pub)
	if err != nil {
		return nil, "", err
	}
	return pub, alg, nil
}

// sdjwtvcAlgForKey infers the JOSE algorithm a "dc+sd-jwt" JWS
// verifies under from its own public key's type — internal/jose's own
// ES256/EdDSA scope (see its doc comment), the same inference
// holderPublicKeyFromCNF and X5CIssuerKeyResolver both need.
func sdjwtvcAlgForKey(pub crypto.PublicKey) (jose.Alg, error) {
	switch pub.(type) {
	case *ecdsa.PublicKey:
		return jose.ES256, nil
	case ed25519.PublicKey:
		return jose.EdDSA, nil
	default:
		return "", fmt.Errorf("unsupported public key type %T", pub)
	}
}
