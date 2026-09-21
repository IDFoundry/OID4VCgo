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

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/oid4vpmdoc"
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
	// Presentation's own Holder Binding proof (§14.1.2). This only
	// proves the response was bound to that nonce, not that this is
	// the FIRST time it's been presented: VerifyResponse itself does
	// not track or consume nonces. Mark the underlying nonce consumed
	// once this call succeeds (see BuildAuthorizationRequestResult.Nonce's
	// own doc comment) or a captured response can be replayed.
	ExpectedNonce string

	// IssuerKeys resolves the Issuer key for each "dc+sd-jwt"
	// Presentation. REQUIRED if Query requests any "dc+sd-jwt"
	// Credential.
	IssuerKeys SDJWTVCIssuerKeyResolver

	// Now, if set, is used instead of time.Now for Key Binding JWT
	// freshness checks. Defaults to time.Now.
	Now func() time.Time

	// MaxKeyBindingAge bounds how old a Key Binding JWT's own "iat"
	// may be. REQUIRED (must be positive) when Query includes any
	// "dc+sd-jwt" Credential Query that requires holder binding (the
	// default — see dcql.CredentialQuery.RequiresCryptographicHolderBinding);
	// VerifyResponse rejects the Go zero value in that case rather
	// than silently disabling this freshness check (see
	// credential/sdjwtvc.KeyBindingCheck.MaxAge's own doc comment for
	// why). Ignored when no requested Credential Query needs it.
	MaxKeyBindingAge time.Duration

	// MdocIssuerKeys resolves the Issuer key for each "mso_mdoc"
	// Presentation. REQUIRED if Query requests any "mso_mdoc"
	// Credential.
	MdocIssuerKeys MdocIssuerKeyResolver

	// TrustedAuthorities enforces a Credential Query's own
	// TrustedAuthorities restriction (§6.1.1) against each verified
	// Presentation's own issuer certificate chain. REQUIRED if Query
	// includes any Credential Query with a non-empty
	// TrustedAuthorities; VerifyResponse rejects that combination
	// outright when this is nil rather than silently skipping the
	// restriction — see dcql.TrustedAuthoritiesChecker's own doc
	// comment. Ignored when no requested Credential Query declares
	// TrustedAuthorities.
	TrustedAuthorities dcql.TrustedAuthoritiesChecker

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
	//
	// WARNING: Origin becomes part of the audience check a "dc+sd-jwt"
	// Presentation's own Key Binding JWT is verified against — it MUST
	// come from the DC API platform's own authoritative report of the
	// calling page's origin (the same value
	// BuildDCAPIAuthorizationRequest's own ExpectedOrigins is compared
	// against on the Wallet side, e.g. Android Credential Manager's
	// own attested origin), never from anything the client/page itself
	// could supply (a query parameter, a postMessage payload,
	// document.location read inside a possibly-compromised or embedded
	// context). Populating it from an untrustworthy source makes this
	// audience check trivially spoofable.
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
// A Credential Query's own TrustedAuthorities (§6.1.1), when
// non-empty, is checked against the verified Presentation's own issuer
// certificate chain via req.TrustedAuthorities — see
// dcql.TrustedAuthoritiesChecker's own doc comment for why this is a
// separate, per-query dependency rather than something
// IssuerKeys/MdocIssuerKeys decide once for every request.
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
	if err := checkMaxKeyBindingAgeRequired(req); err != nil {
		return VerifyResponseResult{}, err
	}
	if err := checkTrustedAuthoritiesConfigured(req); err != nil {
		return VerifyResponseResult{}, err
	}

	if len(req.Query.CredentialSets) == 0 {
		return v.verifyResponseWithoutCredentialSets(ctx, req)
	}
	return v.verifyResponseWithCredentialSets(ctx, req)
}

// checkMaxKeyBindingAgeRequired and checkTrustedAuthoritiesConfigured
// are VerifyResponse's own precondition checks, split into top-level
// helpers purely to keep it under the linter's own cognitive
// complexity ceiling.
func checkMaxKeyBindingAgeRequired(req VerifyResponseRequest) error {
	if req.MaxKeyBindingAge > 0 {
		return nil
	}
	for _, cq := range req.Query.Credentials {
		if cq.Format == sdjwtvc.CredentialFormat && cq.RequiresCryptographicHolderBinding() {
			return fmt.Errorf("verifier: verify response: max_key_binding_age is required (must be positive) when a %q credential query requires holder binding", sdjwtvc.CredentialFormat)
		}
	}
	return nil
}

func checkTrustedAuthoritiesConfigured(req VerifyResponseRequest) error {
	if req.TrustedAuthorities != nil {
		return nil
	}
	for _, cq := range req.Query.Credentials {
		if len(cq.TrustedAuthorities) > 0 {
			return fmt.Errorf("verifier: verify response: trusted_authorities is required when a credential query %q declares trusted_authorities", cq.ID)
		}
	}
	return nil
}

// verifyResponseWithoutCredentialSets is VerifyResponse's own "no
// credential_sets" path — every Credential Query is checked
// unconditionally — split out purely to keep VerifyResponse under the
// linter's own cognitive complexity ceiling.
func (v *Verifier) verifyResponseWithoutCredentialSets(ctx context.Context, req VerifyResponseRequest) (VerifyResponseResult, error) {
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

// verifyResponseWithCredentialSets is VerifyResponse's own
// "credential_sets present" path (§6.4.2) — split out purely to keep
// VerifyResponse under the linter's own cognitive complexity ceiling.
func (v *Verifier) verifyResponseWithCredentialSets(ctx context.Context, req VerifyResponseRequest) (VerifyResponseResult, error) {
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
		return nil, newError("no presentation returned", nil)
	}
	if len(presentations) > 1 && !cq.Multiple {
		return nil, newError("multiple presentations were returned but multiple is not requested", nil)
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
		return nil, newError("parse presentation", err)
	}
	header, rawPayload, err := jose.DecodeUnverified(pres.IssuerJWT)
	if err != nil {
		return nil, newError("decode issuer jwt", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return nil, newError("unmarshal issuer jwt payload", err)
	}

	issuerPub, issuerAlg, err := req.IssuerKeys.ResolveIssuerKey(ctx, header, payload)
	if err != nil {
		return nil, newError("resolve issuer key", err)
	}

	requireHolderBinding := cq.RequiresCryptographicHolderBinding()
	keyBindingRequirement := sdjwtvc.KeyBindingNotRequired
	var holderPub crypto.PublicKey
	var holderAlg jose.Alg
	if requireHolderBinding {
		keyBindingRequirement = sdjwtvc.KeyBindingRequired
		holderPub, holderAlg, err = holderPublicKeyFromCNF(payload["cnf"])
		if err != nil {
			return nil, newError("resolve holder binding key", err)
		}
	}

	claims, _, err := sdjwtvc.Verify(compact, issuerPub, issuerAlg, sdjwtvc.VerifyOptions{
		RequireKeyBinding: keyBindingRequirement,
		HolderPublicKey:   holderPub,
		KeyBindingAlg:     holderAlg,
		ExpectedAudience:  v.expectedAudience(req.Origin),
		ExpectedNonce:     req.ExpectedNonce,
		MaxKeyBindingAge:  req.MaxKeyBindingAge,
		Now:               req.Now,
	})
	if err != nil {
		return nil, newError("verify", err)
	}

	if err := cq.SatisfiedBySDJWTVCClaims(claims); err != nil {
		return nil, newError("satisfied by sdjwtvc claims", err)
	}

	if len(cq.TrustedAuthorities) > 0 {
		chain, err := certchain.X5CDERsFromHeader(header)
		if err != nil {
			return nil, newError("trusted authorities", err)
		}
		if err := req.TrustedAuthorities.CheckTrustedAuthorities(ctx, cq.TrustedAuthorities, chain); err != nil {
			return nil, newError("trusted authorities", err)
		}
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
		return nil, newError("decode device response", err)
	}
	doc, err := oid4vpmdoc.UnmarshalDeviceResponse(raw)
	if err != nil {
		return nil, newError("unmarshal device response", err)
	}

	_, unprotected, _, err := cose.DecodeUnverified(doc.IssuerSigned.IssuerAuth)
	if err != nil {
		return nil, newError("decode issuer auth", err)
	}
	issuerPub, issuerAlg, err := req.MdocIssuerKeys.ResolveMdocIssuerKey(ctx, unprotected.X5Chain, doc.DocType)
	if err != nil {
		return nil, newError("resolve issuer key", err)
	}

	verified, err := mdoc.Verify(doc.IssuerSigned, doc.DocType, issuerPub, issuerAlg, mdoc.VerifyOptions{})
	if err != nil {
		return nil, newError("verify issuer signed", err)
	}

	thumbprintBytes, err := jwk.Thumbprint(&req.ResponseEncryptionKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("response encryption key: %w", err)
	}
	sessionTranscriptBytes, err := v.buildMdocSessionTranscriptBytes(req, thumbprintBytes)
	if err != nil {
		return nil, fmt.Errorf("build session transcript: %w", err)
	}

	if doc.DeviceSigned.AuthType != mdoc.DeviceAuthSignature {
		return nil, newError(fmt.Sprintf("device authentication type %d is not supported (see verifyMdocPresentation's own doc comment)", doc.DeviceSigned.AuthType), nil)
	}
	deviceAlg, err := mdocAlgForKey(verified.DeviceKey)
	if err != nil {
		return nil, newError("device key", err)
	}
	if err := mdoc.VerifyDeviceSignature(doc.DeviceSigned, verified.DeviceKey, deviceAlg, sessionTranscriptBytes, doc.DocType); err != nil {
		return nil, newError("verify device signature", err)
	}

	if err := mdoc.CheckKeyAuthorizations(doc.DeviceSigned.NameSpaces, verified.KeyAuthorizations); err != nil {
		return nil, newError("check key authorizations", err)
	}

	if err := cq.SatisfiedByMdocClaims(verified.DocType, verified.NameSpaces); err != nil {
		return nil, newError("satisfied by mdoc claims", err)
	}

	if len(cq.TrustedAuthorities) > 0 {
		if err := req.TrustedAuthorities.CheckTrustedAuthorities(ctx, cq.TrustedAuthorities, unprotected.X5Chain); err != nil {
			return nil, newError("trusted authorities", err)
		}
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
