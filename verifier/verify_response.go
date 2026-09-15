package verifier

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	"github.com/idfoundry/oid4vcigo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcigo/dcql"
	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/internal/jwk"
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

// VerifyResponse implements §8.6's own VP Token Validation for the
// "dc+sd-jwt" format: for each of req.Query's own Credential Queries,
// it locates the matching Presentation in req.Response.VPToken by id,
// resolves the Issuer key via req.IssuerKeys, derives the Holder
// Binding key from the credential's own (cryptographically verified)
// "cnf" claim — never from an externally-supplied value, since
// accepting one without deriving it from the credential itself would
// make the binding check meaningless — verifies the Presentation via
// credential/sdjwtvc.Verify (checking the Key Binding JWT's own
// "aud"/"nonce" against this Verifier's own ClientID/
// req.ExpectedNonce per §14.1.2, requiring it exactly when the
// Credential Query's own RequiresCryptographicHolderBinding is true),
// and checks the result against the Credential Query itself via
// dcql.CredentialQuery.SatisfiedBySDJWTVCClaims (§8.6 point 3) — the
// same check the future wallet-presentation role uses to decide which
// held credential can satisfy a Credential Query in the first place.
//
// Phase 2 scope, explicitly: exactly one Presentation per Credential
// Query ("multiple: true" isn't supported yet), "claim_sets" isn't
// supported (every entry in a Credential Query's own Claims is treated
// as required), "dc+sd-jwt" only ("mso_mdoc" returns an error — see
// the package doc comment), and every Credential Query in
// req.Query.Credentials is treated as required (no CredentialSets/
// §6.4.2 Credential-selection orchestration).
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
