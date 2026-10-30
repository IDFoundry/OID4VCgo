package verifier

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/internal/strictjson"
	"github.com/idfoundry/oid4vcgo/internal/weborigin"
	"github.com/idfoundry/oid4vcgo/oid4vpmdoc"
)

// errCategoryTrustedAuthorities labels every newError this file raises
// while checking a Presentation's own credential against
// dcql.CredentialQuery.TrustedAuthorities (both sd_jwt_vc's x5c chain
// and mdoc's own unprotected X5Chain).
const errCategoryTrustedAuthorities = "trusted authorities"

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
	ResolveIssuerKey(ctx context.Context, header, payload map[string]any) (crypto.PublicKey, oid4vci.JOSEAlg, error)
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
	ResolveMdocIssuerKey(ctx context.Context, x5chain [][]byte, docType string) (crypto.PublicKey, oid4vci.COSEAlg, error)
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

	// Now, if set, is used instead of time.Now for every time check:
	// credential validity (SD-JWT exp/nbf, mdoc validFrom/validUntil)
	// and Key Binding JWT freshness. Defaults to time.Now.
	Now func() time.Time

	// MaxClockSkew is how far Now may be from the issuer's clock when a
	// credential's validity window is checked: SD-JWT nbf/exp and mdoc
	// validFrom/validUntil are each widened by it. Zero checks them
	// exactly, which refuses a credential presented just after it was
	// issued valid from its signing time, when this Verifier's clock is
	// behind the issuer's. A minute is typical. (A Key Binding JWT's iat
	// is bounded by MaxKeyBindingAge in both directions already.)
	MaxClockSkew time.Duration

	// MaxKeyBindingAge bounds how old a Key Binding JWT's own "iat"
	// may be. REQUIRED (must be positive) when Query includes any
	// "dc+sd-jwt" Credential Query: a credential bound to a key (cnf)
	// is presented with a KB-JWT, which is checked, even where the
	// query doesn't require holder binding (HAIP 1.0 §6.1.1.1).
	// VerifyResponse rejects the Go zero value in that case rather
	// than silently disabling this freshness check (see
	// credential/sdjwtvc.KeyBindingCheck.MaxAge's own doc comment for
	// why). Ignored when no "dc+sd-jwt" Credential Query is asked.
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
	// comment. A dcql.AKITrustedAuthoritiesChecker must have Roots or
	// Anchors set (normally the issuer key resolver's own trust
	// anchors; Anchors where one's Subject Key Identifier isn't derived
	// from its key): without them it only reads what the leaf
	// certificate states about its issuer, which any CA can set.
	// Ignored when no requested Credential Query declares
	// TrustedAuthorities.
	TrustedAuthorities dcql.TrustedAuthoritiesChecker

	// IssuerAuthorized, if set, is asked for each presentation that
	// otherwise verified whether its issuer may issue a credential of
	// the type it's accepted as (see IssuerAuthorization), and an error
	// discards that presentation as ReasonUntrustedIssuer. Without it,
	// any issuer the key resolvers trust is accepted for any type the
	// query asks for, which is enough only where every trusted issuer
	// may issue every requested type. SD-JWT VC draft-19 §7.7 requires
	// the check, through this or the trust configuration itself.
	IssuerAuthorized func(ctx context.Context, a IssuerAuthorization) error

	// AnyIssuerForAnyType declares that every issuer the key resolvers
	// trust may issue every credential type the query asks for, so
	// IssuerAuthorized is deliberately unset. Under AssuranceProduction,
	// VerifyResponse needs IssuerAuthorized or this: without either, any
	// trusted issuer (a loyalty-card issuer under the same ecosystem CA,
	// say) would be accepted for a PID by mistake.
	AnyIssuerForAnyType bool

	// DistinctCredentials refuses a response that presents one
	// credential for more than one credential query (the same
	// Issuer-signed JWT, or mdoc Mobile Security Object, whatever the
	// holder varied around it). Set it where each query is meant to be
	// answered by a credential of its own — two adults, two documents —
	// so one isn't counted as both. Without it, OpenID4VP 1.0 §6.1
	// applies: "Multiple Credential Queries in a request MAY request a
	// presentation of the same Credential", and a Wallet may answer
	// queries for different claims of one credential with it (walletflow
	// does). Under one query's multiple, a credential presented twice is
	// refused either way.
	DistinctCredentials bool

	// Status, if set, checks every verified credential's revocation
	// status (see StatusPolicy) before Accept runs, and its error is
	// VerifyResponse's. Nothing else checks revocation.
	Status *StatusPolicy
	// NoStatusCheck declares that this Verifier deliberately checks no
	// revocation status — its credentials carry none, say, or it checks
	// status its own way in Accept. Under AssuranceProduction,
	// VerifyResponse needs Status or this (CheckStatusDecision), so a
	// Verifier that simply forgot Status doesn't take revoked
	// credentials; an Accept doesn't count.
	NoStatusCheck bool

	// Accept, if set, runs on a response that verified, after Status,
	// before VerifyResponse returns it, and its error is
	// VerifyResponse's: the Verifier's own checks (Chain composes
	// several). id is "" here; Transactions passes its request's.
	Accept func(ctx context.Context, id string, result VerifyResponseResult) error

	// statusByTransactions is set by Transactions, which runs its own
	// Status and Accept once the response is its request's.
	statusByTransactions bool

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
	// B.2.6.1). Leave zero to verify a redirect-flow response.
	//
	// Origin is the origin of the page that made the request — this
	// Verifier's own, as its configuration knows it. It must be one of
	// ExpectedOrigins. Never take it from the response's HTTP request
	// (an Origin header, a parameter): a site that relays a request as
	// its own would then have its presentation accepted.
	Origin string

	// ExpectedOrigins is REQUIRED with Origin: the request's
	// expected_origins (BuildDCAPIAuthorizationRequestResult.ExpectedOrigins).
	// VerifyResponse refuses an Origin that isn't one of them.
	ExpectedOrigins []string
}

// VerifiedCredential is one successfully verified Presentation.
type VerifiedCredential struct {
	// CredentialQueryID is the dcql.CredentialQuery.ID this
	// Presentation was matched against.
	CredentialQueryID string

	// Claims is the Presentation's own disclosed claims — for
	// "dc+sd-jwt", credential/sdjwtvc.Verify's own resolved payload
	// (RFC 9901 §7.1's "Processed SD-JWT Payload"), including its
	// "status" claim when the credential has one.
	Claims map[string]any

	// MdocStatus is an "mso_mdoc" credential's revocation reference,
	// from its issuer-signed MSO (ISO/IEC 18013-5 §12.3.6) — nil for
	// "dc+sd-jwt", whose reference is Claims["status"], and for an mdoc
	// without one. VerifyResponse doesn't check revocation itself:
	// StatusListRef reads this (or Claims["status"]) as one reference,
	// and statuslist.Checker fetches and checks it; an identifier list
	// is identifierlist.Checker's (RequireValidStatus does both).
	MdocStatus *mdoc.Status

	// IssuerChain is the credential's issuer certificate chain (DER,
	// leaf first) when its leaf's key is the one the credential verified
	// with, and nil otherwise. For an SD-JWT VC it's the signed x5c
	// header. For an mdoc it's the path MdocIssuerKeys (an
	// MdocIssuerChainResolver) verified, without the trust anchor: the
	// IssuerAuth x5chain is unprotected, so the holder could edit it; a
	// resolver that verifies no chain gives none. The issuer is that
	// leaf's subject. An SD-JWT VC's "iss" in Claims is the issuer's
	// claim, not checked against the leaf unless
	// X5CIssuerKeyResolver.RequireIssuerName is set (SD-JWT VC §2.5
	// doesn't require them to correspond): don't rely on it as
	// authenticated otherwise.
	IssuerChain [][]byte
}

// VerifyResponseResult is returned by a successful VerifyResponse.
type VerifyResponseResult struct {
	// Credentials are the presentations that verified. Under a Credential
	// Query's multiple, each is a different issued credential:
	// VerifyResponse refuses a response that presents one twice (the
	// same Issuer-signed JWT, or mdoc Mobile Security Object, whatever
	// the holder varied around it). Across Credential Queries the same
	// credential may answer more than one unless
	// VerifyResponseRequest.DistinctCredentials is set. Different credentials can still be
	// the same holder's — batch-issued copies of one credential each
	// have their own key — so a Verifier counting people decides from
	// their claims who is who.
	Credentials []VerifiedCredential

	// Discarded are the presentations that failed verification while
	// the rest still answered the query (OpenID4VP §8.6: "the effected
	// Presentation MUST be discarded"): one under multiple, say, or an
	// optional credential set's. None of their claims are in
	// Credentials.
	Discarded []DiscardedPresentation
}

// DiscardedPresentation is a presentation VerifyResponse discarded.
type DiscardedPresentation struct {
	// CredentialQueryID is the Credential Query it answered.
	CredentialQueryID string
	// Reason is why it failed verification: the error's text, kept as
	// a string so a stored Transaction's result serializes.
	Reason string
}

// Most Verifiers want Transactions, which calls VerifyResponse for each
// answer and also does what it leaves to the caller: routing the answer
// to its request, consuming the nonce, and binding the result to the
// browser that asked. Call VerifyResponse directly only for flows
// Transactions doesn't cover, such as the DC API.
//
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
// The Credential Queries req.Response.VPToken answers must select
// Credentials as §6.4.2's own "Selecting Credentials" rule asks
// (dcql.Query.CheckAnswered), or VerifyResponse fails: every key is
// one of req.Query's Credential Queries; without credential_sets,
// every Credential Query is answered; with them, the answers make up
// exactly one option of each dcql.CredentialSetQuery — none of an
// optional one, and never two alternatives ("presentations of a set
// of Credentials that match to one of the options") — and every
// answered Credential Query belongs to an answered option. A
// response is refused rather than partly ignored. Every answered
// Credential Query is then verified, and a failure fails
// VerifyResponse.
//
// VerifyResponse checks revocation only with req.Status: each
// VerifiedCredential carries its status reference (see
// VerifiedCredential.StatusListRef), which a StatusPolicy checks. A
// caller that sets neither Status nor a check of its own accepts
// revoked credentials.
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
// id, and every one of them is verified and returned, but one
// credential presented more than once refuses the response (see
// VerifyResponseResult.Credentials); when false (the default), more
// than one is a hard error.
func (v *Verifier) VerifyResponse(ctx context.Context, req VerifyResponseRequest) (VerifyResponseResult, error) {
	if req.Now != nil {
		// Certificates are valid, or not, at the verification's instant.
		ctx = WithVerificationTime(ctx, req.Now())
	}
	if err := req.Query.Validate(); err != nil {
		return VerifyResponseResult{}, fmt.Errorf("verifier: verify response: query: %w", err)
	}
	if req.ExpectedNonce == "" {
		return VerifyResponseResult{}, fmt.Errorf("verifier: verify response: expected_nonce is required")
	}
	if req.Origin != "" {
		if err := weborigin.Check(req.Origin); err != nil {
			return VerifyResponseResult{}, fmt.Errorf("verifier: verify response: %w", err)
		}
	}
	if req.Origin != "" && !slices.Contains(req.ExpectedOrigins, req.Origin) {
		return VerifyResponseResult{}, fmt.Errorf("verifier: verify response: origin %q isn't one of the request's expected_origins %v", req.Origin, req.ExpectedOrigins)
	}
	if err := checkMaxKeyBindingAgeRequired(req); err != nil {
		return VerifyResponseResult{}, err
	}
	if err := checkTimeBounds(req); err != nil {
		return VerifyResponseResult{}, err
	}
	if err := checkTrustedAuthoritiesConfigured(req); err != nil {
		return VerifyResponseResult{}, err
	}
	if err := checkIssuerKeysValid(req); err != nil {
		return VerifyResponseResult{}, fmt.Errorf("verifier: verify response: %w", err)
	}
	if v.cfg.Assurance == AssuranceProduction {
		if err := checkProductionKeySources(req); err != nil {
			return VerifyResponseResult{}, fmt.Errorf("verifier: verify response: %w", err)
		}
		if err := checkProductionDecisions(req); err != nil {
			return VerifyResponseResult{}, fmt.Errorf("verifier: verify response: %w", err)
		}
	}
	if !req.statusByTransactions {
		if err := CheckStatusDecision(v.cfg.Assurance, req.Status, req.NoStatusCheck); err != nil {
			return VerifyResponseResult{}, fmt.Errorf("verifier: verify response: %w", err)
		}
	}

	answered := make(map[string]bool, len(req.Response.VPToken))
	for id := range req.Response.VPToken {
		answered[id] = true
	}
	if err := req.Query.CheckAnswered(answered); err != nil {
		return VerifyResponseResult{}, fmt.Errorf("verifier: verify response: %w", newError(ReasonNotAnswered, "the vp_token doesn't answer the query as it asks", err))
	}
	result := VerifyResponseResult{}
	verifiedIDs := make(map[string]bool, len(answered))
	// The credentials verified so far, across every credential query
	// under DistinctCredentials: see verifyCredentialQuery.
	seen := make(map[[sha256.Size]byte]string)
	var firstFailure error
	for _, cq := range req.Query.Credentials {
		if !answered[cq.ID] {
			continue
		}
		vcs, discarded, err := v.verifyCredentialQuery(ctx, cq, req, seen)
		var allFailed *discardedError
		switch {
		case errors.As(err, &allFailed):
			if firstFailure == nil {
				firstFailure = fmt.Errorf("verifier: verify response: credential query %q: %w", cq.ID, allFailed.err)
			}
		case err != nil:
			return VerifyResponseResult{}, fmt.Errorf("verifier: verify response: credential query %q: %w", cq.ID, err)
		}
		result.Credentials = append(result.Credentials, vcs...)
		result.Discarded = append(result.Discarded, discarded...)
		verifiedIDs[cq.ID] = len(vcs) > 0
	}
	if len(result.Discarded) > 0 {
		// §8.6: what's left must still answer the query (§6.4); if it
		// doesn't, the first failure is why.
		if err := req.Query.CheckAnswered(verifiedIDs); err != nil {
			if firstFailure == nil {
				firstFailure = fmt.Errorf("verifier: verify response: %w", newError(ReasonNotAnswered, "what verified doesn't answer the query as it asks", err))
			}
			return VerifyResponseResult{}, firstFailure
		}
	}
	if req.statusByTransactions {
		return result, nil
	}
	if req.Status != nil {
		if err := req.Status.Check(ctx, result.Credentials...); err != nil {
			return VerifyResponseResult{}, err
		}
	}
	if req.Accept != nil {
		if err := req.Accept(ctx, "", result); err != nil {
			return VerifyResponseResult{}, err
		}
	}
	return result, nil
}

// MaxAllowedClockSkew and MaxAllowedKeyBindingAge bound
// VerifyResponseRequest's MaxClockSkew and MaxKeyBindingAge: beyond them
// a credential that has expired, or a Key Binding JWT made long ago for
// another purpose, would be taken as current. Clocks an hour apart are
// already broken; a holder presents within minutes of the request.
const (
	MaxAllowedClockSkew     = time.Hour
	MaxAllowedKeyBindingAge = time.Hour
)

// checkTimeBounds refuses a negative or excessive MaxClockSkew or
// MaxKeyBindingAge.
func checkTimeBounds(req VerifyResponseRequest) error {
	if req.MaxClockSkew < 0 || req.MaxClockSkew > MaxAllowedClockSkew {
		return fmt.Errorf("verifier: verify response: max_clock_skew %s is outside 0..%s", req.MaxClockSkew, MaxAllowedClockSkew)
	}
	if req.MaxKeyBindingAge < 0 || req.MaxKeyBindingAge > MaxAllowedKeyBindingAge {
		return fmt.Errorf("verifier: verify response: max_key_binding_age %s is outside 0..%s", req.MaxKeyBindingAge, MaxAllowedKeyBindingAge)
	}
	return nil
}

// checkProductionDecisions refuses, under AssuranceProduction, a
// request that hasn't decided which issuers may issue which types
// (IssuerAuthorized, or AnyIssuerForAnyType): left undecided, it
// silently accepts what it shouldn't. Its status decision is
// CheckStatusDecision's.
func checkProductionDecisions(req VerifyResponseRequest) error {
	if req.IssuerAuthorized == nil && !req.AnyIssuerForAnyType {
		return errors.New("under AssuranceProduction, set issuer_authorized (which issuers may issue which types) or any_issuer_for_any_type: without either, any trusted issuer is accepted for any type")
	}
	return nil
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
		if cq.Format == sdjwtvc.CredentialFormat {
			return fmt.Errorf("verifier: verify response: max_key_binding_age is required (must be positive) for a %q credential query: a credential bound to a key is checked for its KB-JWT", sdjwtvc.CredentialFormat)
		}
	}
	return nil
}

func checkTrustedAuthoritiesConfigured(req VerifyResponseRequest) error {
	for _, cq := range req.Query.Credentials {
		if len(cq.TrustedAuthorities) == 0 {
			continue
		}
		if req.TrustedAuthorities == nil {
			return fmt.Errorf("verifier: verify response: trusted_authorities is required when a credential query %q declares trusted_authorities", cq.ID)
		}
		if isUnverifiedAKIChecker(req.TrustedAuthorities) {
			return fmt.Errorf("verifier: verify response: trusted_authorities: dcql.AKITrustedAuthoritiesChecker needs Roots or Anchors to verify a presented credential (without them it only reads what the certificate claims about its issuer)")
		}
	}
	return nil
}

// isUnverifiedAKIChecker reports whether checker is a
// dcql.AKITrustedAuthoritiesChecker with neither Roots nor Anchors —
// fit for a Wallet filtering its own credentials, not for verifying a
// presented one (see its doc comment).
func isUnverifiedAKIChecker(checker dcql.TrustedAuthoritiesChecker) bool {
	switch c := checker.(type) {
	case dcql.AKITrustedAuthoritiesChecker:
		return c.Roots == nil && len(c.Anchors) == 0
	case *dcql.AKITrustedAuthoritiesChecker:
		return c == nil || (c.Roots == nil && len(c.Anchors) == 0)
	}
	return false
}

// verifyCredentialQuery locates cq's own Presentation(s) in
// req.Response.VPToken, checks their count against cq.Multiple (§6.1
// and §8.1's own "when multiple is omitted, or set to false, the
// array MUST contain only one Presentation"), and verifies every one
// of them, dispatching to the format-specific verification
// VerifyResponse's own doc comment describes. seen maps each credential
// already verified in this response, by the hash of its signed part, to
// the credential query it answered; verifyCredentialQuery adds cq's, and
// consults another query's only under req.DistinctCredentials.
func (v *Verifier) verifyCredentialQuery(ctx context.Context, cq dcql.CredentialQuery, req VerifyResponseRequest, seen map[[sha256.Size]byte]string) ([]VerifiedCredential, []DiscardedPresentation, error) {
	presentations := req.Response.VPToken[cq.ID]
	if len(presentations) == 0 {
		return nil, nil, newError(ReasonMalformed, "no presentation returned", nil)
	}
	if len(presentations) > 1 && !cq.Multiple {
		return nil, nil, newError(ReasonMalformed, "multiple presentations were returned but multiple is not requested", nil)
	}
	if len(presentations) > MaxPresentationsPerQuery {
		// Each is a chain and signatures to verify: anyone holding the
		// public Request Object could otherwise make one POST cost
		// hundreds of them.
		return nil, nil, newError(ReasonMalformed, fmt.Sprintf("%d presentations for one credential query, over the %d accepted", len(presentations), MaxPresentationsPerQuery), nil)
	}
	var discarded []DiscardedPresentation
	var firstErr error

	vcs := make([]VerifiedCredential, 0, len(presentations))
	for _, presented := range presentations {
		var claims map[string]any
		var status *mdoc.Status
		var chain [][]byte
		var signed []byte
		var err error
		switch cq.Format {
		case sdjwtvc.CredentialFormat:
			claims, chain, err = v.verifySDJWTVCPresentation(ctx, cq, presented, req)
			signed = sdjwtvcSignedPart(presented)
		case mdoc.CredentialFormat:
			claims, status, chain, signed, err = v.verifyMdocPresentation(ctx, cq, presented, req)
		default:
			return nil, nil, fmt.Errorf("format %q is not yet supported", cq.Format)
		}
		if err == nil {
			err = authorizeIssuer(ctx, req, cq, claims, chain)
		}
		if errors.Is(err, errNotThisRequest) {
			// A presentation made for another request, or replayed: the
			// whole response is refused, not just it (§14.1.2: "If any
			// Verifiable Presentation in the response does not contain
			// the correct nonce value, the response MUST be rejected").
			return nil, nil, err
		}
		var failed *Error
		if errors.As(err, &failed) {
			// The presentation failed, not the response or the
			// configuration: discard it (§8.6).
			discarded = append(discarded, DiscardedPresentation{CredentialQueryID: cq.ID, Reason: err.Error()})
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		// One credential presented twice isn't two credentials: under
		// multiple, a Verifier counting them (one per person, say) would
		// be misled. A Wallet never does it, so the response is refused.
		// So is one credential answering two queries, where the Verifier
		// asked for a credential of its own for each.
		identity := sha256.Sum256(signed)
		if other, ok := seen[identity]; ok {
			if other == cq.ID {
				return nil, nil, newError(ReasonMalformed, "the same credential was presented more than once", nil)
			}
			if req.DistinctCredentials {
				return nil, nil, newError(ReasonMalformed, fmt.Sprintf("the same credential was presented for credential queries %q and %q", other, cq.ID), nil)
			}
		}
		seen[identity] = cq.ID
		vcs = append(vcs, VerifiedCredential{CredentialQueryID: cq.ID, Claims: claims, MdocStatus: status, IssuerChain: chain})
	}
	if len(vcs) == 0 && firstErr != nil {
		// Nothing verified: the query's own failure, for the caller to
		// report if what's left doesn't answer the query.
		return nil, discarded, &discardedError{firstErr}
	}
	return vcs, discarded, nil
}

// sdjwtvcSignedPart is what identifies the credential an SD-JWT
// presentation carries: its Issuer-signed JWT's signing input (header
// and payload), which the holder can't change. Not the whole JWT: an
// ECDSA signature has another encoding that verifies too, so the same
// credential can be sent with different signature bytes. Disclosures
// and the KB-JWT are the holder's to vary.
func sdjwtvcSignedPart(compact string) []byte {
	issuerJWT, _, _ := strings.Cut(compact, "~")
	if i := strings.LastIndexByte(issuerJWT, '.'); i >= 0 {
		issuerJWT = issuerJWT[:i]
	}
	return []byte(issuerJWT)
}

// discardedError is a Credential Query all of whose presentations
// failed verification: VerifyResponse discards them, and reports the
// first's error only if the rest of the response doesn't answer the
// query.
type discardedError struct{ err error }

func (e *discardedError) Error() string { return e.err.Error() }
func (e *discardedError) Unwrap() error { return e.err }

func (v *Verifier) verifySDJWTVCPresentation(ctx context.Context, cq dcql.CredentialQuery, compact string, req VerifyResponseRequest) (map[string]any, [][]byte, error) {
	if req.IssuerKeys == nil {
		return nil, nil, fmt.Errorf("dependencies.issuer_keys is required for a %q credential query — see X5CIssuerKeyResolver for a ready-made implementation backed by a trust anchor pool", sdjwtvc.CredentialFormat)
	}
	pres, err := sdjwtvc.Parse(compact)
	if err != nil {
		return nil, nil, newError(ReasonMalformed, "parse presentation", err)
	}
	header, rawPayload, err := jose.DecodeUnverified(pres.IssuerJWT)
	if err != nil {
		return nil, nil, newError(ReasonMalformed, "decode issuer jwt", err)
	}
	var payload map[string]any
	if err := strictjson.Unmarshal(rawPayload, &payload); err != nil {
		return nil, nil, newError(ReasonMalformed, "unmarshal issuer jwt payload", err)
	}

	issuerPub, issuerAlg, err := req.IssuerKeys.ResolveIssuerKey(ctx, header, payload)
	if err != nil {
		return nil, nil, newError(ReasonUntrustedIssuer, "resolve issuer key", err)
	}

	// A credential bound to a key is presented with a KB-JWT whatever
	// the query asks (HAIP 1.0 §6.1.1.1: "If the credential has
	// cryptographic holder binding, a KB-JWT ... MUST always be present
	// when presenting an SD-JWT VC"), and that KB-JWT is verified: one
	// left unchecked could be replayed from another presentation.
	_, bound := payload["cnf"]
	requireHolderBinding := cq.RequiresCryptographicHolderBinding() || bound
	keyBindingRequirement := sdjwtvc.KeyBindingNotRequired
	var holderPub crypto.PublicKey
	var holderAlg jose.Alg
	if requireHolderBinding {
		keyBindingRequirement = sdjwtvc.KeyBindingRequired
		holderPub, holderAlg, err = holderPublicKeyFromCNF(payload["cnf"])
		if err != nil {
			return nil, nil, newError(ReasonHolderBinding, "resolve holder binding key", err)
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
		MaxClockSkew:      req.MaxClockSkew,
	})
	if err != nil {
		reason := ReasonInvalidCredential
		if errors.Is(err, sdjwtvc.ErrKeyBinding) {
			reason = ReasonHolderBinding
		}
		if errors.Is(err, sdjwtvc.ErrNotThisRequest) {
			return nil, nil, newError(reason, "verify", fmt.Errorf("%w: %w", errNotThisRequest, err))
		}
		return nil, nil, newError(reason, "verify", err)
	}

	if err := cq.SatisfiedBySDJWTVCClaims(claims); err != nil {
		return nil, nil, newError(ReasonNotAnswered, "satisfied by sdjwtvc claims", err)
	}

	// The resolver's verified path, where it gives one: the header's x5c
	// can carry certificates that aren't on it. Otherwise the header's
	// chain, and only where it's the key that verified the credential: a
	// header can carry anyone's public chain.
	var chain [][]byte
	if chainResolver, ok := req.IssuerKeys.(SDJWTVCIssuerChainResolver); ok {
		chains, err := chainResolver.ResolveIssuerChains(ctx, header)
		if err != nil {
			return nil, nil, newError(ReasonUntrustedIssuer, "resolve issuer chain", err)
		}
		chain = verifiedPath(chains, issuerPub)
	} else {
		headerChain, _ := certchain.X5CDERsFromHeader(header)
		chain = keyBoundChain(headerChain, issuerPub)
	}
	if len(cq.TrustedAuthorities) > 0 {
		if err := req.TrustedAuthorities.CheckTrustedAuthorities(ctx, cq.TrustedAuthorities, chain); err != nil {
			return nil, nil, newError(ReasonUntrustedIssuer, errCategoryTrustedAuthorities, err)
		}
	}
	return claims, chain, nil
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
//
// msoBytes is the IssuerAuth payload, the issuer-signed Mobile Security
// Object: what identifies the credential, which the holder can't change
// (unlike IssuerAuth's unprotected header, or its signature's
// encoding).
func (v *Verifier) verifyMdocPresentation(ctx context.Context, cq dcql.CredentialQuery, presented string, req VerifyResponseRequest) (claims map[string]any, status *mdoc.Status, chain [][]byte, msoBytes []byte, err error) {
	if req.MdocIssuerKeys == nil {
		return nil, nil, nil, nil, fmt.Errorf("dependencies.mdoc_issuer_keys is required for a %q credential query — see X5ChainIssuerKeyResolver for a ready-made implementation backed by a trust anchor pool", mdoc.CredentialFormat)
	}
	if req.ResponseEncryptionKey == nil {
		return nil, nil, nil, nil, fmt.Errorf("response_encryption_key is required for a %q credential query", mdoc.CredentialFormat)
	}

	raw, err := base64.RawURLEncoding.DecodeString(presented)
	if err != nil {
		return nil, nil, nil, nil, newError(ReasonMalformed, "decode device response", err)
	}
	doc, err := oid4vpmdoc.UnmarshalDeviceResponse(raw)
	if err != nil {
		return nil, nil, nil, nil, newError(ReasonMalformed, "unmarshal device response", err)
	}

	protected, unprotected, payload, err := cose.DecodeUnverified(doc.IssuerSigned.IssuerAuth)
	if err != nil {
		return nil, nil, nil, nil, newError(ReasonMalformed, "decode issuer auth", err)
	}
	// The x5chain is normally in the unprotected header (ISO/IEC 18013-5
	// §12.3.4), so the holder chooses it: any chain to a trusted anchor
	// whose leaf certifies the key that signed the MSO. Every decision
	// made on the chain — the anchors for the doctype, the document
	// signer checks, issuer authorization, trusted_authorities, the
	// status list's signer — is made on the one path CheckMdocIssuer
	// verified, so the holder can only pick among CAs that each certified
	// this same key, each of which vouches for it under the trust
	// configuration. The doctype, claims and status reference are in the
	// signed MSO, and a status list fetched from it is signed under the
	// issuer's own CA: one bound to another chain fails closed.
	// Accepting a chain only from the protected header would refuse
	// conforming mdocs.
	issuerPub, issuerAlg, err := req.MdocIssuerKeys.ResolveMdocIssuerKey(ctx, cose.X5ChainOf(protected, unprotected), doc.DocType)
	if err != nil {
		return nil, nil, nil, nil, newError(ReasonUntrustedIssuer, "resolve issuer key", err)
	}

	verified, err := mdoc.Verify(doc.IssuerSigned, doc.DocType, issuerPub, issuerAlg, mdoc.VerifyOptions{Now: req.Now, MaxClockSkew: req.MaxClockSkew})
	if err != nil {
		return nil, nil, nil, nil, newError(ReasonInvalidCredential, "verify issuer signed", err)
	}
	chain, err = CheckMdocIssuer(ctx, req.MdocIssuerKeys, cose.X5ChainOf(protected, unprotected), doc.DocType, issuerPub, verified)
	if err != nil {
		return nil, nil, nil, nil, newError(ReasonUntrustedIssuer, "check document signer", err)
	}

	thumbprintBytes, err := jwk.Thumbprint(&req.ResponseEncryptionKey.PublicKey)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("response encryption key: %w", err)
	}
	sessionTranscriptBytes, err := v.buildMdocSessionTranscriptBytes(req, thumbprintBytes)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("build session transcript: %w", err)
	}

	if doc.DeviceSigned.AuthType != mdoc.DeviceAuthSignature {
		return nil, nil, nil, nil, newError(ReasonHolderBinding, fmt.Sprintf("device authentication type %d is not supported (see verifyMdocPresentation's own doc comment)", doc.DeviceSigned.AuthType), nil)
	}
	deviceAlg, err := mdocAlgForKey(verified.DeviceKey)
	if err != nil {
		return nil, nil, nil, nil, newError(ReasonHolderBinding, "device key", err)
	}
	if err := mdoc.VerifyDeviceSignature(doc.DeviceSigned, verified.DeviceKey, deviceAlg, sessionTranscriptBytes, doc.DocType); err != nil {
		// The device signature is over a SessionTranscript carrying this
		// request's nonce and client_id (or origin): one that doesn't
		// verify was made for another request, or was tampered with.
		return nil, nil, nil, nil, newError(ReasonHolderBinding, "verify device signature", fmt.Errorf("%w: %w", errNotThisRequest, err))
	}

	if err := mdoc.CheckKeyAuthorizations(doc.DeviceSigned.NameSpaces, verified.KeyAuthorizations); err != nil {
		return nil, nil, nil, nil, newError(ReasonHolderBinding, "check key authorizations", err)
	}

	if err := cq.SatisfiedByMdocClaims(verified.DocType, verified.NameSpaces); err != nil {
		return nil, nil, nil, nil, newError(ReasonNotAnswered, "satisfied by mdoc claims", err)
	}

	if len(cq.TrustedAuthorities) > 0 {
		if err := req.TrustedAuthorities.CheckTrustedAuthorities(ctx, cq.TrustedAuthorities, chain); err != nil {
			return nil, nil, nil, nil, newError(ReasonUntrustedIssuer, errCategoryTrustedAuthorities, err)
		}
	}

	claims = make(map[string]any, len(verified.NameSpaces))
	for namespace, elements := range verified.NameSpaces {
		claims[namespace] = elements
	}
	return claims, verified.Status, chain, payload, nil
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

// errNotThisRequest marks a presentation that isn't bound to this
// request's nonce and audience, which refuses the whole response
// (§14.1.2), not just it.
var errNotThisRequest = errors.New("a presentation isn't bound to this request")

// MaxPresentationsPerQuery bounds how many presentations a response may
// carry for one credential query, under multiple.
const MaxPresentationsPerQuery = 32
