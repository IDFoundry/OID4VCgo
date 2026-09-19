package issuer

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
)

// jwtProofTyp is the required JOSE "typ" header of a jwt-type key proof
// (Appendix F.1).
const jwtProofTyp = "openid4vci-proof+jwt" //nolint:gosec // an OID4VCI typ value, not a credential

// AuthorizedRequest is what a Credential Request needs from an
// already-verified access token — ordinarily
// fapigo/resource.Verifier.Verify's own AuthorizationContext, adapted
// by the caller. RequestCredential doesn't verify the access token
// itself: token verification needs full HTTP request context (method,
// URL, DPoP proof or mTLS certificate) that has nothing to do with
// Credential Request/Response protocol logic, the same separation
// FAPIgo's own resource package draws from its client/server roles —
// see the package doc comment. See resource_verifier.go for the
// worked adaptation recipe.
type AuthorizedRequest struct {
	// ClientID, if non-empty, is checked against a jwt-type key proof's
	// "iss" claim when that claim is present (Appendix F.1), and — via
	// IssueNotificationID — binds any notification_id this request
	// causes to be issued to this same client, later re-checked by
	// RequestNotification. WARNING: leaving this empty doesn't just
	// skip a minor detail — it silently disables both checks entirely
	// (an empty ClientID trivially "matches" everything), for every
	// request that omits it, with no error or warning at runtime. Set
	// this from your own access-token verification (the token's
	// subject/client_id) unless you have a specific reason these
	// bindings shouldn't apply to your deployment.
	ClientID string

	// Scopes is every scope the access token grants. A requested
	// CredentialConfiguration whose Scope is non-empty must be included
	// here (§8.2: "The corresponding object in the
	// credential_configurations_supported map MUST contain one of the
	// value(s) used in the scope parameter in the Authorization
	// Request") — only consulted when the Credential Request uses
	// CredentialRequest.CredentialConfigurationID; ignored entirely for
	// a CredentialIdentifier-based request, which AuthorizationDetails
	// governs instead.
	Scopes []string

	// AuthorizationDetails is every "openid_credential"-typed entry of
	// the access token's own "authorization_details" claim (RFC 9396
	// §2, OID4VCI 1.0 §5.1.1/§6.2) — REQUIRED exactly when a Credential
	// Request presents CredentialIdentifier instead of
	// CredentialConfigurationID (§8.2's own MUST), ignored otherwise.
	// RequestCredential resolves CredentialRequest.CredentialIdentifier
	// against this to find which CredentialConfiguration applies,
	// entirely bypassing the CredentialConfigurationID/Scopes check —
	// the matched entry is itself the grant. This package never mints
	// or verifies this claim itself, the same "resolving trust is the
	// caller's job" split every other field here already takes; see
	// resource_verifier.go for how it feeds in from a verified token's
	// own claims. oid4vci.AuthorizationDetail is JSON-tagged so a caller
	// can json.Unmarshal an already-decoded token claim's raw
	// "authorization_details" array directly into this field, rather
	// than hand-rolling an equivalent wire type themselves.
	AuthorizationDetails []oid4vci.AuthorizationDetail
}

// CredentialRequest is a Credential Request (§8.2).
//
// Only the jwt and attestation proof types are supported (di_vp needs W3C VCDM,
// which this repo doesn't implement). A jwt proof's own binding key may
// be conveyed as jwk (always available), or as kid/x5c when
// Dependencies.ProofBindingKeys is configured — this package takes no
// position on how kid/x5c actually resolve to a trusted key (DID
// resolution, certificate-chain validation, ...); see
// ProofBindingKeyResolver's own doc comment. Request and response
// encryption (§10) are supported via the separate
// DecryptRequestBody/EncryptResponseBody — see their own doc comments
// and ResponseEncryption/RequestWasEncrypted below for how a caller
// wires them in; RequestCredential itself only enforces §8.2-18's own
// "Credential Request encryption MUST be used if the
// credential_response_encryption parameter is included." RequestCredential
// itself never defers
// issuance — it always issues immediately or fails outright; see
// RequestDeferredCredential for the Deferred Credential Endpoint (§9)
// this repo does implement, for a transaction some other,
// deployment-specific process has already decided to defer. A
// CredentialConfiguration with no
// ProofTypesSupported at all (an unbound credential, §14.2) isn't
// supported either, since credential/mdoc's Claims.DeviceKey is
// unconditionally required — there is no way to satisfy "no binding"
// for that format today.
type CredentialRequest struct {
	// CredentialConfigurationID selects a key in
	// Config.CredentialConfigurationsSupported directly, checked against
	// AuthorizedRequest.Scopes (§8.2). REQUIRED unless CredentialIdentifier
	// is present instead — exactly one of the two must be set.
	CredentialConfigurationID string

	// CredentialIdentifier is §8.2's own alternative to
	// CredentialConfigurationID: an opaque value naming one entry of
	// AuthorizedRequest.AuthorizationDetails' own CredentialIdentifiers,
	// which is what actually determines the CredentialConfiguration
	// used — REQUIRED exactly when AuthorizedRequest.AuthorizationDetails
	// carries a matching entry (an authorization_details-based grant,
	// RFC 9396), and MUST NOT be present otherwise (§8.2's own MUST on
	// both directions). Unrecognized (not present in any
	// AuthorizationDetails entry's own CredentialIdentifiers) fails with
	// ErrorUnknownCredentialIdentifier.
	CredentialIdentifier string

	// Proofs is §8.2's own "proofs" parameter: exactly one proof type
	// (a key in this map, either oid4vci.ProofTypeJWT or
	// oid4vci.ProofTypeAttestation) mapped to a non-empty array of raw
	// proof values. One Credential is
	// issued per resolved binding key — a jwt proof contributes exactly
	// one key each; an attestation proof contributes one key per entry
	// in its own attested_keys claim (Appendix F.3's own "SHOULD issue a
	// Credential for each cryptographic public key" guidance) — this is
	// what makes a multi-entry array (or a multi-key attestation) a
	// batch issuance request.
	Proofs map[string][]string

	// SDJWTClaims is the caller-supplied credential content — REQUIRED,
	// and used, exactly when the requested CredentialConfiguration's
	// Format is credential/sdjwtvc.CredentialFormat. This package has no
	// user database of its own; resolving what data belongs in the
	// credential is the caller's job, the same division
	// credential/sdjwtvc.Verify itself draws for key resolution. Leave
	// CNF unset — RequestCredential overwrites it per issued instance,
	// once per resolved binding key.
	SDJWTClaims *sdjwtvc.Claims

	// MdocClaims is SDJWTClaims' mso_mdoc counterpart. Leave DeviceKey
	// unset — RequestCredential overwrites it per issued instance.
	MdocClaims *mdoc.Claims

	// ResponseEncryption is this request's own optional
	// "credential_response_encryption" object (§8.2) — set this from
	// the decrypted request body's own JSON, the same as every other
	// field here. Nil means the Credential Response isn't encrypted;
	// pass whatever RequestCredential doesn't reject on to
	// EncryptResponseBody afterward.
	ResponseEncryption *ResponseEncryptionRequest

	// RequestWasEncrypted reports whether this Credential Request
	// itself arrived as a JWE (§10) — set this from
	// DecryptRequestBody's own second return value.
	// RequestCredential rejects ResponseEncryption being set unless
	// this is also true (§8.2-18).
	RequestWasEncrypted bool
}

// resolvedKey is one Wallet-supplied binding key extracted from a
// Credential Request's proofs, ready to bind one issued Credential
// instance to. JWKRaw is always populated (see CredentialRequest's own
// doc comment on jwk-only key resolution): a jwt proof's own "jwk"
// header, or one entry of an attestation's attested_keys.
type resolvedKey struct {
	Public crypto.PublicKey
	JWKRaw json.RawMessage
}

// RequestCredential implements the Credential Endpoint (§8): it
// resolves the requested CredentialConfiguration — via
// req.CredentialConfigurationID checked against auth's granted scope,
// or via req.CredentialIdentifier resolved against auth's own
// AuthorizationDetails, whichever req uses (see resolveCredentialConfiguration) —
// checks the proofs parameter's own array size against
// Config.BatchCredentialIssuance (see checkBatchSize), verifies every
// key proof in req.Proofs (consuming this issuer's own c_nonce once
// per request, not once per proof — see NonceStore's own doc comment),
// and issues one Credential per resolved binding key by dispatching
// into credential/sdjwtvc.Issue or credential/mdoc.Issue. See
// CredentialRequest's own doc comment for what's out of scope.
func (iss *Issuer) RequestCredential(ctx context.Context, auth AuthorizedRequest, req CredentialRequest) (oid4vci.CredentialResponse, error) {
	resp, err := iss.requestCredential(ctx, auth, req)
	iss.audit(ctx, AuditEventRequestCredential, auth.ClientID, err)
	return resp, err
}

func (iss *Issuer) requestCredential(ctx context.Context, auth AuthorizedRequest, req CredentialRequest) (oid4vci.CredentialResponse, error) {
	if req.ResponseEncryption != nil && !req.RequestWasEncrypted {
		return oid4vci.CredentialResponse{}, newError(ErrorInvalidEncryptionParameters, 400,
			"credential_response_encryption requires the request itself to be encrypted", nil)
	}
	cc, err := iss.resolveCredentialConfiguration(auth, req)
	if err != nil {
		return oid4vci.CredentialResponse{}, err
	}

	proofType, values, err := singleProofType(req.Proofs, cc)
	if err != nil {
		return oid4vci.CredentialResponse{}, err
	}
	if err := iss.checkBatchSize(values); err != nil {
		return oid4vci.CredentialResponse{}, err
	}
	ptc, ok := cc.ProofTypesSupported[proofType]
	if !ok {
		return oid4vci.CredentialResponse{}, newError(ErrorInvalidProof, 400,
			fmt.Sprintf("proof type %q is not supported for this credential_configuration_id", proofType), nil)
	}

	keys, err := iss.resolveProofKeys(ctx, auth, proofType, values, ptc)
	if err != nil {
		return oid4vci.CredentialResponse{}, err
	}

	credentials := make([]oid4vci.IssuedCredential, 0, len(keys))
	for _, key := range keys {
		credential, err := iss.issueOne(cc, req, key)
		if err != nil {
			return oid4vci.CredentialResponse{}, newError(ErrorCredentialRequestDenied, 400, "credential issuance failed", err)
		}
		credentials = append(credentials, oid4vci.IssuedCredential{Credential: credential})
	}

	var notificationID string
	if iss.deps.Notifications != nil {
		notificationID, err = iss.IssueNotificationID(ctx, auth)
		if err != nil {
			return oid4vci.CredentialResponse{}, fmt.Errorf("issuer: request credential: %w", err)
		}
	}
	return oid4vci.CredentialResponse{Credentials: credentials, NotificationID: notificationID}, nil
}

// checkBatchSize enforces §12.2.4's own "batch_size" as an actual cap
// on the proofs parameter's own array size (values, from
// singleProofType) — not on the number of Credentials ultimately
// issued, which for an attestation proof's own attested_keys can
// exceed the array size itself (Appendix F.3's own "one Credential per
// attested key" fan-out). Config.BatchCredentialIssuance's own doc
// comment reads §12.2.4's "the presence of this parameter means the
// issuer supports more than one key proof" as implying absence means
// exactly one — so nil caps at 1, not unlimited.
func (iss *Issuer) checkBatchSize(values []string) error {
	maxBatchSize := 1
	if b := iss.cfg.BatchCredentialIssuance; b != nil {
		maxBatchSize = b.BatchSize
	}
	if len(values) > maxBatchSize {
		return newError(ErrorInvalidProof, 400,
			fmt.Sprintf("proofs array has %d entries, which exceeds this issuer's own batch_size (%d)", len(values), maxBatchSize), nil)
	}
	return nil
}

// resolveCredentialConfiguration implements §8.2's own two mutually
// exclusive ways a Credential Request identifies which
// CredentialConfiguration it wants: exactly one of
// req.CredentialConfigurationID/req.CredentialIdentifier must be set —
// the former checked against auth.Scopes directly, the latter resolved
// against auth.AuthorizationDetails first (resolveCredentialIdentifier),
// which then names the CredentialConfiguration without any further
// Scopes check, since the matched authorization detail is itself the
// grant.
func (iss *Issuer) resolveCredentialConfiguration(auth AuthorizedRequest, req CredentialRequest) (CredentialConfiguration, error) {
	switch {
	case req.CredentialIdentifier != "" && req.CredentialConfigurationID != "":
		return CredentialConfiguration{}, newError(ErrorInvalidCredentialRequest, 400,
			"credential_identifier and credential_configuration_id must not both be present", nil)

	case req.CredentialIdentifier != "":
		configID, err := resolveCredentialIdentifier(auth.AuthorizationDetails, req.CredentialIdentifier)
		if err != nil {
			return CredentialConfiguration{}, err
		}
		cc, ok := iss.cfg.CredentialConfigurationsSupported[configID]
		if !ok {
			return CredentialConfiguration{}, newError(ErrorUnknownCredentialConfig, 400,
				"the credential_configuration_id authorized for this credential_identifier is not supported", nil)
		}
		return cc, nil

	case req.CredentialConfigurationID != "":
		cc, ok := iss.cfg.CredentialConfigurationsSupported[req.CredentialConfigurationID]
		if !ok {
			return CredentialConfiguration{}, newError(ErrorUnknownCredentialConfig, 400, "unknown credential_configuration_id", nil)
		}
		if cc.Scope != "" && !slices.Contains(auth.Scopes, cc.Scope) {
			return CredentialConfiguration{}, newError(ErrorInvalidCredentialRequest, 400,
				"access token does not grant the scope required for this credential_configuration_id", nil)
		}
		return cc, nil

	default:
		return CredentialConfiguration{}, newError(ErrorInvalidCredentialRequest, 400,
			"exactly one of credential_configuration_id or credential_identifier is required", nil)
	}
}

// resolveCredentialIdentifier finds identifier among every
// "openid_credential"-typed entry's own CredentialIdentifiers in
// details (RFC 9396 §5.1.1/§6.2), returning that entry's own
// CredentialConfigurationID — entries of any other Type are ignored,
// matching §5.1.1's own tolerance for coexisting authorization details
// types. No match (including details being empty — a
// credential_identifier presented against an access token that never
// carried one) fails with ErrorUnknownCredentialIdentifier (§8.3.1.2's
// own "Requested Credential identifier is unknown").
func resolveCredentialIdentifier(details []oid4vci.AuthorizationDetail, identifier string) (string, error) {
	for _, d := range details {
		if d.Type != oid4vci.AuthorizationDetailsTypeOpenIDCredential {
			continue
		}
		if slices.Contains(d.CredentialIdentifiers, identifier) {
			return d.CredentialConfigurationID, nil
		}
	}
	return "", newError(ErrorUnknownCredentialIdentifier, 400, "credential_identifier is not authorized for this access token", nil)
}

func singleProofType(proofs map[string][]string, cc CredentialConfiguration) (proofType string, values []string, err error) {
	if len(cc.ProofTypesSupported) == 0 {
		return "", nil, newError(ErrorInvalidCredentialRequest, 400,
			"this credential_configuration_id requires no cryptographic binding, which is not supported", nil)
	}
	if len(proofs) != 1 {
		return "", nil, newError(ErrorInvalidProof, 400, "proofs must contain exactly one proof type", nil)
	}
	for pt, v := range proofs {
		if len(v) == 0 {
			return "", nil, newError(ErrorInvalidProof, 400, "proofs value must be a non-empty array", nil)
		}
		proofType, values = pt, v
	}
	return proofType, values, nil
}

func (iss *Issuer) resolveProofKeys(
	ctx context.Context, auth AuthorizedRequest, proofType string, values []string, ptc oid4vci.ProofTypeConfiguration,
) ([]resolvedKey, error) {
	switch proofType {
	case oid4vci.ProofTypeJWT:
		return iss.resolveJWTProofKeys(ctx, auth, values, ptc)
	case oid4vci.ProofTypeAttestation:
		return iss.resolveAttestationProofKeys(ctx, values)
	default:
		return nil, newError(ErrorInvalidProof, 400, fmt.Sprintf("proof type %q is not supported", proofType), nil)
	}
}

func (iss *Issuer) issueOne(cc CredentialConfiguration, req CredentialRequest, key resolvedKey) (string, error) {
	switch cc.Format {
	case sdjwtvc.CredentialFormat:
		if req.SDJWTClaims == nil {
			return "", fmt.Errorf("issuer: CredentialRequest.SDJWTClaims is required for format %q", cc.Format)
		}
		return iss.issueSDJWT(*req.SDJWTClaims, key)
	case mdoc.CredentialFormat:
		if req.MdocClaims == nil {
			return "", fmt.Errorf("issuer: CredentialRequest.MdocClaims is required for format %q", cc.Format)
		}
		return iss.issueMdoc(*req.MdocClaims, key)
	default:
		return "", fmt.Errorf("issuer: format %q is not supported", cc.Format)
	}
}

// issueSDJWT binds claims to key's public key via cnf.jwk (RFC 7800),
// using key's original JWK bytes verbatim rather than re-deriving them
// from the parsed crypto.PublicKey.
func (iss *Issuer) issueSDJWT(claims sdjwtvc.Claims, key resolvedKey) (string, error) {
	var cnfJWK map[string]any
	if err := json.Unmarshal(key.JWKRaw, &cnfJWK); err != nil {
		return "", fmt.Errorf("issuer: unmarshal jwk for cnf: %w", err)
	}
	claims.CNF = map[string]any{"jwk": cnfJWK}

	sdjwt, _, err := sdjwtvc.Issue(iss.deps.SDJWTSigner.Signer, iss.deps.SDJWTSigner.Alg, claims, sdjwtvc.IssueOptions{
		KeyID:             iss.deps.SDJWTSigner.KeyID,
		IssuerCertificate: iss.deps.SDJWTSigner.IssuerCertificate,
	})
	if err != nil {
		return "", fmt.Errorf("issuer: issue sd-jwt vc: %w", err)
	}
	return sdjwt, nil
}

// issueMdoc binds claims to key's public key via DeviceKeyInfo.DeviceKey,
// then encodes the result per Appendix A.2.4: base64url(CBOR(IssuerSigned)).
func (iss *Issuer) issueMdoc(claims mdoc.Claims, key resolvedKey) (string, error) {
	claims.DeviceKey = key.Public
	signed, err := mdoc.Issue(iss.deps.MdocSigner.Signer, iss.deps.MdocSigner.Alg, claims, mdoc.IssueOptions{
		X5Chain: iss.deps.MdocSigner.X5Chain,
		KeyID:   iss.deps.MdocSigner.KeyID,
	})
	if err != nil {
		return "", fmt.Errorf("issuer: issue mdoc: %w", err)
	}
	wire, err := signed.Marshal()
	if err != nil {
		return "", fmt.Errorf("issuer: marshal IssuerSigned: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(wire), nil
}

// jwkHeaderKey extracts the JSON bytes of a jwt proof's "jwk" header
// (Appendix F.1). Only called once resolveProofBindingKey has already
// established header carries exactly one of jwk/kid/x5c and this is
// the jwk case, so header["jwk"]'s own presence is the only thing left
// to check.
func jwkHeaderKey(header map[string]any) (json.RawMessage, error) {
	jwkVal, hasJWK := header["jwk"]
	if !hasJWK {
		return nil, fmt.Errorf("jwk header is required")
	}
	raw, err := json.Marshal(jwkVal)
	if err != nil {
		return nil, fmt.Errorf("marshal jwk header: %w", err)
	}
	return raw, nil
}
