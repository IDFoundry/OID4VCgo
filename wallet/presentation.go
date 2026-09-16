package wallet

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/idfoundry/oid4vcigo/credential/mdoc"
	"github.com/idfoundry/oid4vcigo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcigo/dcql"
	"github.com/idfoundry/oid4vcigo/internal/cose"
	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/oid4vpmdoc"
)

// HeldCredential is a credential this Wallet holds and may present.
// This package never verifies a held credential's own Issuer
// signature itself — the same "resolving trust is a caller's own job"
// split RequestCredential's own CredentialResult already establishes
// at receipt time (a caller wanting extra defense-in-depth before
// presenting may verify separately, e.g. via credential/sdjwtvc.Verify,
// before constructing a HeldCredential; this package only decodes the
// credential's own claims, it doesn't cryptographically trust them
// beyond "this Wallet already holds it").
type HeldCredential struct {
	// Format is the Credential Format Identifier. This package
	// supports "dc+sd-jwt" (credential/sdjwtvc.CredentialFormat) and
	// "mso_mdoc" (credential/mdoc.CredentialFormat) for presentation.
	Format string

	// Credential is the credential's own wire encoding, matching
	// oid4vci.IssuedCredential's own shape: for "dc+sd-jwt", the
	// compact bare SD-JWT (no Key Binding JWT yet: "~"-terminated);
	// for "mso_mdoc", the base64url-encoded CBOR IssuerSigned
	// structure.
	Credential string

	// HolderKey signs this credential's own proof of possession when
	// presented: a Key Binding JWT for "dc+sd-jwt" (must correspond
	// to the public key the credential's own "cnf" claim declares,
	// RFC 7800), or a DeviceSignature for "mso_mdoc" (must correspond
	// to DeviceKeyInfo.DeviceKey, ISO/IEC 18013-5 §12.3.4) — a
	// mismatch is caught by whichever Verifier receives the resulting
	// Presentation, not by this package.
	HolderKey crypto.Signer

	// HolderKeyAlg is the JOSE algorithm HolderKey signs with —
	// "dc+sd-jwt" only. "mso_mdoc"'s own DeviceSignature algorithm is
	// derived from HolderKey's own public key type instead (see
	// PresentMdoc), since credential/mdoc's own functions take a
	// cose.Alg, not a jose.Alg.
	HolderKeyAlg jose.Alg

	// MdocDocType is this credential's own ISO/IEC 18013-5 docType
	// (e.g. "org.iso.18013.5.1.mDL") — "mso_mdoc" only, REQUIRED for
	// that format. Unlike "dc+sd-jwt"'s own "vct" claim, an mdoc's
	// docType isn't conveniently readable from Credential without
	// cryptographically verifying IssuerSigned first (it lives in the
	// MSO, not IssuerSigned's own NameSpaces) — but the Wallet already
	// knows it from its own issuance-time bookkeeping (it requested
	// one specific credential_configuration_id, which maps to exactly
	// one docType), so this package asks for it directly rather than
	// re-deriving it from an unverified peek at the credential's own
	// bytes.
	MdocDocType string
}

// resolveHeldSDJWTVC parses credential (a HeldCredential's own
// Credential, "dc+sd-jwt" format) and decodes its Issuer JWT's own
// unverified payload — see HeldCredential's own doc comment for why
// this package doesn't verify its own held credential's signature —
// reporting the parsed Presentation, its declared or default hash
// algorithm (RFC 9901 §4.1.1's own "_sd_alg"), and its resolved
// (disclosed) claims.
func resolveHeldSDJWTVC(credential string) (sdjwtvc.Presentation, sdjwtvc.HashAlg, map[string]any, error) {
	pres, err := sdjwtvc.Parse(credential)
	if err != nil {
		return sdjwtvc.Presentation{}, "", nil, fmt.Errorf("parse: %w", err)
	}
	_, rawPayload, err := jose.DecodeUnverified(pres.IssuerJWT)
	if err != nil {
		return sdjwtvc.Presentation{}, "", nil, fmt.Errorf("decode issuer jwt: %w", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return sdjwtvc.Presentation{}, "", nil, fmt.Errorf("unmarshal issuer jwt payload: %w", err)
	}
	hashAlg := sdjwtvc.DefaultHashAlg
	if declared, ok := payload["_sd_alg"].(string); ok {
		hashAlg = sdjwtvc.HashAlg(declared)
	}
	claims, err := sdjwtvc.ResolveDisclosures(payload, hashAlg, pres.Disclosures)
	if err != nil {
		return sdjwtvc.Presentation{}, "", nil, fmt.Errorf("resolve disclosures: %w", err)
	}
	return pres, hashAlg, claims, nil
}

// resolveHeldMdocNameSpaces flattens issuerSigned's own NameSpaces
// (namespace => []IssuerSignedItem) into the namespace =>
// (data element identifier => value) shape
// dcql.CredentialQuery.SatisfiedByMdocClaims and VerifyResponseResult's
// own Claims both use — the same flattening credential/mdoc.Verify
// itself does internally for VerifiedMSO.NameSpaces, but available
// here without needing to cryptographically verify IssuerAuth first
// (see HeldCredential's own doc comment for why matching doesn't
// require that).
func resolveHeldMdocNameSpaces(issuerSigned mdoc.IssuerSigned) map[string]map[string]any {
	out := make(map[string]map[string]any, len(issuerSigned.NameSpaces))
	for namespace, items := range issuerSigned.NameSpaces {
		elements := make(map[string]any, len(items))
		for _, item := range items {
			elements[item.ElementIdentifier] = item.ElementValue
		}
		out[namespace] = elements
	}
	return out
}

// MatchDCQLQuery evaluates query (§6) against candidates and returns,
// for each Credential Query it could satisfy, the HeldCredential
// chosen to satisfy it.
//
// Phase scope, explicitly matching verifier.VerifyResponse's own
// scope: exactly one HeldCredential per Credential Query ("multiple:
// true" isn't supported), and every Credential Query is treated as
// required — one with no matching candidate is a hard error, not
// silently omitted (§6.4.2's own CredentialSets-driven "may be
// omitted" rule isn't implemented yet). "claim_sets" (§6.4.1) is
// handled by dcql.CredentialQuery's own Satisfied* methods — see
// their doc comments for exactly how an option is chosen.
func MatchDCQLQuery(query dcql.Query, candidates []HeldCredential) (map[string]HeldCredential, error) {
	if err := query.Validate(); err != nil {
		return nil, fmt.Errorf("wallet: match dcql query: %w", err)
	}
	matches := make(map[string]HeldCredential, len(query.Credentials))
	for _, cq := range query.Credentials {
		match, err := matchCredentialQuery(cq, candidates)
		if err != nil {
			return nil, fmt.Errorf("wallet: match dcql query: credential query %q: %w", cq.ID, err)
		}
		matches[cq.ID] = match
	}
	return matches, nil
}

func matchCredentialQuery(cq dcql.CredentialQuery, candidates []HeldCredential) (HeldCredential, error) {
	var match func(dcql.CredentialQuery, []HeldCredential) (HeldCredential, bool)
	switch cq.Format {
	case sdjwtvc.CredentialFormat:
		match = matchSDJWTVCQuery
	case mdoc.CredentialFormat:
		match = matchMdocQuery
	default:
		return HeldCredential{}, fmt.Errorf("format %q is not yet supported", cq.Format)
	}
	if cand, ok := match(cq, candidates); ok {
		return cand, nil
	}
	return HeldCredential{}, fmt.Errorf("no held credential satisfies this credential query")
}

func matchSDJWTVCQuery(cq dcql.CredentialQuery, candidates []HeldCredential) (HeldCredential, bool) {
	for _, cand := range candidates {
		if cand.Format != cq.Format {
			continue
		}
		_, _, claims, err := resolveHeldSDJWTVC(cand.Credential)
		if err != nil {
			continue // a malformed held credential isn't this query's fault; skip it
		}
		if cq.SatisfiedBySDJWTVCClaims(claims) == nil {
			return cand, true
		}
	}
	return HeldCredential{}, false
}

func matchMdocQuery(cq dcql.CredentialQuery, candidates []HeldCredential) (HeldCredential, bool) {
	for _, cand := range candidates {
		if cand.Format != cq.Format {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(cand.Credential)
		if err != nil {
			continue
		}
		issuerSigned, err := mdoc.UnmarshalIssuerSigned(raw)
		if err != nil {
			continue
		}
		if cq.SatisfiedByMdocClaims(cand.MdocDocType, resolveHeldMdocNameSpaces(issuerSigned)) == nil {
			return cand, true
		}
	}
	return HeldCredential{}, false
}

// PresentSDJWTVC builds a "dc+sd-jwt" Presentation (a VP Token array
// entry, Appendix B.3) from held: a fresh Key Binding JWT bound to
// aud/nonce (§14.1.2, Appendix B.3.6), reusing every one of held's own
// Disclosures — this package doesn't yet trim down to only the
// requested claims (RFC 9901 §7.2 lets a Holder present a subset; a
// caller wanting minimal disclosure can trim HeldCredential's own
// Disclosures itself before calling this, once dcql.Path.Select has
// told it which ones a Claims Query actually needs).
func PresentSDJWTVC(held HeldCredential, aud, nonce string) (string, error) {
	if held.Format != sdjwtvc.CredentialFormat {
		return "", fmt.Errorf("wallet: present sd-jwt vc: held credential format is %q, want %q", held.Format, sdjwtvc.CredentialFormat)
	}
	pres, hashAlg, _, err := resolveHeldSDJWTVC(held.Credential)
	if err != nil {
		return "", fmt.Errorf("wallet: present sd-jwt vc: %w", err)
	}
	kbJWT, err := sdjwtvc.NewKeyBindingJWT(held.HolderKey, held.HolderKeyAlg, pres, hashAlg, sdjwtvc.KeyBindingClaims{
		Audience: aud, Nonce: nonce,
	})
	if err != nil {
		return "", fmt.Errorf("wallet: present sd-jwt vc: %w", err)
	}
	pres.KeyBindingJWT = kbJWT
	compact, err := pres.Compact()
	if err != nil {
		return "", fmt.Errorf("wallet: present sd-jwt vc: %w", err)
	}
	return compact, nil
}

// mdocDeviceAlgForKey derives the mdoc authentication COSE algorithm
// from pub's own Go type — the same "derive alg from the key itself,
// never trust a wire-declared one" discipline verifier's own
// mdocDeviceAlgForKey applies on the verification side.
func mdocDeviceAlgForKey(pub crypto.PublicKey) (cose.Alg, error) {
	switch pub.(type) {
	case *ecdsa.PublicKey:
		return cose.ES256, nil
	case ed25519.PublicKey:
		return cose.EdDSA, nil
	default:
		return 0, fmt.Errorf("unsupported holder key type %T", pub)
	}
}

// PresentMdocParams bundles the Authorization-Request-derived context
// PresentMdoc needs to build SessionTranscriptBytes identically to
// however the Verifier will reconstruct it (oid4vpmdoc.HandoverParams)
// — unlike "dc+sd-jwt"'s Key Binding JWT, "mso_mdoc"'s own
// DeviceSigned is authenticated over a structure that also commits to
// the response_uri and the Verifier's own response-encryption key, not
// just aud/nonce (Appendix B.2.6.1).
type PresentMdocParams struct {
	Audience                        string // client_id
	Nonce                           string
	ResponseURI                     string
	ResponseEncryptionJWKThumbprint []byte
}

// PresentMdoc builds an "mso_mdoc" Presentation (a VP Token array
// entry, Appendix B.2.5): the base64url-encoded DeviceResponse CBOR
// structure (oid4vpmdoc.MarshalDeviceResponse) carrying held's own
// IssuerSigned plus a fresh DeviceSigned — ECDSA/EdDSA device
// signature (§12.4.6) over SessionTranscriptBytes
// (oid4vpmdoc.BuildSessionTranscriptBytes) built from params, with no
// additional self-asserted DeviceSigned namespaces (an empty
// NameSpaces map — this package only ever proves possession of the
// device key, it doesn't build Holder-asserted claims of its own).
func PresentMdoc(held HeldCredential, params PresentMdocParams) (string, error) {
	if held.Format != mdoc.CredentialFormat {
		return "", fmt.Errorf("wallet: present mdoc: held credential format is %q, want %q", held.Format, mdoc.CredentialFormat)
	}
	if held.MdocDocType == "" {
		return "", fmt.Errorf("wallet: present mdoc: held credential's own mdoc_doc_type is required")
	}
	raw, err := base64.RawURLEncoding.DecodeString(held.Credential)
	if err != nil {
		return "", fmt.Errorf("wallet: present mdoc: decode credential: %w", err)
	}
	issuerSigned, err := mdoc.UnmarshalIssuerSigned(raw)
	if err != nil {
		return "", fmt.Errorf("wallet: present mdoc: unmarshal issuer signed: %w", err)
	}

	sessionTranscriptBytes, err := oid4vpmdoc.BuildSessionTranscriptBytes(oid4vpmdoc.HandoverParams{
		ClientID: params.Audience, Nonce: params.Nonce, ResponseURI: params.ResponseURI,
		ResponseEncryptionJWKThumbprint: params.ResponseEncryptionJWKThumbprint,
	})
	if err != nil {
		return "", fmt.Errorf("wallet: present mdoc: %w", err)
	}
	alg, err := mdocDeviceAlgForKey(held.HolderKey.Public())
	if err != nil {
		return "", fmt.Errorf("wallet: present mdoc: %w", err)
	}
	deviceSigned, err := mdoc.SignDeviceSignature(held.HolderKey, alg, sessionTranscriptBytes, held.MdocDocType, map[string]map[string]interface{}{})
	if err != nil {
		return "", fmt.Errorf("wallet: present mdoc: %w", err)
	}

	deviceResponseBytes, err := oid4vpmdoc.MarshalDeviceResponse(oid4vpmdoc.Document{
		DocType: held.MdocDocType, IssuerSigned: issuerSigned, DeviceSigned: deviceSigned,
	})
	if err != nil {
		return "", fmt.Errorf("wallet: present mdoc: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(deviceResponseBytes), nil
}

// PresentationRequest is the input to PresentCredentials.
type PresentationRequest struct {
	// Query is REQUIRED: the Verifier's own DCQL query, e.g. decoded
	// from its Authorization Request's own "dcql_query".
	Query dcql.Query

	// Credentials is REQUIRED: this Wallet's own held credentials to
	// match Query against.
	Credentials []HeldCredential

	// Audience is REQUIRED: the Verifier's own Client Identifier
	// (the Authorization Request's own "client_id", prefix included).
	Audience string

	// Nonce is REQUIRED: the Authorization Request's own "nonce".
	Nonce string

	// ResponseURI and ResponseEncryptionJWKThumbprint are REQUIRED
	// whenever Query requests any "mso_mdoc" Credential — see
	// PresentMdocParams's own doc comment for why "mso_mdoc" needs
	// them where "dc+sd-jwt" doesn't.
	ResponseURI                     string
	ResponseEncryptionJWKThumbprint []byte
}

// PresentCredentials matches req.Query against req.Credentials
// (MatchDCQLQuery) and builds a VP Token entry for each match — see
// MatchDCQLQuery's own doc comment for this phase's scope. Returns the
// vp_token map ready for a direct_post(.jwt) response body (§8.1):
// {<Credential Query id>: [<Presentation>]}.
func PresentCredentials(req PresentationRequest) (map[string][]string, error) {
	if req.Audience == "" {
		return nil, fmt.Errorf("wallet: present credentials: audience is required")
	}
	if req.Nonce == "" {
		return nil, fmt.Errorf("wallet: present credentials: nonce is required")
	}
	matches, err := MatchDCQLQuery(req.Query, req.Credentials)
	if err != nil {
		return nil, fmt.Errorf("wallet: present credentials: %w", err)
	}

	vpToken := make(map[string][]string, len(matches))
	for id, held := range matches {
		var presented string
		switch held.Format {
		case sdjwtvc.CredentialFormat:
			presented, err = PresentSDJWTVC(held, req.Audience, req.Nonce)
		case mdoc.CredentialFormat:
			presented, err = PresentMdoc(held, PresentMdocParams{
				Audience: req.Audience, Nonce: req.Nonce,
				ResponseURI: req.ResponseURI, ResponseEncryptionJWKThumbprint: req.ResponseEncryptionJWKThumbprint,
			})
		default:
			err = fmt.Errorf("format %q is not yet supported", held.Format)
		}
		if err != nil {
			return nil, fmt.Errorf("wallet: present credentials: credential query %q: %w", id, err)
		}
		vpToken[id] = []string{presented}
	}
	return vpToken, nil
}
