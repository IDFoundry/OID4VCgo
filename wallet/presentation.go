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
// for each Credential Query it could satisfy, the HeldCredential(s)
// chosen to satisfy it — more than one only when the Credential
// Query's own Multiple is true (§6.1); otherwise exactly one.
//
// query.CredentialSets implements §6.4.2's own "Selecting Credentials"
// rule: when absent, every Credential Query in query.Credentials is
// required (a Credential Query with no matching candidate is a hard
// error). When present, only the Credential Queries referenced by
// query.CredentialSets are matched at all — for each
// dcql.CredentialSetQuery, the first Options entry (most-preferred
// first) whose every referenced Credential Query id actually matches
// some candidate wins; a required (dcql.CredentialSetQuery.IsRequired)
// Credential Set with no satisfiable option fails the whole match
// (per §6.4.2's own "MUST NOT return any Credential(s)"), while an
// optional one is silently omitted from the result. A Credential Query
// not referenced by any Credential Set Query is never matched.
//
// "claim_sets" (§6.4.1) is handled by dcql.CredentialQuery's own
// Satisfied* methods — see their doc comments for exactly how an
// option is chosen.
func MatchDCQLQuery(query dcql.Query, candidates []HeldCredential) (map[string][]HeldCredential, error) {
	if err := query.Validate(); err != nil {
		return nil, fmt.Errorf("wallet: match dcql query: %w", err)
	}
	if len(query.CredentialSets) == 0 {
		matches := make(map[string][]HeldCredential, len(query.Credentials))
		for _, cq := range query.Credentials {
			match, err := matchCredentialQuery(cq, candidates)
			if err != nil {
				return nil, fmt.Errorf("wallet: match dcql query: credential query %q: %w", cq.ID, err)
			}
			matches[cq.ID] = match
		}
		return matches, nil
	}

	byID := make(map[string]dcql.CredentialQuery, len(query.Credentials))
	for _, cq := range query.Credentials {
		byID[cq.ID] = cq
	}
	matches := make(map[string][]HeldCredential, len(query.Credentials))
	for _, cs := range query.CredentialSets {
		option, err := satisfiableCredentialSetOption(cs, byID, candidates)
		if err != nil {
			if cs.IsRequired() {
				return nil, fmt.Errorf("wallet: match dcql query: credential set: %w", err)
			}
			continue
		}
		for id, match := range option {
			matches[id] = match
		}
	}
	return matches, nil
}

// satisfiableCredentialSetOption returns the HeldCredential matches
// for the first entry in cs.Options (most-preferred first, §6.4.2)
// whose every referenced Credential Query id actually matches some
// candidate, or an error naming the last option's own failure if none
// does.
func satisfiableCredentialSetOption(cs dcql.CredentialSetQuery, byID map[string]dcql.CredentialQuery, candidates []HeldCredential) (map[string][]HeldCredential, error) {
	var lastErr error
	for _, option := range cs.Options {
		matched := make(map[string][]HeldCredential, len(option))
		satisfied := true
		for _, id := range option {
			match, err := matchCredentialQuery(byID[id], candidates)
			if err != nil {
				satisfied = false
				lastErr = fmt.Errorf("credential query %q: %w", id, err)
				break
			}
			matched[id] = match
		}
		if satisfied {
			return matched, nil
		}
	}
	return nil, fmt.Errorf("no option is satisfied: %w", lastErr)
}

// matchCredentialQuery returns every candidate satisfying cq, trimmed
// to just the first when cq.Multiple is false (§6.1's own default) —
// or an error if none satisfy it at all.
func matchCredentialQuery(cq dcql.CredentialQuery, candidates []HeldCredential) ([]HeldCredential, error) {
	var matchAll func(dcql.CredentialQuery, []HeldCredential) []HeldCredential
	switch cq.Format {
	case sdjwtvc.CredentialFormat:
		matchAll = matchAllSDJWTVCQuery
	case mdoc.CredentialFormat:
		matchAll = matchAllMdocQuery
	default:
		return nil, fmt.Errorf("format %q is not yet supported", cq.Format)
	}
	matches := matchAll(cq, candidates)
	if len(matches) == 0 {
		return nil, fmt.Errorf("no held credential satisfies this credential query")
	}
	if !cq.Multiple {
		return matches[:1], nil
	}
	return matches, nil
}

func matchAllSDJWTVCQuery(cq dcql.CredentialQuery, candidates []HeldCredential) []HeldCredential {
	var matches []HeldCredential
	for _, cand := range candidates {
		if cand.Format != cq.Format {
			continue
		}
		_, _, claims, err := resolveHeldSDJWTVC(cand.Credential)
		if err != nil {
			continue // a malformed held credential isn't this query's fault; skip it
		}
		if cq.SatisfiedBySDJWTVCClaims(claims) == nil {
			matches = append(matches, cand)
		}
	}
	return matches
}

func matchAllMdocQuery(cq dcql.CredentialQuery, candidates []HeldCredential) []HeldCredential {
	var matches []HeldCredential
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
			matches = append(matches, cand)
		}
	}
	return matches
}

// PresentSDJWTVC builds a "dc+sd-jwt" Presentation (a VP Token array
// entry, Appendix B.3) from held: a fresh Key Binding JWT bound to
// aud/nonce (§14.1.2, Appendix B.3.6), reusing every one of held's own
// Disclosures. RFC 9901 §7.2 lets a Holder present a subset instead —
// see PresentSDJWTVCSelective for that; this function's own "disclose
// everything" behavior is unchanged, for a caller with no DCQL query
// context to trim against.
func PresentSDJWTVC(held HeldCredential, aud, nonce string) (string, error) {
	if held.Format != sdjwtvc.CredentialFormat {
		return "", fmt.Errorf("wallet: present sd-jwt vc: held credential format is %q, want %q", held.Format, sdjwtvc.CredentialFormat)
	}
	pres, hashAlg, _, err := resolveHeldSDJWTVC(held.Credential)
	if err != nil {
		return "", fmt.Errorf("wallet: present sd-jwt vc: %w", err)
	}
	return signAndCompactSDJWTVCPresentation(held, pres, hashAlg, aud, nonce)
}

// PresentSDJWTVCSelective is PresentSDJWTVC's own minimal-disclosure
// twin (RFC 9901 §7.2, §6.4.1's own "the Wallet MUST NOT send
// selectively disclosable claims that have not been selected"): it
// builds the same kind of Presentation, but includes only the
// Disclosures requiredPaths actually needs
// (credential/sdjwtvc.SelectDisclosures), dropping every other one —
// PresentCredentials is this function's own real caller, via
// dcql.CredentialQuery.SelectedSDJWTVCClaimPaths.
//
// Each Path in requiredPaths is walked as a sequence of
// object-property names — SelectDisclosures's own contract. A Path
// with a Wildcard/Index component (selecting into an *array*, as
// opposed to an object property) isn't supported for trimming yet:
// this function falls back to PresentSDJWTVC's own full disclosure
// for the whole credential in that case, rather than guessing which
// array elements matter — the one narrow case where this package's
// own output can still exceed what §6.4.1 strictly allows; every
// Claims Path Pointer either format's own DCQL query fixtures in this
// repo actually uses today is Wildcard/Index-free, so this cut costs
// nothing in practice yet.
func PresentSDJWTVCSelective(held HeldCredential, aud, nonce string, requiredPaths []dcql.Path) (string, error) {
	if held.Format != sdjwtvc.CredentialFormat {
		return "", fmt.Errorf("wallet: present sd-jwt vc: held credential format is %q, want %q", held.Format, sdjwtvc.CredentialFormat)
	}
	disclosurePaths, ok := sdjwtvcDisclosurePaths(requiredPaths)
	if !ok {
		return PresentSDJWTVC(held, aud, nonce)
	}

	pres, hashAlg, _, err := resolveHeldSDJWTVC(held.Credential)
	if err != nil {
		return "", fmt.Errorf("wallet: present sd-jwt vc: %w", err)
	}
	payload, err := rawSDJWTVCPayload(pres)
	if err != nil {
		return "", fmt.Errorf("wallet: present sd-jwt vc: %w", err)
	}
	selected, err := sdjwtvc.SelectDisclosures(payload, hashAlg, pres.Disclosures, disclosurePaths)
	if err != nil {
		return "", fmt.Errorf("wallet: present sd-jwt vc: select disclosures: %w", err)
	}
	pres.Disclosures = selected

	return signAndCompactSDJWTVCPresentation(held, pres, hashAlg, aud, nonce)
}

// presentSDJWTVCSelectively builds held's own "dc+sd-jwt" Presentation
// trimmed to exactly what cq's own Claims/ClaimSets say are needed
// (dcql.CredentialQuery.SelectedSDJWTVCClaimPaths) — the entry point
// PresentCredentials uses so its own vp_token is §6.4.1-compliant by
// construction, unlike calling PresentSDJWTVC directly.
func presentSDJWTVCSelectively(held HeldCredential, cq dcql.CredentialQuery, aud, nonce string) (string, error) {
	_, _, claims, err := resolveHeldSDJWTVC(held.Credential)
	if err != nil {
		return "", fmt.Errorf("wallet: present sd-jwt vc: %w", err)
	}
	paths, err := cq.SelectedSDJWTVCClaimPaths(claims)
	if err != nil {
		return "", fmt.Errorf("wallet: present sd-jwt vc: %w", err)
	}
	return PresentSDJWTVCSelective(held, aud, nonce, paths)
}

// rawSDJWTVCPayload decodes pres's own Issuer JWT payload without
// resolving its Disclosures — the shape
// credential/sdjwtvc.SelectDisclosures needs to walk (still carrying
// "_sd"/"_sd_alg"), as opposed to resolveHeldSDJWTVC's own
// fully-resolved claims.
func rawSDJWTVCPayload(pres sdjwtvc.Presentation) (map[string]any, error) {
	_, rawPayload, err := jose.DecodeUnverified(pres.IssuerJWT)
	if err != nil {
		return nil, fmt.Errorf("decode issuer jwt: %w", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return nil, fmt.Errorf("unmarshal issuer jwt payload: %w", err)
	}
	return payload, nil
}

// sdjwtvcDisclosurePaths converts paths into the plain object-property
// key sequences credential/sdjwtvc.SelectDisclosures needs, or
// ok=false if any Path has a Wildcard/Index component — see
// PresentSDJWTVCSelective's own doc comment for what a caller gets in
// that case.
func sdjwtvcDisclosurePaths(paths []dcql.Path) ([][]string, bool) {
	out := make([][]string, 0, len(paths))
	for _, p := range paths {
		keys := make([]string, 0, len(p))
		for _, elem := range p {
			if !elem.IsKey() {
				return nil, false
			}
			keys = append(keys, elem.Key())
		}
		out = append(out, keys)
	}
	return out, true
}

// signAndCompactSDJWTVCPresentation builds a fresh Key Binding JWT
// over pres/hashAlg bound to aud/nonce and returns the compact
// SD-JWT+KB string — the shared tail PresentSDJWTVC and
// PresentSDJWTVCSelective both need once pres.Disclosures already
// carries exactly what each of them decided to disclose.
func signAndCompactSDJWTVCPresentation(held HeldCredential, pres sdjwtvc.Presentation, hashAlg sdjwtvc.HashAlg, aud, nonce string) (string, error) {
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
// however the Verifier will reconstruct it — unlike "dc+sd-jwt"'s Key
// Binding JWT, "mso_mdoc"'s own DeviceSigned is authenticated over a
// structure that also commits to the Verifier's own response-encryption
// key (and, for the redirect flow, its response_uri), not just
// aud/nonce (Appendix B.2.6.1/B.2.6.2).
type PresentMdocParams struct {
	// Audience and ResponseURI are the redirect flow's own fields —
	// this Verifier's own "client_id" and "response_uri" — used to
	// build the OpenID4VPHandover (Appendix B.2.6.1) when Origin is
	// empty.
	Audience    string // client_id
	ResponseURI string

	Nonce                           string
	ResponseEncryptionJWKThumbprint []byte

	// Origin, if set, builds the DC API flow's own OpenID4VPDCAPIHandover
	// (Appendix B.2.6.2) instead — Audience/ResponseURI are then
	// unused, since the DC API flow has neither (see
	// verifier.VerifyResponseRequest.Origin's own doc comment for the
	// same split on the verification side).
	Origin string
}

// buildMdocSessionTranscriptBytes dispatches to
// oid4vpmdoc.BuildSessionTranscriptBytes (redirect flow) or
// BuildDCAPISessionTranscriptBytes (DC API flow) on whether
// params.Origin is set — PresentMdoc's own counterpart to
// verifier's identically-named private helper.
func buildMdocSessionTranscriptBytes(params PresentMdocParams) ([]byte, error) {
	if params.Origin != "" {
		return oid4vpmdoc.BuildDCAPISessionTranscriptBytes(oid4vpmdoc.DCAPIHandoverParams{
			Origin: params.Origin, Nonce: params.Nonce, ResponseEncryptionJWKThumbprint: params.ResponseEncryptionJWKThumbprint,
		})
	}
	return oid4vpmdoc.BuildSessionTranscriptBytes(oid4vpmdoc.HandoverParams{
		ClientID: params.Audience, Nonce: params.Nonce, ResponseURI: params.ResponseURI,
		ResponseEncryptionJWKThumbprint: params.ResponseEncryptionJWKThumbprint,
	})
}

// PresentMdoc builds an "mso_mdoc" Presentation (a VP Token array
// entry, Appendix B.2.5): the base64url-encoded DeviceResponse CBOR
// structure (oid4vpmdoc.MarshalDeviceResponse) carrying held's own
// IssuerSigned plus a fresh DeviceSigned — ECDSA/EdDSA device
// signature (§12.4.6) over SessionTranscriptBytes
// (buildMdocSessionTranscriptBytes) built from params, with no
// additional self-asserted DeviceSigned namespaces (an empty
// NameSpaces map — this package only ever proves possession of the
// device key, it doesn't build Holder-asserted claims of its own).
// Discloses every namespace/element held's own IssuerSigned carries —
// see PresentMdocSelective for a caller with DCQL query context to
// trim against.
func PresentMdoc(held HeldCredential, params PresentMdocParams) (string, error) {
	issuerSigned, err := decodeHeldMdoc(held)
	if err != nil {
		return "", err
	}
	return presentMdocWithIssuerSigned(held, params, issuerSigned)
}

// PresentMdocSelective is PresentMdoc's own minimal-disclosure twin —
// the "mso_mdoc" analog of PresentSDJWTVCSelective: ISO/IEC 18013-5's
// own namespace/data-element selective disclosure mechanism (§10.3.3)
// lets a Holder present only a subset of the elements an Issuer
// originally signed. It trims held's own IssuerSigned to exactly
// requiredPaths (credential/mdoc.IssuerSigned.SelectNameSpaces) before
// wrapping it, dropping every other disclosed element.
// PresentCredentials is this function's own real caller, via
// dcql.CredentialQuery.SelectedMdocClaimPaths.
//
// Each Path in requiredPaths must be a two-component mdoc-form path
// (dcql.Path.MdocNamespaceAndElement) — a Claims Path Pointer that
// isn't (a Wildcard/Index component, or any length other than two)
// isn't supported for trimming yet: this function falls back to
// PresentMdoc's own full disclosure for the whole credential in that
// case, the same narrow cut PresentSDJWTVCSelective's own doc comment
// takes for "dc+sd-jwt" — no mdoc Claims Path Pointer either format's
// own DCQL fixtures in this repo actually uses today has one, so this
// cut costs nothing in practice yet.
func PresentMdocSelective(held HeldCredential, params PresentMdocParams, requiredPaths []dcql.Path) (string, error) {
	issuerSigned, err := decodeHeldMdoc(held)
	if err != nil {
		return "", err
	}
	if selectorPaths, ok := mdocDisclosurePaths(requiredPaths); ok {
		issuerSigned = issuerSigned.SelectNameSpaces(selectorPaths)
	}
	return presentMdocWithIssuerSigned(held, params, issuerSigned)
}

// presentMdocSelectively builds held's own "mso_mdoc" Presentation
// trimmed to exactly what cq's own Claims/ClaimSets say are needed
// (dcql.CredentialQuery.SelectedMdocClaimPaths) — the entry point
// PresentCredentials uses so its own vp_token is §6.4.1-compliant by
// construction, unlike calling PresentMdoc directly.
func presentMdocSelectively(held HeldCredential, cq dcql.CredentialQuery, params PresentMdocParams) (string, error) {
	issuerSigned, err := decodeHeldMdoc(held)
	if err != nil {
		return "", err
	}
	paths, err := cq.SelectedMdocClaimPaths(held.MdocDocType, resolveHeldMdocNameSpaces(issuerSigned))
	if err != nil {
		return "", fmt.Errorf("wallet: present mdoc: %w", err)
	}
	return PresentMdocSelective(held, params, paths)
}

// decodeHeldMdoc validates held's own format/MdocDocType and decodes
// its base64url-encoded IssuerSigned — the shared first step
// PresentMdoc, PresentMdocSelective, and presentMdocSelectively all
// need.
func decodeHeldMdoc(held HeldCredential) (mdoc.IssuerSigned, error) {
	if held.Format != mdoc.CredentialFormat {
		return mdoc.IssuerSigned{}, fmt.Errorf("wallet: present mdoc: held credential format is %q, want %q", held.Format, mdoc.CredentialFormat)
	}
	if held.MdocDocType == "" {
		return mdoc.IssuerSigned{}, fmt.Errorf("wallet: present mdoc: held credential's own mdoc_doc_type is required")
	}
	raw, err := base64.RawURLEncoding.DecodeString(held.Credential)
	if err != nil {
		return mdoc.IssuerSigned{}, fmt.Errorf("wallet: present mdoc: decode credential: %w", err)
	}
	issuerSigned, err := mdoc.UnmarshalIssuerSigned(raw)
	if err != nil {
		return mdoc.IssuerSigned{}, fmt.Errorf("wallet: present mdoc: unmarshal issuer signed: %w", err)
	}
	return issuerSigned, nil
}

// mdocDisclosurePaths converts paths into the [namespace, element]
// pairs credential/mdoc.IssuerSigned.SelectNameSpaces needs, or
// ok=false if any Path isn't a valid two-component mdoc-form path —
// see PresentMdocSelective's own doc comment for what a caller gets in
// that case.
func mdocDisclosurePaths(paths []dcql.Path) ([][2]string, bool) {
	out := make([][2]string, 0, len(paths))
	for _, p := range paths {
		namespace, element, ok := p.MdocNamespaceAndElement()
		if !ok {
			return nil, false
		}
		out = append(out, [2]string{namespace, element})
	}
	return out, true
}

// presentMdocWithIssuerSigned is PresentMdoc/PresentMdocSelective's
// shared tail: signs a fresh DeviceSigned over
// buildMdocSessionTranscriptBytes(params) and wraps issuerSigned (as
// given — already trimmed by the caller, if at all) into a complete
// DeviceResponse.
func presentMdocWithIssuerSigned(held HeldCredential, params PresentMdocParams, issuerSigned mdoc.IssuerSigned) (string, error) {
	sessionTranscriptBytes, err := buildMdocSessionTranscriptBytes(params)
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

	// Audience is REQUIRED for the redirect flow (Origin empty): the
	// Verifier's own Client Identifier (the Authorization Request's
	// own "client_id", prefix included).
	Audience string

	// Nonce is REQUIRED: the Authorization/DC API Request's own
	// "nonce".
	Nonce string

	// ResponseURI and ResponseEncryptionJWKThumbprint are REQUIRED
	// whenever Query requests any "mso_mdoc" Credential — see
	// PresentMdocParams's own doc comment for why "mso_mdoc" needs
	// them where "dc+sd-jwt" doesn't. ResponseURI is a redirect-flow-only
	// field (unused when Origin is set).
	ResponseURI                     string
	ResponseEncryptionJWKThumbprint []byte

	// Origin, if set, presents for the DC API flow instead of the
	// redirect flow: Audience is ignored, and each Presentation is
	// bound to Appendix A.4's own "origin:"-prefixed audience instead
	// — see verifier.VerifyResponseRequest.Origin's own doc comment
	// for the same split on the verification side.
	Origin string
}

// PresentCredentials matches req.Query against req.Credentials
// (MatchDCQLQuery) and builds a VP Token entry for each match — see
// MatchDCQLQuery's own doc comment for this phase's scope. Each
// Presentation is built via presentSDJWTVCSelectively/presentMdocSelectively
// rather than PresentSDJWTVC/PresentMdoc directly, so it's trimmed to
// exactly the matched Credential Query's own Claims/ClaimSets
// (dcql.CredentialQuery.SelectedSDJWTVCClaimPaths/SelectedMdocClaimPaths)
// — §6.4.1's own "MUST NOT send selectively disclosable claims that
// have not been selected" — see PresentSDJWTVCSelective/PresentMdocSelective's
// own doc comments for the one narrow case each (a Wildcard/Index
// Claims Path) that still falls back to full disclosure. Returns the
// vp_token map ready for a direct_post(.jwt)/dc_api(.jwt) response
// body (§8.1): {<Credential Query id>: [<Presentation>]}.
func PresentCredentials(req PresentationRequest) (map[string][]string, error) {
	if req.Origin == "" && req.Audience == "" {
		return nil, fmt.Errorf("wallet: present credentials: audience is required")
	}
	if req.Nonce == "" {
		return nil, fmt.Errorf("wallet: present credentials: nonce is required")
	}
	matches, err := MatchDCQLQuery(req.Query, req.Credentials)
	if err != nil {
		return nil, fmt.Errorf("wallet: present credentials: %w", err)
	}

	aud := req.Audience
	if req.Origin != "" {
		aud = "origin:" + req.Origin
	}
	byID := make(map[string]dcql.CredentialQuery, len(req.Query.Credentials))
	for _, cq := range req.Query.Credentials {
		byID[cq.ID] = cq
	}

	vpToken := make(map[string][]string, len(matches))
	for id, helds := range matches {
		presented := make([]string, 0, len(helds))
		for _, held := range helds {
			var p string
			switch held.Format {
			case sdjwtvc.CredentialFormat:
				p, err = presentSDJWTVCSelectively(held, byID[id], aud, req.Nonce)
			case mdoc.CredentialFormat:
				p, err = presentMdocSelectively(held, byID[id], PresentMdocParams{
					Audience: req.Audience, Nonce: req.Nonce, Origin: req.Origin,
					ResponseURI: req.ResponseURI, ResponseEncryptionJWKThumbprint: req.ResponseEncryptionJWKThumbprint,
				})
			default:
				err = fmt.Errorf("format %q is not yet supported", held.Format)
			}
			if err != nil {
				return nil, fmt.Errorf("wallet: present credentials: credential query %q: %w", id, err)
			}
			presented = append(presented, p)
		}
		vpToken[id] = presented
	}
	return vpToken, nil
}
