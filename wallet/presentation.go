package wallet

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/internal/strictjson"
	"github.com/idfoundry/oid4vcgo/oid4vpmdoc"
)

// ErrNoMatchingCredential indicates a Credential Query (or every
// option of a required Credential Set Query, §6.4.2) has no held
// credential satisfying it — MatchDCQLQuery/PresentCredentials wrap
// this specific sentinel (errors.Is-detectable through the wrap
// chain) so a caller can distinguish "the query itself cannot be
// satisfied" from every other PresentCredentials failure, e.g. to
// choose OID4VP §8.5's own "access_denied" Authorization Response
// error code over the generic "invalid_request" when reporting it
// back to a Verifier (confirmed live against a real OIDF conformance
// suite instance: EnsureErrorResponseForUnsatisfiableDcqlQuery
// specifically expects this distinction).
var ErrNoMatchingCredential = errors.New("no held credential satisfies this credential query")

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
	HolderKeyAlg oid4vci.JOSEAlg

	// withoutKeyBinding presents a "dc+sd-jwt" credential that has no
	// HolderKey without a Key Binding JWT: set only by
	// PresentCredentials, for a Credential Query that sets
	// require_cryptographic_holder_binding to false (OID4VP §6.1).
	withoutKeyBinding bool

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
	if err := strictjson.Unmarshal(rawPayload, &payload); err != nil {
		return sdjwtvc.Presentation{}, "", nil, fmt.Errorf("unmarshal issuer jwt payload: %w", err)
	}
	hashAlg, err := sdjwtvc.PayloadHashAlg(payload, sdjwtvc.DefaultHashAlg)
	if err != nil {
		return sdjwtvc.Presentation{}, "", nil, err
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
//
// A Credential Query's own TrustedAuthorities (§6.1.1), when
// non-empty, restricts eligible candidates to only those trustedAuthorities
// accepts (their issuer certificate chain checked via
// trustedAuthorities.CheckTrustedAuthorities) — §6.1.1's own
// restriction on which Credentials this Wallet may even select, not
// just what a Verifier re-checks on the response side (see
// verifier.VerifyResponseRequest.TrustedAuthorities for that side of
// the same restriction). trustedAuthorities is REQUIRED whenever any
// Credential Query in query declares TrustedAuthorities — see
// dcql.TrustedAuthoritiesChecker's own doc comment for why this is a
// separate, per-query dependency.
func MatchDCQLQuery(ctx context.Context, query dcql.Query, candidates []HeldCredential, trustedAuthorities dcql.TrustedAuthoritiesChecker) (map[string][]HeldCredential, error) {
	if err := query.Validate(); err != nil {
		return nil, fmt.Errorf("wallet: match dcql query: %w", err)
	}
	if trustedAuthorities == nil {
		for _, cq := range query.Credentials {
			if len(cq.TrustedAuthorities) > 0 {
				return nil, fmt.Errorf("wallet: match dcql query: trusted_authorities is required when credential query %q declares trusted_authorities", cq.ID)
			}
		}
	}
	return newMatcher(candidates, trustedAuthorities).matchQuery(ctx, query)
}

// matchQuery is MatchDCQLQuery once query is validated.
func (m *matcher) matchQuery(ctx context.Context, query dcql.Query) (map[string][]HeldCredential, error) {
	if len(query.CredentialSets) == 0 {
		matches := make(map[string][]HeldCredential, len(query.Credentials))
		for _, cq := range query.Credentials {
			match, err := m.match(ctx, cq)
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
		option, err := m.satisfiableCredentialSetOption(ctx, cs, byID)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("wallet: match dcql query: %w", ctxErr)
		}
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

// matcher matches Credential Queries against one set of candidates.
// It decodes each candidate at most once, and matches each Credential
// Query id at most once, however many credential_sets options name it:
// without that, a query whose options each fail on their last id
// re-decoded every held credential for every earlier id of every
// option. A matcher is for one query, whose ids Validate made unique.
type matcher struct {
	candidates         []HeldCredential
	trustedAuthorities dcql.TrustedAuthoritiesChecker
	decoded            []*decodedCandidate
	decodes            int // candidates decoded so far
	results            map[string]matchResult
}

// matchResult is one Credential Query's own outcome.
type matchResult struct {
	matches []HeldCredential
	err     error
}

// decodedCandidate is what matching reads from one held credential:
// for "dc+sd-jwt", its resolved claims and Issuer JWT header; for
// "mso_mdoc", its namespaces and IssuerAuth x5chain. ok is false for a
// credential that doesn't decode, which matches nothing.
type decodedCandidate struct {
	ok          bool
	claims      map[string]any
	header      map[string]any
	nameSpaces  map[string]map[string]any
	issuerChain [][]byte
}

func newMatcher(candidates []HeldCredential, trustedAuthorities dcql.TrustedAuthoritiesChecker) *matcher {
	return &matcher{
		candidates:         candidates,
		trustedAuthorities: trustedAuthorities,
		decoded:            make([]*decodedCandidate, len(candidates)),
		results:            make(map[string]matchResult),
	}
}

// satisfiableCredentialSetOption returns the HeldCredential matches
// for the first entry in cs.Options (most-preferred first, §6.4.2)
// whose every referenced Credential Query id actually matches some
// candidate, or an error naming the last option's own failure if none
// does.
func (m *matcher) satisfiableCredentialSetOption(ctx context.Context, cs dcql.CredentialSetQuery, byID map[string]dcql.CredentialQuery) (map[string][]HeldCredential, error) {
	var lastErr error
	for _, option := range cs.Options {
		matched := make(map[string][]HeldCredential, len(option))
		satisfied := true
		for _, id := range option {
			match, err := m.match(ctx, byID[id])
			if err != nil {
				if ctx.Err() != nil {
					return nil, err
				}
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

// match returns every candidate satisfying cq, trimmed to just the
// first when cq.Multiple is false (§6.1's own default) — or an error
// if none satisfy it at all, or ctx is done.
func (m *matcher) match(ctx context.Context, cq dcql.CredentialQuery) ([]HeldCredential, error) {
	if r, ok := m.results[cq.ID]; ok {
		return r.matches, r.err
	}
	var satisfiedBy func(context.Context, dcql.CredentialQuery, HeldCredential, *decodedCandidate) bool
	switch cq.Format {
	case sdjwtvc.CredentialFormat:
		satisfiedBy = m.sdjwtvcSatisfies
	case mdoc.CredentialFormat:
		satisfiedBy = m.mdocSatisfies
	default:
		return nil, fmt.Errorf("format %q is not yet supported", cq.Format)
	}
	matches, err := m.matchAll(ctx, cq, satisfiedBy)
	if err != nil {
		return nil, err // ctx is done: not an outcome to remember
	}
	r := matchResult{matches: matches}
	switch {
	case len(matches) == 0:
		r = matchResult{err: ErrNoMatchingCredential}
	case !cq.Multiple:
		r.matches = matches[:1]
	}
	m.results[cq.ID] = r
	return r.matches, r.err
}

// matchAll returns every candidate of cq's format that satisfiedBy
// accepts, or ctx's error once it is done.
func (m *matcher) matchAll(ctx context.Context, cq dcql.CredentialQuery, satisfiedBy func(context.Context, dcql.CredentialQuery, HeldCredential, *decodedCandidate) bool) ([]HeldCredential, error) {
	var matches []HeldCredential
	for i, cand := range m.candidates {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if cand.Format != cq.Format {
			continue
		}
		d := m.decode(i)
		if !d.ok {
			continue // a malformed held credential isn't this query's fault; skip it
		}
		if satisfiedBy(ctx, cq, cand, d) {
			matches = append(matches, cand)
		}
	}
	return matches, nil
}

// decode returns candidate i decoded, decoding it on first use.
func (m *matcher) decode(i int) *decodedCandidate {
	if d := m.decoded[i]; d != nil {
		return d
	}
	m.decodes++
	d := &decodedCandidate{}
	m.decoded[i] = d
	cand := m.candidates[i]
	switch cand.Format {
	case sdjwtvc.CredentialFormat:
		pres, _, claims, err := resolveHeldSDJWTVC(cand.Credential)
		if err != nil {
			return d
		}
		header, _, err := jose.DecodeUnverified(pres.IssuerJWT)
		if err != nil {
			return d
		}
		d.ok, d.claims, d.header = true, claims, header
	case mdoc.CredentialFormat:
		raw, err := base64.RawURLEncoding.DecodeString(cand.Credential)
		if err != nil {
			return d
		}
		issuerSigned, err := mdoc.UnmarshalIssuerSigned(raw)
		if err != nil {
			return d
		}
		protected, unprotected, _, err := cose.DecodeUnverified(issuerSigned.IssuerAuth)
		if err != nil {
			return d
		}
		d.ok, d.nameSpaces, d.issuerChain = true, resolveHeldMdocNameSpaces(issuerSigned), cose.X5ChainOf(protected, unprotected)
	}
	return d
}

// candidateSatisfiesTrustedAuthorities reports whether cand's own
// issuer certificate chain (extracted from header, a "dc+sd-jwt"
// candidate's own JOSE header, or issuerChain, a "mso_mdoc"
// candidate's own IssuerAuth x5chain — exactly one of the two is
// non-nil per call site) satisfies cq's own TrustedAuthorities, when
// it declares any — true (vacuously) when cq declares none.
func candidateSatisfiesTrustedAuthorities(ctx context.Context, cq dcql.CredentialQuery, trustedAuthorities dcql.TrustedAuthoritiesChecker, header map[string]any, issuerChain [][]byte) bool {
	if len(cq.TrustedAuthorities) == 0 {
		return true
	}
	if header != nil {
		var err error
		issuerChain, err = certchain.X5CDERsFromHeader(header)
		if err != nil {
			return false
		}
	}
	return trustedAuthorities.CheckTrustedAuthorities(ctx, cq.TrustedAuthorities, issuerChain) == nil
}

func (m *matcher) sdjwtvcSatisfies(ctx context.Context, cq dcql.CredentialQuery, _ HeldCredential, d *decodedCandidate) bool {
	if cq.SatisfiedBySDJWTVCClaims(d.claims) != nil {
		return false
	}
	if _, bound := d.claims["cnf"]; !bound && cq.RequiresCryptographicHolderBinding() {
		return false // no holder key to bind it to, which the query requires (OID4VP §6.1)
	}
	return candidateSatisfiesTrustedAuthorities(ctx, cq, m.trustedAuthorities, d.header, nil)
}

func (m *matcher) mdocSatisfies(ctx context.Context, cq dcql.CredentialQuery, cand HeldCredential, d *decodedCandidate) bool {
	if cq.SatisfiedByMdocClaims(cand.MdocDocType, d.nameSpaces) != nil {
		return false
	}
	return candidateSatisfiesTrustedAuthorities(ctx, cq, m.trustedAuthorities, nil, d.issuerChain)
}

// PresentSDJWTVC builds a "dc+sd-jwt" Presentation (a VP Token array
// entry, Appendix B.3) from held: a fresh Key Binding JWT bound to
// aud/nonce (§14.1.2, Appendix B.3.6), reusing every one of held's own
// Disclosures.
//
// WARNING: despite the generic-sounding name, this always discloses
// EVERY claim held carries — there is no DCQL-query-aware trimming
// here at all. Answering an actual Verifier's Authorization Request
// (which always carries a dcql_query) with this function, instead of
// PresentCredentials (the query-aware entry point) or
// PresentSDJWTVCSelective, silently over-shares every selectively-
// disclosable claim the credential has, not just the ones the
// Verifier asked for — call this only when there genuinely is no DCQL
// query to trim against. RFC 9901 §7.2 lets a Holder present a subset
// instead — see PresentSDJWTVCSelective for that. A Verifier that
// refuses unrequested claims, as package verifier does unless told
// otherwise (VerifyResponseRequest.AllowUnrequestedClaims), refuses
// the over-sharing presentation.
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
// Each Path in requiredPaths is walked as OpenID4VP §7.1 defines,
// object members and array elements alike
// (credential/sdjwtvc.SelectDisclosuresAt): an array index or a
// wildcard discloses that element, or every element, with what the
// rest of the path needs inside it, and nothing else in the array.
func PresentSDJWTVCSelective(held HeldCredential, aud, nonce string, requiredPaths []dcql.Path) (string, error) {
	if held.Format != sdjwtvc.CredentialFormat {
		return "", fmt.Errorf("wallet: present sd-jwt vc: held credential format is %q, want %q", held.Format, sdjwtvc.CredentialFormat)
	}
	disclosurePaths := sdjwtvcDisclosurePaths(requiredPaths)

	pres, hashAlg, _, err := resolveHeldSDJWTVC(held.Credential)
	if err != nil {
		return "", fmt.Errorf("wallet: present sd-jwt vc: %w", err)
	}
	payload, err := rawSDJWTVCPayload(pres)
	if err != nil {
		return "", fmt.Errorf("wallet: present sd-jwt vc: %w", err)
	}
	selected, err := sdjwtvc.SelectDisclosuresAt(payload, hashAlg, pres.Disclosures, disclosurePaths)
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
	// A credential bound to a key (cnf) always carries a KB-JWT (HAIP
	// 1.0 §6.1.1.1), so only an unbound one is presented without.
	held.withoutKeyBinding = held.HolderKey == nil && !cq.RequiresCryptographicHolderBinding() && !sdjwtvcBound(held.Credential)
	paths, err := selectedClaimPaths(held, cq)
	if err != nil {
		return "", fmt.Errorf("wallet: present sd-jwt vc: %w", err)
	}
	return PresentSDJWTVCSelective(held, aud, nonce, paths)
}

// selectedClaimPaths is which of held's claims cq selects (OID4VP
// §6.4.1) — what PresentCredentials discloses, and what
// PreviewPresentation reports it will, from this one function so the
// two can't disagree.
func selectedClaimPaths(held HeldCredential, cq dcql.CredentialQuery) ([]dcql.Path, error) {
	switch held.Format {
	case sdjwtvc.CredentialFormat:
		_, _, claims, err := resolveHeldSDJWTVC(held.Credential)
		if err != nil {
			return nil, err
		}
		return cq.SelectedSDJWTVCClaimPaths(claims)
	case mdoc.CredentialFormat:
		issuerSigned, err := decodeHeldMdoc(held)
		if err != nil {
			return nil, err
		}
		return cq.SelectedMdocClaimPaths(held.MdocDocType, resolveHeldMdocNameSpaces(issuerSigned))
	default:
		return nil, fmt.Errorf("format %q is not yet supported", held.Format)
	}
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
	if err := strictjson.Unmarshal(rawPayload, &payload); err != nil {
		return nil, fmt.Errorf("unmarshal issuer jwt payload: %w", err)
	}
	return payload, nil
}

// sdjwtvcDisclosurePaths converts paths into
// credential/sdjwtvc.SelectDisclosuresAt's form: a string for an object
// member, an int for an array index, nil for every element.
func sdjwtvcDisclosurePaths(paths []dcql.Path) [][]any {
	out := make([][]any, 0, len(paths))
	for _, p := range paths {
		components := make([]any, 0, len(p))
		for _, elem := range p {
			switch {
			case elem.IsKey():
				components = append(components, elem.Key())
			case elem.IsIndex():
				components = append(components, elem.Index())
			default:
				components = append(components, nil)
			}
		}
		out = append(out, components)
	}
	return out
}

// sdjwtvcBound reports whether credential, a "dc+sd-jwt" SD-JWT, names
// a holder key in cnf. One that can't be read counts as bound, so it's
// never presented without a KB-JWT on that account.
func sdjwtvcBound(credential string) bool {
	pres, err := sdjwtvc.Parse(credential)
	if err != nil {
		return true
	}
	_, raw, err := jose.DecodeUnverified(pres.IssuerJWT)
	if err != nil {
		return true
	}
	var payload map[string]any
	if err := strictjson.Unmarshal(raw, &payload); err != nil {
		return true
	}
	_, bound := payload["cnf"]
	return bound
}

// signAndCompactSDJWTVCPresentation builds a fresh Key Binding JWT
// over pres/hashAlg bound to aud/nonce and returns the compact
// SD-JWT+KB string — the shared tail PresentSDJWTVC and
// PresentSDJWTVCSelective both need once pres.Disclosures already
// carries exactly what each of them decided to disclose.
func signAndCompactSDJWTVCPresentation(held HeldCredential, pres sdjwtvc.Presentation, hashAlg sdjwtvc.HashAlg, aud, nonce string) (string, error) {
	if held.HolderKey == nil {
		if !held.withoutKeyBinding {
			return "", errors.New("wallet: present sd-jwt vc: the credential has no holder key to sign a Key Binding JWT with")
		}
		compact, err := pres.Compact()
		if err != nil {
			return "", fmt.Errorf("wallet: present sd-jwt vc: %w", err)
		}
		return compact, nil
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

	Nonce string

	// ResponseEncryptionKey is the Verifier's own response-encryption
	// public key — this package derives its own RFC 7638 JWK
	// thumbprint internally (matching how verifier.VerifyResponseRequest.
	// ResponseEncryptionKey takes the mirror-image private key and
	// derives the same thumbprint on the verifying side), so a caller
	// never has to pre-compute Appendix B.2.6.1/B.2.6.2's own
	// "jwkThumbprint" input by hand.
	ResponseEncryptionKey *ecdsa.PublicKey

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
	if params.ResponseEncryptionKey == nil {
		return nil, fmt.Errorf("response_encryption_key is required for a %q credential", mdoc.CredentialFormat)
	}
	thumbprint, err := jwk.Thumbprint(params.ResponseEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("response encryption key: %w", err)
	}
	if params.Origin != "" {
		return oid4vpmdoc.BuildDCAPISessionTranscriptBytes(oid4vpmdoc.DCAPIHandoverParams{
			Origin: params.Origin, Nonce: params.Nonce, ResponseEncryptionJWKThumbprint: thumbprint,
		})
	}
	return oid4vpmdoc.BuildSessionTranscriptBytes(oid4vpmdoc.HandoverParams{
		ClientID: params.Audience, Nonce: params.Nonce, ResponseURI: params.ResponseURI,
		ResponseEncryptionJWKThumbprint: thumbprint,
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
//
// WARNING: despite the generic-sounding name, this always discloses
// EVERY namespace/element held's own IssuerSigned carries — there is
// no DCQL-query-aware trimming here at all. Answering an actual
// Verifier's Authorization Request (which always carries a
// dcql_query) with this function, instead of PresentCredentials (the
// query-aware entry point) or PresentMdocSelective, silently
// over-shares every element the credential has, not just the ones the
// Verifier asked for — call this only when there genuinely is no DCQL
// query to trim against. See PresentMdocSelective for a caller with
// DCQL query context to trim against. A Verifier that refuses
// unrequested elements, as package verifier and mdocdcapi do, refuses
// the over-sharing presentation.
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
// isn't a valid mdoc claims path (OpenID4VP §7.2, which
// dcql.Query.Validate also enforces), and this function returns an
// error rather than guessing. It deliberately does NOT fall back to
// PresentMdoc's own full disclosure in that case, the same
// "silently exceeding what a query asked for is a privacy violation,
// not a graceful degradation" reasoning PresentSDJWTVCSelective's own
// doc comment explains — an earlier version of this function did fall
// back to full disclosure here; found and fixed in a repo-wide
// security review. No mdoc Claims Path Pointer either format's own
// DCQL fixtures in this repo actually uses today needs this, so this
// was always unreachable in practice, but silently wrong the moment a
// real Verifier sent one.
func PresentMdocSelective(held HeldCredential, params PresentMdocParams, requiredPaths []dcql.Path) (string, error) {
	issuerSigned, err := decodeHeldMdoc(held)
	if err != nil {
		return "", err
	}
	selectorPaths, ok := mdocDisclosurePaths(requiredPaths)
	if !ok {
		return "", fmt.Errorf("wallet: present mdoc: one or more requested claim paths aren't a valid two-component [namespace, element] path, which selective disclosure trimming doesn't support — refusing to fall back to disclosing the whole credential")
	}
	issuerSigned = issuerSigned.SelectNameSpaces(selectorPaths)
	return presentMdocWithIssuerSigned(held, params, issuerSigned)
}

// presentMdocSelectively builds held's own "mso_mdoc" Presentation
// trimmed to exactly what cq's own Claims/ClaimSets say are needed
// (dcql.CredentialQuery.SelectedMdocClaimPaths) — the entry point
// PresentCredentials uses so its own vp_token is §6.4.1-compliant by
// construction, unlike calling PresentMdoc directly.
func presentMdocSelectively(held HeldCredential, cq dcql.CredentialQuery, params PresentMdocParams) (string, error) {
	paths, err := selectedClaimPaths(held, cq)
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
	if held.HolderKey == nil {
		return "", errors.New("wallet: present mdoc: the credential has no holder key to sign the DeviceSignature with")
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

	// Selection, when set, is presented exactly — for each Credential
	// Query ID, the credentials chosen to answer it — after
	// ValidateSelection, instead of matching Credentials against Query.
	Selection map[string][]HeldCredential

	// Audience is REQUIRED for the redirect flow (Origin empty): the
	// Verifier's own Client Identifier (the Authorization Request's
	// own "client_id", prefix included).
	Audience string

	// Nonce is REQUIRED: the Authorization/DC API Request's own
	// "nonce".
	Nonce string

	// ResponseURI and ResponseEncryptionKey are REQUIRED whenever Query
	// requests any "mso_mdoc" Credential — see PresentMdocParams's own
	// doc comment for why "mso_mdoc" needs them where "dc+sd-jwt"
	// doesn't. ResponseURI is a redirect-flow-only field (unused when
	// Origin is set).
	ResponseURI           string
	ResponseEncryptionKey *ecdsa.PublicKey

	// TrustedAuthorities is MatchDCQLQuery's own trustedAuthorities
	// parameter — REQUIRED whenever any Credential Query in Query
	// declares TrustedAuthorities. See MatchDCQLQuery's own doc
	// comment.
	TrustedAuthorities dcql.TrustedAuthoritiesChecker

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
// have not been selected". An SD-JWT VC's claims path may walk into
// arrays; an mdoc's is always [namespace, element], and anything else
// is refused rather than disclosing the whole credential. Returns the
// vp_token map ready for a direct_post(.jwt)/dc_api(.jwt) response
// body (§8.1): {<Credential Query id>: [<Presentation>]}.
func PresentCredentials(ctx context.Context, req PresentationRequest) (map[string][]string, error) {
	if req.Origin == "" && req.Audience == "" {
		return nil, fmt.Errorf("wallet: present credentials: audience is required")
	}
	if req.Nonce == "" {
		return nil, fmt.Errorf("wallet: present credentials: nonce is required")
	}
	matches := req.Selection
	if matches != nil {
		if err := ValidateSelection(ctx, req.Query, matches, req.TrustedAuthorities); err != nil {
			return nil, fmt.Errorf("wallet: present credentials: %w", err)
		}
	} else {
		m, err := MatchDCQLQuery(ctx, req.Query, req.Credentials, req.TrustedAuthorities)
		if err != nil {
			return nil, fmt.Errorf("wallet: present credentials: %w", err)
		}
		matches = m
	}
	var err error

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
					ResponseURI: req.ResponseURI, ResponseEncryptionKey: req.ResponseEncryptionKey,
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
