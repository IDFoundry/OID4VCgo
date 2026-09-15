package wallet

import (
	"crypto"
	"encoding/json"
	"fmt"

	"github.com/idfoundry/oid4vcigo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcigo/dcql"
	"github.com/idfoundry/oid4vcigo/internal/jose"
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
	// supports "dc+sd-jwt" (credential/sdjwtvc.CredentialFormat) for
	// presentation — see the package doc comment for what's not yet
	// supported.
	Format string

	// Credential is the credential's own wire encoding — for
	// "dc+sd-jwt", the compact bare SD-JWT (no Key Binding JWT yet:
	// "~"-terminated), matching oid4vci.IssuedCredential's own shape.
	Credential string

	// HolderKey signs this credential's own Key Binding JWT when
	// presented — must correspond to the public key this credential's
	// own "cnf" claim declares (RFC 7800): a mismatch is caught by
	// whichever Verifier receives the resulting Presentation, not by
	// this package.
	HolderKey crypto.Signer

	// HolderKeyAlg is the JOSE algorithm HolderKey signs with.
	HolderKeyAlg jose.Alg
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

// MatchDCQLQuery evaluates query (§6) against candidates and returns,
// for each Credential Query it could satisfy, the HeldCredential
// chosen to satisfy it.
//
// Phase scope, explicitly matching verifier.VerifyResponse's own
// scope: exactly one HeldCredential per Credential Query ("multiple:
// true" isn't supported), "claim_sets" isn't supported, "dc+sd-jwt"
// only, and every Credential Query is treated as required — one with
// no matching candidate is a hard error, not silently omitted
// (§6.4.2's own CredentialSets-driven "may be omitted" rule isn't
// implemented yet).
func MatchDCQLQuery(query dcql.Query, candidates []HeldCredential) (map[string]HeldCredential, error) {
	if err := query.Validate(); err != nil {
		return nil, fmt.Errorf("wallet: match dcql query: %w", err)
	}
	matches := make(map[string]HeldCredential, len(query.Credentials))
	for _, cq := range query.Credentials {
		if len(cq.ClaimSets) > 0 {
			return nil, fmt.Errorf("wallet: match dcql query: credential query %q: claim_sets is not yet supported", cq.ID)
		}
		match, err := matchCredentialQuery(cq, candidates)
		if err != nil {
			return nil, fmt.Errorf("wallet: match dcql query: credential query %q: %w", cq.ID, err)
		}
		matches[cq.ID] = match
	}
	return matches, nil
}

func matchCredentialQuery(cq dcql.CredentialQuery, candidates []HeldCredential) (HeldCredential, error) {
	if cq.Format != sdjwtvc.CredentialFormat {
		return HeldCredential{}, fmt.Errorf("format %q is not yet supported", cq.Format)
	}
	for _, cand := range candidates {
		if cand.Format != cq.Format {
			continue
		}
		_, _, claims, err := resolveHeldSDJWTVC(cand.Credential)
		if err != nil {
			continue // a malformed held credential isn't this query's fault; skip it
		}
		if cq.SatisfiedBySDJWTVCClaims(claims) == nil {
			return cand, nil
		}
	}
	return HeldCredential{}, fmt.Errorf("no held credential satisfies this credential query")
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

// PresentationRequest is the input to PresentCredentials.
type PresentationRequest struct {
	// Query is REQUIRED: the Verifier's own DCQL query, e.g. decoded
	// from its Authorization Request's own "dcql_query".
	Query dcql.Query

	// Credentials is REQUIRED: this Wallet's own held credentials to
	// match Query against.
	Credentials []HeldCredential

	// Audience is REQUIRED: the Verifier's own Client Identifier
	// (the Authorization Request's own "client_id", prefix included)
	// — every Presentation's own Key Binding JWT is bound to it.
	Audience string

	// Nonce is REQUIRED: the Authorization Request's own "nonce".
	Nonce string
}

// PresentCredentials matches req.Query against req.Credentials
// (MatchDCQLQuery) and builds a VP Token entry for each match —
// "dc+sd-jwt" only, see MatchDCQLQuery's own doc comment for the rest
// of this phase's scope. Returns the vp_token map ready for a
// direct_post(.jwt) response body (§8.1):
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
		presented, err := PresentSDJWTVC(held, req.Audience, req.Nonce)
		if err != nil {
			return nil, fmt.Errorf("wallet: present credentials: credential query %q: %w", id, err)
		}
		vpToken[id] = []string{presented}
	}
	return vpToken, nil
}
