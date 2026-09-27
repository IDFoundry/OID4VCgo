package wallet

import (
	"context"
	"fmt"
	"sort"

	"github.com/idfoundry/oid4vcgo/dcql"
)

// PreviewedCredential is one credential PresentCredentials would present.
type PreviewedCredential struct {
	// QueryID is the DCQL Credential Query it answers.
	QueryID string

	// Credential is the held credential that would be presented.
	Credential HeldCredential

	// Claims are the claim paths the query selects (OID4VP §6.4.1): the
	// selectively disclosable claims that would be disclosed — for an
	// mdoc, every element presented. Claims the issuer didn't make
	// selectively disclosable (an SD-JWT VC's vct, iss, cnf, or any
	// other always-visible claim) are seen by every Verifier regardless.
	Claims []dcql.Path
}

// PreviewPresentation reports what PresentCredentials would present for
// query from candidates — which credential answers each Credential
// Query, and exactly which claims it would disclose, respecting
// claim_sets and credential_sets — without presenting anything, so a
// Wallet can show the holder before asking for consent. It makes the
// same choices PresentCredentials does, through the same matching
// (MatchDCQLQuery) and claim selection. Credentials are ordered by
// QueryID.
func PreviewPresentation(ctx context.Context, query dcql.Query, candidates []HeldCredential, trustedAuthorities dcql.TrustedAuthoritiesChecker) ([]PreviewedCredential, error) {
	matches, err := MatchDCQLQuery(ctx, query, candidates, trustedAuthorities)
	if err != nil {
		return nil, fmt.Errorf("wallet: preview presentation: %w", err)
	}
	byID := make(map[string]dcql.CredentialQuery, len(query.Credentials))
	for _, cq := range query.Credentials {
		byID[cq.ID] = cq
	}
	ids := make([]string, 0, len(matches))
	for id := range matches {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var preview []PreviewedCredential
	for _, id := range ids {
		for _, held := range matches[id] {
			paths, err := selectedClaimPaths(held, byID[id])
			if err != nil {
				return nil, fmt.Errorf("wallet: preview presentation: credential query %q: %w", id, err)
			}
			preview = append(preview, PreviewedCredential{QueryID: id, Credential: held, Claims: paths})
		}
	}
	return preview, nil
}
