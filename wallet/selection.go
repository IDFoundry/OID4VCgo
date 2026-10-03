package wallet

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/idfoundry/fapigo/fapihttp"

	"github.com/idfoundry/oid4vcgo/dcql"
)

// ErrInvalidSelection is wrapped by ValidateSelection, and so by
// PreviewSelection, RespondSelection and a PresentationRequest with a
// Selection, for a selection that doesn't answer the query as it asks.
var ErrInvalidSelection = errors.New("wallet: the selection doesn't answer the query")

// ValidateSelection checks that selection — for each Credential Query
// ID, the credentials chosen to answer it — answers query exactly as
// OpenID4VP 1.0 §6 asks, so the wallet presents what the holder (or the
// application's own policy) chose, never something the library picked:
//
//   - every query ID is one of query's, with at least one credential;
//   - each credential satisfies its query (format, meta, claims,
//     trusted_authorities);
//   - more than one credential only for a query whose multiple is true
//     (§6.1);
//   - without credential_sets, every query is answered; with them, each
//     required set has one option fully answered, and every answered
//     query belongs to a fully answered option (§6.4.2).
//
// It returns an error wrapping ErrInvalidSelection naming what's wrong.
func ValidateSelection(ctx context.Context, query dcql.Query, selection map[string][]HeldCredential, trustedAuthorities dcql.TrustedAuthoritiesChecker) error {
	if err := query.Validate(); err != nil {
		return fmt.Errorf("wallet: validate selection: %w", err)
	}
	byID := make(map[string]dcql.CredentialQuery, len(query.Credentials))
	for _, cq := range query.Credentials {
		byID[cq.ID] = cq
	}
	for _, id := range sortedKeys(selection) {
		cq, ok := byID[id]
		switch {
		case !ok:
			return fmt.Errorf("%w: the query has no credential query %q", ErrInvalidSelection, id)
		case len(selection[id]) == 0:
			return fmt.Errorf("%w: credential query %q has no credential selected", ErrInvalidSelection, id)
		case len(selection[id]) > 1 && !cq.Multiple:
			return fmt.Errorf("%w: credential query %q takes one credential, not %d (multiple is false)", ErrInvalidSelection, id, len(selection[id]))
		}
		for i, held := range selection[id] {
			if err := satisfies(ctx, cq, held, trustedAuthorities); err != nil {
				return fmt.Errorf("%w: credential %d for credential query %q: %w", ErrInvalidSelection, i, id, err)
			}
		}
	}
	return checkCredentialSets(query, selection)
}

// satisfies reports whether held answers cq on its own.
func satisfies(ctx context.Context, cq dcql.CredentialQuery, held HeldCredential, trustedAuthorities dcql.TrustedAuthoritiesChecker) error {
	if trustedAuthorities == nil && len(cq.TrustedAuthorities) > 0 {
		return fmt.Errorf("trusted_authorities is required when the credential query declares trusted_authorities")
	}
	_, err := matchCredentialQuery(ctx, cq, []HeldCredential{held}, trustedAuthorities)
	return err
}

// checkCredentialSets checks the selection answers query's
// credential_sets, or every query when there are none (§6.4.2).
func checkCredentialSets(query dcql.Query, selection map[string][]HeldCredential) error {
	if len(query.CredentialSets) == 0 {
		for _, cq := range query.Credentials {
			if len(selection[cq.ID]) == 0 {
				return fmt.Errorf("%w: credential query %q is required and has no credential selected", ErrInvalidSelection, cq.ID)
			}
		}
		return nil
	}
	answered := func(option []string) bool {
		return !slices.ContainsFunc(option, func(id string) bool { return len(selection[id]) == 0 })
	}
	covered := map[string]bool{}
	for i, cs := range query.CredentialSets {
		any := false
		for _, option := range cs.Options {
			if answered(option) {
				any = true
				for _, id := range option {
					covered[id] = true
				}
			}
		}
		if !any && cs.IsRequired() {
			return fmt.Errorf("%w: credential set %d is required and none of its options is fully selected", ErrInvalidSelection, i)
		}
	}
	for _, id := range sortedKeys(selection) {
		if !covered[id] {
			return fmt.Errorf("%w: credential query %q is selected but no credential set option it's part of is fully selected", ErrInvalidSelection, id)
		}
	}
	return nil
}

// DefaultSelection is the selection the wallet would make itself:
// MatchDCQLQuery's choice among candidates — the first satisfiable
// option of each credential set, the first matching credential of each
// query (all of them when multiple is true). An application with no
// policy of its own can present it, or start from it.
func DefaultSelection(ctx context.Context, query dcql.Query, candidates []HeldCredential, trustedAuthorities dcql.TrustedAuthoritiesChecker) (map[string][]HeldCredential, error) {
	return MatchDCQLQuery(ctx, query, candidates, trustedAuthorities)
}

// PreviewSelection reports what presenting selection would disclose,
// after ValidateSelection, without signing or sending anything.
func PreviewSelection(ctx context.Context, query dcql.Query, selection map[string][]HeldCredential, trustedAuthorities dcql.TrustedAuthoritiesChecker) ([]PreviewedCredential, error) {
	if err := ValidateSelection(ctx, query, selection, trustedAuthorities); err != nil {
		return nil, fmt.Errorf("wallet: preview selection: %w", err)
	}
	byID := make(map[string]dcql.CredentialQuery, len(query.Credentials))
	for _, cq := range query.Credentials {
		byID[cq.ID] = cq
	}
	var preview []PreviewedCredential
	for _, id := range sortedKeys(selection) {
		for _, held := range selection[id] {
			paths, err := selectedClaimPaths(held, byID[id])
			if err != nil {
				return nil, fmt.Errorf("wallet: preview selection: credential query %q: %w", id, err)
			}
			preview = append(preview, PreviewedCredential{QueryID: id, Credential: held, Claims: paths})
		}
	}
	return preview, nil
}

// RespondSelection is Respond for exactly selection — each Credential
// Query's chosen credentials — after ValidateSelection: the wallet
// presents what was chosen, never another match.
func RespondSelection(ctx context.Context, client fapihttp.HTTPClient, req AuthorizationRequest, selection map[string][]HeldCredential, trustedAuthorities dcql.TrustedAuthoritiesChecker) (Responded, error) {
	return respond(ctx, client, req, PresentationRequest{Selection: selection}, trustedAuthorities)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
