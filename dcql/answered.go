package dcql

import (
	"fmt"
	"slices"
	"sort"
)

// CheckAnswered checks that answered — the IDs of the Credential
// Queries a response answers, or a selection would — select Credentials
// as OpenID4VP 1.0 §6.4.2 asks:
//
//   - every ID is one of q's Credential Queries;
//   - without credential_sets, every Credential Query is answered;
//   - with them, the answered IDs among each Credential Set Query's
//     options make up exactly one option ("presentations of a set of
//     Credentials that match to one of the options"): answering two
//     alternatives discloses more than the request needs, so it's
//     refused rather than one of them being dropped. Options nested in
//     another (["a"] within ["a", "b"]) count as the larger. A required
//     set must have its option answered; an optional one may have none.
//   - every answered ID belongs to a set's answered option.
//
// q must already be valid (Validate).
func (q Query) CheckAnswered(answered map[string]bool) error {
	known := make(map[string]bool, len(q.Credentials))
	for _, cq := range q.Credentials {
		known[cq.ID] = true
	}
	for _, id := range sortedIDs(answered) {
		if !known[id] {
			return fmt.Errorf("dcql: %q isn't one of the query's credential queries", id)
		}
	}
	if len(q.CredentialSets) == 0 {
		for _, cq := range q.Credentials {
			if !answered[cq.ID] {
				return fmt.Errorf("dcql: credential query %q is required and isn't answered", cq.ID)
			}
		}
		return nil
	}
	covered := map[string]bool{}
	for i, cs := range q.CredentialSets {
		option, err := answeredOption(cs, answered)
		if err != nil {
			return fmt.Errorf("dcql: credential_sets[%d]: %w", i, err)
		}
		if option == nil && cs.IsRequired() {
			return fmt.Errorf("dcql: credential_sets[%d] is required and none of its options is answered", i)
		}
		for _, id := range option {
			covered[id] = true
		}
	}
	for _, id := range sortedIDs(answered) {
		if !covered[id] {
			return fmt.Errorf("dcql: credential query %q is answered but isn't part of an answered credential set option", id)
		}
	}
	return nil
}

// answeredOption is the one option of cs answered fully, nil for none,
// or an error when answers make up more than one: options not nested in
// the largest answered one.
func answeredOption(cs CredentialSetQuery, answered map[string]bool) ([]string, error) {
	var full [][]string
	for _, option := range cs.Options {
		if !slices.ContainsFunc(option, func(id string) bool { return !answered[id] }) {
			full = append(full, option)
		}
	}
	if len(full) == 0 {
		return nil, nil
	}
	largest := slices.MaxFunc(full, func(a, b []string) int { return len(a) - len(b) })
	for _, option := range full {
		if slices.ContainsFunc(option, func(id string) bool { return !slices.Contains(largest, id) }) {
			return nil, fmt.Errorf("options %q and %q are both answered; a credential set takes one", largest, option)
		}
	}
	return largest, nil
}

func sortedIDs(m map[string]bool) []string {
	ids := make([]string, 0, len(m))
	for id, ok := range m {
		if ok {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}
