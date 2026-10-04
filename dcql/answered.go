package dcql

import (
	"errors"
	"fmt"
	"slices"
	"sort"
)

// maxOptionCombinations bounds CheckAnswered's search for the options
// a response answers.
const maxOptionCombinations = 10000

// CheckAnswered checks that answered — the IDs of the Credential
// Queries a response answers, or a selection would — select Credentials
// as OpenID4VP 1.0 §6.4.2 asks:
//
//   - every ID is one of q's Credential Queries;
//   - without credential_sets, every Credential Query is answered;
//   - with them, the answered IDs are exactly one option of each
//     required Credential Set Query, together with one option of each
//     optional one or none ("presentations of a set of Credentials that
//     match to one of the options"). A query two sets share counts for
//     both. Answering two alternatives of one set — or any query no
//     such choice of options includes — discloses more than the request
//     needs, so it's refused rather than part of it being dropped.
//
// q must already be valid (Validate).
func (q Query) CheckAnswered(answered map[string]bool) error {
	known := make(map[string]bool, len(q.Credentials))
	for _, cq := range q.Credentials {
		known[cq.ID] = true
	}
	ids := sortedIDs(answered)
	for _, id := range ids {
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
	// For each set, the options the answer includes whole: only those
	// can be the one it answers.
	choices := make([][][]string, len(q.CredentialSets))
	reachable := map[string]bool{}
	for i, cs := range q.CredentialSets {
		for _, option := range cs.Options {
			if !slices.ContainsFunc(option, func(id string) bool { return !answered[id] }) {
				choices[i] = append(choices[i], option)
				for _, id := range option {
					reachable[id] = true
				}
			}
		}
		if len(choices[i]) == 0 && cs.IsRequired() {
			return fmt.Errorf("dcql: credential_sets[%d] is required and none of its options is answered", i)
		}
		if !cs.IsRequired() {
			choices[i] = append(choices[i], nil) // left out
		}
	}
	for _, id := range ids {
		if !reachable[id] {
			return fmt.Errorf("dcql: credential query %q is answered but isn't part of an answered credential set option", id)
		}
	}
	switch found, err := coverExactly(ids, choices); {
	case err != nil:
		return err
	case !found:
		return errors.New("dcql: the answered credential queries are more than one option of each credential set: a credential set takes one")
	}
	return nil
}

// coverExactly reports whether one of choices[i] for each set (nil
// leaving it out) together are exactly ids — every chosen option is
// within ids already, so only covering all of them is left to find.
func coverExactly(ids []string, choices [][][]string) (bool, error) {
	covered := map[string]int{}
	tried := 0
	var pick func(i int) (bool, error)
	pick = func(i int) (bool, error) {
		if i == len(choices) {
			return !slices.ContainsFunc(ids, func(id string) bool { return covered[id] == 0 }), nil
		}
		for _, option := range choices[i] {
			if tried++; tried > maxOptionCombinations {
				return false, errors.New("dcql: too many combinations of credential set options to check")
			}
			for _, id := range option {
				covered[id]++
			}
			found, err := pick(i + 1)
			if found || err != nil {
				return found, err
			}
			for _, id := range option {
				covered[id]--
			}
		}
		return false, nil
	}
	return pick(0)
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
