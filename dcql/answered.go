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
	ids := sortedIDs(answered)
	if err := q.checkKnown(ids); err != nil {
		return err
	}
	if len(q.CredentialSets) == 0 {
		return q.checkAllAnswered(answered)
	}
	choices, reachable, err := q.answeredOptions(answered)
	if err != nil {
		return err
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

// checkKnown checks every one of ids is a Credential Query of q.
func (q Query) checkKnown(ids []string) error {
	for _, id := range ids {
		if !slices.ContainsFunc(q.Credentials, func(cq CredentialQuery) bool { return cq.ID == id }) {
			return fmt.Errorf("dcql: %q isn't one of the query's credential queries", id)
		}
	}
	return nil
}

// checkAllAnswered checks every Credential Query of q, which has no
// credential_sets, is answered.
func (q Query) checkAllAnswered(answered map[string]bool) error {
	for _, cq := range q.Credentials {
		if !answered[cq.ID] {
			return fmt.Errorf("dcql: credential query %q is required and isn't answered", cq.ID)
		}
	}
	return nil
}

// answeredOptions is, for each Credential Set Query, the options the
// answer includes whole — only those can be the one it answers — with
// nil for leaving an optional set out, and every ID in one of them. A
// required set with none is an error.
func (q Query) answeredOptions(answered map[string]bool) ([][][]string, map[string]bool, error) {
	choices := make([][][]string, len(q.CredentialSets))
	reachable := map[string]bool{}
	for i, cs := range q.CredentialSets {
		for _, option := range cs.Options {
			if slices.ContainsFunc(option, func(id string) bool { return !answered[id] }) {
				continue
			}
			choices[i] = append(choices[i], option)
			for _, id := range option {
				reachable[id] = true
			}
		}
		if !cs.IsRequired() {
			choices[i] = append(choices[i], nil) // left out
		} else if len(choices[i]) == 0 {
			return nil, nil, fmt.Errorf("dcql: credential_sets[%d] is required and none of its options is answered", i)
		}
	}
	return choices, reachable, nil
}

// coverExactly reports whether one of choices[i] for each set (nil
// leaving it out) together are exactly ids — every chosen option is
// within ids already, so only covering all of them is left to find.
func coverExactly(ids []string, choices [][][]string) (bool, error) {
	c := cover{ids: ids, choices: choices, covered: map[string]int{}}
	return c.pick(0)
}

// cover is coverExactly's search: covered counts how many chosen
// options include each ID, tried the combinations tried so far.
type cover struct {
	ids     []string
	choices [][][]string
	covered map[string]int
	tried   int
}

// pick chooses an option for set i onwards, reporting whether some
// choice covers every ID.
func (c *cover) pick(i int) (bool, error) {
	if i == len(c.choices) {
		return !slices.ContainsFunc(c.ids, func(id string) bool { return c.covered[id] == 0 }), nil
	}
	for _, option := range c.choices[i] {
		if c.tried++; c.tried > maxOptionCombinations {
			return false, errors.New("dcql: too many combinations of credential set options to check")
		}
		c.add(option, 1)
		if found, err := c.pick(i + 1); found || err != nil {
			return found, err
		}
		c.add(option, -1)
	}
	return false, nil
}

func (c *cover) add(option []string, n int) {
	for _, id := range option {
		c.covered[id] += n
	}
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
