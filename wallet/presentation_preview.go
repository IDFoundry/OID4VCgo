package wallet

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
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

	// AlwaysDisclosed are the SD-JWT VC claims this presentation
	// discloses beyond Claims, which the Verifier receives whatever the
	// selection: every claim it receives that no path in Claims
	// selects. That's the claims the issuer didn't make selectively
	// disclosable, and what shares a Disclosure with a claim in Claims:
	// the plaintext members of a disclosed object or array element a
	// claim sits within, and the other elements of an array the issuer
	// disclosed as one. Each is a leaf, walked into objects and arrays;
	// an object or array the Verifier receives empty (one holding only
	// decoys, or only claims not sent) is a leaf itself, as a literal {}
	// or [] is. An index counts the elements the holder's credential
	// has. The
	// registered JWT and SD-JWT VC claims (iss, vct, cnf, iat, nbf, exp,
	// status, jti) aside. Show them with Claims. None for an mdoc, whose
	// every element is selectively disclosed.
	AlwaysDisclosed []dcql.Path

	// DisclosedAlong are the AlwaysDisclosed claims sent only because a
	// claim in Claims is: those sharing its Disclosure, not those every
	// presentation of the credential reveals. What a Verifier asks for
	// brings them, so it's judged on them as on Claims (a registration's
	// coverage, for one).
	DisclosedAlong []dcql.Path

	// Retained are the Claims the Verifier says it intends to keep: an
	// mdoc's elements its query marks intent_to_retain (OpenID4VP
	// Appendix B.2.4). Show them to the holder with Claims.
	Retained []dcql.Path
}

// retainedClaims are the paths among selected that cq marks
// intent_to_retain.
func retainedClaims(cq dcql.CredentialQuery, selected []dcql.Path) []dcql.Path {
	var retained []dcql.Path
	for _, cl := range cq.Claims {
		if cl.IntentToRetain == nil || !*cl.IntentToRetain {
			continue
		}
		if slices.ContainsFunc(selected, func(p dcql.Path) bool { return slices.Equal(p, cl.Path) }) {
			retained = append(retained, cl.Path)
		}
	}
	return retained
}

// PreviewPresentation reports what PresentCredentials would present for
// query from candidates — which credential answers each Credential
// Query, and exactly which claims it would disclose, respecting
// claim_sets and credential_sets — without presenting anything, so a
// Wallet can show the holder before asking for consent. It makes the
// same choices PresentCredentials does, through the same matching
// (MatchDCQLQuery) and claim selection. Credentials are ordered by
// QueryID.
//
// It lists the claims a presentation sends, not what the Verifier can
// infer from which were chosen. Where claim_sets or credential_sets
// offer options and a claim carries values (DCQL's own design), the
// first option the holder's credentials satisfy is the one answered,
// so answering with a later one says the earlier one's value filter
// failed: with claim_sets [[x], [y]], x asking for birthdate with
// values ["1990-01-01"], a presentation of y's given_name alone tells
// the Verifier the holder's birthdate is not 1990-01-01. Each such
// probe needs the holder's consent, which a consent screen can ask
// with this in mind.
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
			preview = append(preview, previewedCredential(id, held, byID[id], paths))
		}
	}
	return preview, nil
}

// previewedCredential is held, answering cq (whose ID is id) with paths.
func previewedCredential(id string, held HeldCredential, cq dcql.CredentialQuery, paths []dcql.Path) PreviewedCredential {
	always, along := alwaysDisclosed(held, paths)
	return PreviewedCredential{QueryID: id, Credential: held, Claims: paths, AlwaysDisclosed: always, DisclosedAlong: along, Retained: retainedClaims(cq, paths)}
}

// registeredClaims are an SD-JWT VC's registered members: about the
// credential, not its holder, and shown to a holder as its type and
// issuer, not as disclosed claims.
var registeredClaims = map[string]bool{
	"iss": true, "vct": true, "vct#integrity": true, "cnf": true, "iat": true, "nbf": true, "exp": true, "status": true, "jti": true,
	"_sd": true, "_sd_alg": true,
}

// alwaysDisclosed is what presenting held for paths discloses beyond
// paths themselves, for an SD-JWT VC: every leaf of the credential that
// the Disclosures a presentation for paths sends (as
// sdjwtvc.SelectDisclosuresAt picks them, the same as Respond) reveal,
// and that no path covers (dcql.Path.Covers). That's the claims the
// issuer didn't make selectively disclosable, and what shares a
// Disclosure with a path's claim (RFC 9901 lets an issuer mix the two):
// the plaintext members of a disclosed object or array element
// (selecting address.street sends the address Disclosure, and with it
// address.country), and the other elements of an array disclosed as
// one (selecting nationalities[0] sends them all). along is the part of
// always a presentation selecting nothing wouldn't reveal. Leaves are
// paths into the holder's credential: an index counts the elements it
// has, as SelectDisclosuresAt's do.
func alwaysDisclosed(held HeldCredential, paths []dcql.Path) (always, along []dcql.Path) {
	if held.Format != sdjwtvc.CredentialFormat {
		return nil, nil
	}
	pres, hashAlg, _, err := resolveHeldSDJWTVC(held.Credential)
	if err != nil {
		return nil, nil
	}
	payload, err := rawSDJWTVCPayload(pres)
	if err != nil {
		return nil, nil
	}
	selected, err := sdjwtvc.SelectDisclosuresAt(payload, hashAlg, pres.Disclosures, sdjwtvcDisclosurePaths(paths))
	if err != nil {
		return nil, nil
	}
	byDigest, err := disclosuresByDigest(pres.Disclosures, hashAlg)
	if err != nil {
		return nil, nil
	}
	sent := make(map[string]bool, len(selected))
	for _, d := range selected {
		digest, err := d.Digest(hashAlg)
		if err != nil {
			return nil, nil
		}
		sent[digest] = true
	}
	plaintext := revealedLeaves(payload, byDigest, nil)
	for _, leaf := range revealedLeaves(payload, byDigest, sent) {
		if slices.ContainsFunc(paths, func(p dcql.Path) bool { return p.Covers(leaf) }) {
			continue
		}
		always = append(always, leaf)
		if !slices.ContainsFunc(plaintext, func(p dcql.Path) bool { return slices.Equal(p, leaf) }) {
			along = append(along, leaf)
		}
	}
	return always, along
}

// disclosuresByDigest indexes disclosures by their digest under alg.
func disclosuresByDigest(disclosures []sdjwtvc.Disclosure, alg sdjwtvc.HashAlg) (map[string]sdjwtvc.Disclosure, error) {
	out := make(map[string]sdjwtvc.Disclosure, len(disclosures))
	for _, d := range disclosures {
		digest, err := d.Digest(alg)
		if err != nil {
			return nil, err
		}
		out[digest] = d
	}
	return out, nil
}

// revealedLeaves are the leaves of payload, an Issuer JWT's raw payload,
// that a presentation sending the Disclosures whose digests are in sent
// reveals, its registered members aside, in member order.
func revealedLeaves(payload map[string]any, byDigest map[string]sdjwtvc.Disclosure, sent map[string]bool) []dcql.Path {
	var out []dcql.Path
	for _, m := range revealedMembers(payload, byDigest, sent) {
		if registeredClaims[m.name] {
			continue
		}
		out = appendRevealedLeaves(out, dcql.Path{dcql.PathKey(m.name)}, m.value, byDigest, sent, 1)
	}
	return out
}

// revealedMember is one member of a raw SD-JWT object a presentation
// reveals.
type revealedMember struct {
	name  string
	value any
}

// revealedMembers are obj's members a presentation sending sent
// reveals, by name: its plaintext ones, and those whose Disclosure is
// sent. A digest the holder has no Disclosure for (a decoy) reveals
// nothing.
func revealedMembers(obj map[string]any, byDigest map[string]sdjwtvc.Disclosure, sent map[string]bool) []revealedMember {
	var out []revealedMember
	for k, v := range obj {
		if k != "_sd" && k != "_sd_alg" {
			out = append(out, revealedMember{k, v})
		}
	}
	for _, digest := range sdDigests(obj) {
		if d, ok := byDigest[digest]; ok && sent[digest] && !d.IsArrayElement() {
			out = append(out, revealedMember{d.Name, d.Value})
		}
	}
	slices.SortFunc(out, func(a, b revealedMember) int { return strings.Compare(a.name, b.name) })
	return out
}

// appendRevealedLeaves appends to out the leaves of v, at path, a
// presentation sending sent reveals: the members of an object and the
// elements of an array it reveals, walked down to their values. An
// element's index counts the elements the holder's credential has (a
// decoy isn't one), revealed or not. An object or array that reveals
// no member or element is a leaf itself: the Verifier receives it
// empty, whether it is empty in the credential, holds only decoys, or
// holds only claims the presentation doesn't send.
func appendRevealedLeaves(out []dcql.Path, path dcql.Path, v any, byDigest map[string]sdjwtvc.Disclosure, sent map[string]bool, depth int) []dcql.Path {
	if depth > sdjwtvc.MaxResolveDepth {
		return append(out, path)
	}
	before := len(out)
	switch t := v.(type) {
	case map[string]any:
		for _, m := range revealedMembers(t, byDigest, sent) {
			out = appendRevealedLeaves(out, childPath(path, dcql.PathKey(m.name)), m.value, byDigest, sent, depth+1)
		}
	case []any:
		out = appendRevealedElementLeaves(out, path, t, byDigest, sent, depth)
	default:
		return append(out, path)
	}
	if len(out) == before {
		out = append(out, path)
	}
	return out
}

// appendRevealedElementLeaves appends to out the leaves of arr, an
// array at path, as appendRevealedLeaves does: of each
// element it reveals, indexed among the elements the holder's
// credential has.
func appendRevealedElementLeaves(out []dcql.Path, path dcql.Path, arr []any, byDigest map[string]sdjwtvc.Disclosure, sent map[string]bool, depth int) []dcql.Path {
	i := 0
	for _, el := range arr {
		value := el
		if digest, isRef := arrayElementDigest(el); isRef {
			d, held := byDigest[digest]
			if !held {
				continue
			}
			if !sent[digest] {
				i++
				continue
			}
			value = d.Value
		}
		out = appendRevealedLeaves(out, childPath(path, dcql.PathIndex(i)), value, byDigest, sent, depth+1)
		i++
	}
	return out
}

// childPath is path extended by elem, sharing no storage with path.
func childPath(path dcql.Path, elem dcql.PathElement) dcql.Path {
	return append(slices.Clone(path), elem)
}

// sdDigests are obj's "_sd" digests that are strings (RFC 9901 §4.1.1).
func sdDigests(obj map[string]any) []string {
	raw, _ := obj["_sd"].([]any)
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if digest, ok := item.(string); ok {
			out = append(out, digest)
		}
	}
	return out
}

// arrayElementDigest reports whether el is a selectively disclosable
// array element's placeholder, {"...": digest} (RFC 9901 §4.2.4.2), and
// its digest.
func arrayElementDigest(el any) (string, bool) {
	obj, ok := el.(map[string]any)
	if !ok || len(obj) != 1 {
		return "", false
	}
	digest, ok := obj["..."].(string)
	return digest, ok
}
