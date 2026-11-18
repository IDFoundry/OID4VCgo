package wallet_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// The preview is the holder's consent: for random SD-JWT VC shapes
// (nested objects and arrays, selectively disclosable members and
// elements, decoys) and random DCQL claims paths (keys, indices,
// wildcards), every claim the Verifier can read from the presentation
// PresentCredentials builds is covered by a path in PreviewPresentation's
// Claims or listed in its AlwaysDisclosed, and everything AlwaysDisclosed
// lists the Verifier can read. The oracle, previewOracleWalk, is written
// independently of the wallet's own walk.

// previewSeeds bounds TestPreview_CoversDisclosure; FuzzPreviewCoversDisclosure
// explores further.
const previewSeeds = 2000

// previewIssuer signs the random credentials.
type previewIssuer struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func newPreviewIssuer(tb testing.TB) previewIssuer {
	tb.Helper()
	ca, caKey := testcert.CA(tb, "preview property CA")
	leaf, leafKey := testcert.Leaf(tb, "preview property issuer", ca, caKey)
	return previewIssuer{leafKey, leaf}
}

// previewGen builds random issuance claims.
type previewGen struct{ r *rand.Rand }

func (g previewGen) scalar() any {
	switch g.r.IntN(4) {
	case 0:
		return fmt.Sprintf("s%d", g.r.IntN(5))
	case 1:
		return g.r.IntN(5)
	case 2:
		return g.r.IntN(2) == 0
	default:
		return nil
	}
}

func (g previewGen) value(depth int) any {
	if depth == 0 || g.r.IntN(10) < 4 {
		return g.scalar()
	}
	if g.r.IntN(2) == 0 {
		return g.object(depth - 1)
	}
	n := g.r.IntN(4)
	arr := make([]any, 0, n)
	for range n {
		v := g.value(depth - 1)
		if g.r.IntN(2) == 0 {
			v = sdjwtvc.SDElement(v)
		}
		arr = append(arr, v)
	}
	return arr
}

func (g previewGen) object(depth int) any {
	obj := map[string]any{}
	for _, name := range []string{"a", "b", "c", "d"}[:g.r.IntN(4)] {
		v := g.value(depth)
		if g.r.IntN(2) == 0 {
			v = sdjwtvc.SD(v)
		}
		obj[name] = v
	}
	if g.r.IntN(4) == 0 {
		return sdjwtvc.WithDecoys(obj, 1+g.r.IntN(2))
	}
	return obj
}

// previewLeaf is a leaf of the holder's credential, and whether the
// Disclosures a presentation sends reveal it.
type previewLeaf struct {
	path     dcql.Path
	revealed bool
}

func previewChild(p dcql.Path, e dcql.PathElement) dcql.Path { return append(slices.Clone(p), e) }

// previewOracleWalk records the leaves of node, a raw SD-JWT subtree at
// path; revealed is whether every Disclosure on the way to it was sent.
// A member or element is the holder's when it is plaintext or its
// Disclosure is held (a decoy digest is neither); indices count the
// holder's elements. An object or array none of whose members or
// elements is revealed reaches the Verifier as {} or [], so is a leaf.
func previewOracleWalk(node any, path dcql.Path, revealed bool, byDigest map[string]sdjwtvc.Disclosure, sent map[string]bool, out *[]previewLeaf) {
	type child struct {
		elem     dcql.PathElement
		value    any
		revealed bool
	}
	var children []child
	switch t := node.(type) {
	case map[string]any:
		for k, v := range t {
			if k != "_sd" && k != "_sd_alg" {
				children = append(children, child{dcql.PathKey(k), v, revealed})
			}
		}
		sd, _ := t["_sd"].([]any)
		for _, item := range sd {
			digest, _ := item.(string)
			if d, held := byDigest[digest]; held && !d.IsArrayElement() {
				children = append(children, child{dcql.PathKey(d.Name), d.Value, revealed && sent[digest]})
			}
		}
	case []any:
		for _, el := range t {
			if ref, ok := el.(map[string]any); ok && len(ref) == 1 {
				if digest, ok := ref["..."].(string); ok {
					if d, held := byDigest[digest]; held {
						children = append(children, child{dcql.PathIndex(len(children)), d.Value, revealed && sent[digest]})
					}
					continue
				}
			}
			children = append(children, child{dcql.PathIndex(len(children)), el, revealed})
		}
	default:
		*out = append(*out, previewLeaf{path, revealed})
		return
	}
	anyRevealed := false
	for _, c := range children {
		anyRevealed = anyRevealed || c.revealed
		previewOracleWalk(c.value, previewChild(path, c.elem), c.revealed, byDigest, sent, out)
	}
	if !anyRevealed && len(path) > 0 {
		*out = append(*out, previewLeaf{path, revealed})
	}
}

// previewQueryPaths are the node paths of resolved, the holder's
// processed claims, for a query to ask for.
func previewQueryPaths(v any, path dcql.Path, out *[]dcql.Path) {
	switch t := v.(type) {
	case map[string]any:
		for k, c := range t {
			if path == nil && previewRegistered[k] {
				continue
			}
			p := previewChild(path, dcql.PathKey(k))
			*out = append(*out, p)
			previewQueryPaths(c, p, out)
		}
	case []any:
		for i, c := range t {
			p := previewChild(path, dcql.PathIndex(i))
			*out = append(*out, p)
			previewQueryPaths(c, p, out)
		}
	}
}

var previewRegistered = map[string]bool{"iss": true, "vct": true, "vct#integrity": true, "cnf": true, "iat": true, "nbf": true, "exp": true, "status": true, "jti": true, "_sd_alg": true}

// checkPreviewCoversDisclosure issues a random credential and query from
// seed, and checks the preview against what the presentation reveals.
func checkPreviewCoversDisclosure(t *testing.T, iss previewIssuer, seed uint64) {
	t.Helper()
	g := previewGen{rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))}
	add := map[string]any{}
	for _, name := range []string{"a", "b", "c", "d", "e"}[:1+g.r.IntN(5)] {
		v := g.value(3)
		if g.r.IntN(3) != 0 {
			v = sdjwtvc.SD(v)
		}
		add[name] = v
	}
	exp := time.Now().Add(time.Hour).Unix()
	compact, _, err := sdjwtvc.Issue(iss.key, jose.ES256, sdjwtvc.Claims{VCT: "urn:x", Exp: &exp, Additional: add},
		sdjwtvc.IssueOptions{IssuerCertificate: iss.cert, Decoys: g.r.IntN(2)})
	if err != nil {
		t.Fatalf("seed %d: issue: %v", seed, err)
	}
	pres, err := sdjwtvc.Parse(compact)
	if err != nil {
		t.Fatal(err)
	}
	_, raw, err := jose.DecodeUnverified(pres.IssuerJWT)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	resolved, err := sdjwtvc.ResolveDisclosures(payload, sdjwtvc.SHA256, pres.Disclosures)
	if err != nil {
		t.Fatalf("seed %d: resolve: %v", seed, err)
	}
	var all []dcql.Path
	previewQueryPaths(resolved, nil, &all)
	if len(all) == 0 {
		return
	}
	// One to three distinct paths, each index possibly widened to a
	// wildcard.
	var claims []map[string]any
	seen := map[string]bool{}
	for range 1 + g.r.IntN(3) {
		p := slices.Clone(all[g.r.IntN(len(all))])
		for i := range p {
			if p[i].IsIndex() && g.r.IntN(2) == 0 {
				p[i] = dcql.Wildcard
			}
		}
		key, _ := json.Marshal(p)
		if seen[string(key)] {
			continue
		}
		seen[string(key)] = true
		claims = append(claims, map[string]any{"path": p})
	}
	queryJSON, err := json.Marshal(map[string]any{"credentials": []any{map[string]any{
		"id": "q", "format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []string{"urn:x"}},
		"require_cryptographic_holder_binding": false, "claims": claims,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	var q dcql.Query
	if err := json.Unmarshal(queryJSON, &q); err != nil {
		t.Fatal(err)
	}
	held := wallet.HeldCredential{Format: sdjwtvc.CredentialFormat, Credential: compact}
	preview, err := wallet.PreviewPresentation(t.Context(), q, []wallet.HeldCredential{held}, nil)
	if err != nil {
		return // the query doesn't match: nothing is presented either
	}
	vp, err := wallet.PresentCredentials(t.Context(), wallet.PresentationRequest{Query: q, Credentials: []wallet.HeldCredential{held}, Audience: "x509_hash:preview", Nonce: "n"})
	if err != nil {
		t.Fatalf("seed %d: preview succeeded but present failed: %v", seed, err)
	}
	if len(preview) != 1 || len(vp["q"]) != 1 {
		t.Fatalf("seed %d: preview %d, presentations %d", seed, len(preview), len(vp["q"]))
	}
	sentPres, err := sdjwtvc.Parse(vp["q"][0])
	if err != nil {
		t.Fatal(err)
	}
	byDigest := map[string]sdjwtvc.Disclosure{}
	for _, d := range pres.Disclosures {
		digest, err := d.Digest(sdjwtvc.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		byDigest[digest] = d
	}
	sent := map[string]bool{}
	for _, d := range sentPres.Disclosures {
		digest, err := d.Digest(sdjwtvc.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := byDigest[digest]; !ok {
			t.Fatalf("seed %d: a sent Disclosure isn't the holder's", seed)
		}
		sent[digest] = true
	}
	var leaves []previewLeaf
	previewOracleWalk(payload, nil, true, byDigest, sent, &leaves)
	pv := preview[0]
	var revealed []dcql.Path
	for _, l := range leaves {
		if !l.revealed || (l.path[0].IsKey() && previewRegistered[l.path[0].Key()]) {
			continue
		}
		revealed = append(revealed, l.path)
		if !slices.ContainsFunc(pv.Claims, func(p dcql.Path) bool { return p.Covers(l.path) }) &&
			!slices.ContainsFunc(pv.AlwaysDisclosed, func(p dcql.Path) bool { return slices.Equal(p, l.path) }) {
			t.Fatalf("seed %d: the presentation reveals %v, which the preview doesn't show (Claims %v, AlwaysDisclosed %v); credential %v", seed, l.path, pv.Claims, pv.AlwaysDisclosed, resolved)
		}
	}
	for _, p := range pv.AlwaysDisclosed {
		if !slices.ContainsFunc(revealed, func(l dcql.Path) bool { return slices.Equal(p, l) }) {
			t.Fatalf("seed %d: AlwaysDisclosed lists %v, which the presentation doesn't reveal (revealed %v); credential %v", seed, p, revealed, resolved)
		}
	}
}

func TestPreview_CoversDisclosure(t *testing.T) {
	iss := newPreviewIssuer(t)
	seeds := uint64(previewSeeds)
	if testing.Short() {
		seeds /= 10
	}
	for seed := range seeds {
		checkPreviewCoversDisclosure(t, iss, seed)
	}
}

func FuzzPreviewCoversDisclosure(f *testing.F) {
	iss := newPreviewIssuer(f)
	for seed := range uint64(16) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, seed uint64) {
		checkPreviewCoversDisclosure(t, iss, seed)
	})
}

// An object the Verifier receives empty is listed, whether it is empty
// in the credential, holds only decoy digests, or holds only claims
// the presentation doesn't send; and an array none of whose elements
// is sent, likewise.
func TestPreview_ListsContainersReceivedEmpty(t *testing.T) {
	iss := newPreviewIssuer(t)
	exp := time.Now().Add(time.Hour).Unix()
	compact, _, err := sdjwtvc.Issue(iss.key, jose.ES256, sdjwtvc.Claims{VCT: "urn:x", Exp: &exp, Additional: map[string]any{
		"literal":    map[string]any{},
		"decoy_only": sdjwtvc.WithDecoys(map[string]any{}, 2),
		"unsent":     map[string]any{"street": sdjwtvc.SD("Main St 1")},
		"elements":   []any{sdjwtvc.SDElement("DE"), sdjwtvc.SDElement("FR")},
		"asked":      sdjwtvc.SD("x"),
	}}, sdjwtvc.IssueOptions{IssuerCertificate: iss.cert})
	if err != nil {
		t.Fatal(err)
	}
	var q dcql.Query
	if err := json.Unmarshal([]byte(`{"credentials":[{"id":"q","format":"dc+sd-jwt","meta":{"vct_values":["urn:x"]},"require_cryptographic_holder_binding":false,"claims":[{"path":["asked"]}]}]}`), &q); err != nil {
		t.Fatal(err)
	}
	preview, err := wallet.PreviewPresentation(t.Context(), q, []wallet.HeldCredential{{Format: sdjwtvc.CredentialFormat, Credential: compact}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(preview) != 1 {
		t.Fatalf("preview = %v", preview)
	}
	for _, name := range []string{"literal", "decoy_only", "unsent", "elements"} {
		if !slices.ContainsFunc(preview[0].AlwaysDisclosed, func(p dcql.Path) bool { return slices.Equal(p, dcql.Path{dcql.PathKey(name)}) }) {
			t.Errorf("AlwaysDisclosed = %v, missing %s, which the Verifier receives empty", preview[0].AlwaysDisclosed, name)
		}
	}
	if len(preview[0].DisclosedAlong) != 0 {
		t.Errorf("DisclosedAlong = %v, want none: every presentation reveals these", preview[0].DisclosedAlong)
	}
}
