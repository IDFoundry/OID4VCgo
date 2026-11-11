package walletflow

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// structureIssuer issues SD-JWT VCs with additional claims, for
// comparing their structure; also returns the claims they resolve to.
func structureIssuer(t *testing.T) func(additional map[string]any, opts sdjwtvc.IssueOptions, exp int64) (string, map[string]any) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return func(additional map[string]any, opts sdjwtvc.IssueOptions, exp int64) (string, map[string]any) {
		t.Helper()
		c, _, err := sdjwtvc.Issue(key, jose.ES256, sdjwtvc.Claims{VCT: "urn:x", Exp: &exp, Additional: additional}, opts)
		if err != nil {
			t.Fatal(err)
		}
		claims, _, err := sdjwtvc.Verify(c, &key.PublicKey, jose.ES256, sdjwtvc.VerifyOptions{RequireKeyBinding: sdjwtvc.KeyBindingNotRequired})
		if err != nil {
			t.Fatal(err)
		}
		return c, claims
	}
}

// Copies of a batch must have the same claim structure: one that
// always discloses birthdate, where another makes it selectively
// disclosable, would send what the holder's preview didn't show; so
// would one disclosing within one Disclosure what another discloses
// separately, at any depth, in arrays too. Per-copy claims and decoys
// may differ.
func TestSameStructure(t *testing.T) {
	issue := structureIssuer(t)
	exp := time.Now().Add(time.Hour).Unix()
	base := func(birthdate any) map[string]any {
		return map[string]any{"given_name": sdjwtvc.SD("A"), "birthdate": birthdate}
	}
	selective, _ := issue(base(sdjwtvc.SD("1990-01-01")), sdjwtvc.IssueOptions{}, exp)
	same, _ := issue(base(sdjwtvc.SD("1990-01-01")), sdjwtvc.IssueOptions{Decoys: 3, NestedDecoys: func() (int, error) { return 2, nil }}, exp+3600)
	if !sameStructure(selective, same) {
		t.Error("copies differing only in decoys and exp were refused")
	}
	for name, tc := range map[string]struct{ a, b map[string]any }{
		"plaintext beside selectively disclosable": {base(sdjwtvc.SD("1990-01-01")), base("1990-01-01")},
		"members within one Disclosure beside their own": {
			map[string]any{"address": sdjwtvc.SD(map[string]any{"street": sdjwtvc.SD("1 Main St"), "locality": sdjwtvc.SD("Town")})},
			map[string]any{"address": sdjwtvc.SD(map[string]any{"street": "1 Main St", "locality": "Town"})},
		},
		"a deeper member plaintext": {
			map[string]any{"a": map[string]any{"b": sdjwtvc.SD(map[string]any{"c": sdjwtvc.SD("x")})}},
			map[string]any{"a": map[string]any{"b": sdjwtvc.SD(map[string]any{"c": "x"})}},
		},
		"array elements disclosed differently": {
			map[string]any{"nationalities": []any{sdjwtvc.SDElement("DE"), "FR"}},
			map[string]any{"nationalities": []any{"DE", sdjwtvc.SDElement("FR")}},
		},
		"an array's elements within one Disclosure": {
			map[string]any{"nationalities": sdjwtvc.SD([]any{sdjwtvc.SDElement("DE"), sdjwtvc.SDElement("FR")})},
			map[string]any{"nationalities": sdjwtvc.SD([]any{"DE", "FR"})},
		},
	} {
		a, _ := issue(tc.a, sdjwtvc.IssueOptions{}, exp)
		b, _ := issue(tc.b, sdjwtvc.IssueOptions{}, exp)
		if sameStructure(a, b) {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Two copies whose address claim is one Disclosure in both, but whose
// members are their own Disclosures in only one, resolve to the same
// claims and leave the same claims plaintext in the Issuer JWT; but
// asked for address.locality, one discloses address.street too. Such a
// batch is refused.
func TestCopyDiffers_NestedStructure(t *testing.T) {
	issue := structureIssuer(t)
	exp := time.Now().Add(time.Hour).Unix()
	fine, fineClaims := issue(map[string]any{"address": sdjwtvc.SD(map[string]any{"street": sdjwtvc.SD("1 Main St"), "locality": sdjwtvc.SD("Town")})}, sdjwtvc.IssueOptions{}, exp)
	coarse, coarseClaims := issue(map[string]any{"address": sdjwtvc.SD(map[string]any{"street": "1 Main St", "locality": "Town"})}, sdjwtvc.IssueOptions{}, exp)

	q := dcql.Query{Credentials: []dcql.CredentialQuery{{ID: "q", Format: sdjwtvc.CredentialFormat, RequireCryptographicHolderBinding: new(bool),
		Meta:   json.RawMessage(`{"vct_values":["urn:x"]}`),
		Claims: []dcql.ClaimsQuery{{Path: dcql.Path{dcql.PathKey("address"), dcql.PathKey("locality")}}}}}}
	disclosed := func(c string) []dcql.Path {
		t.Helper()
		prev, err := wallet.PreviewPresentation(context.Background(), q, []wallet.HeldCredential{{Format: sdjwtvc.CredentialFormat, Credential: c}}, nil)
		if err != nil || len(prev) != 1 {
			t.Fatalf("PreviewPresentation = %v, %v", prev, err)
		}
		return prev[0].AlwaysDisclosed
	}
	street := dcql.Path{dcql.PathKey("address"), dcql.PathKey("street")}
	hasStreet := func(paths []dcql.Path) bool {
		return slices.ContainsFunc(paths, func(p dcql.Path) bool { return slices.Equal(p, street) })
	}
	if hasStreet(disclosed(fine)) || !hasStreet(disclosed(coarse)) {
		t.Fatalf("the copies disclose alike: %v, %v", disclosed(fine), disclosed(coarse))
	}
	if d := copyDiffers(wallet.VerifiedIssuedCredential{Claims: fineClaims}, wallet.VerifiedIssuedCredential{Claims: coarseClaims}, fine, coarse); d != "claims differ" {
		t.Errorf("copyDiffers = %q, want claims differ", d)
	}
}
