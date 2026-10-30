package mdoc

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/cose"
)

const decoyTestNamespace = "org.iso.18013.5.1"

// issueWithDecoys issues f's claims with Claims.Decoys set to decoys
// under alg, over the wire and back, as a holder receives them.
func issueWithDecoys(t *testing.T, f fixture, decoys map[string]int, alg DigestAlg) (Claims, IssuerSigned) {
	t.Helper()
	claims := f.claims
	claims.Decoys = decoys
	signed, err := Issue(f.issuerKey, cose.ES256, claims, IssueOptions{X5Chain: [][]byte{f.cert}, DigestAlg: alg})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	wire, err := signed.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	received, err := UnmarshalIssuerSigned(wire)
	if err != nil {
		t.Fatalf("UnmarshalIssuerSigned: %v", err)
	}
	return claims, received
}

// Claims.Decoys adds exactly that many digests to the namespace's
// valueDigests, of the digest algorithm's length, under DigestIDs no
// data element uses; the credential verifies in full and with only
// some of its elements presented, the reader seeing nothing of the
// decoys.
func TestIssue_DecoyDigests(t *testing.T) {
	f := newFixture(t)
	for alg, size := range map[DigestAlg]int{SHA256: 32, SHA384: 48, SHA512: 64} {
		t.Run(string(alg), func(t *testing.T) {
			claims, signed := issueWithDecoys(t, f, map[string]int{decoyTestNamespace: 5}, alg)
			mso, err := IssuerAuthMSO(signed)
			if err != nil {
				t.Fatal(err)
			}
			digests := mso.ValueDigests[decoyTestNamespace]
			if len(digests) != 2+5 {
				t.Fatalf("valueDigests has %d entries, want 2 elements + 5 decoys", len(digests))
			}
			for _, item := range signed.NameSpaces[decoyTestNamespace] {
				if _, ok := digests[item.DigestID]; !ok {
					t.Errorf("element %q's DigestID %d has no digest", item.ElementIdentifier, item.DigestID)
				}
			}
			for id, d := range digests {
				if id >= maxDigestID || len(d) != size {
					t.Errorf("digest %d: %d bytes, want a DigestID below 2^31 and %d bytes", id, len(d), size)
				}
			}

			now := func() time.Time { return claims.Signed.Add(time.Hour) }
			verified, err := Verify(signed, claims.DocType, &f.issuerKey.PublicKey, cose.ES256, VerifyOptions{Now: now})
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if got := len(verified.NameSpaces[decoyTestNamespace]); got != 2 {
				t.Errorf("verified %d elements, want the 2 issued", got)
			}
			partial := signed.SelectNameSpaces([][2]string{{decoyTestNamespace, "given_name"}})
			verified, err = Verify(partial, claims.DocType, &f.issuerKey.PublicKey, cose.ES256, VerifyOptions{Now: now})
			if err != nil {
				t.Fatalf("Verify of one element: %v", err)
			}
			if got := verified.NameSpaces[decoyTestNamespace]; len(got) != 1 || got["given_name"] != "John" {
				t.Errorf("verified %v, want given_name alone", got)
			}
		})
	}
}

// Decoy digests are distinct from one another, and fresh each time.
func TestIssue_DecoyDigestsAreRandom(t *testing.T) {
	f := newFixture(t)
	seen := map[string]bool{}
	for range 2 {
		_, signed := issueWithDecoys(t, f, map[string]int{decoyTestNamespace: 50}, SHA256)
		mso, err := IssuerAuthMSO(signed)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range mso.ValueDigests[decoyTestNamespace] {
			if seen[string(d)] {
				t.Fatalf("digest %x repeats", d)
			}
			seen[string(d)] = true
		}
	}
}

// Issue refuses decoys it can't honor: for a namespace the claims
// haven't, a count outside 0..MaxDecoys, or one that takes the
// namespace's valueDigests past what this package decodes, or an
// IssuerAuth past the size Verify accepts.
func TestIssue_RejectsInvalidDecoys(t *testing.T) {
	f := newFixture(t)
	many := make(map[string]interface{}, MaxCBORContainerItems)
	for i := range MaxCBORContainerItems - MaxDecoys + 1 {
		many[fmt.Sprintf("e%d", i)] = i
	}
	for name, tc := range map[string]struct {
		decoys map[string]int
		mutate func(*Claims)
		want   string
	}{
		"unknown namespace": {decoys: map[string]int{"org.example.other": 1}, want: "hasn't"},
		"negative":          {decoys: map[string]int{decoyTestNamespace: -1}, want: "outside"},
		"too many":          {decoys: map[string]int{decoyTestNamespace: MaxDecoys + 1}, want: "outside"},
		"past the decoder": {
			decoys: map[string]int{"org.example.big": MaxDecoys},
			mutate: func(c *Claims) {
				c.NameSpaces = map[string]map[string]interface{}{"org.example.big": many}
			},
			want: "digests",
		},
		"past what Verify accepts": {
			decoys: map[string]int{decoyTestNamespace: MaxDecoys, "org.example.second": MaxDecoys},
			mutate: func(c *Claims) {
				c.NameSpaces = map[string]map[string]interface{}{
					decoyTestNamespace:   c.NameSpaces[decoyTestNamespace],
					"org.example.second": {"x": 1},
				}
			},
			want: "Verify accepts",
		},
	} {
		claims := f.claims
		if tc.mutate != nil {
			tc.mutate(&claims)
		}
		claims.Decoys = tc.decoys
		_, err := Issue(f.issuerKey, cose.ES256, claims, IssueOptions{X5Chain: [][]byte{f.cert}})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: Issue = %v, want an error mentioning %q", name, err, tc.want)
		}
	}
}
