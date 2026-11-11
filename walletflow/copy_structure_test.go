package walletflow_test

import (
	"context"
	"errors"
	"maps"
	"slices"
	"testing"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// The copy Respond reserves is checked to disclose what Preview showed:
// a credential stored with copies that disclose differently — address's
// members their own Disclosures in one, sharing address's in the other,
// as a batch stored before copies' structure was compared could be —
// isn't presented once the copy previewed is revoked and the other
// would be sent, disclosing address.street with address.locality. Copies
// that disclose alike are presented.
func TestPresentation_RefusesCopyDisclosingOtherwise(t *testing.T) {
	fine := sdjwtvc.SD(map[string]any{"street": sdjwtvc.SD("1 Main St"), "locality": sdjwtvc.SD("Town")})
	coarse := sdjwtvc.SD(map[string]any{"street": "1 Main St", "locality": "Town"})
	for name, tc := range map[string]struct {
		second any
		want   error
	}{
		"copies disclosing alike":     {fine, nil},
		"copies disclosing otherwise": {coarse, walletflow.ErrCredentialChanged},
	} {
		t.Run(name, func(t *testing.T) {
			issued := 0
			address := func(batch []*issuer.CredentialInstance) {
				addr := fine
				if issued++; issued > 1 {
					addr = tc.second
				}
				for _, ci := range batch {
					additional := maps.Clone(ci.SDJWTClaims.Additional)
					additional["address"] = addr
					ci.SDJWTClaims.Additional = additional
				}
			}
			f := newFixture(t, walletflowtest.Options{AlterBatch: address})
			v := f.env.StartVerifier(t)
			w := f.newWalletTrusting(t, f.env.IssuerRoots, v.Trust)
			first := receive(t, f, w, walletflowtest.SDJWTConfigurationID)[0]
			second := receive(t, f, w, walletflowtest.SDJWTConfigurationID)[0]
			ctx := context.Background()
			// One credential, its copies the two received.
			if err := f.store.Update(ctx, first.ID, func(c *walletflow.StoredCredential) error {
				c.Copies = []walletflow.CredentialCopy{first.Copies[0], second.Copies[0]}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			q := f.env.SDJWTQuery(t, "pid")
			q.Claims = []dcql.ClaimsQuery{{Path: dcql.KeyPath("address", "locality")}}
			_, link := v.Begin(t, dcql.Query{Credentials: []dcql.CredentialQuery{q}})
			p, err := w.StartPresentation(ctx, link)
			if err != nil {
				t.Fatal(err)
			}
			sel := walletflow.Selection{"pid": {first.ID}}
			shown, err := p.Preview(ctx, sel)
			if err != nil {
				t.Fatal(err)
			}
			street := dcql.KeyPath("address", "street")
			if slices.ContainsFunc(shown[0].AlwaysDisclosed, func(p dcql.Path) bool { return slices.Equal(p, street) }) {
				t.Fatalf("Preview showed %v, want the first copy, without address.street", shown[0].AlwaysDisclosed)
			}
			// CheckStatus finds the copy shown revoked: Respond reserves the other.
			if err := f.store.Update(ctx, first.ID, func(c *walletflow.StoredCredential) error {
				c.Copies[0].Revoked = true
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := p.Respond(ctx, sel); !errors.Is(err, tc.want) {
				t.Fatalf("Respond = %v, want %v", err, tc.want)
			}
			if tc.want == nil {
				return
			}
			if c, err := f.store.Get(ctx, first.ID); err != nil || c.Copies[1].Presented {
				t.Errorf("the copy not sent is left presented: %v", err)
			}
		})
	}
}
