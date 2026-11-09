package walletflow_test

import (
	"context"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// A batch whose copies differ is refused and none of it stored: a copy
// without the status list entry the others have couldn't be revoked
// with them, and a copy with other claims would present what the
// holder didn't see.
func TestIssuance_RefusesCopiesThatDiffer(t *testing.T) {
	for name, tc := range map[string]struct {
		alter func(batch []*issuer.CredentialInstance)
		want  string
	}{
		"a copy without a status": {func(batch []*issuer.CredentialInstance) { batch[1].SDJWTClaims.Status = nil }, "status differs"},
		"a copy with other claims": {func(batch []*issuer.CredentialInstance) {
			additional := map[string]any{}
			for k, v := range batch[2].SDJWTClaims.Additional {
				additional[k] = v
			}
			additional["given_name"] = sdjwtvc.SD("Mallory")
			batch[2].SDJWTClaims.Additional = additional
		}, "claims differ"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, walletflowtest.Options{BatchSize: 3, AlterBatch: tc.alter})
			ctx := context.Background()
			s, err := f.w.StartIssuance(ctx, f.env.PreAuthorizedOffer(t, "493536", walletflowtest.SDJWTConfigurationID))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = s.Close(ctx) }()
			if err := s.RedeemPreAuthorizedCode(ctx, "493536"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.RequestCredentials(ctx); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("RequestCredentials = %v, want %q", err, tc.want)
			}
			if held, err := f.store.List(ctx); err != nil || len(held) != 0 {
				t.Errorf("stored %d credentials, %v; want none", len(held), err)
			}
		})
	}
}
