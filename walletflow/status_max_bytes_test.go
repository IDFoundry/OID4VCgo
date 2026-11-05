package walletflow_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/identifierlist"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/internal/teststatuslist"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// StatusMaxBytes bounds the status lists CheckStatus reads, and
// IdentifierListMaxBytes the identifier lists, each apart from the
// other; New refuses either outside its package's limits.
func TestCheckStatus_MaxBytes(t *testing.T) {
	signer := teststatuslist.NewSigner(t)
	ctx := context.Background()
	for name, tc := range map[string]struct {
		cfg  walletflow.Config
		want string // "" for refused
	}{
		"defaults":                   {walletflow.Config{Development: true}, walletflow.StatusValid},
		"status list over the limit": {walletflow.Config{Development: true, StatusMaxBytes: 64}, ""},
		"identifier list over it":    {walletflow.Config{Development: true, IdentifierListMaxBytes: 64}, ""},
		"both raised":                {walletflow.Config{Development: true, StatusMaxBytes: 8 << 20, IdentifierListMaxBytes: 8 << 20}, walletflow.StatusValid},
	} {
		t.Run(name, func(t *testing.T) {
			statusURI, idsURI, client := signer.ServeLists(t, teststatuslist.WellFormed, []byte{7})
			status := mdoc.Status{
				StatusList:     &mdoc.StatusListRef{Idx: 3, URI: statusURI, Certificate: signer.CA.Raw},
				IdentifierList: &mdoc.IdentifierListRef{ID: []byte{2}, URI: idsURI, Certificate: signer.CA.Raw},
			}
			c := mdocCredential(t, time.Now().Add(time.Hour), testmdoc.WithMSOStatus(t, testmdoc.Issue(t), status).IssuerSigned)
			checked, err := walletHoldingWith(t, tc.cfg, client, c).CheckStatus(ctx, c.ID)
			switch {
			case tc.want == "" && (err == nil || !strings.Contains(err.Error(), "exceeds 64 bytes")):
				t.Errorf("CheckStatus = %+v, %v, want it refused for its size", checked.Status, err)
			case tc.want != "" && (err != nil || checked.Status.Value != tc.want):
				t.Errorf("CheckStatus = %+v, %v, want %s", checked.Status, err, tc.want)
			}
		})
	}

	for name, cfg := range map[string]walletflow.Config{
		"negative StatusMaxBytes":         {Development: true, StatusMaxBytes: -1},
		"StatusMaxBytes over the limit":   {Development: true, StatusMaxBytes: statuslist.MaxTokenBytesLimit + 1},
		"IdentifierListMaxBytes negative": {Development: true, IdentifierListMaxBytes: -1},
		"IdentifierListMaxBytes over it":  {Development: true, IdentifierListMaxBytes: identifierlist.MaxTokenBytesLimit + 1},
	} {
		_, err := walletflow.New(cfg, walletflow.Dependencies{Keys: walletflow.NewMemoryKeyStore(), Credentials: walletflow.NewMemoryCredentialStore()})
		if err == nil || !strings.Contains(err.Error(), "not between 0 and") {
			t.Errorf("%s: New = %v", name, err)
		}
	}
}
