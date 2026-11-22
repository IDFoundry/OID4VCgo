package walletflow_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/internal/teststatuslist"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// StatusMaxAge refuses a status list or an identifier list signed
// longer ago, each kind alike, however far off its exp is, and passes
// one signed within it. teststatuslist signs each list a minute before
// it's served, valid for an hour.
func TestCheckStatus_MaxAge(t *testing.T) {
	signer := teststatuslist.NewSigner(t)
	statusOf := map[string]func(statusURI, idsURI string) mdoc.Status{
		"status list": func(statusURI, _ string) mdoc.Status {
			return mdoc.Status{StatusList: &mdoc.StatusListRef{Idx: 3, URI: statusURI, Certificate: signer.CA.Raw}}
		},
		"identifier list": func(_, idsURI string) mdoc.Status {
			return mdoc.Status{IdentifierList: &mdoc.IdentifierListRef{ID: []byte{2}, URI: idsURI, Certificate: signer.CA.Raw}}
		},
	}
	for kind, status := range statusOf {
		for maxAge, refused := range map[time.Duration]bool{30 * time.Second: true, time.Hour: false, 0: false} {
			statusURI, idsURI, client := signer.ServeLists(t, teststatuslist.WellFormed)
			c := mdocCredential(t, time.Now().Add(time.Hour), testmdoc.WithMSOStatus(t, testmdoc.Issue(t), status(statusURI, idsURI)).IssuerSigned)
			cfg := walletflow.Config{Development: true, StatusMaxAge: maxAge}
			checked, err := walletHoldingWith(t, cfg, client, c).CheckStatus(context.Background(), c.ID)
			switch {
			case refused && (err == nil || !strings.Contains(err.Error(), "over the 30s allowed")):
				t.Errorf("%s, StatusMaxAge %s: CheckStatus = %+v, %v, want it refused for its age", kind, maxAge, checked.Status, err)
			case !refused && (err != nil || checked.Status.Value != walletflow.StatusValid):
				t.Errorf("%s, StatusMaxAge %s: CheckStatus = %+v, %v, want valid", kind, maxAge, checked.Status, err)
			}
		}
	}
}
