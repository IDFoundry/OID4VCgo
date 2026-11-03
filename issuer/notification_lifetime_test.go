package issuer_test

import (
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/issuer"
)

// Under production, a Notification Endpoint's records expire: each
// names the client and subject, and one that never expires is kept,
// and never swept, for ever.
func TestNewProductionRequiresNotificationLifetime(t *testing.T) {
	cfg, deps := productionIssuer(t)
	cfg.Limits.NotificationLifetime = 0
	if _, err := issuer.New(cfg, deps); err == nil || !strings.Contains(err.Error(), "notification_lifetime") {
		t.Fatalf("New with no notification lifetime = %v, want it refused", err)
	}
	cfg.Assurance = issuer.AssuranceDevelopment
	if _, err := issuer.New(cfg, deps); err != nil {
		t.Errorf("New under development with no notification lifetime: %v", err)
	}
}
